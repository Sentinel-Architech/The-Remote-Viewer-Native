//! HYDRA — on-device safety incident protocol.
//!
//! Pure Rust, std-only. Implements the NIST SP 800-61 incident lifecycle
//! for the device itself:
//!
//! 1. **Preparation** — readiness checks; an [`Incident`] opens here.
//! 2. **Detection & Analysis** — [`SpySignal`] heuristics score
//!    platform-supplied observations; [`seal_evidence`] hashes evidence
//!    with SHA-512 and holds the bytes in memory only.
//! 3. **Containment / Eradication / Recovery** — the threat is isolated
//!    locally; [`Incident::censored_packet`] builds the ONLY thing ever
//!    allowed off-device: incident type, timestamp, evidence hash, a
//!    short description, and optional caller-supplied coarse location.
//! 4. **Post-Incident Activity** — every state transition appends to a
//!    hash-chained, tamper-evident audit log; [`Incident::gate_check`]
//!    must pass before normal operation resumes.
//!
//! ## Privacy rule (hard)
//!
//! The original evidence NEVER leaves the device. The [`OutboundPacket`]
//! carries no raw evidence bytes and no identifiers beyond what the
//! caller explicitly passes in. This module never touches GPS, the
//! network, or any sensor — the platform layer feeds it observations
//! and coarse location strings; it only scores, seals, and chains.
//!
//! Timestamps are caller-supplied `u64` seconds and are informational
//! only — there is no trusted on-device time source, so no skew or
//! freshness enforcement is attempted.
//!
//! NOT externally audited — like the rest of `trv_core`, this is
//! implemented from first principles and unit-tested, but no
//! independent security audit has happened. Do not rely on this for
//! production safety workflows until that audit happens.

use crate::crypto::ed25519::sha512::digest;

/// Maximum description length for a censored outbound packet, in
/// Unicode scalar values (chars), not bytes.
pub const MAX_DESCRIPTION_CHARS: usize = 280;

/// Maximum raw evidence size accepted for sealing (8 MiB). Larger
/// inputs fail closed rather than being silently truncated.
pub const MAX_EVIDENCE_BYTES: usize = 8 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Every way HYDRA can refuse to proceed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HydraError {
    /// A state-machine jump that is not on the allowed path.
    InvalidTransition,
    /// The censored-packet description exceeded 280 chars.
    DescriptionTooLong,
    /// Evidence input exceeded [`MAX_EVIDENCE_BYTES`].
    EvidenceTooLarge,
    /// Recomputed evidence hash did not match the seal.
    EvidenceTampered,
    /// No evidence has been sealed yet (e.g. censor called pre-detect).
    NoEvidence,
    /// An audit-log link failed to validate.
    ChainBroken,
    /// The audit log has no entries at all.
    EmptyLog,
}

impl std::fmt::Display for HydraError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HydraError::InvalidTransition => f.write_str("invalid incident state transition"),
            HydraError::DescriptionTooLong => f.write_str("description exceeds 280 characters"),
            HydraError::EvidenceTooLarge => f.write_str("evidence exceeds 8 MiB"),
            HydraError::EvidenceTampered => f.write_str("evidence failed integrity check"),
            HydraError::NoEvidence => f.write_str("no sealed evidence for this incident"),
            HydraError::ChainBroken => f.write_str("audit chain link failed validation"),
            HydraError::EmptyLog => f.write_str("audit log is empty"),
        }
    }
}

impl std::error::Error for HydraError {}

// ---------------------------------------------------------------------------
// Incident types
// ---------------------------------------------------------------------------

/// The four incident classes HYDRA handles. Nothing else is in scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncidentType {
    /// Suspicious sensor / permission behavior (mic, camera, …).
    SpywareSignal,
    /// Child-safety trigger: suspected exploitation attempt.
    ExploitationAttempt,
    /// Suspected unauthorized access attempt.
    IntrusionAttempt,
    /// Local integrity violation (binary / vault / audit tamper).
    TamperingDetected,
}

impl IncidentType {
    fn code(self) -> u8 {
        match self {
            IncidentType::SpywareSignal => 0x01,
            IncidentType::ExploitationAttempt => 0x02,
            IncidentType::IntrusionAttempt => 0x03,
            IncidentType::TamperingDetected => 0x04,
        }
    }

    /// Short stable label for logs and packets.
    pub fn label(self) -> &'static str {
        match self {
            IncidentType::SpywareSignal => "spyware-signal",
            IncidentType::ExploitationAttempt => "exploitation-attempt",
            IncidentType::IntrusionAttempt => "intrusion-attempt",
            IncidentType::TamperingDetected => "tampering-detected",
        }
    }
}

// ---------------------------------------------------------------------------
// Evidence seal
// ---------------------------------------------------------------------------

/// Evidence sealed on-device: SHA-512 over
/// `type_code || timestamp_be || evidence_bytes`, plus the bytes held
/// in memory only. The bytes are deliberately NOT exposed — the caller
/// already owns them and decides vault persistence; this type is the
/// integrity wrapper, not a courier.
pub struct SealedEvidence {
    incident_type: IncidentType,
    timestamp: u64,
    hash: [u8; 64],
    evidence: Vec<u8>,
}

impl SealedEvidence {
    /// Hash of the sealed evidence (safe to log / transmit).
    pub fn hash(&self) -> &[u8; 64] {
        &self.hash
    }

    /// Incident class this evidence belongs to.
    pub fn incident_type(&self) -> IncidentType {
        self.incident_type
    }

    /// Caller-supplied timestamp (informational only).
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    /// Length of the held evidence, without exposing it.
    pub fn len(&self) -> usize {
        self.evidence.len()
    }

    /// Recompute the hash and compare. Fails closed on any mismatch.
    pub fn verify(&self) -> Result<(), HydraError> {
        let recomputed = seal_hash(self.incident_type, self.timestamp, &self.evidence);
        if recomputed == self.hash {
            Ok(())
        } else {
            Err(HydraError::EvidenceTampered)
        }
    }
}

fn seal_hash(incident_type: IncidentType, timestamp: u64, evidence: &[u8]) -> [u8; 64] {
    let mut preimage = Vec::with_capacity(1 + 8 + evidence.len());
    preimage.push(incident_type.code());
    preimage.extend_from_slice(&timestamp.to_be_bytes());
    preimage.extend_from_slice(evidence);
    digest(&preimage)
}

/// Seal evidence for an incident. Fails closed when the input exceeds
/// [`MAX_EVIDENCE_BYTES`].
pub fn seal_evidence(
    incident_type: IncidentType,
    timestamp: u64,
    evidence: &[u8],
) -> Result<SealedEvidence, HydraError> {
    if evidence.len() > MAX_EVIDENCE_BYTES {
        return Err(HydraError::EvidenceTooLarge);
    }
    Ok(SealedEvidence {
        incident_type,
        timestamp,
        hash: seal_hash(incident_type, timestamp, evidence),
        evidence: evidence.to_vec(),
    })
}

// ---------------------------------------------------------------------------
// Censored outbound packet
// ---------------------------------------------------------------------------

/// The ONLY data ever allowed off-device for an incident: type,
/// timestamp, evidence hash, a short caller-written description, and
/// an optional caller-supplied coarse region string. No raw evidence
/// bytes. No device identifiers. No fine location — the module never
/// sees GPS; the caller decides what "coarse" means and whether the
/// user consented.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundPacket {
    incident_type: IncidentType,
    timestamp: u64,
    evidence_hash: [u8; 64],
    description: String,
    coarse_location: Option<String>,
}

impl OutboundPacket {
    /// Build the censored packet from sealed evidence. The description
    /// is capped at [`MAX_DESCRIPTION_CHARS`] chars; longer input fails
    /// closed instead of being truncated (truncation could mangle
    /// meaning — the caller rewrites and retries).
    pub fn censor(
        sealed: &SealedEvidence,
        description: &str,
        coarse_location: Option<&str>,
    ) -> Result<Self, HydraError> {
        if description.chars().count() > MAX_DESCRIPTION_CHARS {
            return Err(HydraError::DescriptionTooLong);
        }
        Ok(OutboundPacket {
            incident_type: sealed.incident_type,
            timestamp: sealed.timestamp,
            evidence_hash: sealed.hash,
            description: description.to_string(),
            coarse_location: coarse_location.map(|s| s.to_string()),
        })
    }

    pub fn incident_type(&self) -> IncidentType {
        self.incident_type
    }
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }
    pub fn evidence_hash(&self) -> &[u8; 64] {
        &self.evidence_hash
    }
    pub fn description(&self) -> &str {
        &self.description
    }
    pub fn coarse_location(&self) -> Option<&str> {
        self.coarse_location.as_deref()
    }

    /// Minimal binary encoding for future transport. Length-prefixed,
    /// hand-rolled, no dependencies:
    /// `magic("HYDR") || version(0x01) || type(1) || ts(8 BE) ||
    /// hash(64) || desc_len(4 BE) || desc || loc_flag(1) ||
    /// [loc_len(4 BE) || loc]`.
    pub fn encode(&self) -> Vec<u8> {
        let desc = self.description.as_bytes();
        let loc = self.coarse_location.as_ref().map(|s| s.as_bytes());
        let mut out = Vec::with_capacity(4 + 1 + 1 + 8 + 64 + 4 + desc.len() + 1 + 8);
        out.extend_from_slice(b"HYDR");
        out.push(0x01);
        out.push(self.incident_type.code());
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(&self.evidence_hash);
        out.extend_from_slice(&(desc.len() as u32).to_be_bytes());
        out.extend_from_slice(desc);
        match loc {
            Some(l) => {
                out.push(1);
                out.extend_from_slice(&(l.len() as u32).to_be_bytes());
                out.extend_from_slice(l);
            }
            None => out.push(0),
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Incident lifecycle (NIST SP 800-61)
// ---------------------------------------------------------------------------

/// Lifecycle states. Strictly linear — any other jump fails closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncidentState {
    Preparation,
    Detected,
    Analyzed,
    Contained,
    Recovered,
    Closed,
}

impl IncidentState {
    fn label(self) -> &'static str {
        match self {
            IncidentState::Preparation => "preparation",
            IncidentState::Detected => "detected",
            IncidentState::Analyzed => "analyzed",
            IncidentState::Contained => "contained",
            IncidentState::Recovered => "recovered",
            IncidentState::Closed => "closed",
        }
    }

    /// The single legal successor of each state, if any.
    fn next(self) -> Option<IncidentState> {
        match self {
            IncidentState::Preparation => Some(IncidentState::Detected),
            IncidentState::Detected => Some(IncidentState::Analyzed),
            IncidentState::Analyzed => Some(IncidentState::Contained),
            IncidentState::Contained => Some(IncidentState::Recovered),
            IncidentState::Recovered => Some(IncidentState::Closed),
            IncidentState::Closed => None,
        }
    }
}

/// One link in the tamper-evident audit chain.
/// `entry_hash = SHA-512(prev_hash || entry_bytes)` where entry_bytes
/// is `seq(8 BE) || from_len(1) || from || to_len(1) || to ||
/// timestamp(8 BE) || note_len(4 BE) || note`.
#[derive(Debug, Clone)]
pub struct AuditEntry {
    seq: u64,
    from: IncidentState,
    to: IncidentState,
    timestamp: u64,
    note: String,
    prev_hash: [u8; 64],
    entry_hash: [u8; 64],
}

impl AuditEntry {
    fn entry_bytes(&self) -> Vec<u8> {
        let from = self.from.label().as_bytes();
        let to = self.to.label().as_bytes();
        let note = self.note.as_bytes();
        let mut b = Vec::with_capacity(8 + 1 + from.len() + 1 + to.len() + 8 + 4 + note.len());
        b.extend_from_slice(&self.seq.to_be_bytes());
        b.push(from.len() as u8);
        b.extend_from_slice(from);
        b.push(to.len() as u8);
        b.extend_from_slice(to);
        b.extend_from_slice(&self.timestamp.to_be_bytes());
        b.extend_from_slice(&(note.len() as u32).to_be_bytes());
        b.extend_from_slice(note);
        b
    }

    fn compute_hash(prev_hash: &[u8; 64], entry_bytes: &[u8]) -> [u8; 64] {
        let mut preimage = Vec::with_capacity(64 + entry_bytes.len());
        preimage.extend_from_slice(prev_hash);
        preimage.extend_from_slice(entry_bytes);
        digest(&preimage)
    }
}

/// The tamper-evident audit log. Append-only; verification walks the
/// whole chain.
#[derive(Debug, Clone, Default)]
pub struct AuditLog {
    entries: Vec<AuditEntry>,
}

impl AuditLog {
    /// Append a transition. The caller has already validated the jump.
    fn append(&mut self, from: IncidentState, to: IncidentState, timestamp: u64, note: &str) {
        let prev_hash = self
            .entries
            .last()
            .map(|e| e.entry_hash)
            .unwrap_or([0u8; 64]); // genesis links to zero
        let mut entry = AuditEntry {
            seq: self.entries.len() as u64,
            from,
            to,
            timestamp,
            note: note.to_string(),
            prev_hash,
            entry_hash: [0u8; 64],
        };
        let bytes = entry.entry_bytes();
        entry.entry_hash = AuditEntry::compute_hash(&prev_hash, &bytes);
        self.entries.push(entry);
    }

    /// Number of entries (genesis counts as one).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Verify every link: recompute each entry hash from its recorded
    /// `prev_hash` + entry bytes, and check each `prev_hash` matches
    /// the previous entry's hash (genesis must link to zero).
    pub fn verify_chain(&self) -> Result<(), HydraError> {
        if self.entries.is_empty() {
            return Err(HydraError::EmptyLog);
        }
        let mut expected_prev = [0u8; 64];
        for e in &self.entries {
            if e.prev_hash != expected_prev {
                return Err(HydraError::ChainBroken);
            }
            let bytes = e.entry_bytes();
            if AuditEntry::compute_hash(&e.prev_hash, &bytes) != e.entry_hash {
                return Err(HydraError::ChainBroken);
            }
            expected_prev = e.entry_hash;
        }
        Ok(())
    }
}

/// A safety incident moving through the NIST SP 800-61 lifecycle.
pub struct Incident {
    incident_type: IncidentType,
    state: IncidentState,
    sealed: Option<SealedEvidence>,
    audit: AuditLog,
}

impl Incident {
    /// Open an incident in Preparation with a genesis audit entry.
    pub fn new(incident_type: IncidentType, timestamp: u64) -> Self {
        let mut audit = AuditLog::default();
        audit.append(
            IncidentState::Preparation,
            IncidentState::Preparation,
            timestamp,
            "incident opened",
        );
        Incident {
            incident_type,
            state: IncidentState::Preparation,
            sealed: None,
            audit,
        }
    }

    pub fn incident_type(&self) -> IncidentType {
        self.incident_type
    }
    pub fn state(&self) -> IncidentState {
        self.state
    }
    pub fn audit(&self) -> &AuditLog {
        &self.audit
    }

    fn transition(
        &mut self,
        to: IncidentState,
        timestamp: u64,
        note: &str,
    ) -> Result<(), HydraError> {
        match self.state.next() {
            Some(next) if next == to => {
                self.audit.append(self.state, to, timestamp, note);
                self.state = to;
                Ok(())
            }
            _ => Err(HydraError::InvalidTransition),
        }
    }

    /// Detection: seal the evidence and move Preparation → Detected.
    /// The audit entry records the evidence HASH only — never bytes.
    pub fn detect(&mut self, evidence: &[u8], timestamp: u64) -> Result<(), HydraError> {
        let sealed = seal_evidence(self.incident_type, timestamp, evidence)?;
        let mut hash_hex = [0u8; 128];
        for (i, b) in sealed.hash.iter().enumerate() {
            let hi = b"0123456789abcdef"[(b >> 4) as usize];
            let lo = b"0123456789abcdef"[(b & 0x0f) as usize];
            hash_hex[2 * i] = hi;
            hash_hex[2 * i + 1] = lo;
        }
        let note = format!(
            "detected; evidence sha512={}",
            String::from_utf8_lossy(&hash_hex)
        );
        self.sealed = Some(sealed);
        self.transition(IncidentState::Detected, timestamp, &note)
    }

    /// Analysis complete: Detected → Analyzed.
    pub fn analyze(&mut self, timestamp: u64, note: &str) -> Result<(), HydraError> {
        self.transition(IncidentState::Analyzed, timestamp, note)
    }

    /// Threat isolated locally: Analyzed → Contained.
    pub fn contain(&mut self, timestamp: u64, note: &str) -> Result<(), HydraError> {
        self.transition(IncidentState::Contained, timestamp, note)
    }

    /// Recovery done: Contained → Recovered.
    pub fn recover(&mut self, timestamp: u64, note: &str) -> Result<(), HydraError> {
        self.transition(IncidentState::Recovered, timestamp, note)
    }

    /// Post-incident review done: Recovered → Closed.
    pub fn close(&mut self, timestamp: u64, note: &str) -> Result<(), HydraError> {
        self.transition(IncidentState::Closed, timestamp, note)
    }

    /// Build the censored outbound packet. Fails closed if no evidence
    /// has been sealed yet.
    pub fn censored_packet(
        &self,
        description: &str,
        coarse_location: Option<&str>,
    ) -> Result<OutboundPacket, HydraError> {
        match &self.sealed {
            Some(s) => OutboundPacket::censor(s, description, coarse_location),
            None => Err(HydraError::NoEvidence),
        }
    }

    /// Integrity gate: the audit chain must be unbroken before normal
    /// operation resumes post-incident.
    pub fn gate_check(&self) -> Result<(), HydraError> {
        self.audit.verify_chain()
    }
}

// ---------------------------------------------------------------------------
// Spy-detection hooks (pure logic — no hardware access)
// ---------------------------------------------------------------------------

/// One bundle of platform observations. The platform layer fills this
/// in from real sensor/permission state; this module only scores it.
#[derive(Debug, Clone, Copy, Default)]
pub struct Observation {
    /// Microphone active with no user-visible cause.
    pub mic_active_unexpected: bool,
    /// Camera active with no user-visible cause.
    pub camera_active_unexpected: bool,
    /// A dangerous permission was granted without a user-visible prompt.
    pub permission_escalated_silently: bool,
    /// Large background network burst shortly after sensor activation.
    pub network_burst_after_sensor: bool,
    /// The same suspicious pattern was seen in the previous window too.
    pub repeated_window: bool,
}

/// Tunable weights and thresholds. Documented heuristics, no ML:
///
/// 1. **Sensor ambush** — mic/camera live with no user-visible cause.
///    Each unexpected sensor contributes `w_sensor`.
/// 2. **Silent permission escalation** — a dangerous permission appears
///    granted without a prompt the user could have seen: `w_permission`.
/// 3. **Exfil pattern** — bulk network egress right after sensor
///    activity, the classic capture-then-upload shape: `w_exfil`.
/// 4. **Persistence** — the pattern repeats across consecutive
///    observation windows; one-offs are often benign, repeats are not:
///    `w_repeat`.
///
#[derive(Debug, Clone, Copy)]
pub struct SpySignalConfig {
    pub w_sensor: u32,
    pub w_permission: u32,
    pub w_exfil: u32,
    pub w_repeat: u32,
    /// Score at or above this → [`Verdict::Suspicious`].
    pub suspicious_at: u32,
    /// Score at or above this → [`Verdict::Alert`].
    pub alert_at: u32,
}

impl Default for SpySignalConfig {
    fn default() -> Self {
        SpySignalConfig {
            w_sensor: 30,
            w_permission: 40,
            w_exfil: 50,
            w_repeat: 20,
            suspicious_at: 50,
            alert_at: 100,
        }
    }
}

/// Transparent scoring outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Benign,
    Suspicious,
    Alert,
}

/// Score an observation bundle. Returns `(score, verdict)`. Pure
/// function of the inputs — same bundle, same score, every time.
pub fn score_signals(obs: &Observation, cfg: &SpySignalConfig) -> (u32, Verdict) {
    let mut score: u32 = 0;
    if obs.mic_active_unexpected {
        score = score.saturating_add(cfg.w_sensor);
    }
    if obs.camera_active_unexpected {
        score = score.saturating_add(cfg.w_sensor);
    }
    if obs.permission_escalated_silently {
        score = score.saturating_add(cfg.w_permission);
    }
    if obs.network_burst_after_sensor {
        score = score.saturating_add(cfg.w_exfil);
    }
    if obs.repeated_window {
        score = score.saturating_add(cfg.w_repeat);
    }
    let verdict = if score >= cfg.alert_at {
        Verdict::Alert
    } else if score >= cfg.suspicious_at {
        Verdict::Suspicious
    } else {
        Verdict::Benign
    };
    (score, verdict)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_verify_round_trip() {
        let s = seal_evidence(IncidentType::IntrusionAttempt, 1_700_000_000, b"evidence-bytes")
            .unwrap();
        assert_eq!(s.incident_type(), IncidentType::IntrusionAttempt);
        assert_eq!(s.timestamp(), 1_700_000_000);
        assert_eq!(s.len(), 14);
        assert!(s.verify().is_ok());
        // Deterministic: same inputs, same hash.
        let s2 = seal_evidence(IncidentType::IntrusionAttempt, 1_700_000_000, b"evidence-bytes")
            .unwrap();
        assert_eq!(s.hash(), s2.hash());
        // Different type → different hash.
        let s3 = seal_evidence(IncidentType::SpywareSignal, 1_700_000_000, b"evidence-bytes")
            .unwrap();
        assert_ne!(s.hash(), s3.hash());
    }

    #[test]
    fn flipped_byte_fails_verify() {
        let mut s =
            seal_evidence(IncidentType::TamperingDetected, 42, b"pristine").unwrap();
        assert!(s.verify().is_ok());
        s.evidence[0] ^= 0x01; // simulate tampering with held bytes
        assert_eq!(s.verify(), Err(HydraError::EvidenceTampered));
    }

    #[test]
    fn oversized_evidence_fails_closed() {
        let big = vec![0u8; MAX_EVIDENCE_BYTES + 1];
        assert!(matches!(
            seal_evidence(IncidentType::SpywareSignal, 0, &big),
            Err(HydraError::EvidenceTooLarge)
        ));
        let ok = vec![0u8; MAX_EVIDENCE_BYTES];
        assert!(seal_evidence(IncidentType::SpywareSignal, 0, &ok).is_ok());
    }

    #[test]
    fn censored_packet_holds_no_raw_evidence() {
        let secret = b"super-secret-raw-evidence-that-must-never-leave";
        let s = seal_evidence(IncidentType::ExploitationAttempt, 99, secret).unwrap();
        let p = OutboundPacket::censor(&s, "suspicious contact attempt", Some("Ohio, US")).unwrap();
        assert_eq!(p.incident_type(), IncidentType::ExploitationAttempt);
        assert_eq!(p.description(), "suspicious contact attempt");
        assert_eq!(p.coarse_location(), Some("Ohio, US"));
        assert_eq!(p.evidence_hash(), s.hash());
        // The encoded packet must not contain the raw evidence bytes.
        let enc = p.encode();
        assert!(!enc.windows(secret.len()).any(|w| w == secret));
        // Location is optional.
        let p2 = OutboundPacket::censor(&s, "x", None).unwrap();
        assert_eq!(p2.coarse_location(), None);
    }

    #[test]
    fn oversized_description_rejected() {
        let s = seal_evidence(IncidentType::SpywareSignal, 1, b"e").unwrap();
        let exactly = "a".repeat(MAX_DESCRIPTION_CHARS);
        assert!(OutboundPacket::censor(&s, &exactly, None).is_ok());
        let too_long = "a".repeat(MAX_DESCRIPTION_CHARS + 1);
        assert!(matches!(
            OutboundPacket::censor(&s, &too_long, None),
            Err(HydraError::DescriptionTooLong)
        ));
        // Char count, not byte count: 280 multi-byte chars are fine.
        let wide = "é".repeat(MAX_DESCRIPTION_CHARS);
        assert!(OutboundPacket::censor(&s, &wide, None).is_ok());
    }

    #[test]
    fn lifecycle_happy_path() {
        let mut inc = Incident::new(IncidentType::IntrusionAttempt, 1000);
        assert_eq!(inc.state(), IncidentState::Preparation);
        inc.detect(b"packet-capture", 1001).unwrap();
        assert_eq!(inc.state(), IncidentState::Detected);
        inc.analyze(1002, "analyzed headers").unwrap();
        inc.contain(1003, "blocked source").unwrap();
        inc.recover(1004, "keys rotated").unwrap();
        inc.close(1005, "review complete").unwrap();
        assert_eq!(inc.state(), IncidentState::Closed);
        // Genesis + 5 transitions = 6 entries; chain validates.
        assert_eq!(inc.audit().len(), 6);
        assert!(inc.gate_check().is_ok());
        // Censored packet works after detection.
        let p = inc.censored_packet("intrusion attempt blocked", None).unwrap();
        assert_eq!(p.incident_type(), IncidentType::IntrusionAttempt);
    }

    #[test]
    fn invalid_transitions_rejected() {
        let mut inc = Incident::new(IncidentType::SpywareSignal, 1);
        // Can't skip: Preparation -> Analyzed.
        assert_eq!(
            inc.analyze(2, "skip"),
            Err(HydraError::InvalidTransition)
        );
        // Can't jump to the end: Preparation -> Closed.
        assert_eq!(inc.close(2, "skip"), Err(HydraError::InvalidTransition));
        inc.detect(b"e", 2).unwrap();
        // Detected -> Closed is the documented forbidden jump.
        assert_eq!(inc.close(3, "skip"), Err(HydraError::InvalidTransition));
        // Detected -> Contained also illegal (must analyze first).
        assert_eq!(
            inc.contain(3, "skip"),
            Err(HydraError::InvalidTransition)
        );
        assert_eq!(inc.state(), IncidentState::Detected); // unchanged
        // Censor before detect fails closed.
        let fresh = Incident::new(IncidentType::SpywareSignal, 1);
        assert_eq!(
            fresh.censored_packet("too early", None),
            Err(HydraError::NoEvidence)
        );
    }

    #[test]
    fn audit_chain_detects_forgery() {
        let mut inc = Incident::new(IncidentType::TamperingDetected, 10);
        inc.detect(b"e", 11).unwrap();
        inc.analyze(12, "looks bad").unwrap();
        assert!(inc.audit().verify_chain().is_ok());
        // Forge: rewrite a note in the middle of the chain.
        inc.audit.entries[1].note = "all clear, nothing to see".to_string();
        assert_eq!(inc.audit().verify_chain(), Err(HydraError::ChainBroken));
        assert_eq!(inc.gate_check(), Err(HydraError::ChainBroken));
    }

    #[test]
    fn empty_log_fails_gate() {
        let log = AuditLog::default();
        assert_eq!(log.verify_chain(), Err(HydraError::EmptyLog));
    }

    #[test]
    fn spy_scoring_behaves() {
        let cfg = SpySignalConfig::default();
        // All clear → benign, zero score.
        let (s, v) = score_signals(&Observation::default(), &cfg);
        assert_eq!((s, v), (0, Verdict::Benign));
        // One unexpected mic: 30 < 50 → still benign.
        let obs = Observation {
            mic_active_unexpected: true,
            ..Default::default()
        };
        let (s, v) = score_signals(&obs, &cfg);
        assert_eq!(s, 30);
        assert_eq!(v, Verdict::Benign);
        // Mic + silent permission: 70 → suspicious.
        let obs = Observation {
            mic_active_unexpected: true,
            permission_escalated_silently: true,
            ..Default::default()
        };
        let (s, v) = score_signals(&obs, &cfg);
        assert_eq!(s, 70);
        assert_eq!(v, Verdict::Suspicious);
        // Full capture-then-upload with repeat: 30+40+50+20=140 → alert.
        let obs = Observation {
            mic_active_unexpected: true,
            permission_escalated_silently: true,
            network_burst_after_sensor: true,
            repeated_window: true,
            ..Default::default()
        };
        let (s, v) = score_signals(&obs, &cfg);
        assert_eq!(s, 140);
        assert_eq!(v, Verdict::Alert);
        // Deterministic: same input twice.
        assert_eq!(score_signals(&obs, &cfg), score_signals(&obs, &cfg));
        // Custom thresholds are honored.
        let strict = SpySignalConfig {
            suspicious_at: 1,
            alert_at: 31,
            ..cfg
        };
        let (_, v) = score_signals(
            &Observation {
                mic_active_unexpected: true,
                ..Default::default()
            },
            &strict,
        );
        assert_eq!(v, Verdict::Suspicious);
    }

    #[test]
    fn packet_encode_shape() {
        let s = seal_evidence(IncidentType::SpywareSignal, 7, b"e").unwrap();
        let p = OutboundPacket::censor(&s, "hi", Some("region")).unwrap();
        let enc = p.encode();
        assert_eq!(&enc[0..4], b"HYDR");
        assert_eq!(enc[4], 0x01);
        assert_eq!(enc[5], 0x01); // SpywareSignal code
    }
}
