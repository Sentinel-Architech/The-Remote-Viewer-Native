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
//!
//! ## Safety is never paywalled
//!
//! HYDRA emergency functions — threat detection, evidence sealing,
//! and emergency dispatch — are available to ALL tiers including
//! ghost. A safety system that only protects paying users is not a
//! safety system. Non-emergency HYDRA features (detailed threat
//! reports, historical analytics) may be gated by the app layer, but
//! the emergency path here takes no entitlement and performs no
//! gate check, by design.
//!
//! ## Platform boundary
//!
//! This module never touches sensors, GPS, the radio, or the
//! network. The platform layer implements [`ThreatMonitor`] (threat
//! observations) and [`DispatchTransport`] (packet transmission and
//! coarse location). The core scores, seals, encrypts, signs, queues,
//! and persists — the platform moves bytes and reads hardware.

use crate::crypto::chacha20poly1305;
use crate::crypto::ed25519::{self, sha512::digest, PublicKey, SecretKey, Signature};
use std::path::{Path, PathBuf};

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
    /// OS entropy (`/dev/urandom`) was unavailable. No weak fallback.
    EntropyUnavailable,
    /// A filesystem operation for persistence failed.
    StorageFailed,
    /// A persisted evidence package failed integrity checks. The file
    /// was moved to quarantine; the caller must audit-log this.
    CorruptPackage,
    /// A dispatch envelope signature did not verify.
    BadSignature,
    /// A dispatch envelope failed authenticated decryption.
    DecryptionFailed,
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
            HydraError::EntropyUnavailable => f.write_str("OS entropy unavailable"),
            HydraError::StorageFailed => f.write_str("persistence storage operation failed"),
            HydraError::CorruptPackage => {
                f.write_str("persisted evidence package failed integrity; quarantined")
            }
            HydraError::BadSignature => f.write_str("dispatch envelope signature invalid"),
            HydraError::DecryptionFailed => f.write_str("dispatch envelope decryption failed"),
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

// ---------------------------------------------------------------------------
// Internal helpers: entropy, atomic writes, hex
// ---------------------------------------------------------------------------

/// Fill `buf` from the OS CSPRNG. Fails closed — no weak fallback.
fn read_urandom(buf: &mut [u8]) -> Result<(), HydraError> {
    use std::io::Read;
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(buf))
        .map_err(|_| HydraError::EntropyUnavailable)?;
    Ok(())
}

/// Write `bytes` to `path` atomically: stage to a temp file in the
/// same directory (so the rename is atomic), fsync, then rename over
/// the target. On any failure the temp file is removed and any
/// previous target is untouched.
fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), HydraError> {
    let mut rand = [0u8; 8];
    read_urandom(&mut rand)?;
    let mut tmp_name = path
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_default();
    tmp_name.push(format!(".tmp.{}-", std::process::id()));
    for b in &rand {
        tmp_name.push(format!("{b:02x}"));
    }
    let tmp = path.with_file_name(tmp_name);
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(|_| HydraError::StorageFailed)?;
        use std::io::Write;
        f.write_all(bytes)
            .map_err(|_| HydraError::StorageFailed)?;
        f.flush().map_err(|_| HydraError::StorageFailed)?;
        f.sync_all().map_err(|_| HydraError::StorageFailed)?;
    }
    if std::fs::rename(&tmp, path).is_err() {
        let _ = std::fs::remove_file(&tmp);
        return Err(HydraError::StorageFailed);
    }
    // Best-effort parent-dir sync so the rename itself is durable.
    if let Some(parent) = path.parent() {
        if let Ok(d) = std::fs::File::open(parent) {
            let _ = d.sync_all();
        }
    }
    Ok(())
}

/// Lowercase hex of a 16-byte id (for filenames).
fn hex16(id: &[u8; 16]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(32);
    for b in id {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 0x0f) as usize] as char);
    }
    s
}

// ---------------------------------------------------------------------------
// Evidence persistence
// ---------------------------------------------------------------------------

/// Magic + version for persisted evidence packages.
const EVIDENCE_MAGIC: &[u8; 4] = b"HYDE";
const EVIDENCE_VERSION: u8 = 0x01;

/// Package format (all integers big-endian):
/// `HYDE || 0x01 || type(1) || timestamp(8) || seal_hash(64) ||
///  nonce(12) || ct_len(4) || ct`
///
/// `ct` is ChaCha20-Poly1305 over the raw evidence bytes with AAD =
/// `HYDE || 0x01 || type || timestamp_be || seal_hash`, binding the
/// ciphertext to its seal metadata. A fresh random nonce per package.
///
/// The raw evidence NEVER leaves the device through this store: there
/// is no transmit path here. Only censored summaries (via
/// [`Incident::censored_packet`]) are ever allowed outbound.
pub struct EvidenceStore {
    dir: PathBuf,
    enc_key: [u8; 32],
}

/// Package identifier: first 16 bytes of the SHA-512 evidence seal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PackageId([u8; 16]);

impl PackageId {
    /// Hex string (for filenames / logs; safe to expose).
    pub fn hex(&self) -> String {
        hex16(&self.0)
    }
}

impl EvidenceStore {
    /// Open (creating if needed) the evidence directory. `enc_key` is
    /// the caller-provided 32-byte at-rest encryption key — derived by
    /// the platform from the device key; this module never derives or
    /// stores it beyond this struct's lifetime.
    pub fn open(dir: &Path, enc_key: &[u8; 32]) -> Result<Self, HydraError> {
        std::fs::create_dir_all(dir).map_err(|_| HydraError::StorageFailed)?;
        let q = dir.join("quarantine");
        std::fs::create_dir_all(&q).map_err(|_| HydraError::StorageFailed)?;
        Ok(EvidenceStore {
            dir: dir.to_path_buf(),
            enc_key: *enc_key,
        })
    }

    fn package_path(&self, id: &PackageId) -> PathBuf {
        self.dir.join(format!("{}.pkg", id.hex()))
    }

    fn quarantine_path(&self, id: &PackageId) -> PathBuf {
        self.dir
            .join("quarantine")
            .join(format!("{}.pkg.quarantined", id.hex()))
    }

    /// Seal evidence and persist it encrypted. Enforces the 8 MiB cap
    /// via [`seal_evidence`] (fails closed). Returns the package id.
    pub fn persist(
        &self,
        incident_type: IncidentType,
        timestamp: u64,
        evidence: &[u8],
    ) -> Result<PackageId, HydraError> {
        let sealed = seal_evidence(incident_type, timestamp, evidence)?;
        let mut id = [0u8; 16];
        id.copy_from_slice(&sealed.hash[..16]);
        let package_id = PackageId(id);

        let mut nonce = [0u8; 12];
        read_urandom(&mut nonce)?;

        // AAD binds ciphertext to seal metadata.
        let mut aad = Vec::with_capacity(4 + 1 + 1 + 8 + 64);
        aad.extend_from_slice(EVIDENCE_MAGIC);
        aad.push(EVIDENCE_VERSION);
        aad.push(incident_type.code());
        aad.extend_from_slice(&timestamp.to_be_bytes());
        aad.extend_from_slice(&sealed.hash);

        let ct = chacha20poly1305::encrypt(&self.enc_key, &nonce, &aad, evidence);

        let mut pkg = Vec::with_capacity(4 + 1 + 1 + 8 + 64 + 12 + 4 + ct.len());
        pkg.extend_from_slice(EVIDENCE_MAGIC);
        pkg.push(EVIDENCE_VERSION);
        pkg.push(incident_type.code());
        pkg.extend_from_slice(&timestamp.to_be_bytes());
        pkg.extend_from_slice(&sealed.hash);
        pkg.extend_from_slice(&nonce);
        pkg.extend_from_slice(&(ct.len() as u32).to_be_bytes());
        pkg.extend_from_slice(&ct);

        atomic_write(&self.package_path(&package_id), &pkg)?;
        Ok(package_id)
    }

    /// Load, decrypt, and re-verify a package. On ANY integrity
    /// failure the file is moved to quarantine (never silently
    /// dropped) and [`HydraError::CorruptPackage`] is returned — the
    /// caller must record the quarantine in the incident audit log.
    pub fn load(&self, id: &PackageId) -> Result<SealedEvidence, HydraError> {
        let path = self.package_path(id);
        let bytes = std::fs::read(&path).map_err(|_| HydraError::StorageFailed)?;
        match self.parse_package(&bytes) {
            Ok(sealed) => Ok(sealed),
            Err(_) => {
                // Fail closed: quarantine the file, never delete it.
                let _ = std::fs::rename(&path, self.quarantine_path(id));
                Err(HydraError::CorruptPackage)
            }
        }
    }

    fn parse_package(&self, bytes: &[u8]) -> Result<SealedEvidence, HydraError> {
        // Minimum: magic(4) + ver(1) + type(1) + ts(8) + hash(64) +
        // nonce(12) + ct_len(4) = 94 bytes.
        if bytes.len() < 94
            || &bytes[0..4] != EVIDENCE_MAGIC
            || bytes[4] != EVIDENCE_VERSION
        {
            return Err(HydraError::CorruptPackage);
        }
        let incident_type = match bytes[5] {
            0x01 => IncidentType::SpywareSignal,
            0x02 => IncidentType::ExploitationAttempt,
            0x03 => IncidentType::IntrusionAttempt,
            0x04 => IncidentType::TamperingDetected,
            _ => return Err(HydraError::CorruptPackage),
        };
        let mut ts = [0u8; 8];
        ts.copy_from_slice(&bytes[6..14]);
        let timestamp = u64::from_be_bytes(ts);
        let mut hash = [0u8; 64];
        hash.copy_from_slice(&bytes[14..78]);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&bytes[78..90]);
        let mut len = [0u8; 4];
        len.copy_from_slice(&bytes[90..94]);
        let ct_len = u32::from_be_bytes(len) as usize;
        if bytes.len() != 94 + ct_len {
            return Err(HydraError::CorruptPackage);
        }
        let ct = &bytes[94..];

        let mut aad = Vec::with_capacity(4 + 1 + 1 + 8 + 64);
        aad.extend_from_slice(EVIDENCE_MAGIC);
        aad.push(EVIDENCE_VERSION);
        aad.push(incident_type.code());
        aad.extend_from_slice(&timestamp.to_be_bytes());
        aad.extend_from_slice(&hash);

        let evidence =
            chacha20poly1305::decrypt(&self.enc_key, &nonce, &aad, ct)
                .map_err(|_| HydraError::CorruptPackage)?;

        // Re-seal to re-verify the hash chain end to end.
        let sealed = seal_evidence(incident_type, timestamp, &evidence)?;
        if sealed.hash != hash {
            return Err(HydraError::CorruptPackage);
        }
        Ok(sealed)
    }

    /// List persisted (non-quarantined) package ids.
    pub fn list(&self) -> Result<Vec<PackageId>, HydraError> {
        let mut out = Vec::new();
        let entries =
            std::fs::read_dir(&self.dir).map_err(|_| HydraError::StorageFailed)?;
        for e in entries {
            let e = e.map_err(|_| HydraError::StorageFailed)?;
            let name = e.file_name();
            let name = name.to_string_lossy();
            if let Some(hex) = name.strip_suffix(".pkg") {
                if hex.len() == 32 {
                    if let Some(id) = parse_hex16(hex) {
                        out.push(PackageId(id));
                    }
                }
            }
        }
        Ok(out)
    }
}

fn parse_hex16(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16)? as u8;
        let lo = (chunk[1] as char).to_digit(16)? as u8;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Monitoring hooks (platform implements; core scores)
// ---------------------------------------------------------------------------

/// Where a threat signal was observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalSource {
    Sensor,
    Process,
    Network,
}

/// What kind of pattern the platform observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalKind {
    /// Microphone active with no user-visible cause.
    MicUnexpected,
    /// Camera active with no user-visible cause.
    CameraUnexpected,
    /// Dangerous permission granted without a visible prompt.
    PermissionSilent,
    /// Bulk network egress shortly after sensor activity.
    NetBurstAfterSensor,
    /// Unknown background process with sensor permissions.
    UnknownProcess,
    /// Outbound connection to an unexpected endpoint.
    UnexpectedConnection,
}

/// Maximum [`SpySignal`] detail length, in chars.
pub const MAX_SIGNAL_DETAIL_CHARS: usize = 140;

/// One platform-observed threat signal. The platform fills these from
/// real hardware/OS state; the core only scores them.
///
/// Contract: `detail` describes the *pattern*, never PII — no names,
/// no exact addresses, no message contents (e.g. "mic active 34s,
/// screen off" is fine; anything identifying the user is not).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpySignal {
    pub source: SignalSource,
    pub kind: SignalKind,
    /// 0–100. Signals below 50 do not flip observation flags.
    pub severity: u8,
    pub detail: String,
}

impl SpySignal {
    /// Build a signal. Fails closed on over-long detail (the platform
    /// truncates and retries) — unbounded strings are a memory vector.
    pub fn new(
        source: SignalSource,
        kind: SignalKind,
        severity: u8,
        detail: &str,
    ) -> Result<Self, HydraError> {
        if detail.chars().count() > MAX_SIGNAL_DETAIL_CHARS {
            return Err(HydraError::DescriptionTooLong);
        }
        Ok(SpySignal {
            source,
            kind,
            severity: severity.min(100),
            detail: detail.to_string(),
        })
    }
}

/// Platform threat-monitoring surface. The embedding app implements
/// this against real sensors, process tables, and network state. The
/// core calls it, scores what comes back, and escalates per the NIST
/// lifecycle. No hardware access happens in core, ever.
pub trait ThreatMonitor {
    /// Sensor anomalies: mic/camera/GPS active with no user-visible cause.
    fn check_sensors(&mut self) -> Vec<SpySignal>;
    /// Process anomalies: unknown background processes, especially
    /// ones holding sensor permissions.
    fn check_processes(&mut self) -> Vec<SpySignal>;
    /// Network anomalies: unexpected outbound connections, bulk egress
    /// bursts correlated with sensor activity.
    fn check_network(&mut self) -> Vec<SpySignal>;
}

/// Fold platform signals into the transparent [`Observation`] scoring
/// input. Signals with severity < 50 are ignored (noise floor).
/// `repeated` marks that the same pattern fired in the previous
/// window — the app tracks this; one-offs are often benign.
pub fn signals_to_observation(signals: &[SpySignal], repeated: bool) -> Observation {
    let mut obs = Observation::default();
    for s in signals {
        if s.severity < 50 {
            continue;
        }
        match s.kind {
            SignalKind::MicUnexpected => obs.mic_active_unexpected = true,
            SignalKind::CameraUnexpected => obs.camera_active_unexpected = true,
            SignalKind::PermissionSilent | SignalKind::UnknownProcess => {
                obs.permission_escalated_silently = true
            }
            SignalKind::NetBurstAfterSensor | SignalKind::UnexpectedConnection => {
                obs.network_burst_after_sensor = true
            }
        }
    }
    obs.repeated_window = repeated;
    obs
}

/// Run one full monitoring sweep: gather signals from all three
/// platform surfaces, score transparently, return the raw signals
/// plus `(score, verdict)`.
pub fn threat_sweep<M: ThreatMonitor>(
    monitor: &mut M,
    cfg: &SpySignalConfig,
    repeated: bool,
) -> (Vec<SpySignal>, u32, Verdict) {
    let mut signals = monitor.check_sensors();
    signals.extend(monitor.check_processes());
    signals.extend(monitor.check_network());
    let obs = signals_to_observation(&signals, repeated);
    let (score, verdict) = score_signals(&obs, cfg);
    (signals, score, verdict)
}

// ---------------------------------------------------------------------------
// Coarse location (emergency packets only, ~1km precision cap)
// ---------------------------------------------------------------------------

/// Coarse location for emergency packets ONLY.
///
/// Privacy by construction: latitude/longitude are quantized to
/// 0.01° (≈1.1 km at the equator, less at higher latitudes) and ONLY
/// the quantized values are stored. There is no API on this type that
/// recovers finer precision.
///
/// Included in an outbound emergency packet ONLY when:
/// - (a) the user explicitly triggers an emergency, or
/// - (b) an [`IncidentType::ExploitationAttempt`] is detected
///   (child-safety rule: exploitation attempts are geo-located).
/// Never for any other incident type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoarseLocation {
    /// Latitude × 100, floored. 0.01° ≈ 1.1 km.
    lat_e2: i32,
    /// Longitude × 100, floored.
    lon_e2: i32,
    /// ISO 3166-1 alpha-2 country code, uppercased.
    country: [u8; 2],
}

impl CoarseLocation {
    /// Quantize raw GPS to the ~1km grid. Returns None for
    /// out-of-range coordinates or a non-alphabetic country code.
    pub fn from_lat_lon(lat: f64, lon: f64, country: [u8; 2]) -> Option<Self> {
        if !(-90.0..=90.0).contains(&lat) || !(-180.0..=180.0).contains(&lon) {
            return None;
        }
        if !country.iter().all(|b| b.is_ascii_alphabetic()) {
            return None;
        }
        if !lat.is_finite() || !lon.is_finite() {
            return None;
        }
        Some(CoarseLocation {
            lat_e2: (lat * 100.0).floor() as i32,
            lon_e2: (lon * 100.0).floor() as i32,
            country: [
                country[0].to_ascii_uppercase(),
                country[1].to_ascii_uppercase(),
            ],
        })
    }

    /// Quantized latitude × 100.
    pub fn lat_e2(&self) -> i32 {
        self.lat_e2
    }
    /// Quantized longitude × 100.
    pub fn lon_e2(&self) -> i32 {
        self.lon_e2
    }
    /// ISO country code.
    pub fn country(&self) -> [u8; 2] {
        self.country
    }

    /// Region string for censored packets, e.g. `"US 40.71,-74.01"`.
    /// Quantized — never more precise than ~1 km.
    pub fn region_string(&self) -> String {
        format!(
            "{} {:.2},{:.2}",
            String::from_utf8_lossy(&self.country),
            self.lat_e2 as f64 / 100.0,
            self.lon_e2 as f64 / 100.0
        )
    }
}

// ---------------------------------------------------------------------------
// Emergency directory (per-region numbers; platform places the call)
// ---------------------------------------------------------------------------

/// Per-region emergency numbers. The core prepares the censored
/// packet; the PLATFORM places the actual call/SMS via
/// [`DispatchTransport`]. Numbers below are the standard public
/// emergency numbers (US/CA/MX 911, EU 112, UK 999, AU 000, NZ 111).
pub struct EmergencyDirectory;

impl EmergencyDirectory {
    /// Look up the emergency number for an ISO 3166-1 alpha-2 country
    /// code (case-insensitive). Returns None for unlisted regions —
    /// the caller falls back to [`EmergencyDirectory::fallback`].
    pub fn lookup(country: &[u8; 2]) -> Option<&'static str> {
        let up = [
            country[0].to_ascii_uppercase(),
            country[1].to_ascii_uppercase(),
        ];
        // Route UK through 999; 112 also works there.
        match &up {
            b"US" | b"CA" | b"MX" => Some("911"),
            b"GB" => Some("999"),
            b"AU" => Some("000"),
            b"NZ" => Some("111"),
            b"JP" => Some("110"),
            b"KR" => Some("112"),
            b"CN" => Some("110"),
            b"IN" => Some("112"),
            b"BR" => Some("190"),
            // EU/EEA members and others on the 112 standard.
            b"DE" | b"FR" | b"IT" | b"ES" | b"NL" | b"SE" | b"NO" | b"FI" | b"DK"
            | b"IE" | b"PT" | b"GR" | b"PL" | b"AT" | b"BE" | b"CH" | b"CZ" | b"HU"
            | b"RO" | b"HR" | b"SK" | b"SI" | b"EE" | b"LV" | b"LT" | b"LU"
            | b"MT" | b"CY" | b"BG" => Some("112"),
            _ => None,
        }
    }

    /// GSM-standard fallback: 112 works on most mobile networks
    /// worldwide when no regional number is known.
    pub fn fallback() -> &'static str {
        "112"
    }
}

// ---------------------------------------------------------------------------
// Secure dispatch envelope (encrypted + signed, replay-protected)
// ---------------------------------------------------------------------------

/// Domain separation for dispatch encryption AAD.
const DISPATCH_AAD: &[u8] = b"TRV-HYDRA-DISPATCH-v1";
/// Domain separation for dispatch signatures.
const DISPATCH_SIG_DOMAIN: &[u8] = b"TRV-HYDRA-DISPATCH-SIG-v1";

/// An emergency packet sealed for transport: the censored
/// [`OutboundPacket`] encoding, encrypted with ChaCha20-Poly1305
/// (fresh 96-bit nonce per packet) and signed with the device Ed25519
/// key.
///
/// Replay protection: the nonce and timestamp are part of the SIGNED
/// envelope and exposed via accessors. Receivers deduplicate on
/// `(nonce, timestamp)` and reject timestamps outside their policy
/// window. The core does not enforce a clock — there is no trusted
/// on-device time source.
///
/// The envelope carries NO raw evidence and NO personal data beyond
/// what the censored packet already holds.
#[derive(Debug, Clone)]
pub struct SecureDispatch {
    nonce: [u8; 12],
    timestamp: u64,
    ciphertext: Vec<u8>,
    signature: Signature,
    sender: PublicKey,
}

impl SecureDispatch {
    /// Seal a censored packet for transport. `enc_key` is the
    /// caller-provided 32-byte transport encryption key.
    pub fn seal(
        packet: &OutboundPacket,
        enc_key: &[u8; 32],
        device_secret: &SecretKey,
        device_public: &PublicKey,
        timestamp: u64,
    ) -> Result<Self, HydraError> {
        let mut nonce = [0u8; 12];
        read_urandom(&mut nonce)?;
        let plaintext = packet.encode();
        let ciphertext = chacha20poly1305::encrypt(enc_key, &nonce, DISPATCH_AAD, &plaintext);
        let mut sig_msg =
            Vec::with_capacity(DISPATCH_SIG_DOMAIN.len() + 12 + 8 + ciphertext.len());
        sig_msg.extend_from_slice(DISPATCH_SIG_DOMAIN);
        sig_msg.extend_from_slice(&nonce);
        sig_msg.extend_from_slice(&timestamp.to_be_bytes());
        sig_msg.extend_from_slice(&ciphertext);
        let signature = ed25519::sign(device_secret, device_public, &sig_msg);
        Ok(SecureDispatch {
            nonce,
            timestamp,
            ciphertext,
            signature,
            sender: *device_public,
        })
    }

    /// Verify the device signature, then authenticated-decrypt.
    /// Returns the censored packet encoding. Fails closed on any
    /// tampering. Replay deduplication is the receiver's job — use
    /// [`SecureDispatch::nonce`] and [`SecureDispatch::timestamp`].
    pub fn open(&self, enc_key: &[u8; 32]) -> Result<Vec<u8>, HydraError> {
        let mut sig_msg =
            Vec::with_capacity(DISPATCH_SIG_DOMAIN.len() + 12 + 8 + self.ciphertext.len());
        sig_msg.extend_from_slice(DISPATCH_SIG_DOMAIN);
        sig_msg.extend_from_slice(&self.nonce);
        sig_msg.extend_from_slice(&self.timestamp.to_be_bytes());
        sig_msg.extend_from_slice(&self.ciphertext);
        if !ed25519::verify(&self.sender, &sig_msg, &self.signature) {
            return Err(HydraError::BadSignature);
        }
        chacha20poly1305::decrypt(enc_key, &self.nonce, DISPATCH_AAD, &self.ciphertext)
            .map_err(|_| HydraError::DecryptionFailed)
    }

    /// Replay-protection nonce (also the dedup key with timestamp).
    pub fn nonce(&self) -> &[u8; 12] {
        &self.nonce
    }
    /// Caller-supplied timestamp (informational; signed).
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }
    /// Device key that sealed this envelope.
    pub fn sender(&self) -> &PublicKey {
        &self.sender
    }

    /// Wire encoding for the platform transport:
    /// `nonce(12) || timestamp(8 BE) || sender(32) || sig(64) ||
    ///  ct_len(4 BE) || ct`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(12 + 8 + 32 + 64 + 4 + self.ciphertext.len());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(self.sender.as_bytes());
        out.extend_from_slice(self.signature.as_bytes());
        out.extend_from_slice(&(self.ciphertext.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Parse a wire-encoded envelope. Signature is NOT verified here —
    /// call [`SecureDispatch::open`] for that. Fail closed on malformed
    /// input.
    pub fn decode(bytes: &[u8]) -> Result<Self, HydraError> {
        if bytes.len() < 12 + 8 + 32 + 64 + 4 {
            return Err(HydraError::CorruptPackage);
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&bytes[0..12]);
        let mut ts = [0u8; 8];
        ts.copy_from_slice(&bytes[12..20]);
        let mut sk = [0u8; 32];
        sk.copy_from_slice(&bytes[20..52]);
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&bytes[52..116]);
        let mut len = [0u8; 4];
        len.copy_from_slice(&bytes[116..120]);
        let ct_len = u32::from_be_bytes(len) as usize;
        if bytes.len() != 120 + ct_len {
            return Err(HydraError::CorruptPackage);
        }
        Ok(SecureDispatch {
            nonce,
            timestamp: u64::from_be_bytes(ts),
            ciphertext: bytes[120..].to_vec(),
            signature: Signature::from_bytes(sig),
            sender: PublicKey::from_bytes(sk),
        })
    }
}

// ---------------------------------------------------------------------------
// Platform transport trait
// ---------------------------------------------------------------------------

/// Platform transmission surface for HYDRA. The core prepares sealed
/// envelopes; the platform moves the bytes and supplies coarse
/// location. Implementations live in platform code, never in core.
pub trait DispatchTransport {
    /// Transmit one sealed envelope. The bytes are already encrypted
    /// and signed; the transport must not inspect, log, or alter them.
    fn send_packet(&mut self, envelope: &[u8]) -> Result<(), HydraError>;
    /// Coarse location for emergency packets, when policy allows.
    /// None when unavailable or not consented.
    fn coarse_location(&mut self) -> Option<CoarseLocation>;
}

// ---------------------------------------------------------------------------
// Persistent dispatch queue (retry with backoff, 24h quarantine)
// ---------------------------------------------------------------------------

/// Queue entry format:
/// `HYDQ || 0x01 || attempts(4 BE) || first_queued(8 BE) ||
///  last_attempt(8 BE) || env_len(4 BE) || envelope`
const QUEUE_MAGIC: &[u8; 4] = b"HYDQ";
const QUEUE_VERSION: u8 = 0x01;

/// Maximum age of a queued packet: 24h. Older packets are moved to
/// quarantine (the caller audit-logs the quarantine).
pub const MAX_QUEUE_AGE_SECS: u64 = 24 * 3600;

/// Backoff between attempts: 60s, doubling, capped at 1h.
fn backoff_secs(attempts: u32) -> u64 {
    (60u64 << attempts.min(6)).min(3600)
}

/// Queue identifier: first 16 bytes of SHA-512 over the envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct QueueId([u8; 16]);

impl QueueId {
    pub fn hex(&self) -> String {
        hex16(&self.0)
    }
}

/// Outcome of one [`DispatchQueue::drain`] pass.
#[derive(Debug, Clone, Default)]
pub struct DispatchReport {
    /// Packets transmitted and removed from the queue.
    pub sent: Vec<QueueId>,
    /// Packets still queued (backoff not elapsed, or send failed and
    /// the retry budget remains).
    pub pending: Vec<QueueId>,
    /// Packets that exceeded 24h and were moved to quarantine. The
    /// caller must record each quarantine in the audit log.
    pub quarantined: Vec<QueueId>,
}

/// Persistent outbound queue for emergency packets. Unsent packets
/// survive restarts via atomic writes. [`DispatchQueue::drain`]
/// attempts transmission through the platform transport with
/// exponential backoff; packets older than 24h are quarantined.
pub struct DispatchQueue {
    dir: PathBuf,
}

struct QueueEntry {
    attempts: u32,
    first_queued: u64,
    last_attempt: u64,
    envelope: Vec<u8>,
}

impl DispatchQueue {
    /// Open (creating if needed) the queue directory.
    pub fn open(dir: &Path) -> Result<Self, HydraError> {
        std::fs::create_dir_all(dir).map_err(|_| HydraError::StorageFailed)?;
        let q = dir.join("quarantine");
        std::fs::create_dir_all(&q).map_err(|_| HydraError::StorageFailed)?;
        Ok(DispatchQueue {
            dir: dir.to_path_buf(),
        })
    }

    fn entry_path(&self, id: &QueueId) -> PathBuf {
        self.dir.join(format!("{}.q", id.hex()))
    }

    fn quarantine_path(&self, id: &QueueId) -> PathBuf {
        self.dir
            .join("quarantine")
            .join(format!("{}.q.quarantined", id.hex()))
    }

    fn encode_entry(e: &QueueEntry) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 1 + 4 + 8 + 8 + 4 + e.envelope.len());
        out.extend_from_slice(QUEUE_MAGIC);
        out.push(QUEUE_VERSION);
        out.extend_from_slice(&e.attempts.to_be_bytes());
        out.extend_from_slice(&e.first_queued.to_be_bytes());
        out.extend_from_slice(&e.last_attempt.to_be_bytes());
        out.extend_from_slice(&(e.envelope.len() as u32).to_be_bytes());
        out.extend_from_slice(&e.envelope);
        out
    }

    fn decode_entry(bytes: &[u8]) -> Result<QueueEntry, HydraError> {
        if bytes.len() < 4 + 1 + 4 + 8 + 8 + 4
            || &bytes[0..4] != QUEUE_MAGIC
            || bytes[4] != QUEUE_VERSION
        {
            return Err(HydraError::CorruptPackage);
        }
        let mut a = [0u8; 4];
        a.copy_from_slice(&bytes[5..9]);
        let mut f = [0u8; 8];
        f.copy_from_slice(&bytes[9..17]);
        let mut l = [0u8; 8];
        l.copy_from_slice(&bytes[17..25]);
        let mut n = [0u8; 4];
        n.copy_from_slice(&bytes[25..29]);
        let env_len = u32::from_be_bytes(n) as usize;
        if bytes.len() != 29 + env_len {
            return Err(HydraError::CorruptPackage);
        }
        Ok(QueueEntry {
            attempts: u32::from_be_bytes(a),
            first_queued: u64::from_be_bytes(f),
            last_attempt: u64::from_be_bytes(l),
            envelope: bytes[29..].to_vec(),
        })
    }

    /// Enqueue a sealed dispatch for transmission. Idempotent on the
    /// envelope hash: re-enqueueing the same envelope returns the same
    /// id without duplicating.
    pub fn enqueue(&self, dispatch: &SecureDispatch, now: u64) -> Result<QueueId, HydraError> {
        let envelope = dispatch.encode();
        let digest = digest(&envelope);
        let mut id = [0u8; 16];
        id.copy_from_slice(&digest[..16]);
        let qid = QueueId(id);
        let path = self.entry_path(&qid);
        if path.exists() {
            return Ok(qid);
        }
        let entry = QueueEntry {
            attempts: 0,
            first_queued: now,
            last_attempt: 0,
            envelope,
        };
        atomic_write(&path, &Self::encode_entry(&entry))?;
        Ok(qid)
    }

    /// Attempt transmission of all queued packets.
    ///
    /// For each entry: quarantine if older than 24h; skip if backoff
    /// has not elapsed; otherwise call the transport. On success the
    /// entry is deleted; on failure the attempt counter advances and
    /// the entry is rewritten. Corrupt entries are quarantined.
    pub fn drain(
        &self,
        transport: &mut dyn DispatchTransport,
        now: u64,
    ) -> DispatchReport {
        let mut report = DispatchReport::default();
        let entries = match std::fs::read_dir(&self.dir) {
            Ok(rd) => rd,
            Err(_) => return report,
        };
        for e in entries.flatten() {
            let name = e.file_name();
            let name = name.to_string_lossy();
            let hex = match name.strip_suffix(".q") {
                Some(h) if h.len() == 32 => h,
                _ => continue,
            };
            let id = match parse_hex16(hex) {
                Some(b) => QueueId(b),
                None => continue,
            };
            let path = e.path();
            let bytes = match std::fs::read(&path) {
                Ok(b) => b,
                Err(_) => {
                    report.pending.push(id);
                    continue;
                }
            };
            let mut entry = match Self::decode_entry(&bytes) {
                Ok(en) => en,
                Err(_) => {
                    let _ = std::fs::rename(&path, self.quarantine_path(&id));
                    report.quarantined.push(id);
                    continue;
                }
            };
            // Age-out: 24h budget exhausted → quarantine.
            if now.saturating_sub(entry.first_queued) > MAX_QUEUE_AGE_SECS {
                let _ = std::fs::rename(&path, self.quarantine_path(&id));
                report.quarantined.push(id);
                continue;
            }
            // Backoff: not yet time to retry.
            if now.saturating_sub(entry.last_attempt) < backoff_secs(entry.attempts)
                && entry.attempts > 0
            {
                report.pending.push(id);
                continue;
            }
            match transport.send_packet(&entry.envelope) {
                Ok(()) => {
                    let _ = std::fs::remove_file(&path);
                    report.sent.push(id);
                }
                Err(_) => {
                    entry.attempts = entry.attempts.saturating_add(1);
                    entry.last_attempt = now;
                    // Best-effort rewrite; on failure keep the old file
                    // and report pending (it will be retried next drain).
                    if atomic_write(&path, &Self::encode_entry(&entry)).is_ok() {
                        report.pending.push(id);
                    } else {
                        report.pending.push(id);
                    }
                }
            }
        }
        report
    }

    /// Number of queued (non-quarantined) entries.
    pub fn len(&self) -> usize {
        std::fs::read_dir(&self.dir)
            .map(|rd| {
                rd.flatten()
                    .filter(|e| {
                        e.file_name()
                            .to_string_lossy()
                            .ends_with(".q")
                    })
                    .count()
            })
            .unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ---------------------------------------------------------------------------
// Tests: persistence, monitoring hooks, location, dispatch
// ---------------------------------------------------------------------------

#[cfg(test)]
mod persistence_tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    /// Unique temp dir per test (cleaned up on success).
    fn test_dir(name: &str) -> PathBuf {
        let n = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "hydra-test-{}-{}-{}",
            name,
            std::process::id(),
            n
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn test_enc_key() -> [u8; 32] {
        [0x42u8; 32]
    }

    fn test_device_key() -> (SecretKey, PublicKey) {
        ed25519::generate(&[0x77u8; 32])
    }

    struct MockTransport {
        sent: Vec<Vec<u8>>,
        fail: bool,
        location: Option<CoarseLocation>,
    }

    impl MockTransport {
        fn ok() -> Self {
            MockTransport {
                sent: Vec::new(),
                fail: false,
                location: None,
            }
        }
        fn failing() -> Self {
            MockTransport {
                sent: Vec::new(),
                fail: true,
                location: None,
            }
        }
    }

    impl DispatchTransport for MockTransport {
        fn send_packet(&mut self, envelope: &[u8]) -> Result<(), HydraError> {
            if self.fail {
                return Err(HydraError::StorageFailed);
            }
            self.sent.push(envelope.to_vec());
            Ok(())
        }
        fn coarse_location(&mut self) -> Option<CoarseLocation> {
            self.location
        }
    }

    struct MockMonitor {
        sensors: Vec<SpySignal>,
        processes: Vec<SpySignal>,
        network: Vec<SpySignal>,
    }

    impl ThreatMonitor for MockMonitor {
        fn check_sensors(&mut self) -> Vec<SpySignal> {
            std::mem::take(&mut self.sensors)
        }
        fn check_processes(&mut self) -> Vec<SpySignal> {
            std::mem::take(&mut self.processes)
        }
        fn check_network(&mut self) -> Vec<SpySignal> {
            std::mem::take(&mut self.network)
        }
    }

    // -- Evidence persistence ------------------------------------------------

    #[test]
    fn evidence_persist_load_round_trip() {
        let dir = test_dir("persist");
        let store = EvidenceStore::open(&dir, &test_enc_key()).unwrap();
        let evidence = b"camera frame bytes, sensor log, process list";
        let id = store
            .persist(IncidentType::SpywareSignal, 1_700_000_000, evidence)
            .unwrap();
        // Listed.
        let listed = store.list().unwrap();
        assert_eq!(listed, vec![id]);
        // Loaded: seal re-verifies.
        let sealed = store.load(&id).unwrap();
        assert_eq!(sealed.incident_type(), IncidentType::SpywareSignal);
        assert_eq!(sealed.timestamp(), 1_700_000_000);
        assert_eq!(sealed.len(), evidence.len());
        assert!(sealed.verify().is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn evidence_persist_enforces_8mib_cap() {
        let dir = test_dir("cap");
        let store = EvidenceStore::open(&dir, &test_enc_key()).unwrap();
        let big = vec![0u8; MAX_EVIDENCE_BYTES + 1];
        assert_eq!(
            store.persist(IncidentType::IntrusionAttempt, 0, &big),
            Err(HydraError::EvidenceTooLarge)
        );
        // Nothing was written.
        assert!(store.list().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_package_is_quarantined_never_dropped() {
        let dir = test_dir("quarantine");
        let store = EvidenceStore::open(&dir, &test_enc_key()).unwrap();
        let id = store
            .persist(IncidentType::TamperingDetected, 5, b"real-evidence")
            .unwrap();
        // Tamper with the ciphertext on disk.
        let path = dir.join(format!("{}.pkg", id.hex()));
        let mut bytes = std::fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        std::fs::write(&path, &bytes).unwrap();

        assert!(matches!(store.load(&id), Err(HydraError::CorruptPackage)));
        // Original is gone from the live dir...
        assert!(!path.exists());
        // ...but preserved in quarantine, not deleted.
        let qpath = dir
            .join("quarantine")
            .join(format!("{}.pkg.quarantined", id.hex()));
        assert!(qpath.exists());
        assert!(store.list().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn garbage_file_is_quarantined() {
        let dir = test_dir("garbage");
        let store = EvidenceStore::open(&dir, &test_enc_key()).unwrap();
        // Write a bogus package file directly with a valid-looking name.
        let fake_id = PackageId([0xAAu8; 16]);
        std::fs::write(
            dir.join(format!("{}.pkg", fake_id.hex())),
            b"this is not a package",
        )
        .unwrap();
        assert!(matches!(store.load(&fake_id), Err(HydraError::CorruptPackage)));
        assert!(dir
            .join("quarantine")
            .join(format!("{}.pkg.quarantined", fake_id.hex()))
            .exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wrong_key_cannot_read_evidence() {
        let dir = test_dir("wrongkey");
        let store = EvidenceStore::open(&dir, &test_enc_key()).unwrap();
        let id = store
            .persist(IncidentType::SpywareSignal, 1, b"sensitive-bytes")
            .unwrap();
        // A store opened with a different key sees only corruption
        // (which quarantines — the attacker's copy is preserved for
        // forensics, not decrypted).
        let evil = EvidenceStore::open(&dir, &[0x99u8; 32]).unwrap();
        assert!(matches!(evil.load(&id), Err(HydraError::CorruptPackage)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- Monitoring hooks ----------------------------------------------------

    #[test]
    fn threat_sweep_scores_platform_signals() {
        let mut monitor = MockMonitor {
            sensors: vec![
                SpySignal::new(
                    SignalSource::Sensor,
                    SignalKind::MicUnexpected,
                    80,
                    "mic active 34s, screen off",
                )
                .unwrap(),
            ],
            processes: vec![],
            network: vec![
                SpySignal::new(
                    SignalSource::Network,
                    SignalKind::NetBurstAfterSensor,
                    90,
                    "2.1MB egress after mic",
                )
                .unwrap(),
            ],
        };
        let cfg = SpySignalConfig::default();
        let (signals, score, verdict) = threat_sweep(&mut monitor, &cfg, false);
        assert_eq!(signals.len(), 2);
        // 30 (mic) + 50 (exfil) = 80 → suspicious.
        assert_eq!(score, 80);
        assert_eq!(verdict, Verdict::Suspicious);
        // Same sweep with repeat flag → 100 → alert.
        let mut monitor = MockMonitor {
            sensors: vec![SpySignal::new(
                SignalSource::Sensor,
                SignalKind::MicUnexpected,
                80,
                "mic",
            )
            .unwrap()],
            processes: vec![],
            network: vec![SpySignal::new(
                SignalSource::Network,
                SignalKind::NetBurstAfterSensor,
                90,
                "egress",
            )
            .unwrap()],
        };
        let (_, score, verdict) = threat_sweep(&mut monitor, &cfg, true);
        assert_eq!(score, 100);
        assert_eq!(verdict, Verdict::Alert);
    }

    #[test]
    fn low_severity_signals_are_noise() {
        let signals = vec![
            SpySignal::new(SignalSource::Sensor, SignalKind::MicUnexpected, 10, "blip").unwrap(),
        ];
        let obs = signals_to_observation(&signals, false);
        assert!(!obs.mic_active_unexpected);
        let (score, verdict) = score_signals(&obs, &SpySignalConfig::default());
        assert_eq!((score, verdict), (0, Verdict::Benign));
    }

    #[test]
    fn oversized_signal_detail_fails_closed() {
        let long = "x".repeat(MAX_SIGNAL_DETAIL_CHARS + 1);
        assert!(SpySignal::new(
            SignalSource::Sensor,
            SignalKind::MicUnexpected,
            80,
            &long
        )
        .is_err());
    }

    // -- Coarse location -----------------------------------------------------

    #[test]
    fn coarse_location_caps_precision_at_1km() {
        // Two points ~470m apart must quantize identically: no API on
        // CoarseLocation can distinguish them.
        let a = CoarseLocation::from_lat_lon(40.7128, -74.0060, *b"US").unwrap();
        let b = CoarseLocation::from_lat_lon(40.7170, -74.0060, *b"US").unwrap();
        assert_eq!(a, b);
        assert_eq!(a.region_string(), "US 40.71,-74.01");
        // The grid cell is 0.01° ≈ 1.1km: points 2km apart differ.
        let c = CoarseLocation::from_lat_lon(40.7328, -74.0060, *b"US").unwrap();
        assert_ne!(a, c);
        // Invalid inputs fail closed.
        assert!(CoarseLocation::from_lat_lon(91.0, 0.0, *b"US").is_none());
        assert!(CoarseLocation::from_lat_lon(0.0, 181.0, *b"US").is_none());
        assert!(CoarseLocation::from_lat_lon(0.0, 0.0, *b"1!").is_none());
        assert!(CoarseLocation::from_lat_lon(f64::NAN, 0.0, *b"US").is_none());
    }

    #[test]
    fn emergency_directory_numbers() {
        // Verified standard public emergency numbers.
        assert_eq!(EmergencyDirectory::lookup(b"US"), Some("911"));
        assert_eq!(EmergencyDirectory::lookup(b"CA"), Some("911"));
        assert_eq!(EmergencyDirectory::lookup(b"GB"), Some("999"));
        assert_eq!(EmergencyDirectory::lookup(b"DE"), Some("112"));
        assert_eq!(EmergencyDirectory::lookup(b"FR"), Some("112"));
        assert_eq!(EmergencyDirectory::lookup(b"AU"), Some("000"));
        assert_eq!(EmergencyDirectory::lookup(b"NZ"), Some("111"));
        assert_eq!(EmergencyDirectory::lookup(b"JP"), Some("110"));
        // Case-insensitive.
        assert_eq!(EmergencyDirectory::lookup(b"us"), Some("911"));
        // Unknown → None; caller uses the GSM fallback.
        assert_eq!(EmergencyDirectory::lookup(b"XX"), None);
        assert_eq!(EmergencyDirectory::fallback(), "112");
    }

    // -- Secure dispatch -----------------------------------------------------

    fn emergency_packet() -> (OutboundPacket, Vec<u8>) {
        // Secret raw evidence that must never appear in any envelope.
        let secret = b"RAW-EVIDENCE-BYTES-0123456789abcdef-super-secret";
        let sealed =
            seal_evidence(IncidentType::ExploitationAttempt, 1_700_000_001, secret).unwrap();
        let packet = OutboundPacket::censor(&sealed, "suspected exploitation attempt", None)
            .unwrap();
        (packet, secret.to_vec())
    }

    #[test]
    fn emergency_envelope_holds_zero_raw_evidence() {
        let (packet, secret) = emergency_packet();
        let (ds, dp) = test_device_key();
        let env = SecureDispatch::seal(&packet, &test_enc_key(), &ds, &dp, 1_700_000_002)
            .unwrap();
        let wire = env.encode();
        // Byte-scan the entire envelope: the secret must not appear.
        assert!(!wire.windows(secret.len()).any(|w| w == secret.as_slice()));
        // The plaintext packet encoding also holds no raw evidence
        // (censored packet invariant, re-checked at this layer).
        let plain = packet.encode();
        assert!(!plain.windows(secret.len()).any(|w| w == secret.as_slice()));
    }

    #[test]
    fn dispatch_seal_open_round_trip() {
        let (packet, _) = emergency_packet();
        let (ds, dp) = test_device_key();
        let env = SecureDispatch::seal(&packet, &test_enc_key(), &ds, &dp, 999).unwrap();
        // Nonce/timestamp exposed for receiver replay dedup.
        assert_eq!(env.nonce().len(), 12);
        assert_eq!(env.timestamp(), 999);
        assert_eq!(env.sender().as_bytes(), dp.as_bytes());
        // Wire round-trip, then open.
        let rt = SecureDispatch::decode(&env.encode()).unwrap();
        let plain = rt.open(&test_enc_key()).unwrap();
        assert_eq!(plain, packet.encode());
    }

    #[test]
    fn dispatch_tamper_fails_closed() {
        let (packet, _) = emergency_packet();
        let (ds, dp) = test_device_key();
        let env = SecureDispatch::seal(&packet, &test_enc_key(), &ds, &dp, 999).unwrap();
        // Flip a ciphertext byte: signature must fail.
        let mut tampered = env.clone();
        let last = tampered.ciphertext.len() - 1;
        tampered.ciphertext[last] ^= 0x01;
        assert_eq!(
            tampered.open(&test_enc_key()),
            Err(HydraError::BadSignature)
        );
        // Wrong decryption key: signature verifies (same sender) but
        // authenticated decryption fails.
        assert_eq!(env.open(&[0x11u8; 32]), Err(HydraError::DecryptionFailed));
        // Wrong sender key: signature fails.
        let (_, dp2) = ed25519::generate(&[0x88u8; 32]);
        let mut wrong_sender = env.clone();
        wrong_sender.sender = dp2;
        assert_eq!(
            wrong_sender.open(&test_enc_key()),
            Err(HydraError::BadSignature)
        );
    }

    #[test]
    fn dispatch_nonces_are_unique() {
        let (packet, _) = emergency_packet();
        let (ds, dp) = test_device_key();
        let a = SecureDispatch::seal(&packet, &test_enc_key(), &ds, &dp, 1).unwrap();
        let b = SecureDispatch::seal(&packet, &test_enc_key(), &ds, &dp, 1).unwrap();
        assert_ne!(a.nonce(), b.nonce());
        assert_ne!(a.encode(), b.encode());
    }

    #[test]
    fn dispatch_decode_rejects_garbage() {
        assert!(SecureDispatch::decode(b"too short").is_err());
        let mut bad = vec![0u8; 200];
        assert!(SecureDispatch::decode(&bad).is_err());
        bad[0..4].copy_from_slice(b"XXXX");
        assert!(SecureDispatch::decode(&bad).is_err());
    }

    // -- Dispatch queue ------------------------------------------------------

    #[test]
    fn queue_persists_across_restarts() {
        let dir = test_dir("queue");
        let (packet, _) = emergency_packet();
        let (ds, dp) = test_device_key();
        let env = SecureDispatch::seal(&packet, &test_enc_key(), &ds, &dp, 100).unwrap();

        let qid = {
            let q = DispatchQueue::open(&dir).unwrap();
            let id = q.enqueue(&env, 1000).unwrap();
            assert_eq!(q.len(), 1);
            // Re-enqueue is idempotent.
            assert_eq!(q.enqueue(&env, 1001).unwrap(), id);
            assert_eq!(q.len(), 1);
            id
        };
        // "Restart": new queue over the same dir sees the entry.
        {
            let q = DispatchQueue::open(&dir).unwrap();
            assert_eq!(q.len(), 1);
            let mut t = MockTransport::ok();
            let report = q.drain(&mut t, 1001);
            assert_eq!(report.sent, vec![qid]);
            assert!(report.pending.is_empty());
            assert!(report.quarantined.is_empty());
            assert_eq!(t.sent.len(), 1);
            // Envelope delivered intact: decode + open.
            let rt = SecureDispatch::decode(&t.sent[0]).unwrap();
            assert_eq!(rt.open(&test_enc_key()).unwrap(), packet.encode());
            assert!(q.is_empty());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn queue_backoff_and_retry() {
        let dir = test_dir("backoff");
        let q = DispatchQueue::open(&dir).unwrap();
        let (packet, _) = emergency_packet();
        let (ds, dp) = test_device_key();
        let env = SecureDispatch::seal(&packet, &test_enc_key(), &ds, &dp, 100).unwrap();
        let qid = q.enqueue(&env, 1000).unwrap();

        // Transport down: first drain attempts (attempts 0 → immediate).
        let mut t = MockTransport::failing();
        let r1 = q.drain(&mut t, 1000);
        assert!(r1.sent.is_empty());
        assert_eq!(r1.pending, vec![qid]);

        // 30s later: backoff (60s) not elapsed → no attempt, still pending.
        let r2 = q.drain(&mut t, 1030);
        assert_eq!(r2.pending, vec![qid]);

        // 61s later: backoff elapsed → attempt fails again.
        let r3 = q.drain(&mut t, 1061);
        assert_eq!(r3.pending, vec![qid]);

        // Transport recovers: next eligible drain sends.
        let mut t2 = MockTransport::ok();
        let r4 = q.drain(&mut t2, 2000);
        assert_eq!(r4.sent, vec![qid]);
        assert!(q.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn queue_quarantines_after_24h() {
        let dir = test_dir("quarantine24");
        let q = DispatchQueue::open(&dir).unwrap();
        let (packet, _) = emergency_packet();
        let (ds, dp) = test_device_key();
        let env = SecureDispatch::seal(&packet, &test_enc_key(), &ds, &dp, 100).unwrap();
        // Enqueued "long ago".
        let qid = q.enqueue(&env, 1000).unwrap();

        let mut t = MockTransport::failing();
        let report = q.drain(&mut t, 1000 + MAX_QUEUE_AGE_SECS + 1);
        assert!(report.sent.is_empty());
        assert!(report.pending.is_empty());
        assert_eq!(report.quarantined, vec![qid]);
        // Moved to quarantine, preserved — not deleted.
        assert!(q.is_empty());
        assert!(dir
            .join("quarantine")
            .join(format!("{}.q.quarantined", qid.hex()))
            .exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- Safety is never paywalled -------------------------------------------

    #[test]
    fn ghost_tier_can_trigger_emergency_no_entitlement() {
        // The emergency path takes no entitlement and performs no gate
        // check, by design: a ghost-tier user in danger gets the same
        // sealed, encrypted, signed dispatch as anyone else. This test
        // walks the whole path with no entitlement object in scope —
        // there is no parameter for one.
        let dir = test_dir("ghost");
        let store = EvidenceStore::open(&dir, &test_enc_key()).unwrap();
        let queue = DispatchQueue::open(&dir.join("queue")).unwrap();

        // 1. Detect + seal (would normally feed the Incident lifecycle).
        let mut incident = Incident::new(IncidentType::ExploitationAttempt, 5000);
        incident.detect(b"exploitation evidence bytes", 5001).unwrap();

        // 2. Persist evidence (stays on device).
        let pkg = store
            .persist(
                IncidentType::ExploitationAttempt,
                5001,
                b"exploitation evidence bytes",
            )
            .unwrap();
        assert!(store.load(&pkg).is_ok());

        // 3. Censored packet with coarse location (child-safety rule).
        let loc =
            CoarseLocation::from_lat_lon(41.10, -80.65, *b"US").expect("valid coarse location");
        let packet = incident
            .censored_packet("suspected exploitation attempt", Some(&loc.region_string()))
            .unwrap();
        assert_eq!(
            packet.coarse_location(),
            Some(loc.region_string()).as_deref()
        );

        // 4. Seal + queue + dispatch — no entitlement anywhere.
        let (ds, dp) = test_device_key();
        let env = SecureDispatch::seal(&packet, &test_enc_key(), &ds, &dp, 5002).unwrap();
        let qid = queue.enqueue(&env, 5002).unwrap();
        let mut t = MockTransport::ok();
        let report = queue.drain(&mut t, 5003);
        assert_eq!(report.sent, vec![qid]);
        assert_eq!(t.sent.len(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
