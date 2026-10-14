//! On-device ID verification framework.
//!
//! Pure Rust, std-only. The phone checks the ID document itself, runs a
//! liveness challenge (video selfie OR bioprint — the user's choice),
//! and issues a signed attestation. No ID provider, no human reviewers.
//!
//! ## Privacy guarantee (hard)
//!
//! Verifiable personal information NEVER ends up in a stranger's hands,
//! because it never leaves the device at all:
//!
//! - [`check_mrz`] takes MRZ lines and returns only pass/fail plus a
//!   reason *code*. Error values carry no input data; they cannot echo
//!   the document back. Tested: no error rendering contains MRZ text.
//! - The liveness protocol only ever handles verdicts (pass/fail),
//!   challenge nonces, method codes, and signatures. Video frames and
//!   biometric templates are captured, analyzed, and wiped by the
//!   platform layer; this module has no field, parameter, or code path
//!   that could hold them. [`ProofOfLife`] structurally cannot contain
//!   video or biometric data — there is nowhere to put it.
//! - [`VerificationAttestation`] — the ONLY artifact that may leave the
//!   device — contains the subject's public key, a verification level
//!   code, timestamps, and a device signature. Zero personal data: no
//!   name, no birth date, no document number, no photo, no address.
//! - This module performs no I/O beyond `/dev/urandom` for challenge
//!   nonces. No network, no camera, no logging of personal data.
//!
//! ## Verification levels
//!
//! [`VerificationLevel::Unverified`] → [`VerificationLevel::DocumentChecked`]
//! (MRZ checks pass) → [`VerificationLevel::HumanVerified`] (document +
//! liveness both pass). An attestation is only issued for the two
//! verified levels, never for [`VerificationLevel::Unverified`].
//!
//! ## Liveness flow
//!
//! 1. The user picks a method: [`LivenessMethod::VideoSelfie`] or
//!    [`LivenessMethod::Bioprint`].
//! 2. [`LivenessSession::issue_challenge`] creates a fresh challenge:
//!    a 32-byte nonce plus a random action sequence (for video) bound
//!    to the chosen method.
//! 3. The platform layer captures the video selfie or biometric,
//!    analyzes it ENTIRELY on-device, wipes the raw bytes from memory,
//!    and signs `(method, verdict, nonce)` with the device identity key
//!    via [`LivenessResponse::sign`].
//! 4. [`LivenessSession::verify_response`] checks the challenge is
//!    fresh (replay rejected), the method matches the issued challenge
//!    (mixing methods fails closed), and the device signature is valid.
//! 5. [`ProofOfLife::attest`] records the signed verdict — method code,
//!    pass/fail, nonce, timestamp, signature. No video, no templates.
//!
//! NOT externally audited — like the rest of `trv_core`, this module is
//! hand-written and has not had an independent cryptographic or
//! biometric-security audit. Do not rely on it for production identity
//! decisions until that audit happens.

use crate::crypto::ed25519::{self, PublicKey, SecretKey, Signature};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Every failure this module can report.
///
/// Variants carry NO data — only reason codes — so an error can never
/// echo back MRZ lines, names, or any other personal information.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    /// OS entropy (`/dev/urandom`) was unavailable. No weak fallback.
    EntropyUnavailable,
    /// An MRZ line was not exactly 44 bytes (TD3).
    MrzBadLength,
    /// An MRZ line contained a byte outside `[A-Z0-9<]`.
    MrzBadCharset,
    /// Document-number check digit mismatch (positions 1-10).
    MrzDocNumberChecksum,
    /// Date-of-birth check digit mismatch (positions 14-20).
    MrzBirthDateChecksum,
    /// Expiry-date check digit mismatch (positions 22-28).
    MrzExpiryChecksum,
    /// Personal-number check digit mismatch (positions 29-43).
    MrzPersonalNumberChecksum,
    /// Composite check digit mismatch (position 44).
    MrzCompositeChecksum,
    /// All checksums passed but the document is expired.
    MrzDocumentExpired,
    /// The response's nonce does not match a live issued challenge.
    ChallengeMismatch,
    /// The response's method differs from the issued challenge's
    /// method (e.g. challenge for video, response claims bioprint).
    LivenessMethodMismatch,
    /// The challenge nonce was already consumed: replay.
    LivenessReplayRejected,
    /// The device signature on a liveness response / proof is invalid.
    LivenessBadSignature,
    /// Malformed proof-of-life or attestation encoding.
    BadEncoding,
    /// The attestation's device signature is invalid.
    AttestBadSignature,
    /// The attestation is expired (or not yet valid) at `now`.
    AttestExpired,
    /// Refused: attestations are never issued for `Unverified`.
    AttestUnverifiedLevel,
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            VerifyError::EntropyUnavailable => "OS entropy unavailable",
            VerifyError::MrzBadLength => "MRZ line is not 44 bytes",
            VerifyError::MrzBadCharset => "MRZ line has invalid characters",
            VerifyError::MrzDocNumberChecksum => "document number check digit mismatch",
            VerifyError::MrzBirthDateChecksum => "birth date check digit mismatch",
            VerifyError::MrzExpiryChecksum => "expiry date check digit mismatch",
            VerifyError::MrzPersonalNumberChecksum => "personal number check digit mismatch",
            VerifyError::MrzCompositeChecksum => "composite check digit mismatch",
            VerifyError::MrzDocumentExpired => "document is expired",
            VerifyError::ChallengeMismatch => "challenge nonce mismatch",
            VerifyError::LivenessMethodMismatch => "liveness method mismatch",
            VerifyError::LivenessReplayRejected => "challenge nonce already used",
            VerifyError::LivenessBadSignature => "liveness signature invalid",
            VerifyError::BadEncoding => "malformed encoding",
            VerifyError::AttestBadSignature => "attestation signature invalid",
            VerifyError::AttestExpired => "attestation expired",
            VerifyError::AttestUnverifiedLevel => "attestation requires a verified level",
        };
        f.write_str(s)
    }
}

impl std::error::Error for VerifyError {}

// ---------------------------------------------------------------------------
// Verification levels
// ---------------------------------------------------------------------------

/// How far identity verification has progressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VerificationLevel {
    /// Nothing verified yet. Attestations are never issued at this level.
    Unverified = 0,
    /// ID document authenticity checks (MRZ) passed.
    DocumentChecked = 1,
    /// Document checks plus a liveness proof both passed.
    HumanVerified = 2,
}

impl VerificationLevel {
    /// Stable wire code.
    pub fn code(self) -> u8 {
        self as u8
    }

    /// Human-readable label.
    pub fn label(self) -> &'static str {
        match self {
            VerificationLevel::Unverified => "unverified",
            VerificationLevel::DocumentChecked => "document-checked",
            VerificationLevel::HumanVerified => "human-verified",
        }
    }

    /// Parse a wire code. Unknown codes fail closed.
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(VerificationLevel::Unverified),
            1 => Some(VerificationLevel::DocumentChecked),
            2 => Some(VerificationLevel::HumanVerified),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// MRZ document checks (ICAO 9303 TD3)
// ---------------------------------------------------------------------------

/// Length of each TD3 MRZ line in bytes.
const TD3_LEN: usize = 44;

/// Field layout on MRZ line 2 (0-based byte ranges).
const DOC_NUM: std::ops::Range<usize> = 0..9;
const DOC_NUM_CHECK: usize = 9;
const BIRTH: std::ops::Range<usize> = 13..19;
const BIRTH_CHECK: usize = 19;
const EXPIRY: std::ops::Range<usize> = 21..27;
const EXPIRY_CHECK: usize = 27;
const PERSONAL: std::ops::Range<usize> = 28..42;
const PERSONAL_CHECK: usize = 42;
const COMPOSITE_CHECK: usize = 43;

/// Numeric value of an MRZ character per ICAO 9303: `0-9` → 0-9,
/// `A-Z` → 10-35, `<` → 0.
fn mrz_value(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'A'..=b'Z' => Some(c - b'A' + 10),
        b'<' => Some(0),
        _ => None,
    }
}

/// ICAO 9303 check digit: weights 7-3-1 cycling, sum mod 10.
fn mrz_checksum(data: &[u8]) -> u8 {
    const WEIGHTS: [u32; 3] = [7, 3, 1];
    let mut sum: u32 = 0;
    for (i, &c) in data.iter().enumerate() {
        // Charset is validated before any checksum runs; a `None` here
        // is unreachable in practice. Treat as 0 rather than panicking.
        let v = mrz_value(c).unwrap_or(0) as u32;
        sum = sum.saturating_add(v * WEIGHTS[i % 3]);
    }
    (sum % 10) as u8
}

/// Parse an ASCII check digit byte.
fn ascii_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        _ => None,
    }
}

/// The minimum document facts extracted from a passing MRZ.
///
/// The caller already possesses the MRZ lines; this returns only what
/// downstream logic needs (document type, issuer, expiry). It is never
/// transmitted — only the [`VerificationAttestation`] leaves the device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MrzDocument {
    /// Document type code, e.g. `P<` (line 1, bytes 0-2).
    pub doc_type: [u8; 2],
    /// Issuing state, 3-letter code (line 1, bytes 2-5).
    pub issuing_country: [u8; 3],
    /// Expiry date as (YY, MM, DD).
    pub expiry: (u8, u8, u8),
}

/// Generic ID fields with expiry validation.
///
/// `today` is caller-supplied `(YY, MM, DD)`. There is no trusted
/// on-device clock, so freshness is the caller's responsibility.
/// YY years are compared directly: this assumes document and "today"
/// fall in the same century window — documented, not hidden.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdFields {
    /// Document type code, e.g. `P<`.
    pub doc_type: [u8; 2],
    /// Issuing state, 3-letter code.
    pub issuing_country: [u8; 3],
    /// Expiry date as (YY, MM, DD).
    pub expiry: (u8, u8, u8),
}

impl IdFields {
    /// True when `expiry` is strictly before `today`. A document is
    /// considered valid through its expiry date.
    pub fn is_expired(&self, today: (u8, u8, u8)) -> bool {
        self.expiry < today
    }
}

impl From<MrzDocument> for IdFields {
    fn from(d: MrzDocument) -> Self {
        IdFields {
            doc_type: d.doc_type,
            issuing_country: d.issuing_country,
            expiry: d.expiry,
        }
    }
}

fn check_field(
    line: &[u8],
    data: std::ops::Range<usize>,
    check_at: usize,
    err: VerifyError,
) -> Result<(), VerifyError> {
    let expected = mrz_checksum(&line[data]);
    // A non-digit in a check position is a checksum failure, not a
    // charset failure: the line charset was already validated.
    let actual = ascii_digit(line[check_at]).ok_or(err)?;
    if expected == actual {
        Ok(())
    } else {
        Err(err)
    }
}

/// Validate two TD3 MRZ lines per ICAO 9303.
///
/// Checks: both lines exactly 44 bytes, charset `[A-Z0-9<]`, then the
/// document-number, birth-date, expiry-date, personal-number, and
/// composite check digits, then expiry against caller-supplied `today`
/// `(YY, MM, DD)`.
///
/// Returns the extracted [`MrzDocument`] on success. On failure returns
/// only a reason code — the input lines are NEVER echoed back.
pub fn check_mrz(
    line1: &str,
    line2: &str,
    today: (u8, u8, u8),
) -> Result<MrzDocument, VerifyError> {
    let l1 = line1.as_bytes();
    let l2 = line2.as_bytes();
    if l1.len() != TD3_LEN || l2.len() != TD3_LEN {
        return Err(VerifyError::MrzBadLength);
    }
    for &c in l1.iter().chain(l2.iter()) {
        if mrz_value(c).is_none() {
            return Err(VerifyError::MrzBadCharset);
        }
    }

    check_field(l2, DOC_NUM, DOC_NUM_CHECK, VerifyError::MrzDocNumberChecksum)?;
    check_field(l2, BIRTH, BIRTH_CHECK, VerifyError::MrzBirthDateChecksum)?;
    check_field(l2, EXPIRY, EXPIRY_CHECK, VerifyError::MrzExpiryChecksum)?;
    check_field(l2, PERSONAL, PERSONAL_CHECK, VerifyError::MrzPersonalNumberChecksum)?;

    // Composite: positions 1-10, 14-20, 22-43 (1-based), i.e. each
    // field including its own check digit.
    let mut composite = Vec::with_capacity(39);
    composite.extend_from_slice(&l2[0..10]);
    composite.extend_from_slice(&l2[13..20]);
    composite.extend_from_slice(&l2[21..28]);
    composite.extend_from_slice(&l2[28..43]);
    let expected = mrz_checksum(&composite);
    let actual = ascii_digit(l2[COMPOSITE_CHECK]).ok_or(VerifyError::MrzCompositeChecksum)?;
    if expected != actual {
        return Err(VerifyError::MrzCompositeChecksum);
    }

    let expiry = (
        ascii_digit(l2[21]).ok_or(VerifyError::MrzBadCharset)? * 10
            + ascii_digit(l2[22]).ok_or(VerifyError::MrzBadCharset)?,
        ascii_digit(l2[23]).ok_or(VerifyError::MrzBadCharset)? * 10
            + ascii_digit(l2[24]).ok_or(VerifyError::MrzBadCharset)?,
        ascii_digit(l2[25]).ok_or(VerifyError::MrzBadCharset)? * 10
            + ascii_digit(l2[26]).ok_or(VerifyError::MrzBadCharset)?,
    );
    if expiry < today {
        return Err(VerifyError::MrzDocumentExpired);
    }

    Ok(MrzDocument {
        doc_type: [l1[0], l1[1]],
        issuing_country: [l1[2], l1[3], l1[4]],
        expiry,
    })
}

// ---------------------------------------------------------------------------
// Liveness challenge/response
// ---------------------------------------------------------------------------

/// How the user proved they are alive. Recorded as a code only —
/// never the underlying video or biometric data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LivenessMethod {
    /// On-device video selfie with random action sequence.
    VideoSelfie = 1,
    /// On-device platform biometric (fingerprint / face / etc.).
    Bioprint = 2,
}

impl LivenessMethod {
    /// Stable wire code.
    pub fn code(self) -> u8 {
        self as u8
    }

    /// Human-readable label.
    pub fn label(self) -> &'static str {
        match self {
            LivenessMethod::VideoSelfie => "video-selfie",
            LivenessMethod::Bioprint => "bioprint",
        }
    }

    /// Parse a wire code. Unknown codes fail closed.
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(LivenessMethod::VideoSelfie),
            2 => Some(LivenessMethod::Bioprint),
            _ => None,
        }
    }
}

/// One action in a video-selfie challenge sequence, encoded as a byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LivenessAction {
    Blink = 1,
    TurnLeft = 2,
    TurnRight = 3,
    NodUp = 4,
    NodDown = 5,
    Smile = 6,
}

impl LivenessAction {
    fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(LivenessAction::Blink),
            2 => Some(LivenessAction::TurnLeft),
            3 => Some(LivenessAction::TurnRight),
            4 => Some(LivenessAction::NodUp),
            5 => Some(LivenessAction::NodDown),
            6 => Some(LivenessAction::Smile),
            _ => None,
        }
    }
}

/// Number of actions in each video challenge sequence.
pub const CHALLENGE_ACTIONS: usize = 3;

/// A liveness challenge: fresh nonce + random action sequence.
///
/// For [`LivenessMethod::Bioprint`] the action sequence is ignored by
/// the platform (a biometric match needs no acted sequence); the nonce
/// still binds the fresh capture to this challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LivenessChallenge {
    /// 32 bytes of fresh OS entropy. Single-use.
    pub nonce: [u8; 32],
    /// The method this challenge was issued for. A response claiming a
    /// different method fails closed.
    pub method: LivenessMethod,
    /// Random action sequence (video selfie). Encoded as bytes.
    pub actions: [LivenessAction; CHALLENGE_ACTIONS],
    /// Caller-supplied issue time, informational only.
    pub issued_at: u64,
}

impl LivenessChallenge {
    /// Wire encoding: `TRVC || 0x01 || method || nonce(32) ||
    /// actions(3) || issued_at(8 BE)`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 1 + 1 + 32 + 3 + 8);
        out.extend_from_slice(b"TRVC");
        out.push(0x01);
        out.push(self.method.code());
        out.extend_from_slice(&self.nonce);
        for a in self.actions {
            out.push(a as u8);
        }
        out.extend_from_slice(&self.issued_at.to_be_bytes());
        out
    }

    /// Parse and validate a wire-encoded challenge. Fail closed.
    pub fn from_bytes(b: &[u8]) -> Result<Self, VerifyError> {
        if b.len() != 4 + 1 + 1 + 32 + 3 + 8
            || &b[0..4] != b"TRVC"
            || b[4] != 0x01
        {
            return Err(VerifyError::BadEncoding);
        }
        let method = LivenessMethod::from_code(b[5]).ok_or(VerifyError::BadEncoding)?;
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&b[6..38]);
        let mut actions = [LivenessAction::Blink; CHALLENGE_ACTIONS];
        for (i, a) in actions.iter_mut().enumerate() {
            *a = LivenessAction::from_code(b[38 + i]).ok_or(VerifyError::BadEncoding)?;
        }
        let mut ts = [0u8; 8];
        ts.copy_from_slice(&b[41..49]);
        Ok(LivenessChallenge {
            nonce,
            method,
            actions,
            issued_at: u64::from_be_bytes(ts),
        })
    }
}

/// The platform layer's signed answer to a challenge.
///
/// Constructed by the platform AFTER it has captured the video selfie
/// or biometric, analyzed it ENTIRELY on-device, and wiped the raw
/// bytes from memory. This struct carries only the verdict — the
/// video/biometric data never reaches this module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LivenessResponse {
    /// The challenge nonce being answered.
    pub nonce: [u8; 32],
    /// Which method produced this verdict.
    pub method: LivenessMethod,
    /// Did the on-device analysis pass?
    pub passed: bool,
    /// Device identity key that performed the capture and signed.
    pub device_key: PublicKey,
    /// Ed25519 signature over the domain-separated canonical encoding.
    pub signature: Signature,
}

/// Domain separation for liveness response signatures.
const LIVENESS_DOMAIN: &[u8] = b"TRV-LIVENESS-v1";

fn liveness_signed_bytes(
    method: LivenessMethod,
    passed: bool,
    nonce: &[u8; 32],
    device_key: &PublicKey,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        LIVENESS_DOMAIN.len() + 1 + 1 + 32 + 32,
    );
    out.extend_from_slice(LIVENESS_DOMAIN);
    out.push(method.code());
    out.push(if passed { 1 } else { 0 });
    out.extend_from_slice(nonce);
    out.extend_from_slice(device_key.as_bytes());
    out
}

impl LivenessResponse {
    /// Sign a verdict. This is the platform layer's call, made AFTER
    /// the raw video/biometric bytes have been analyzed on-device and
    /// wiped. Nothing but the verdict crosses into this module.
    pub fn sign(
        device_secret: &SecretKey,
        device_public: &PublicKey,
        method: LivenessMethod,
        passed: bool,
        nonce: [u8; 32],
    ) -> Self {
        let msg = liveness_signed_bytes(method, passed, &nonce, device_public);
        let signature = ed25519::sign(device_secret, device_public, &msg);
        LivenessResponse {
            nonce,
            method,
            passed,
            device_key: *device_public,
            signature,
        }
    }

    /// Check the device signature. Used by [`LivenessSession`].
    fn verify_sig(&self) -> bool {
        let msg = liveness_signed_bytes(self.method, self.passed, &self.nonce, &self.device_key);
        ed25519::verify(&self.device_key, &msg, &self.signature)
    }
}

/// The verified outcome of one liveness check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LivenessVerdict {
    /// Which method produced the verdict.
    pub method: LivenessMethod,
    /// Did the on-device analysis pass?
    pub passed: bool,
}

/// Cap on tracked nonces: unbounded growth is a memory-exhaustion
/// vector. Oldest entries are evicted first; challenges also carry
/// `issued_at` so callers can enforce freshness themselves.
const MAX_TRACKED_NONCES: usize = 1024;

/// Issues challenges and verifies responses, enforcing single-use
/// nonces (replay rejected) and method binding (mixing methods fails
/// closed).
pub struct LivenessSession {
    /// Live challenges: (nonce, method issued for).
    issued: Vec<([u8; 32], LivenessMethod)>,
    /// Consumed nonces: replay of any of these is rejected.
    used: Vec<[u8; 32]>,
}

impl LivenessSession {
    pub fn new() -> Self {
        LivenessSession {
            issued: Vec::new(),
            used: Vec::new(),
        }
    }

    /// Issue a fresh challenge for `method`. The nonce is 32 bytes of
    /// OS entropy; the action sequence is 3 random actions (the
    /// security rests on the nonce, not the action selection).
    pub fn issue_challenge(
        &mut self,
        method: LivenessMethod,
        issued_at: u64,
    ) -> Result<LivenessChallenge, VerifyError> {
        let nonce = random32()?;
        let r = random32()?;
        const CHOICES: [LivenessAction; 6] = [
            LivenessAction::Blink,
            LivenessAction::TurnLeft,
            LivenessAction::TurnRight,
            LivenessAction::NodUp,
            LivenessAction::NodDown,
            LivenessAction::Smile,
        ];
        let mut actions = [LivenessAction::Blink; CHALLENGE_ACTIONS];
        for (i, a) in actions.iter_mut().enumerate() {
            *a = CHOICES[(r[i] % 6) as usize];
        }
        if self.issued.len() >= MAX_TRACKED_NONCES {
            self.issued.remove(0);
        }
        self.issued.push((nonce, method));
        Ok(LivenessChallenge {
            nonce,
            method,
            actions,
            issued_at,
        })
    }

    /// Verify a platform response. Fail-closed ordering:
    /// replay → unknown challenge → method mismatch → bad signature.
    /// A failed attempt burns the challenge (it is removed from the
    /// live set); only a success moves the nonce to the used set.
    pub fn verify_response(
        &mut self,
        response: &LivenessResponse,
    ) -> Result<LivenessVerdict, VerifyError> {
        if self.used.contains(&response.nonce) {
            return Err(VerifyError::LivenessReplayRejected);
        }
        let pos = self
            .issued
            .iter()
            .position(|(n, _)| *n == response.nonce)
            .ok_or(VerifyError::ChallengeMismatch)?;
        let (_, issued_method) = self.issued.remove(pos);
        if response.method != issued_method {
            return Err(VerifyError::LivenessMethodMismatch);
        }
        if !response.verify_sig() {
            return Err(VerifyError::LivenessBadSignature);
        }
        if self.used.len() >= MAX_TRACKED_NONCES {
            self.used.remove(0);
        }
        self.used.push(response.nonce);
        Ok(LivenessVerdict {
            method: response.method,
            passed: response.passed,
        })
    }
}

impl Default for LivenessSession {
    fn default() -> Self {
        Self::new()
    }
}

/// 32 bytes of OS entropy, or [`VerifyError::EntropyUnavailable`].
/// No weak fallback — a predictable challenge nonce breaks liveness.
fn random32() -> Result<[u8; 32], VerifyError> {
    use std::io::Read;
    let mut b = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut b))
        .map_err(|_| VerifyError::EntropyUnavailable)?;
    Ok(b)
}

// ---------------------------------------------------------------------------
// Proof of life
// ---------------------------------------------------------------------------

/// Domain separation for proof-of-life signatures.
const PROOF_DOMAIN: &[u8] = b"TRV-PROOFOFLIFE-v1";

/// The signed, storable record of a liveness check.
///
/// Contains ONLY: the method code, the verdict, the challenge nonce, a
/// timestamp, the device key, and the device signature. There are no
/// video bytes, no biometric templates, no frames — structurally, there
/// is nowhere to put them. The raw capture was analyzed on-device and
/// wiped before this record existed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofOfLife {
    /// Which method produced the verdict (code only, never the data).
    pub method: LivenessMethod,
    /// Did the on-device analysis pass?
    pub passed: bool,
    /// The challenge nonce this verdict answers.
    pub challenge_nonce: [u8; 32],
    /// Caller-supplied time of the verdict, informational only.
    pub timestamp: u64,
    /// Device identity key that performed the check and signed.
    pub device_key: PublicKey,
    /// Ed25519 device signature over the canonical encoding.
    pub signature: Signature,
}

fn proof_signed_bytes(
    method: LivenessMethod,
    passed: bool,
    nonce: &[u8; 32],
    timestamp: u64,
    device_key: &PublicKey,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(PROOF_DOMAIN.len() + 1 + 1 + 32 + 8 + 32);
    out.extend_from_slice(PROOF_DOMAIN);
    out.push(method.code());
    out.push(if passed { 1 } else { 0 });
    out.extend_from_slice(nonce);
    out.extend_from_slice(&timestamp.to_be_bytes());
    out.extend_from_slice(device_key.as_bytes());
    out
}

impl ProofOfLife {
    /// Record a signed verdict. Called by the platform AFTER the raw
    /// capture has been analyzed on-device and wiped from memory.
    pub fn attest(
        device_secret: &SecretKey,
        device_public: &PublicKey,
        method: LivenessMethod,
        passed: bool,
        challenge_nonce: [u8; 32],
        timestamp: u64,
    ) -> Self {
        let msg = proof_signed_bytes(method, passed, &challenge_nonce, timestamp, device_public);
        let signature = ed25519::sign(device_secret, device_public, &msg);
        ProofOfLife {
            method,
            passed,
            challenge_nonce,
            timestamp,
            device_key: *device_public,
            signature,
        }
    }

    /// Verify the device signature. Fails closed on tampering.
    pub fn verify(&self) -> Result<(), VerifyError> {
        let msg = proof_signed_bytes(
            self.method,
            self.passed,
            &self.challenge_nonce,
            self.timestamp,
            &self.device_key,
        );
        if ed25519::verify(&self.device_key, &msg, &self.signature) {
            Ok(())
        } else {
            Err(VerifyError::LivenessBadSignature)
        }
    }

    /// Wire encoding: `TRVP || 0x01 || method || verdict ||
    /// nonce(32) || timestamp(8 BE) || device_key(32) || sig(64)`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 1 + 1 + 1 + 32 + 8 + 32 + 64);
        out.extend_from_slice(b"TRVP");
        out.push(0x01);
        out.push(self.method.code());
        out.push(if self.passed { 1 } else { 0 });
        out.extend_from_slice(&self.challenge_nonce);
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(self.device_key.as_bytes());
        out.extend_from_slice(self.signature.as_bytes());
        out
    }

    /// Parse and signature-check a wire-encoded record. Fail closed.
    pub fn from_bytes(b: &[u8]) -> Result<Self, VerifyError> {
        if b.len() != 4 + 1 + 1 + 1 + 32 + 8 + 32 + 64
            || &b[0..4] != b"TRVP"
            || b[4] != 0x01
        {
            return Err(VerifyError::BadEncoding);
        }
        let method = LivenessMethod::from_code(b[5]).ok_or(VerifyError::BadEncoding)?;
        let passed = match b[6] {
            0 => false,
            1 => true,
            _ => return Err(VerifyError::BadEncoding),
        };
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&b[7..39]);
        let mut ts = [0u8; 8];
        ts.copy_from_slice(&b[39..47]);
        let mut dk = [0u8; 32];
        dk.copy_from_slice(&b[47..79]);
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&b[79..143]);
        let rec = ProofOfLife {
            method,
            passed,
            challenge_nonce: nonce,
            timestamp: u64::from_be_bytes(ts),
            device_key: PublicKey::from_bytes(dk),
            signature: Signature::from_bytes(sig),
        };
        rec.verify()?;
        Ok(rec)
    }
}

// ---------------------------------------------------------------------------
// Attestation (the only thing that may leave the device)
// ---------------------------------------------------------------------------

/// How long an attestation stays valid: 365 days in seconds.
pub const ATTESTATION_VALIDITY_SECS: u64 = 31_536_000;

/// Domain separation for attestation signatures.
const ATTEST_DOMAIN: &[u8] = b"TRV-ATTEST-v1";

/// A signed "verified human" attestation.
///
/// This is the ONLY artifact from the verification process that may
/// ever leave the device. It contains the subject's identity public
/// key, a verification level code, timestamps, and the verifying
/// device's signature — and ZERO personal data: no name, no birth
/// date, no document number, no photo, no address, no MRZ, no
/// biometric anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerificationAttestation {
    /// The verified user's Ed25519 identity public key.
    pub subject_key: PublicKey,
    /// How far verification progressed (never `Unverified`).
    pub level: VerificationLevel,
    /// Caller-supplied issue time, informational only.
    pub issued_at: u64,
    /// `issued_at + 365 days` (saturating).
    pub expires_at: u64,
    /// Device identity key that performed verification and signed.
    pub device_key: PublicKey,
    /// Ed25519 device signature over the canonical encoding.
    pub signature: Signature,
}

fn attest_signed_bytes(
    subject_key: &PublicKey,
    level: VerificationLevel,
    issued_at: u64,
    expires_at: u64,
    device_key: &PublicKey,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(ATTEST_DOMAIN.len() + 32 + 1 + 8 + 8 + 32);
    out.extend_from_slice(ATTEST_DOMAIN);
    out.extend_from_slice(subject_key.as_bytes());
    out.push(level.code());
    out.extend_from_slice(&issued_at.to_be_bytes());
    out.extend_from_slice(&expires_at.to_be_bytes());
    out.extend_from_slice(device_key.as_bytes());
    out
}

impl VerificationAttestation {
    /// Issue an attestation, signed by the verifying device.
    /// Refuses [`VerificationLevel::Unverified`] — fail closed.
    pub fn issue(
        device_secret: &SecretKey,
        device_public: &PublicKey,
        subject_key: &PublicKey,
        level: VerificationLevel,
        issued_at: u64,
    ) -> Result<Self, VerifyError> {
        if level == VerificationLevel::Unverified {
            return Err(VerifyError::AttestUnverifiedLevel);
        }
        let expires_at = issued_at.saturating_add(ATTESTATION_VALIDITY_SECS);
        let msg = attest_signed_bytes(subject_key, level, issued_at, expires_at, device_public);
        let signature = ed25519::sign(device_secret, device_public, &msg);
        Ok(VerificationAttestation {
            subject_key: *subject_key,
            level,
            issued_at,
            expires_at,
            device_key: *device_public,
            signature,
        })
    }

    /// Verify the device signature and the validity window.
    /// `now` is caller-supplied; there is no trusted on-device clock.
    pub fn verify(&self, now: u64) -> Result<(), VerifyError> {
        let msg = attest_signed_bytes(
            &self.subject_key,
            self.level,
            self.issued_at,
            self.expires_at,
            &self.device_key,
        );
        if !ed25519::verify(&self.device_key, &msg, &self.signature) {
            return Err(VerifyError::AttestBadSignature);
        }
        if now < self.issued_at || now > self.expires_at {
            return Err(VerifyError::AttestExpired);
        }
        Ok(())
    }

    /// Wire encoding: `TRVA || 0x01 || subject(32) || level ||
    /// issued_at(8 BE) || expires_at(8 BE) || device_key(32) ||
    /// sig(64)`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 1 + 32 + 1 + 8 + 8 + 32 + 64);
        out.extend_from_slice(b"TRVA");
        out.push(0x01);
        out.extend_from_slice(self.subject_key.as_bytes());
        out.push(self.level.code());
        out.extend_from_slice(&self.issued_at.to_be_bytes());
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out.extend_from_slice(self.device_key.as_bytes());
        out.extend_from_slice(self.signature.as_bytes());
        out
    }

    /// Parse a wire-encoded attestation. Signature is NOT checked here;
    /// call [`VerificationAttestation::verify`] with `now` for that.
    /// Fail closed on malformed input.
    pub fn from_bytes(b: &[u8]) -> Result<Self, VerifyError> {
        if b.len() != 4 + 1 + 32 + 1 + 8 + 8 + 32 + 64
            || &b[0..4] != b"TRVA"
            || b[4] != 0x01
        {
            return Err(VerifyError::BadEncoding);
        }
        let mut sk = [0u8; 32];
        sk.copy_from_slice(&b[5..37]);
        let level = VerificationLevel::from_code(b[37]).ok_or(VerifyError::BadEncoding)?;
        let mut ia = [0u8; 8];
        ia.copy_from_slice(&b[38..46]);
        let mut ea = [0u8; 8];
        ea.copy_from_slice(&b[46..54]);
        let mut dk = [0u8; 32];
        dk.copy_from_slice(&b[54..86]);
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&b[86..150]);
        Ok(VerificationAttestation {
            subject_key: PublicKey::from_bytes(sk),
            level,
            issued_at: u64::from_be_bytes(ia),
            expires_at: u64::from_be_bytes(ea),
            device_key: PublicKey::from_bytes(dk),
            signature: Signature::from_bytes(sig),
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ICAO 9303 specimen passport MRZ (public spec example).
    const SPEC_L1: &str = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<";
    const SPEC_L2: &str = "L898902C36UTO7408122F1204159ZE184226B<<<<<10";

    fn device_keypair() -> (SecretKey, PublicKey) {
        ed25519::generate(&[0xA5u8; 32])
    }

    fn user_keypair() -> (SecretKey, PublicKey) {
        ed25519::generate(&[0x5Au8; 32])
    }

    /// Sliding-window scan: true if `needle` appears anywhere in `haystack`.
    fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() || needle.len() > haystack.len() {
            return false;
        }
        haystack
            .windows(needle.len())
            .any(|w| w == needle)
    }

    // -- MRZ ---------------------------------------------------------------

    #[test]
    fn mrz_specimen_passes() {
        let doc = check_mrz(SPEC_L1, SPEC_L2, (10, 1, 1)).expect("specimen must pass");
        assert_eq!(doc.doc_type, *b"P<");
        assert_eq!(doc.issuing_country, *b"UTO");
        assert_eq!(doc.expiry, (12, 4, 15));
        let fields = IdFields::from(doc);
        assert!(!fields.is_expired((10, 1, 1)));
        assert!(fields.is_expired((26, 10, 14)));
    }

    #[test]
    fn mrz_tampered_doc_number_fails() {
        let mut l2 = SPEC_L2.to_string().into_bytes();
        l2[0] = b'M'; // L -> M breaks the doc-number check digit
        let line2 = String::from_utf8(l2).unwrap();
        assert_eq!(
            check_mrz(SPEC_L1, &line2, (10, 1, 1)),
            Err(VerifyError::MrzDocNumberChecksum)
        );
    }

    #[test]
    fn mrz_tampered_expiry_check_digit_fails() {
        let mut l2 = SPEC_L2.to_string().into_bytes();
        l2[27] = b'0'; // expiry check digit 9 -> 0
        let line2 = String::from_utf8(l2).unwrap();
        assert_eq!(
            check_mrz(SPEC_L1, &line2, (10, 1, 1)),
            Err(VerifyError::MrzExpiryChecksum)
        );
    }

    #[test]
    fn mrz_tampered_composite_fails() {
        let mut l2 = SPEC_L2.to_string().into_bytes();
        l2[43] = b'1'; // composite check digit 0 -> 1
        let line2 = String::from_utf8(l2).unwrap();
        assert_eq!(
            check_mrz(SPEC_L1, &line2, (10, 1, 1)),
            Err(VerifyError::MrzCompositeChecksum)
        );
    }

    #[test]
    fn mrz_bad_length_fails() {
        let short = &SPEC_L2[..43];
        assert_eq!(
            check_mrz(SPEC_L1, short, (10, 1, 1)),
            Err(VerifyError::MrzBadLength)
        );
        assert_eq!(
            check_mrz(SPEC_L1, SPEC_L2, (10, 1, 1)).is_ok(),
            true
        );
    }

    #[test]
    fn mrz_bad_charset_fails() {
        let mut l2 = SPEC_L2.to_string().into_bytes();
        l2[5] = b'a'; // lowercase not in MRZ charset
        let line2 = String::from_utf8(l2).unwrap();
        assert_eq!(
            check_mrz(SPEC_L1, &line2, (10, 1, 1)),
            Err(VerifyError::MrzBadCharset)
        );
    }

    #[test]
    fn mrz_expired_document_fails() {
        // Specimen expires 12-04-15; "today" 26-10-14 is after.
        assert_eq!(
            check_mrz(SPEC_L1, SPEC_L2, (26, 10, 14)),
            Err(VerifyError::MrzDocumentExpired)
        );
    }

    #[test]
    fn mrz_errors_never_echo_input() {
        // Every error variant must render without any MRZ content.
        let needles: &[&[u8]] = &[
            b"ERIKSSON",
            b"ANNA<MARIA",
            b"L898902C3",
            b"740812",
            b"ZE184226B",
            SPEC_L1.as_bytes(),
            SPEC_L2.as_bytes(),
        ];
        let variants = [
            VerifyError::EntropyUnavailable,
            VerifyError::MrzBadLength,
            VerifyError::MrzBadCharset,
            VerifyError::MrzDocNumberChecksum,
            VerifyError::MrzBirthDateChecksum,
            VerifyError::MrzExpiryChecksum,
            VerifyError::MrzPersonalNumberChecksum,
            VerifyError::MrzCompositeChecksum,
            VerifyError::MrzDocumentExpired,
            VerifyError::ChallengeMismatch,
            VerifyError::LivenessMethodMismatch,
            VerifyError::LivenessReplayRejected,
            VerifyError::LivenessBadSignature,
            VerifyError::BadEncoding,
            VerifyError::AttestBadSignature,
            VerifyError::AttestExpired,
            VerifyError::AttestUnverifiedLevel,
        ];
        for v in variants {
            let rendered = format!("{:?} | {}", v, v);
            for n in needles {
                assert!(
                    !contains_bytes(rendered.as_bytes(), n),
                    "error {:?} echoes MRZ data",
                    v
                );
            }
        }
    }

    // -- Levels / methods ----------------------------------------------------

    #[test]
    fn level_codes_round_trip() {
        assert_eq!(VerificationLevel::Unverified.code(), 0);
        assert_eq!(VerificationLevel::DocumentChecked.code(), 1);
        assert_eq!(VerificationLevel::HumanVerified.code(), 2);
        assert_eq!(VerificationLevel::from_code(2), Some(VerificationLevel::HumanVerified));
        assert_eq!(VerificationLevel::from_code(9), None);
        assert_eq!(LivenessMethod::VideoSelfie.code(), 1);
        assert_eq!(LivenessMethod::Bioprint.code(), 2);
        assert_eq!(LivenessMethod::from_code(1), Some(LivenessMethod::VideoSelfie));
        assert_eq!(LivenessMethod::from_code(0), None);
    }

    // -- Liveness ------------------------------------------------------------

    #[test]
    fn liveness_video_round_trip() {
        let (ds, dp) = device_keypair();
        let mut sess = LivenessSession::new();
        let ch = sess
            .issue_challenge(LivenessMethod::VideoSelfie, 1_000)
            .unwrap();
        assert_eq!(ch.method, LivenessMethod::VideoSelfie);
        assert_eq!(ch.actions.len(), CHALLENGE_ACTIONS);
        // Wire round-trip of the challenge itself.
        let ch2 = LivenessChallenge::from_bytes(&ch.to_bytes()).unwrap();
        assert_eq!(ch, ch2);

        let resp = LivenessResponse::sign(&ds, &dp, LivenessMethod::VideoSelfie, true, ch.nonce);
        let verdict = sess.verify_response(&resp).unwrap();
        assert!(verdict.passed);
        assert_eq!(verdict.method, LivenessMethod::VideoSelfie);
    }

    #[test]
    fn liveness_bioprint_round_trip_records_method() {
        let (ds, dp) = device_keypair();
        let mut sess = LivenessSession::new();
        let ch = sess.issue_challenge(LivenessMethod::Bioprint, 1_000).unwrap();
        let resp = LivenessResponse::sign(&ds, &dp, LivenessMethod::Bioprint, true, ch.nonce);
        let verdict = sess.verify_response(&resp).unwrap();
        assert!(verdict.passed);
        assert_eq!(verdict.method, LivenessMethod::Bioprint);
        assert_eq!(verdict.method.code(), 2);
    }

    #[test]
    fn liveness_replay_rejected() {
        let (ds, dp) = device_keypair();
        let mut sess = LivenessSession::new();
        let ch = sess.issue_challenge(LivenessMethod::VideoSelfie, 1_000).unwrap();
        let resp = LivenessResponse::sign(&ds, &dp, LivenessMethod::VideoSelfie, true, ch.nonce);
        sess.verify_response(&resp).unwrap();
        assert_eq!(
            sess.verify_response(&resp),
            Err(VerifyError::LivenessReplayRejected)
        );
    }

    #[test]
    fn liveness_method_mismatch_fails_closed() {
        let (ds, dp) = device_keypair();
        let mut sess = LivenessSession::new();
        // Challenge issued for video...
        let ch = sess.issue_challenge(LivenessMethod::VideoSelfie, 1_000).unwrap();
        // ...but the response claims bioprint.
        let resp = LivenessResponse::sign(&ds, &dp, LivenessMethod::Bioprint, true, ch.nonce);
        assert_eq!(
            sess.verify_response(&resp),
            Err(VerifyError::LivenessMethodMismatch)
        );
    }

    #[test]
    fn liveness_bad_signature_fails() {
        let (_ds, dp) = device_keypair();
        let (es, ep) = ed25519::generate(&[0x11u8; 32]);
        let mut sess = LivenessSession::new();
        let ch = sess.issue_challenge(LivenessMethod::VideoSelfie, 1_000).unwrap();
        // Signed by the wrong device key.
        let resp = LivenessResponse::sign(&es, &ep, LivenessMethod::VideoSelfie, true, ch.nonce);
        let mut evil = resp;
        evil.device_key = dp; // claim the right key with the wrong signature
        assert_eq!(
            sess.verify_response(&evil),
            Err(VerifyError::LivenessBadSignature)
        );
    }

    #[test]
    fn liveness_unknown_challenge_fails() {
        let (ds, dp) = device_keypair();
        let mut sess = LivenessSession::new();
        let resp = LivenessResponse::sign(&ds, &dp, LivenessMethod::VideoSelfie, true, [7u8; 32]);
        assert_eq!(
            sess.verify_response(&resp),
            Err(VerifyError::ChallengeMismatch)
        );
    }

    // -- Proof of life ---------------------------------------------------------

    #[test]
    fn proof_of_life_round_trip_and_tamper() {
        let (ds, dp) = device_keypair();
        let pol = ProofOfLife::attest(&ds, &dp, LivenessMethod::VideoSelfie, true, [9u8; 32], 2_000);
        assert_eq!(pol.method, LivenessMethod::VideoSelfie);
        assert!(pol.passed);
        pol.verify().unwrap();
        // Wire round-trip (parse re-verifies the signature).
        let rt = ProofOfLife::from_bytes(&pol.to_bytes()).unwrap();
        assert_eq!(rt, pol);

        // Flip the verdict byte in the encoding: signature must fail.
        let mut tampered = pol.to_bytes();
        tampered[6] ^= 1; // verdict byte 1 -> 0
        assert_eq!(
            ProofOfLife::from_bytes(&tampered),
            Err(VerifyError::LivenessBadSignature)
        );
    }

    #[test]
    fn proof_of_life_bioprint_method_recorded() {
        let (ds, dp) = device_keypair();
        let pol = ProofOfLife::attest(&ds, &dp, LivenessMethod::Bioprint, true, [3u8; 32], 2_000);
        assert_eq!(pol.method, LivenessMethod::Bioprint);
        assert_eq!(pol.method.code(), 2);
        pol.verify().unwrap();
    }

    #[test]
    fn proof_of_life_contains_no_video_or_biometric_data() {
        let (ds, dp) = device_keypair();
        // Simulated raw capture bytes that must NEVER appear in the record.
        let fake_video: &[u8] = b"FAKE_VIDEO_FRAME_BYTES_1080p_RAW_CAPTURE_DATA_001";
        let fake_template: &[u8] = b"FAKE_BIOMETRIC_TEMPLATE_MINUTIAE_DATA_XYZ_999";
        let fake_name: &[u8] = b"ANNA<MARIA<<ERIKSSON";

        for method in [LivenessMethod::VideoSelfie, LivenessMethod::Bioprint] {
            let pol = ProofOfLife::attest(&ds, &dp, method, true, [4u8; 32], 2_000);
            let enc = pol.to_bytes();
            for needle in [fake_video, fake_template, fake_name] {
                assert!(
                    !contains_bytes(&enc, needle),
                    "proof-of-life leaks raw capture data"
                );
            }
        }
    }

    // -- Attestation -----------------------------------------------------------

    #[test]
    fn attestation_round_trip() {
        let (ds, dp) = device_keypair();
        let (_, up) = user_keypair();
        let att = VerificationAttestation::issue(
            &ds,
            &dp,
            &up,
            VerificationLevel::HumanVerified,
            1_000_000,
        )
        .unwrap();
        assert_eq!(att.level, VerificationLevel::HumanVerified);
        assert_eq!(att.expires_at, 1_000_000 + ATTESTATION_VALIDITY_SECS);
        att.verify(1_000_001).unwrap();
        // Wire round-trip then verify.
        let rt = VerificationAttestation::from_bytes(&att.to_bytes()).unwrap();
        assert_eq!(rt, att);
        rt.verify(1_000_001).unwrap();
    }

    #[test]
    fn attestation_expired_fails() {
        let (ds, dp) = device_keypair();
        let (_, up) = user_keypair();
        let att = VerificationAttestation::issue(
            &ds,
            &dp,
            &up,
            VerificationLevel::DocumentChecked,
            1_000,
        )
        .unwrap();
        assert_eq!(
            att.verify(1_000 + ATTESTATION_VALIDITY_SECS + 1),
            Err(VerifyError::AttestExpired)
        );
        // Not yet valid either.
        assert_eq!(att.verify(999), Err(VerifyError::AttestExpired));
    }

    #[test]
    fn attestation_tampered_fails() {
        let (ds, dp) = device_keypair();
        let (_, up) = user_keypair();
        let att = VerificationAttestation::issue(
            &ds,
            &dp,
            &up,
            VerificationLevel::DocumentChecked,
            5_000,
        )
        .unwrap();
        // Flip the level byte in the encoding: signature check must fail.
        let mut tampered = att.to_bytes();
        tampered[37] = VerificationLevel::HumanVerified.code();
        let parsed = VerificationAttestation::from_bytes(&tampered).unwrap();
        assert_eq!(
            parsed.verify(5_001),
            Err(VerifyError::AttestBadSignature)
        );
    }

    #[test]
    fn attestation_unverified_level_refused() {
        let (ds, dp) = device_keypair();
        let (_, up) = user_keypair();
        assert_eq!(
            VerificationAttestation::issue(&ds, &dp, &up, VerificationLevel::Unverified, 5_000),
            Err(VerifyError::AttestUnverifiedLevel)
        );
    }

    #[test]
    fn attestation_contains_zero_personal_data() {
        let (ds, dp) = device_keypair();
        let (_, up) = user_keypair();
        let att = VerificationAttestation::issue(
            &ds,
            &dp,
            &up,
            VerificationLevel::HumanVerified,
            9_000,
        )
        .unwrap();
        let enc = att.to_bytes();
        // Personal strings that must never appear in the attestation.
        let needles: &[&[u8]] = &[
            b"ERIKSSON",
            b"ANNA<MARIA",
            b"L898902C3",
            b"740812",
            b"ZE184226B",
            b"P<UTO",
        ];
        for n in needles {
            assert!(
                !contains_bytes(&enc, n),
                "attestation leaks personal data"
            );
        }
    }
}
