//! VerificationRegistry — on-chain identity verification for TRV.
//!
//! **Status: scaffold.** Pure-Rust program logic, zero dependencies,
//! std-only. It compiles and tests offline today; a thin Anchor (or
//! `solana-program`) adapter will deserialize real accounts and
//! forward to [`process_instruction`] at deploy time. There is no
//! deployed program, no RPC client, and no wallet integration yet.
//!
//! # What this program does
//!
//! Every Remote Viewer proves they are a real, verified human
//! on-device ([`trv_core::verify_flow`] — document check + liveness).
//! The device then anchors a *cryptographic commitment* to that proof
//! on Solana so anyone can check "this device verified a human at
//! this level" without learning anything about the person.
//!
//! # Privacy invariant (HARD — enforced by test)
//!
//! NO personal data ever goes on-chain. Not the name, not the
//! document number, not the birth date, not the biometric template,
//! not even the subject's identity key. The ONLY things stored are:
//!
//! * `device_key` — a pseudonymous 32-byte device public key (the PDA
//!   seed; not linkable to a real identity from chain data alone)
//! * `attestation_hash` — SHA-512 of the canonical attestation bytes
//! * `level` — 1 = document-checked, 2 = human-verified
//! * timestamps and bookkeeping (`registered_at`, `expires_at`,
//!   revocation flags, rate-limit window)
//!
//! The full attestation (150 bytes: subject key, level, timestamps,
//! device key, device signature) NEVER leaves the device except when
//! the viewer *chooses* to show it peer-to-peer (QR / proximity).
//! A verifier hashes what they are shown and compares against the
//! on-chain hash. See [`verify_off_chain`].
//!
//! # Instructions
//!
//! * `RegisterAttestation` — anchor a hash. One active attestation
//!   per device; re-registering requires revoking first. Max 3
//!   registrations per 365-day window (anti-farming).
//! * `RevokeAttestation` — the device revokes its own attestation
//!   (lost phone, re-verification at a higher level, …).
//! * Verification *checks* are reads — no instruction needed. Use
//!   [`is_verified`] / [`verification_status`] off-chain against the
//!   fetched account.
//!
//! # Anti-Sybil posture
//!
//! One device key = one attestation slot, plus registration rate
//! limits. This is Sybil-*resistant*, not Sybil-proof: an attacker
//! with many physical devices can still register many attestations.
//! Device attestation binding (proving the key lives in real
//! hardware) is future platform work.
//!
//! # Deploy mapping (for the Anchor adapter, later)
//!
//! | Anchor concept              | Here                                              |
//! |-----------------------------|---------------------------------------------------|
//! | `#[program]` module         | [`process_instruction`]                           |
//! | `#[derive(Accounts)]`      | [`IdentityAccounts`] — explicit account bundle    |
//! | `#[account]` struct         | [`AttestationRecord`]                             |
//! | `declare_id!`               | [`IDENTITY_PROGRAM_ID`] (placeholder)             |
//! | `Clock::get()`              | `now` parameter (unix seconds; injected)           |
//! | `Signer` checks             | `is_signer` flag + `device_key` match             |

use core::fmt;

/// Placeholder program ID for the VerificationRegistry program.
/// **Replaced by the real address at deploy.**
pub const IDENTITY_PROGRAM_ID: &str = "TRVIdnt1111111111111111111111111111111111111";

// ---------------------------------------------------------------------------
// SHA-512 (FIPS 180-4), std-only
// ---------------------------------------------------------------------------
//
// The solana crate is standalone (no dependency on trv_core), so it
// carries its own SHA-512 for attestation hashing. This is the
// standard FIPS 180-4 construction; correctness is pinned by the
// empty-string and "abc" test vectors below.

/// SHA-512 round constants: fractional parts of the cube roots of the
/// first 80 primes.
const SHA512_K: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

/// Compute SHA-512 over `message`. Pure function, no I/O.
pub fn sha512(message: &[u8]) -> [u8; 64] {
    let mut h: [u64; 8] = [
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179,
    ];

    // Pad: 0x80, zeros, then the 128-bit big-endian bit length.
    let mut padded = message.to_vec();
    let bit_len = (message.len() as u128).wrapping_mul(8);
    padded.push(0x80);
    while padded.len() % 128 != 112 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.chunks_exact(128) {
        let mut w = [0u64; 80];
        for (i, slot) in w.iter_mut().enumerate().take(16) {
            let mut b = [0u8; 8];
            b.copy_from_slice(&chunk[i * 8..i * 8 + 8]);
            *slot = u64::from_be_bytes(b);
        }
        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..80 {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA512_K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 64];
    for (i, v) in h.iter().enumerate() {
        out[i * 8..i * 8 + 8].copy_from_slice(&v.to_be_bytes());
    }
    out
}

// ---------------------------------------------------------------------------
// Canonical attestation format (mirrors trv_core::verify)
// ---------------------------------------------------------------------------
//
// Wire encoding produced by `VerificationAttestation::to_bytes()`:
// `TRVA || 0x01 || subject_key(32) || level(1) || issued_at(8 BE) ||
//  expires_at(8 BE) || device_key(32) || signature(64)` = 150 bytes.
// The anchor hash is SHA-512 over exactly these bytes.

/// Length of a canonical attestation encoding.
pub const ATTESTATION_WIRE_LEN: usize = 150;
const ATTEST_MAGIC: &[u8; 4] = b"TRVA";
const ATTEST_VERSION: u8 = 0x01;

/// Verification levels (wire codes mirror `trv_core::verify`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationLevel {
    /// ID document authenticity checks passed.
    DocumentChecked = 1,
    /// Document checks plus a liveness proof both passed.
    HumanVerified = 2,
}

impl VerificationLevel {
    pub fn code(self) -> u8 {
        self as u8
    }

    pub fn label(self) -> &'static str {
        match self {
            VerificationLevel::DocumentChecked => "document-checked",
            VerificationLevel::HumanVerified => "human-verified",
        }
    }

    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(VerificationLevel::DocumentChecked),
            2 => Some(VerificationLevel::HumanVerified),
            _ => None,
        }
    }
}

/// Validate the canonical attestation encoding without parsing
/// personal data out of it. Returns the level on success.
fn check_attestation_encoding(b: &[u8]) -> Result<VerificationLevel, IdentityError> {
    if b.len() != ATTESTATION_WIRE_LEN
        || &b[0..4] != ATTEST_MAGIC
        || b[4] != ATTEST_VERSION
    {
        return Err(IdentityError::BadAttestationEncoding);
    }
    VerificationLevel::from_code(b[37]).ok_or(IdentityError::InvalidLevel)
}

/// Field offsets inside the canonical encoding.
fn attestation_device_key(b: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 32];
    k.copy_from_slice(&b[54..86]);
    k
}

fn attestation_expires_at(b: &[u8]) -> u64 {
    let mut e = [0u8; 8];
    e.copy_from_slice(&b[46..54]);
    u64::from_be_bytes(e)
}

/// The on-chain commitment: SHA-512 over the canonical attestation
/// bytes. Only this hash is stored on-chain — never the attestation.
pub fn attestation_hash(attestation_bytes: &[u8]) -> Result<[u8; 64], IdentityError> {
    check_attestation_encoding(attestation_bytes)?;
    Ok(sha512(attestation_bytes))
}

// ---------------------------------------------------------------------------
// On-chain account
// ---------------------------------------------------------------------------

/// Max registrations per device inside one rate-limit window.
pub const MAX_REGISTRATIONS_PER_WINDOW: u32 = 3;
/// Rate-limit window: one year, in seconds.
pub const RATE_LIMIT_WINDOW_SECS: u64 = 365 * 24 * 3600;

/// On-chain attestation record (Anchor `#[account]` equivalent).
///
/// PDA seeds: `[b"trv-attestation", device_key]`. Rent paid by the
/// device at registration.
///
/// **Privacy:** this struct has no field capable of holding personal
/// data — no name, no document number, no birth date, no biometrics,
/// no subject key. The `privacy_byte_scan` test enforces this on the
/// serialized form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttestationRecord {
    /// Pseudonymous device public key (PDA seed component).
    pub device_key: [u8; 32],
    /// SHA-512 of the canonical attestation bytes. NOT the attestation.
    pub attestation_hash: [u8; 64],
    /// Verification level wire code (1 or 2).
    pub level: u8,
    /// Unix seconds when this registration landed.
    pub registered_at: u64,
    /// Unix seconds when the attestation expires (from the device).
    pub expires_at: u64,
    /// True once the device revokes. A revoked record stays readable
    /// so verifiers see "was verified, now revoked" — it is never
    /// silently deleted.
    pub revoked: bool,
    /// Unix seconds of revocation; 0 if never revoked.
    pub revoked_at: u64,
    /// False until the first registration (fresh PDA).
    pub initialized: bool,
    /// Start of the current rate-limit window (unix seconds).
    pub window_start: u64,
    /// Registrations consumed inside the current window.
    pub window_count: u32,
}

impl AttestationRecord {
    /// A fresh, never-registered record (what a new PDA holds).
    pub fn uninitialized() -> Self {
        AttestationRecord {
            device_key: [0u8; 32],
            attestation_hash: [0u8; 64],
            level: 0,
            registered_at: 0,
            expires_at: 0,
            revoked: false,
            revoked_at: 0,
            initialized: false,
            window_start: 0,
            window_count: 0,
        }
    }

    /// Fixed-size serialization for the byte-scan privacy test and
    /// for the future Anchor adapter's space calculation.
    /// Layout: device_key(32) || hash(64) || level(1) || registered(8)
    /// || expires(8) || revoked(1) || revoked_at(8) || init(1) ||
    /// window_start(8) || window_count(4) = 135 bytes.
    pub fn to_bytes(&self) -> [u8; 135] {
        let mut out = [0u8; 135];
        out[0..32].copy_from_slice(&self.device_key);
        out[32..96].copy_from_slice(&self.attestation_hash);
        out[96] = self.level;
        out[97..105].copy_from_slice(&self.registered_at.to_be_bytes());
        out[105..113].copy_from_slice(&self.expires_at.to_be_bytes());
        out[113] = self.revoked as u8;
        out[114..122].copy_from_slice(&self.revoked_at.to_be_bytes());
        out[122] = self.initialized as u8;
        out[123..131].copy_from_slice(&self.window_start.to_be_bytes());
        out[131..135].copy_from_slice(&self.window_count.to_be_bytes());
        out
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Every failure the VerificationRegistry can report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityError {
    /// Attestation bytes are not the canonical 150-byte encoding.
    BadAttestationEncoding,
    /// Level wire code is not 1 or 2.
    InvalidLevel,
    /// The attestation already expired (`expires_at <= now`).
    AttestationExpired,
    /// This device already has an active attestation — revoke it
    /// before registering a new one.
    DuplicateRegistration,
    /// More than [`MAX_REGISTRATIONS_PER_WINDOW`] registrations
    /// inside [`RATE_LIMIT_WINDOW_SECS`].
    RateLimited,
    /// Nothing registered for this device yet.
    NotRegistered,
    /// Already revoked — revocation is one-way.
    AlreadyRevoked,
    /// The transaction signer is not the device key on the record.
    NotDeviceSigner,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            IdentityError::BadAttestationEncoding => "attestation is not the canonical encoding",
            IdentityError::InvalidLevel => "verification level must be 1 or 2",
            IdentityError::AttestationExpired => "attestation already expired",
            IdentityError::DuplicateRegistration => {
                "device already has an active attestation; revoke first"
            }
            IdentityError::RateLimited => "too many registrations in the rate-limit window",
            IdentityError::NotRegistered => "no attestation registered for this device",
            IdentityError::AlreadyRevoked => "attestation already revoked",
            IdentityError::NotDeviceSigner => "signer is not the device key",
        };
        f.write_str(s)
    }
}

// ---------------------------------------------------------------------------
// Instructions
// ---------------------------------------------------------------------------

/// Every instruction the VerificationRegistry program accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityInstruction {
    /// Anchor an attestation hash for this device.
    /// Args: device pubkey, attestation hash, level code, now.
    RegisterAttestation {
        device_key: [u8; 32],
        attestation_hash: [u8; 64],
        level: u8,
        expires_at: u64,
        now: u64,
    },
    /// Revoke this device's attestation. Args: device pubkey, now.
    RevokeAttestation { device_key: [u8; 32], now: u64 },
}

/// Explicit account bundle for [`process_instruction`].
#[derive(Debug)]
pub struct IdentityAccounts<'a> {
    /// The PDA attestation record for the device.
    pub record: Option<&'a mut AttestationRecord>,
    /// True if the device key signed the transaction.
    pub is_signer: bool,
    /// The public key that signed (must equal the device key).
    pub signer_key: [u8; 32],
}

/// What an instruction produced (for the adapter to persist).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityOutput {
    Registered { registered_at: u64 },
    Revoked { revoked_at: u64 },
}

fn require_device_signer(
    accts: &IdentityAccounts,
    device_key: &[u8; 32],
) -> Result<(), IdentityError> {
    if accts.is_signer && &accts.signer_key == device_key {
        Ok(())
    } else {
        Err(IdentityError::NotDeviceSigner)
    }
}

/// Register (or re-register after revocation) an attestation hash.
///
/// Pure logic — no syscalls, no clock reads. The Anchor adapter
/// builds [`IdentityAccounts`] from the deserialized PDA.
pub fn register_attestation(
    record: &mut AttestationRecord,
    device_key: [u8; 32],
    attestation_hash: [u8; 64],
    level: u8,
    expires_at: u64,
    now: u64,
) -> Result<u64, IdentityError> {
    if VerificationLevel::from_code(level).is_none() {
        return Err(IdentityError::InvalidLevel);
    }
    if expires_at <= now {
        return Err(IdentityError::AttestationExpired);
    }
    if record.initialized && !record.revoked {
        // One active attestation per device: revoke before replacing.
        return Err(IdentityError::DuplicateRegistration);
    }
    // Rate limit: at most MAX_REGISTRATIONS_PER_WINDOW per window.
    // A fresh window starts when the old one elapsed.
    let (window_start, window_count) = if !record.initialized
        || now >= record.window_start.saturating_add(RATE_LIMIT_WINDOW_SECS)
    {
        (now, 0)
    } else {
        (record.window_start, record.window_count)
    };
    if window_count >= MAX_REGISTRATIONS_PER_WINDOW {
        return Err(IdentityError::RateLimited);
    }

    record.device_key = device_key;
    record.attestation_hash = attestation_hash;
    record.level = level;
    record.registered_at = now;
    record.expires_at = expires_at;
    record.revoked = false;
    record.revoked_at = 0;
    record.initialized = true;
    record.window_start = window_start;
    record.window_count = window_count + 1;
    Ok(now)
}

/// Revoke this device's attestation. One-way: a revoked record can
/// never become active again without a fresh registration (which
/// counts against the rate limit).
pub fn revoke_attestation(
    record: &mut AttestationRecord,
    device_key: [u8; 32],
    now: u64,
) -> Result<u64, IdentityError> {
    if !record.initialized {
        return Err(IdentityError::NotRegistered);
    }
    if record.device_key != device_key {
        return Err(IdentityError::NotDeviceSigner);
    }
    if record.revoked {
        return Err(IdentityError::AlreadyRevoked);
    }
    record.revoked = true;
    record.revoked_at = now;
    Ok(now)
}

/// Dispatch one instruction. Pure logic — no syscalls, no clock reads.
pub fn process_instruction(
    ix: IdentityInstruction,
    accts: &mut IdentityAccounts,
) -> Result<IdentityOutput, IdentityError> {
    match ix {
        IdentityInstruction::RegisterAttestation {
            device_key,
            attestation_hash,
            level,
            expires_at,
            now,
        } => {
            require_device_signer(accts, &device_key)?;
            let record = accts
                .record
                .as_mut()
                .ok_or(IdentityError::NotRegistered)?;
            let registered_at =
                register_attestation(record, device_key, attestation_hash, level, expires_at, now)?;
            Ok(IdentityOutput::Registered { registered_at })
        }
        IdentityInstruction::RevokeAttestation { device_key, now } => {
            require_device_signer(accts, &device_key)?;
            let record = accts
                .record
                .as_mut()
                .ok_or(IdentityError::NotRegistered)?;
            let revoked_at = revoke_attestation(record, device_key, now)?;
            Ok(IdentityOutput::Revoked { revoked_at })
        }
    }
}

// ---------------------------------------------------------------------------
// Verification status (read path — no instruction needed)
// ---------------------------------------------------------------------------

/// What a fetched attestation record says about a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationStatus {
    /// Active attestation at this level.
    Verified { level: VerificationLevel },
    /// Never registered.
    NeverRegistered,
    /// Registered but revoked by the device.
    Revoked,
    /// Registered but past `expires_at`.
    Expired,
}

/// Rich status for a fetched record at time `now`.
pub fn verification_status(record: &AttestationRecord, now: u64) -> VerificationStatus {
    if !record.initialized {
        return VerificationStatus::NeverRegistered;
    }
    if record.revoked {
        return VerificationStatus::Revoked;
    }
    if now > record.expires_at {
        return VerificationStatus::Expired;
    }
    match VerificationLevel::from_code(record.level) {
        Some(level) => VerificationStatus::Verified { level },
        None => VerificationStatus::NeverRegistered, // corrupt level: fail closed
    }
}

/// Simple boolean check: `check_verification(device) -> bool`.
pub fn is_verified(record: &AttestationRecord, now: u64) -> bool {
    matches!(
        verification_status(record, now),
        VerificationStatus::Verified { .. }
    )
}

// ---------------------------------------------------------------------------
// Off-chain verifier — "anyone can verify anyone", peer to peer
// ---------------------------------------------------------------------------

/// The on-chain data a verifier fetches for a device: hash + metadata.
/// Built from a fetched [`AttestationRecord`]; carries no personal data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainAttestationView {
    pub attestation_hash: [u8; 64],
    pub level: u8,
    pub revoked: bool,
    pub expires_at: u64,
}

impl ChainAttestationView {
    pub fn from_record(record: &AttestationRecord) -> Option<Self> {
        if !record.initialized {
            return None;
        }
        Some(ChainAttestationView {
            attestation_hash: record.attestation_hash,
            level: record.level,
            revoked: record.revoked,
            expires_at: record.expires_at,
        })
    }
}

/// Outcome of an off-chain verification. The verifier learns NOTHING
/// about the person — only whether the presented attestation matches
/// the on-chain commitment and is still valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// The presented attestation hashes to the on-chain commitment,
    /// is not revoked, and has not expired.
    Verified { level: VerificationLevel },
    /// The hash does not match: tampered or wrong attestation.
    HashMismatch,
    /// The device revoked this attestation.
    Revoked,
    /// Past `expires_at`.
    Expired,
    /// Not the canonical 150-byte encoding, or bad level code.
    BadAttestation,
}

/// Constant-time 64-byte comparison (no timing oracle on the hash).
fn ct_eq(a: &[u8; 64], b: &[u8; 64]) -> bool {
    let mut diff = 0u8;
    for i in 0..64 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Verify a viewer-presented attestation against the on-chain view.
///
/// Flow: the viewer shows their 150-byte attestation over QR or
/// ~1-mile proximity; the verifier fetched `chain` for the device key
/// beforehand. This hashes the presented bytes and compares with the
/// chain commitment — the verifier never sees, stores, or transmits
/// anything personal.
pub fn verify_off_chain(
    attestation_bytes: &[u8],
    chain: &ChainAttestationView,
    now: u64,
) -> VerifyOutcome {
    let level = match check_attestation_encoding(attestation_bytes) {
        Ok(l) => l,
        Err(_) => return VerifyOutcome::BadAttestation,
    };
    // The presented level must agree with what was registered —
    // a level downgrade/upgrade without re-registering is tampering.
    if level.code() != chain.level {
        return VerifyOutcome::HashMismatch;
    }
    if chain.revoked {
        return VerifyOutcome::Revoked;
    }
    if now > chain.expires_at {
        return VerifyOutcome::Expired;
    }
    let hash = sha512(attestation_bytes);
    if !ct_eq(&hash, &chain.attestation_hash) {
        return VerifyOutcome::HashMismatch;
    }
    VerifyOutcome::Verified { level }
}

// ---------------------------------------------------------------------------
// Bridge: from the on-device flow to the anchor request
// ---------------------------------------------------------------------------

/// Everything the wallet/RPC layer needs to submit a
/// `RegisterAttestation` instruction — built on-device the moment
/// [`trv_core::verify_flow::VerificationFlow`] reaches `Complete`.
///
/// Consumes the canonical 150-byte encoding produced by
/// `VerificationAttestation::to_bytes()`. The actual transaction
/// submission (wallet signing + RPC) is future work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorRequest {
    pub device_key: [u8; 32],
    pub attestation_hash: [u8; 64],
    pub level: u8,
    pub expires_at: u64,
}

/// Build the anchor request from a completed verification's
/// attestation bytes. Fails closed on any encoding problem.
pub fn anchor_request_from_attestation(
    attestation_bytes: &[u8],
) -> Result<AnchorRequest, IdentityError> {
    let level = check_attestation_encoding(attestation_bytes)?;
    let hash = sha512(attestation_bytes);
    Ok(AnchorRequest {
        device_key: attestation_device_key(attestation_bytes),
        attestation_hash: hash,
        level: level.code(),
        expires_at: attestation_expires_at(attestation_bytes),
    })
}

impl AnchorRequest {
    /// Convert into the program instruction, with the caller-supplied
    /// `now` (unix seconds).
    pub fn into_instruction(self, now: u64) -> IdentityInstruction {
        IdentityInstruction::RegisterAttestation {
            device_key: self.device_key,
            attestation_hash: self.attestation_hash,
            level: self.level,
            expires_at: self.expires_at,
            now,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        const H: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push(H[(b >> 4) as usize] as char);
            s.push(H[(b & 15) as usize] as char);
        }
        s
    }

    /// Build canonical attestation bytes, mirroring
    /// `VerificationAttestation::to_bytes()`.
    fn fake_attestation(
        subject: [u8; 32],
        level: u8,
        issued_at: u64,
        expires_at: u64,
        device: [u8; 32],
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(ATTESTATION_WIRE_LEN);
        out.extend_from_slice(b"TRVA");
        out.push(0x01);
        out.extend_from_slice(&subject);
        out.push(level);
        out.extend_from_slice(&issued_at.to_be_bytes());
        out.extend_from_slice(&expires_at.to_be_bytes());
        out.extend_from_slice(&device);
        out.extend_from_slice(&[0xAAu8; 64]); // fake signature bytes
        out
    }

    fn device_key(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    fn accounts<'a>(
        record: &'a mut AttestationRecord,
        signer: [u8; 32],
    ) -> IdentityAccounts<'a> {
        IdentityAccounts {
            record: Some(record),
            is_signer: true,
            signer_key: signer,
        }
    }

    /// Full register flow: attestation -> anchor request -> instruction.
    fn register(
        record: &mut AttestationRecord,
        att: &[u8],
        now: u64,
    ) -> Result<IdentityOutput, IdentityError> {
        let req = anchor_request_from_attestation(att).unwrap();
        let ix = req.into_instruction(now);
        let mut accts = accounts(record, attestation_device_key(att));
        process_instruction(ix, &mut accts)
    }

    // -- SHA-512 -----------------------------------------------------------

    #[test]
    fn sha512_empty_vector() {
        assert_eq!(
            hex(&sha512(b"")),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
    }

    #[test]
    fn sha512_abc_vector() {
        assert_eq!(
            hex(&sha512(b"abc")),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }

    #[test]
    fn sha512_multiblock_deterministic() {
        // 200 bytes forces multi-block processing; determinism + length.
        let m = vec![0x55u8; 200];
        let h1 = sha512(&m);
        let h2 = sha512(&m);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
        // And it differs from the single-block hash.
        assert_ne!(h1, sha512(&vec![0x55u8; 100]));
    }

    // -- Registration ------------------------------------------------------

    #[test]
    fn register_then_check_verified() {
        let mut record = AttestationRecord::uninitialized();
        let dk = device_key(7);
        let att = fake_attestation(device_key(9), 2, 1_000, 1_000 + 365 * 86400, dk);
        let out = register(&mut record, &att, 2_000).unwrap();
        assert_eq!(out, IdentityOutput::Registered { registered_at: 2_000 });
        assert!(is_verified(&record, 2_001));
        assert_eq!(
            verification_status(&record, 2_001),
            VerificationStatus::Verified {
                level: VerificationLevel::HumanVerified
            }
        );
        // The stored hash is the SHA-512 of the attestation bytes.
        assert_eq!(record.attestation_hash, sha512(&att));
    }

    #[test]
    fn document_checked_level_registers() {
        let mut record = AttestationRecord::uninitialized();
        let dk = device_key(7);
        let att = fake_attestation(device_key(9), 1, 1_000, 1_000 + 365 * 86400, dk);
        register(&mut record, &att, 2_000).unwrap();
        assert_eq!(
            verification_status(&record, 2_001),
            VerificationStatus::Verified {
                level: VerificationLevel::DocumentChecked
            }
        );
    }

    #[test]
    fn duplicate_registration_rejected_until_revoked() {
        let mut record = AttestationRecord::uninitialized();
        let dk = device_key(7);
        let att = fake_attestation(device_key(9), 2, 1_000, 1_000 + 365 * 86400, dk);
        register(&mut record, &att, 2_000).unwrap();

        // Second registration without revoke: rejected.
        let att2 = fake_attestation(device_key(9), 2, 3_000, 3_000 + 365 * 86400, dk);
        let req = anchor_request_from_attestation(&att2).unwrap();
        let mut accts = accounts(&mut record, dk);
        let err = process_instruction(req.into_instruction(4_000), &mut accts).unwrap_err();
        assert_eq!(err, IdentityError::DuplicateRegistration);

        // Revoke, then re-register works (counts against the rate limit).
        let mut accts = accounts(&mut record, dk);
        let out = process_instruction(
            IdentityInstruction::RevokeAttestation { device_key: dk, now: 5_000 },
            &mut accts,
        )
        .unwrap();
        assert_eq!(out, IdentityOutput::Revoked { revoked_at: 5_000 });
        assert!(!is_verified(&record, 5_001));
        assert_eq!(
            verification_status(&record, 5_001),
            VerificationStatus::Revoked
        );

        register(&mut record, &att2, 6_000).unwrap();
        assert!(is_verified(&record, 6_001));
        assert_eq!(record.attestation_hash, sha512(&att2));
    }

    #[test]
    fn revoke_requires_device_signer() {
        let mut record = AttestationRecord::uninitialized();
        let dk = device_key(7);
        let att = fake_attestation(device_key(9), 2, 1_000, 1_000 + 365 * 86400, dk);
        register(&mut record, &att, 2_000).unwrap();

        // Wrong signer cannot revoke.
        let mut accts = IdentityAccounts {
            record: Some(&mut record),
            is_signer: true,
            signer_key: device_key(99),
        };
        let err = process_instruction(
            IdentityInstruction::RevokeAttestation { device_key: dk, now: 3_000 },
            &mut accts,
        )
        .unwrap_err();
        assert_eq!(err, IdentityError::NotDeviceSigner);

        // Unsigned registration rejected.
        let att2 = fake_attestation(device_key(9), 1, 1_000, 1_000 + 365 * 86400, dk);
        let req = anchor_request_from_attestation(&att2).unwrap();
        let mut accts = IdentityAccounts {
            record: Some(&mut record),
            is_signer: false,
            signer_key: dk,
        };
        let err = process_instruction(req.into_instruction(3_000), &mut accts).unwrap_err();
        assert_eq!(err, IdentityError::NotDeviceSigner);
    }

    #[test]
    fn double_revoke_rejected() {
        let mut record = AttestationRecord::uninitialized();
        let dk = device_key(7);
        let att = fake_attestation(device_key(9), 2, 1_000, 1_000 + 365 * 86400, dk);
        register(&mut record, &att, 2_000).unwrap();
        let mut accts = accounts(&mut record, dk);
        process_instruction(
            IdentityInstruction::RevokeAttestation { device_key: dk, now: 3_000 },
            &mut accts,
        )
        .unwrap();
        let mut accts = accounts(&mut record, dk);
        let err = process_instruction(
            IdentityInstruction::RevokeAttestation { device_key: dk, now: 4_000 },
            &mut accts,
        )
        .unwrap_err();
        assert_eq!(err, IdentityError::AlreadyRevoked);
    }

    #[test]
    fn expired_attestation_rejected_at_register() {
        let mut record = AttestationRecord::uninitialized();
        let dk = device_key(7);
        // expires_at (500) is already past now (2_000).
        let att = fake_attestation(device_key(9), 2, 100, 500, dk);
        let err = register(&mut record, &att, 2_000).unwrap_err();
        assert_eq!(err, IdentityError::AttestationExpired);
        assert!(!record.initialized);
    }

    #[test]
    fn expired_record_reads_expired() {
        let mut record = AttestationRecord::uninitialized();
        let dk = device_key(7);
        let att = fake_attestation(device_key(9), 2, 1_000, 2_000, dk);
        register(&mut record, &att, 1_500).unwrap();
        assert!(is_verified(&record, 1_999));
        assert!(!is_verified(&record, 2_001));
        assert_eq!(
            verification_status(&record, 2_001),
            VerificationStatus::Expired
        );
    }

    #[test]
    fn invalid_level_rejected() {
        let mut record = AttestationRecord::uninitialized();
        let dk = device_key(7);
        // Level 0 (Unverified) must never anchor.
        let att = fake_attestation(device_key(9), 0, 1_000, 1_000 + 365 * 86400, dk);
        let err = anchor_request_from_attestation(&att).unwrap_err();
        assert_eq!(err, IdentityError::InvalidLevel);
        // Level 3 (unknown) also rejected.
        let att = fake_attestation(device_key(9), 3, 1_000, 1_000 + 365 * 86400, dk);
        let err = anchor_request_from_attestation(&att).unwrap_err();
        assert_eq!(err, IdentityError::InvalidLevel);
    }

    #[test]
    fn malformed_attestation_rejected() {
        // Wrong magic.
        let mut bad = fake_attestation(device_key(9), 2, 1_000, 999_999, device_key(7));
        bad[0] = b'X';
        assert_eq!(
            anchor_request_from_attestation(&bad).unwrap_err(),
            IdentityError::BadAttestationEncoding
        );
        // Truncated.
        let bad = &bad[..100];
        assert_eq!(
            anchor_request_from_attestation(bad).unwrap_err(),
            IdentityError::BadAttestationEncoding
        );
        // Empty.
        assert_eq!(
            anchor_request_from_attestation(&[]).unwrap_err(),
            IdentityError::BadAttestationEncoding
        );
    }

    // -- Rate limiting -----------------------------------------------------

    #[test]
    fn rate_limit_three_per_year() {
        let mut record = AttestationRecord::uninitialized();
        let dk = device_key(7);
        let mk = |issued: u64| {
            fake_attestation(device_key(9), 2, issued, issued + 365 * 86400 + 10_000, dk)
        };
        // Register -> revoke -> register -> revoke -> register: 3 used.
        register(&mut record, &mk(1_000), 2_000).unwrap();
        let mut accts = accounts(&mut record, dk);
        process_instruction(
            IdentityInstruction::RevokeAttestation { device_key: dk, now: 3_000 },
            &mut accts,
        )
        .unwrap();
        register(&mut record, &mk(4_000), 5_000).unwrap();
        let mut accts = accounts(&mut record, dk);
        process_instruction(
            IdentityInstruction::RevokeAttestation { device_key: dk, now: 6_000 },
            &mut accts,
        )
        .unwrap();
        register(&mut record, &mk(7_000), 8_000).unwrap();

        // Fourth inside the window: rejected.
        let mut accts = accounts(&mut record, dk);
        process_instruction(
            IdentityInstruction::RevokeAttestation { device_key: dk, now: 9_000 },
            &mut accts,
        )
        .unwrap();
        let err = register(&mut record, &mk(10_000), 11_000).unwrap_err();
        assert_eq!(err, IdentityError::RateLimited);

        // After the window elapses, registration works again.
        let err = register(
            &mut record,
            &mk(RATE_LIMIT_WINDOW_SECS + 20_000),
            RATE_LIMIT_WINDOW_SECS + 21_000,
        );
        assert!(err.is_ok(), "window should have reset: {:?}", err);
    }

    // -- Off-chain verifier --------------------------------------------------

    fn chain_view(record: &AttestationRecord) -> ChainAttestationView {
        ChainAttestationView::from_record(record).expect("registered")
    }

    #[test]
    fn off_chain_verify_happy_path() {
        let mut record = AttestationRecord::uninitialized();
        let dk = device_key(7);
        let att = fake_attestation(device_key(9), 2, 1_000, 1_000 + 365 * 86400, dk);
        register(&mut record, &att, 2_000).unwrap();
        let view = chain_view(&record);
        assert_eq!(
            verify_off_chain(&att, &view, 3_000),
            VerifyOutcome::Verified {
                level: VerificationLevel::HumanVerified
            }
        );
    }

    #[test]
    fn off_chain_tampered_attestation_fails() {
        let mut record = AttestationRecord::uninitialized();
        let dk = device_key(7);
        let att = fake_attestation(device_key(9), 2, 1_000, 1_000 + 365 * 86400, dk);
        register(&mut record, &att, 2_000).unwrap();
        let view = chain_view(&record);

        // Flip one byte in the signature region: hash mismatch.
        let mut tampered = att.clone();
        tampered[100] ^= 0x01;
        assert_eq!(
            verify_off_chain(&tampered, &view, 3_000),
            VerifyOutcome::HashMismatch
        );

        // A completely different attestation: mismatch too.
        let other = fake_attestation(device_key(11), 2, 1_000, 1_000 + 365 * 86400, dk);
        assert_eq!(
            verify_off_chain(&other, &view, 3_000),
            VerifyOutcome::HashMismatch
        );
    }

    #[test]
    fn off_chain_level_tamper_fails() {
        let mut record = AttestationRecord::uninitialized();
        let dk = device_key(7);
        // Registered at level 1...
        let att = fake_attestation(device_key(9), 1, 1_000, 1_000 + 365 * 86400, dk);
        register(&mut record, &att, 2_000).unwrap();
        let view = chain_view(&record);
        // ...but presented as level 2: rejected even before hashing.
        let forged = fake_attestation(device_key(9), 2, 1_000, 1_000 + 365 * 86400, dk);
        assert_eq!(
            verify_off_chain(&forged, &view, 3_000),
            VerifyOutcome::HashMismatch
        );
    }

    #[test]
    fn off_chain_revoked_and_expired() {
        let mut record = AttestationRecord::uninitialized();
        let dk = device_key(7);
        let att = fake_attestation(device_key(9), 2, 1_000, 5_000, dk);
        register(&mut record, &att, 2_000).unwrap();
        let mut accts = accounts(&mut record, dk);
        process_instruction(
            IdentityInstruction::RevokeAttestation { device_key: dk, now: 3_000 },
            &mut accts,
        )
        .unwrap();
        let view = chain_view(&record);
        assert_eq!(
            verify_off_chain(&att, &view, 4_000),
            VerifyOutcome::Revoked
        );

        // Fresh record, verify after expiry.
        let mut record = AttestationRecord::uninitialized();
        register(&mut record, &att, 2_000).unwrap();
        let view = chain_view(&record);
        assert_eq!(
            verify_off_chain(&att, &view, 5_001),
            VerifyOutcome::Expired
        );
    }

    #[test]
    fn off_chain_garbage_attestation() {
        let view = ChainAttestationView {
            attestation_hash: [1u8; 64],
            level: 2,
            revoked: false,
            expires_at: 9_999_999,
        };
        assert_eq!(
            verify_off_chain(&[0u8; 10], &view, 1),
            VerifyOutcome::BadAttestation
        );
        assert_eq!(
            verify_off_chain(&[], &view, 1),
            VerifyOutcome::BadAttestation
        );
    }

    // -- Privacy ---------------------------------------------------------------

    /// The hard invariant: NOTHING personal reaches the chain. This
    /// test plants recognizable "personal" marker bytes inside the
    /// subject-key and signature fields of a well-formed attestation,
    /// runs the whole anchor pipeline, then byte-scans the serialized
    /// on-chain record for any trace of them.
    #[test]
    fn privacy_byte_scan_no_personal_data_on_chain() {
        // Markers stand in for a name, document number, birth date.
        let mut subject = [0u8; 32];
        subject[..12].copy_from_slice(b"DOE<<JOHN<<<");
        subject[12..22].copy_from_slice(b"L898902C36");
        subject[22..28].copy_from_slice(b"740812");

        let dk = device_key(7);
        let att = fake_attestation(subject, 2, 1_000, 1_000 + 365 * 86400, dk);

        // Full pipeline: bridge -> register -> serialize record.
        let mut record = AttestationRecord::uninitialized();
        register(&mut record, &att, 2_000).unwrap();
        let bytes = record.to_bytes();

        let needles: &[&[u8]] = &[
            b"DOE<<JOHN<<<",
            b"L898902C36",
            b"740812",
            &subject,      // the whole subject key must not appear
            &att[..],      // nor the attestation itself
        ];
        for n in needles {
            assert!(
                !bytes.windows(n.len()).any(|w| w == *n),
                "on-chain record leaks attestation bytes"
            );
        }
        // The ONLY 32-byte key on-chain is the pseudonymous device key.
        assert!(bytes.windows(32).any(|w| w == dk));
    }

    /// Schema-level guard: the record's serialized form is exactly the
    /// documented 135 bytes of hashes/keys/timestamps/flags — there is
    /// structurally nowhere to put a name or document number.
    #[test]
    fn record_schema_is_fixed_and_minimal() {
        let record = AttestationRecord::uninitialized();
        let bytes = record.to_bytes();
        assert_eq!(bytes.len(), 135);
        // Fresh record is all zeros: no default personal data either.
        assert!(bytes.iter().all(|b| *b == 0));
    }

    // -- Bridge ------------------------------------------------------------------

    #[test]
    fn anchor_request_extracts_fields() {
        let dk = device_key(42);
        let att = fake_attestation(device_key(9), 2, 1_000, 77_000, dk);
        let req = anchor_request_from_attestation(&att).unwrap();
        assert_eq!(req.device_key, dk);
        assert_eq!(req.level, 2);
        assert_eq!(req.expires_at, 77_000);
        assert_eq!(req.attestation_hash, sha512(&att));

        // Into instruction round-trips the fields.
        let ix = req.into_instruction(2_000);
        match ix {
            IdentityInstruction::RegisterAttestation {
                device_key,
                level,
                expires_at,
                now,
                ..
            } => {
                assert_eq!(device_key, dk);
                assert_eq!(level, 2);
                assert_eq!(expires_at, 77_000);
                assert_eq!(now, 2_000);
            }
            _ => panic!("wrong instruction"),
        }
    }
}
