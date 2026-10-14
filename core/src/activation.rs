//! Asymmetric activation codes for The Remote Viewer Network.
//!
//! # Protocol (v2, "TRV2")
//!
//! The issuer holds an Ed25519 private key OFF-device. Buyer devices
//! embed ONLY the issuer's public key. Activation codes are signed
//! tokens; there are no shared secrets anywhere in the buyer binary.
//!
//! A code is:
//! ```text
//! TRV2-<base32(claims) >-<base32(signature)>
//! ```
//! - `claims` (34 bytes): code_id(16) ‖ tier(1) ‖ issued_at(8 LE) ‖
//!   expires_at(8 LE) ‖ max_devices(1)
//! - `signature` (64 bytes): Ed25519 sign(claims) under the issuer key.
//!
//! Verification (buyer device):
//! 1. Parse and base32-decode the two segments.
//! 2. Verify the Ed25519 signature against the embedded issuer public key.
//! 3. Check `issued_at <= now <= expires_at`.
//! 4. Check the tier is a known [`PaidTier`].
//! 5. Enforce single-device binding via [`FileCodeRegistry`]: a code_id
//!    may only be redeemed on up to `max_devices` distinct device ids.
//!
//! # Redemption registry
//!
//! [`FileCodeRegistry`] is a file-backed, append-only log of redeemed
//! code ids. It replaces the old memory-only registry (which permitted
//! replay after restart).
//!
//! **Corruption policy — fail closed (deny).** If the registry file is
//! missing, it is created. If it exists but cannot be parsed, ALL
//! redemptions are denied until an operator restores or clears the
//! file. Rationale: treating a corrupt registry as "empty" would let
//! an attacker replay codes by corrupting the file. Denying service is
//! the safe failure mode; the issuer can re-issue codes after recovery.
//!
//! # Audit status
//!
//! The Ed25519 implementation in [`crate::crypto::ed25519`] is pure
//! Rust, std-only, and **NOT externally audited**. Do not use for
//! production sales until an independent audit is complete. See the
//! spec's "needs external audit before production sales" flag.
//!
//! Local-only, std-only, no network I/O.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::ed25519;

/// Code format version prefix.
const CODE_PREFIX: &str = "TRV2";

/// Length of the serialized claims payload in bytes:
/// 16 (code_id) + 1 (tier) + 8 (issued_at) + 8 (expires_at) + 1 (max_devices).
const CLAIMS_LEN: usize = 34;

/// Length of an Ed25519 signature in bytes.
const SIG_LEN: usize = 64;

/// Length of a code_id in bytes.
const CODE_ID_LEN: usize = 16;

// ---------------------------------------------------------------------------
// Tiers
// ---------------------------------------------------------------------------

/// Paid tiers from the spec (decided 2026-10-13):
/// Tier 1 — $10/mo or $100/yr; Tier 2 — $25/mo or $150/yr;
/// Tier 3 — $45/mo or $200/yr.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PaidTier {
    Tier1,
    Tier2,
    Tier3,
}

impl PaidTier {
    /// Wire value used in the claims payload.
    pub fn as_u8(self) -> u8 {
        match self {
            PaidTier::Tier1 => 1,
            PaidTier::Tier2 => 2,
            PaidTier::Tier3 => 3,
        }
    }

    /// Parse a wire value. Rejects 0 and values > 3.
    pub fn from_u8(v: u8) -> Option<PaidTier> {
        match v {
            1 => Some(PaidTier::Tier1),
            2 => Some(PaidTier::Tier2),
            3 => Some(PaidTier::Tier3),
            _ => None,
        }
    }

    /// Human label.
    pub fn label(self) -> &'static str {
        match self {
            PaidTier::Tier1 => "Tier 1",
            PaidTier::Tier2 => "Tier 2",
            PaidTier::Tier3 => "Tier 3",
        }
    }
}

// ---------------------------------------------------------------------------
// Claims
// ---------------------------------------------------------------------------

/// The signed claims carried by an activation code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claims {
    /// 128-bit random code identifier (also the registry key).
    pub code_id: [u8; CODE_ID_LEN],
    /// Paid tier this code unlocks.
    pub tier: PaidTier,
    /// Unix seconds when the code becomes valid.
    pub issued_at: u64,
    /// Unix seconds when the code expires.
    pub expires_at: u64,
    /// Maximum distinct device ids that may redeem this code.
    /// 1 = single-device binding.
    pub max_devices: u8,
}

impl Claims {
    /// Serialize to the 34-byte canonical payload.
    fn to_bytes(&self) -> [u8; CLAIMS_LEN] {
        let mut out = [0u8; CLAIMS_LEN];
        out[..16].copy_from_slice(&self.code_id);
        out[16] = self.tier.as_u8();
        out[17..25].copy_from_slice(&self.issued_at.to_le_bytes());
        out[25..33].copy_from_slice(&self.expires_at.to_le_bytes());
        out[33] = self.max_devices;
        out
    }

    /// Parse from the 34-byte canonical payload.
    fn from_bytes(b: &[u8; CLAIMS_LEN]) -> Option<Claims> {
        let tier = PaidTier::from_u8(b[16])?;
        let mut issued = [0u8; 8];
        let mut expires = [0u8; 8];
        issued.copy_from_slice(&b[17..25]);
        expires.copy_from_slice(&b[25..33]);
        let mut code_id = [0u8; CODE_ID_LEN];
        code_id.copy_from_slice(&b[..16]);
        Some(Claims {
            code_id,
            tier,
            issued_at: u64::from_le_bytes(issued),
            expires_at: u64::from_le_bytes(expires),
            max_devices: b[33],
        })
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// All failures for minting, verifying, and redeeming activation codes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActivationError {
    /// Code does not start with the `TRV2-` prefix or has wrong segments.
    Malformed,
    /// Base32 decoding failed.
    BadEncoding,
    /// Payload or signature has the wrong length.
    BadLength,
    /// Ed25519 signature verification failed.
    BadSignature,
    /// Claims carry an unknown tier value.
    UnknownTier,
    /// `now` is outside `[issued_at, expires_at]`.
    Expired,
    /// `issued_at` is in the future (clock skew or forged).
    NotYetValid,
    /// `max_devices` is 0 (a code must allow at least one device).
    NoDevicesAllowed,
    /// This code_id was already redeemed on a different device and the
    /// `max_devices` limit is reached.
    AlreadyRedeemed,
    /// The registry file exists but is corrupt. Fail closed: deny.
    RegistryCorrupt(String),
    /// Filesystem I/O failure.
    Io(String),
}

impl std::fmt::Display for ActivationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ActivationError::Malformed => write!(f, "malformed activation code"),
            ActivationError::BadEncoding => write!(f, "base32 decoding failed"),
            ActivationError::BadLength => write!(f, "wrong payload/signature length"),
            ActivationError::BadSignature => write!(f, "signature verification failed"),
            ActivationError::UnknownTier => write!(f, "unknown tier in claims"),
            ActivationError::Expired => write!(f, "code has expired"),
            ActivationError::NotYetValid => write!(f, "code is not yet valid"),
            ActivationError::NoDevicesAllowed => {
                write!(f, "code allows zero devices")
            }
            ActivationError::AlreadyRedeemed => {
                write!(f, "code already redeemed on another device")
            }
            ActivationError::RegistryCorrupt(e) => {
                write!(f, "registry corrupt, redemption denied: {e}")
            }
            ActivationError::Io(e) => write!(f, "registry I/O error: {e}"),
        }
    }
}

impl std::error::Error for ActivationError {}

// ---------------------------------------------------------------------------
// Base32 (RFC 4648, uppercase, no padding)
// ---------------------------------------------------------------------------

const B32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn base32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() * 8 + 4) / 5);
    let mut bits: u32 = 0;
    let mut nbits: u32 = 0;
    for &b in data {
        bits = (bits << 8) | u32::from(b);
        nbits += 8;
        while nbits >= 5 {
            nbits -= 5;
            out.push(B32_ALPHABET[((bits >> nbits) & 31) as usize] as char);
        }
    }
    if nbits > 0 {
        out.push(B32_ALPHABET[((bits << (5 - nbits)) & 31) as usize] as char);
    }
    out
}

fn base32_decode(s: &str) -> Result<Vec<u8>, ActivationError> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let mut bits: u32 = 0;
    let mut nbits: u32 = 0;
    for c in s.chars() {
        let v = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            '2'..='7' => 26 + (c as u32 - '2' as u32),
            // Accept lowercase on input for user convenience.
            'a'..='z' => c as u32 - 'a' as u32,
            _ => return Err(ActivationError::BadEncoding),
        };
        bits = (bits << 5) | v;
        nbits += 5;
        if nbits >= 8 {
            nbits -= 8;
            out.push(((bits >> nbits) & 0xFF) as u8);
        }
    }
    // Trailing bits must be zero (canonical encoding).
    if nbits > 0 && (bits & ((1 << nbits) - 1)) != 0 {
        return Err(ActivationError::BadEncoding);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Mint / verify
// ---------------------------------------------------------------------------

/// Current Unix time in seconds. Used for `issued_at` and expiry checks.
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Mint a signed activation code (ISSUER side).
///
/// `issuer_secret` is the 32-byte Ed25519 seed. It never leaves the
/// issuer machine. `code_id` should be 128 bits from a CSPRNG;
/// `issued_at`/`expires_at` are Unix seconds; `max_devices` is the
/// device-binding limit (1 = single device).
pub fn mint(
    issuer_secret: &[u8; 32],
    code_id: [u8; CODE_ID_LEN],
    tier: PaidTier,
    issued_at: u64,
    expires_at: u64,
    max_devices: u8,
) -> Result<String, ActivationError> {
    if max_devices == 0 {
        return Err(ActivationError::NoDevicesAllowed);
    }
    if expires_at < issued_at {
        return Err(ActivationError::Expired);
    }
    let claims = Claims {
        code_id,
        tier,
        issued_at,
        expires_at,
        max_devices,
    };
    let payload = claims.to_bytes();
    let (secret, public) = ed25519::generate(issuer_secret);
    let sig = ed25519::sign(&secret, &public, &payload);
    Ok(format!(
        "{CODE_PREFIX}-{}-{}",
        base32_encode(&payload),
        base32_encode(sig.as_bytes())
    ))
}

/// Verify an activation code (BUYER side).
///
/// `issuer_public` is the 32-byte Ed25519 public key embedded in the
/// buyer binary. `now` is Unix seconds (pass [`now_unix`] in production;
/// injectable for tests).
pub fn verify(
    code: &str,
    issuer_public: &[u8; 32],
    now: u64,
) -> Result<Claims, ActivationError> {
    let code = code.trim();
    let rest = code
        .strip_prefix(CODE_PREFIX)
        .and_then(|r| r.strip_prefix('-'))
        .ok_or(ActivationError::Malformed)?;
    let mut parts = rest.splitn(2, '-');
    let payload_b32 = parts.next().ok_or(ActivationError::Malformed)?;
    let sig_b32 = parts.next().ok_or(ActivationError::Malformed)?;

    let payload = base32_decode(payload_b32)?;
    let sig = base32_decode(sig_b32)?;
    if payload.len() != CLAIMS_LEN || sig.len() != SIG_LEN {
        return Err(ActivationError::BadLength);
    }
    let mut payload_arr = [0u8; CLAIMS_LEN];
    payload_arr.copy_from_slice(&payload);
    let mut sig_arr = [0u8; SIG_LEN];
    sig_arr.copy_from_slice(&sig);

    let public = ed25519::PublicKey::from_bytes(*issuer_public);
    let sig = ed25519::Signature::from_bytes(sig_arr);
    if !ed25519::verify(&public, &payload_arr, &sig) {
        return Err(ActivationError::BadSignature);
    }
    let claims = Claims::from_bytes(&payload_arr).ok_or(ActivationError::UnknownTier)?;
    if claims.max_devices == 0 {
        return Err(ActivationError::NoDevicesAllowed);
    }
    if now < claims.issued_at {
        return Err(ActivationError::NotYetValid);
    }
    if now > claims.expires_at {
        return Err(ActivationError::Expired);
    }
    Ok(claims)
}

// ---------------------------------------------------------------------------
// File-backed redemption registry
// ---------------------------------------------------------------------------

/// One redeemed code: which code_id, on which device, when.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Redemption {
    code_id: [u8; CODE_ID_LEN],
    device_id: String,
    redeemed_at: u64,
}

/// File-backed registry of redeemed activation codes.
///
/// Format: one record per line,
/// `<hex code_id>:<device_id>:<unix seconds>`.
/// Appends only; loaded fully into memory on open (code counts are
/// small — manual sales).
///
/// Corruption policy: if any line fails to parse, the registry is
/// marked corrupt and [`FileCodeRegistry::redeem`] denies ALL
/// redemptions ([`ActivationError::RegistryCorrupt`]). This is fail
/// closed: an attacker who corrupts the file cannot replay codes.
pub struct FileCodeRegistry {
    path: PathBuf,
    /// code_id -> list of redemptions (one per device).
    redemptions: HashMap<[u8; CODE_ID_LEN], Vec<Redemption>>,
    corrupt: Option<String>,
}

impl FileCodeRegistry {
    /// Open (or create) the registry at `path`. Loads existing records.
    pub fn open(path: &Path) -> Result<FileCodeRegistry, ActivationError> {
        let mut reg = FileCodeRegistry {
            path: path.to_path_buf(),
            redemptions: HashMap::new(),
            corrupt: None,
        };
        if !path.exists() {
            // Create the file so later appends cannot fail on missing parents
            // (parent dir must already exist; we do not create directories).
            File::create(path).map_err(|e| ActivationError::Io(e.to_string()))?;
            return Ok(reg);
        }
        let file = File::open(path).map_err(|e| ActivationError::Io(e.to_string()))?;
        for (lineno, line) in BufReader::new(file).lines().enumerate() {
            let line = line.map_err(|e| ActivationError::Io(e.to_string()))?;
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match parse_redemption_line(line) {
                Some(r) => {
                    reg.redemptions.entry(r.code_id).or_default().push(r);
                }
                None => {
                    reg.corrupt = Some(format!("line {}: unparseable", lineno + 1));
                    break;
                }
            }
        }
        Ok(reg)
    }

    /// Returns true if the registry file was corrupt on load.
    pub fn is_corrupt(&self) -> bool {
        self.corrupt.is_some()
    }

    /// Attempt to redeem `claims` for `device_id`.
    ///
    /// - Fail closed: if the registry is corrupt, deny.
    /// - Idempotent: redeeming the same code on the same device again succeeds.
    /// - Device binding: a new device is accepted only while fewer than
    ///   `claims.max_devices` distinct devices have redeemed this code.
    pub fn redeem(
        &mut self,
        claims: &Claims,
        device_id: &str,
    ) -> Result<(), ActivationError> {
        if let Some(reason) = &self.corrupt {
            return Err(ActivationError::RegistryCorrupt(reason.clone()));
        }
        if device_id.is_empty() {
            return Err(ActivationError::Malformed);
        }
        let entry = self.redemptions.entry(claims.code_id).or_default();
        if entry.iter().any(|r| r.device_id == device_id) {
            // Already redeemed on this device: idempotent success.
            return Ok(());
        }
        if entry.len() >= claims.max_devices as usize {
            return Err(ActivationError::AlreadyRedeemed);
        }
        let r = Redemption {
            code_id: claims.code_id,
            device_id: device_id.to_string(),
            redeemed_at: now_unix(),
        };
        append_redemption_line(&self.path, &r)?;
        entry.push(r);
        Ok(())
    }

    /// How many distinct devices have redeemed `code_id`.
    pub fn redemption_count(&self, code_id: &[u8; CODE_ID_LEN]) -> usize {
        self.redemptions.get(code_id).map(|v| v.len()).unwrap_or(0)
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(s: &str, out_len: usize) -> Option<Vec<u8>> {
    if s.len() != out_len * 2 {
        return None;
    }
    let mut out = Vec::with_capacity(out_len);
    let bytes = s.as_bytes();
    for pair in bytes.chunks(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

fn parse_redemption_line(line: &str) -> Option<Redemption> {
    let mut parts = line.splitn(3, ':');
    let code_hex = parts.next()?;
    let device_id = parts.next()?;
    let ts_str = parts.next()?;
    if device_id.is_empty() || device_id.contains(':') || device_id.contains('\n') {
        return None;
    }
    let code_bytes = hex_decode(code_hex, CODE_ID_LEN)?;
    let mut code_id = [0u8; CODE_ID_LEN];
    code_id.copy_from_slice(&code_bytes);
    let redeemed_at: u64 = ts_str.parse().ok()?;
    Some(Redemption {
        code_id,
        device_id: device_id.to_string(),
        redeemed_at,
    })
}

fn append_redemption_line(path: &Path, r: &Redemption) -> Result<(), ActivationError> {
    let mut file = OpenOptions::new()
        .append(true)
        .open(path)
        .map_err(|e| ActivationError::Io(e.to_string()))?;
    writeln!(
        file,
        "{}:{}:{}",
        hex_encode(&r.code_id),
        r.device_id,
        r.redeemed_at
    )
    .map_err(|e| ActivationError::Io(e.to_string()))?;
    file.flush().map_err(|e| ActivationError::Io(e.to_string()))?;
    Ok(())
}

/// Default registry path under the app's data dir.
pub fn default_registry_path(data_dir: &Path) -> PathBuf {
    data_dir.join("activation_registry.log")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    /// Unique temp path per test (parallel-safe).
    fn temp_registry_path() -> PathBuf {
        let n = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        std::env::temp_dir().join(format!("trv_act_reg_{}_{}.log", std::process::id(), n))
    }

    /// Deterministic test issuer keypair (NOT secret; tests only).
    fn test_issuer() -> ([u8; 32], [u8; 32]) {
        let seed = [0x42u8; 32];
        let (_, public) = ed25519::generate(&seed);
        (seed, *public.as_bytes())
    }

    fn test_claims() -> ([u8; 32], [u8; 32], Claims) {
        let (secret, public) = test_issuer();
        let claims = Claims {
            code_id: [0xABu8; 16],
            tier: PaidTier::Tier2,
            issued_at: 1_700_000_000,
            expires_at: 1_800_000_000,
            max_devices: 1,
        };
        (secret, public, claims)
    }

    fn mint_test_code(secret: &[u8; 32], claims: &Claims) -> String {
        mint(
            secret,
            claims.code_id,
            claims.tier,
            claims.issued_at,
            claims.expires_at,
            claims.max_devices,
        )
        .expect("mint must succeed")
    }

    #[test]
    fn keygen_mint_verify_roundtrip() {
        let (secret, public, claims) = test_claims();
        let code = mint_test_code(&secret, &claims);
        assert!(code.starts_with("TRV2-"), "code: {code}");
        let back = verify(&code, &public, 1_750_000_000).expect("verify must succeed");
        assert_eq!(back, claims);
    }

    #[test]
    fn all_tiers_roundtrip() {
        let (secret, public, _) = test_claims();
        for tier in [PaidTier::Tier1, PaidTier::Tier2, PaidTier::Tier3] {
            let claims = Claims {
                code_id: [tier.as_u8(); 16],
                tier,
                issued_at: 1_700_000_000,
                expires_at: 1_800_000_000,
                max_devices: 1,
            };
            let code = mint_test_code(&secret, &claims);
            let back = verify(&code, &public, 1_750_000_000).unwrap();
            assert_eq!(back.tier, tier);
        }
    }

    #[test]
    fn tampered_code_rejected() {
        let (secret, public, claims) = test_claims();
        let code = mint_test_code(&secret, &claims);
        // Flip a char in the signature segment.
        let mut tampered = code.clone();
        let last = tampered.pop().unwrap();
        tampered.push(if last == 'A' { 'B' } else { 'A' });
        assert_eq!(
            verify(&tampered, &public, 1_750_000_000),
            Err(ActivationError::BadSignature)
        );
        // Flip a char in the payload segment (breaks signature too).
        let parts: Vec<&str> = code.split('-').collect();
        let mut payload_chars: Vec<char> = parts[1].chars().collect();
        payload_chars[0] = if payload_chars[0] == 'A' { 'B' } else { 'A' };
        let tampered2 = format!("TRV2-{}-{}", payload_chars.into_iter().collect::<String>(), parts[2]);
        assert_eq!(
            verify(&tampered2, &public, 1_750_000_000),
            Err(ActivationError::BadSignature)
        );
    }

    #[test]
    fn expired_code_rejected() {
        let (secret, public, claims) = test_claims();
        let code = mint_test_code(&secret, &claims);
        assert_eq!(
            verify(&code, &public, 1_800_000_001),
            Err(ActivationError::Expired)
        );
    }

    #[test]
    fn not_yet_valid_rejected() {
        let (secret, public, claims) = test_claims();
        let code = mint_test_code(&secret, &claims);
        assert_eq!(
            verify(&code, &public, 1_699_999_999),
            Err(ActivationError::NotYetValid)
        );
    }

    #[test]
    fn wrong_key_rejected() {
        let (secret, _, claims) = test_claims();
        let (_, other_public) = ed25519::generate(&[0x99u8; 32]);
        let code = mint_test_code(&secret, &claims);
        assert_eq!(
            verify(&code, other_public.as_bytes(), 1_750_000_000),
            Err(ActivationError::BadSignature)
        );
    }

    #[test]
    fn malformed_codes_rejected() {
        let (_, public, _) = test_claims();
        assert_eq!(
            verify("TRV1-AAAA-BBBB", &public, 1_750_000_000),
            Err(ActivationError::Malformed)
        );
        assert_eq!(
            verify("TRV2-onlyone", &public, 1_750_000_000),
            Err(ActivationError::Malformed)
        );
        assert_eq!(
            verify("TRV2-!!!-???", &public, 1_750_000_000),
            Err(ActivationError::BadEncoding)
        );
    }

    #[test]
    fn mint_rejects_zero_devices_and_inverted_dates() {
        let (secret, _, _) = test_claims();
        assert_eq!(
            mint(&secret, [0u8; 16], PaidTier::Tier1, 100, 200, 0),
            Err(ActivationError::NoDevicesAllowed)
        );
        assert_eq!(
            mint(&secret, [0u8; 16], PaidTier::Tier1, 200, 100, 1),
            Err(ActivationError::Expired)
        );
    }

    #[test]
    fn replay_rejected_across_simulated_restart() {
        let (secret, public, claims) = test_claims();
        let code = mint_test_code(&secret, &claims);
        let path = temp_registry_path();

        // First launch: redeem on device A.
        {
            let mut reg = FileCodeRegistry::open(&path).unwrap();
            let c = verify(&code, &public, 1_750_000_000).unwrap();
            reg.redeem(&c, "device-A").unwrap();
        }
        // Simulated restart: drop the registry, reopen from disk.
        {
            let mut reg = FileCodeRegistry::open(&path).unwrap();
            assert!(!reg.is_corrupt());
            assert_eq!(reg.redemption_count(&claims.code_id), 1);
            // Same device: idempotent success.
            let c = verify(&code, &public, 1_750_000_000).unwrap();
            reg.redeem(&c, "device-A").unwrap();
            // Different device: denied (max_devices = 1).
            assert_eq!(
                reg.redeem(&c, "device-B"),
                Err(ActivationError::AlreadyRedeemed)
            );
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn multi_device_code_allows_up_to_max() {
        let (secret, public, _) = test_claims();
        let claims = Claims {
            code_id: [0xCDu8; 16],
            tier: PaidTier::Tier3,
            issued_at: 1_700_000_000,
            expires_at: 1_800_000_000,
            max_devices: 2,
        };
        let code = mint_test_code(&secret, &claims);
        let path = temp_registry_path();
        let mut reg = FileCodeRegistry::open(&path).unwrap();
        let c = verify(&code, &public, 1_750_000_000).unwrap();
        reg.redeem(&c, "device-A").unwrap();
        reg.redeem(&c, "device-B").unwrap();
        assert_eq!(reg.redemption_count(&claims.code_id), 2);
        assert_eq!(
            reg.redeem(&c, "device-C"),
            Err(ActivationError::AlreadyRedeemed)
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn corrupt_registry_fails_closed() {
        let (secret, public, claims) = test_claims();
        let code = mint_test_code(&secret, &claims);
        let path = temp_registry_path();
        // Write garbage into the registry file.
        std::fs::write(&path, "not-a-valid-record\n").unwrap();

        let mut reg = FileCodeRegistry::open(&path).unwrap();
        assert!(reg.is_corrupt());
        let c = verify(&code, &public, 1_750_000_000).unwrap();
        // Even a perfectly valid code is denied: fail closed.
        match reg.redeem(&c, "device-A") {
            Err(ActivationError::RegistryCorrupt(_)) => {}
            other => panic!("expected RegistryCorrupt, got {:?}", other),
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn corrupt_middle_line_fails_closed() {
        let path = temp_registry_path();
        let good = format!(
            "{}:device-A:1700000000\n",
            hex_encode(&[0xABu8; 16])
        );
        std::fs::write(&path, format!("{good}GARBAGE LINE\n")).unwrap();
        let reg = FileCodeRegistry::open(&path).unwrap();
        assert!(reg.is_corrupt());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn base32_roundtrip() {
        let data: Vec<u8> = (0..100).collect();
        assert_eq!(base32_decode(&base32_encode(&data)).unwrap(), data);
    }

    #[test]
    fn paid_tier_wire_values() {
        assert_eq!(PaidTier::Tier1.as_u8(), 1);
        assert_eq!(PaidTier::from_u8(2), Some(PaidTier::Tier2));
        assert_eq!(PaidTier::from_u8(0), None);
        assert_eq!(PaidTier::from_u8(4), None);
    }
}
