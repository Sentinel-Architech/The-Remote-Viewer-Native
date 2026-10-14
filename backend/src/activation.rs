//! Manual activation codes for The Remote Viewer Network.
//!
//! Sales flow (user decision 2026-10-13): the founder sells activation
//! codes manually over X. The buyer pays out-of-band, receives a code,
//! and types it into the app to unlock a paid tier. No payment
//! processor, no network — everything here runs fully offline,
//! on-device.
//!
//! Code format: `TRV1-<TIER>-<RANDOM>-<CHECKSUM>`, e.g.
//! `TRV1-MO-A9K3Q7-7X2M`. The `<RANDOM>` segment is 6 chars: the first
//! two encode `duration_days` in base-31 (max 960 days), the last four
//! are xorshift output. The `<CHECKSUM>` segment is 4 base-31 chars of
//! FNV-1a over (tier + random + seller secret), which binds the code to
//! the secret so buyers cannot mint their own.
//!
//! Honest threat model: this is obfuscation plus a shared secret, NOT
//! unforgeable cryptography. FNV-1a is not a MAC and the xorshift
//! stream is not a CSPRNG. A motivated attacker who recovers the secret
//! can mint codes. This is adequate for manual X sales where the
//! secret never leaves the seller's device. TODO: replace with real
//! Ed25519 signatures (sign tier + duration + nonce) before any
//! production rollout.
//!
//! Local-only, std-only, no network I/O.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use trv_core::crypto::fnv1a64;

use crate::subscriptions::Tier;

/// Code format version / prefix.
const CODE_PREFIX: &str = "TRV1";

/// Unambiguous alphabet for hand-typed codes: no 0/O, no 1/I/L.
/// 31 symbols; indexing is done with modulo, never bit-masking.
const ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";

/// Number of symbols in [`ALPHABET`].
const ALPHABET_LEN: u64 = 31;

/// Full length of the `<RANDOM>` segment in chars.
const RANDOM_SEGMENT_LEN: usize = 6;

/// Leading chars of `<RANDOM>` that encode the duration (base-31).
const DURATION_CHARS: usize = 2;

/// Longest duration a code can carry: 2 base-31 chars, i.e. 31*31-1.
pub const MAX_DURATION_DAYS: u32 = 960;

/// Length of the `<CHECKSUM>` segment in chars (4 base-31 chars of FNV-1a).
const CHECKSUM_LEN: usize = 4;

/// A minted activation code plus the entitlement it unlocks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivationCode {
    /// The full code string, e.g. `TRV1-MO-A9K3Q7-7X2M`.
    pub code: String,
    /// Tier the code unlocks once redeemed.
    pub tier: Tier,
    /// Days the tier lasts once redeemed (clamped to
    /// [`MAX_DURATION_DAYS`]).
    pub duration_days: u32,
}

/// Why a code failed validation or redemption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationError {
    /// Not shaped like `TRV1-<TIER>-<RANDOM>-<CHECKSUM>`.
    BadFormat,
    /// Checksum does not match the code body under this secret.
    BadChecksum,
    /// Tier segment is not a known tier code.
    UnknownTier,
    /// The code was already redeemed.
    AlreadyUsed,
}

/// Short tier segment used inside codes.
fn tier_segment(tier: Tier) -> &'static str {
    match tier {
        Tier::Free => "FR",
        Tier::Monthly => "MO",
        Tier::Yearly => "YR",
        Tier::Founding => "FD",
    }
}

/// Parse a tier segment back into a [`Tier`].
fn tier_from_segment(seg: &str) -> Option<Tier> {
    match seg {
        "FR" => Some(Tier::Free),
        "MO" => Some(Tier::Monthly),
        "YR" => Some(Tier::Yearly),
        "FD" => Some(Tier::Founding),
        _ => None,
    }
}

/// Monotonic counter folded into the PRNG seed so two codes minted in
/// the same nanosecond still differ.
static CODE_COUNTER: AtomicU64 = AtomicU64::new(0);

fn xorshift64(mut x: u64) -> u64 {
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    x
}

/// Build the 6-char `<RANDOM>` segment: 2 chars of duration + 4 chars of
/// xorshift output.
///
/// NOT a CSPRNG. The stream is seeded from the wall clock, a process
/// counter, and the seller secret — enough to make codes unique and
/// unpredictable to a buyer, but NOT suitable for key material.
/// Unforgeability comes from the checksum binding to the secret, not
/// from this randomness.
fn random_segment(secret: &[u8], duration_days: u32) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| {
            d.as_secs()
                .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                ^ u64::from(d.subsec_nanos())
        })
        .unwrap_or(0x243F_6A88_85A3_08D3);
    let count = CODE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut state = fnv1a64(secret)
        .wrapping_add(nanos.rotate_left(17))
        .wrapping_add(count.wrapping_mul(0x9E37_79B9_7F4A_7C15));
    if state == 0 {
        // xorshift(0) is stuck at 0 forever; pick a nonzero fallback.
        state = 0x2545_F491_4F6C_DD1D;
    }

    let duration = duration_days.min(MAX_DURATION_DAYS);
    let mut out = String::with_capacity(RANDOM_SEGMENT_LEN);
    out.push(ALPHABET[(duration / ALPHABET_LEN as u32) as usize] as char);
    out.push(ALPHABET[(duration % ALPHABET_LEN as u32) as usize] as char);
    for _ in 0..(RANDOM_SEGMENT_LEN - DURATION_CHARS) {
        state = xorshift64(state);
        out.push(ALPHABET[(state % ALPHABET_LEN) as usize] as char);
    }
    out
}

/// 4-char checksum binding tier + random segment to the seller secret.
///
/// FNV-1a over `tier + "-" + random + secret`, rendered as 4 base-31
/// chars. This is a keyed integrity tag, NOT a MAC — see the module
/// docs for the honest threat model.
fn checksum_segment(tier_seg: &str, random: &str, secret: &[u8]) -> String {
    let mut input = Vec::with_capacity(tier_seg.len() + 1 + random.len() + secret.len());
    input.extend_from_slice(tier_seg.as_bytes());
    input.push(b'-');
    input.extend_from_slice(random.as_bytes());
    input.extend_from_slice(secret);
    let mut v = fnv1a64(&input);
    let mut out = String::with_capacity(CHECKSUM_LEN);
    for _ in 0..CHECKSUM_LEN {
        out.push(ALPHABET[(v % ALPHABET_LEN) as usize] as char);
        v /= ALPHABET_LEN;
    }
    out
}

/// Normalize hand-typed input: trim whitespace, uppercase.
fn normalize(code: &str) -> String {
    code.trim().to_ascii_uppercase()
}

/// Mint a new activation code for `tier`, good for `duration_days` days.
///
/// The seller keeps `secret` private; buyers never see it. A code is
/// only verifiable by someone holding the same secret. Durations above
/// [`MAX_DURATION_DAYS`] are clamped to the maximum encodable value.
pub fn generate(tier: Tier, duration_days: u32, secret: &[u8]) -> ActivationCode {
    let tier_seg = tier_segment(tier);
    let random = random_segment(secret, duration_days);
    let checksum = checksum_segment(tier_seg, &random, secret);
    let code = format!("{CODE_PREFIX}-{tier_seg}-{random}-{checksum}");
    ActivationCode {
        code,
        tier,
        duration_days: duration_days.min(MAX_DURATION_DAYS),
    }
}

fn decode_duration(seg: &str) -> u32 {
    let bytes = seg.as_bytes();
    // `validate` guarantees both chars are in ALPHABET before this runs.
    let hi = ALPHABET
        .iter()
        .position(|&b| b == bytes[0])
        .unwrap_or(0) as u32;
    let lo = ALPHABET
        .iter()
        .position(|&b| b == bytes[1])
        .unwrap_or(0) as u32;
    hi * ALPHABET_LEN as u32 + lo
}

/// Validate a code string against the seller `secret`.
///
/// Forgiving of hand typing (trims whitespace, uppercases). Returns the
/// unlocked tier and duration in days on success.
pub fn validate(code: &str, secret: &[u8]) -> Result<(Tier, u32), ActivationError> {
    let normalized = normalize(code);
    let parts: Vec<&str> = normalized.split('-').collect();
    if parts.len() != 4 || parts[0] != CODE_PREFIX {
        return Err(ActivationError::BadFormat);
    }
    let (tier_seg, random_seg, checksum_seg) = (parts[1], parts[2], parts[3]);
    let tier = tier_from_segment(tier_seg).ok_or(ActivationError::UnknownTier)?;
    if random_seg.len() != RANDOM_SEGMENT_LEN
        || checksum_seg.len() != CHECKSUM_LEN
        || !random_seg.bytes().all(|b| ALPHABET.contains(&b))
        || !checksum_seg.bytes().all(|b| ALPHABET.contains(&b))
    {
        return Err(ActivationError::BadFormat);
    }
    let expected = checksum_segment(tier_seg, random_seg, secret);
    if expected != checksum_seg {
        return Err(ActivationError::BadChecksum);
    }
    Ok((tier, decode_duration(&random_seg[..DURATION_CHARS])))
}

/// In-memory record of redeemed codes. Prevents double-spend of a code.
///
/// Local-only. Persistence (SQLite) is a future step: a process restart
/// currently forgets redemptions, so a code could be redeemed twice
/// across restarts. Do not rely on this alone in production.
#[derive(Debug, Default)]
pub struct CodeRegistry {
    used: HashSet<String>,
}

impl CodeRegistry {
    /// Empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// True if `code` was already redeemed. Normalizes like [`validate`].
    pub fn is_used(&self, code: &str) -> bool {
        self.used.contains(&normalize(code))
    }

    /// Record `code` as redeemed. Returns true when newly marked
    /// (false = it was already used).
    pub fn mark_used(&mut self, code: &str) -> bool {
        self.used.insert(normalize(code))
    }
}

/// Validate a code and redeem it in one step.
///
/// Fails with [`ActivationError::AlreadyUsed`] when the code was
/// redeemed before; otherwise validates, marks it used, and returns
/// the unlocked tier + duration in days.
pub fn redeem(
    code: &str,
    secret: &[u8],
    registry: &mut CodeRegistry,
) -> Result<(Tier, u32), ActivationError> {
    let (tier, duration) = validate(code, secret)?;
    if registry.is_used(code) {
        return Err(ActivationError::AlreadyUsed);
    }
    registry.mark_used(code);
    Ok((tier, duration))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"test-seller-secret-do-not-use-in-prod";
    const OTHER_SECRET: &[u8] = b"a-different-secret";

    #[test]
    fn alphabet_is_31_unique_unambiguous_chars() {
        assert_eq!(ALPHABET.len(), 31);
        assert_eq!(ALPHABET_LEN, 31);
        let mut seen = [false; 256];
        for &b in ALPHABET {
            assert!(!seen[b as usize], "duplicate char {b}");
            seen[b as usize] = true;
        }
        // Confusable pairs stay out: no 0/O, no 1/I/L.
        for &b in b"01OIL" {
            assert!(!ALPHABET.contains(&b), "ambiguous char {b}");
        }
    }

    #[test]
    fn generate_validate_roundtrip() {
        let ac = generate(Tier::Monthly, 30, SECRET);
        assert!(ac.code.starts_with("TRV1-MO-"));
        assert_eq!(ac.code.split('-').count(), 4);
        let (tier, days) = validate(&ac.code, SECRET).expect("roundtrip");
        assert_eq!(tier, Tier::Monthly);
        assert_eq!(days, 30);
        assert_eq!(ac.tier, Tier::Monthly);
        assert_eq!(ac.duration_days, 30);
    }

    #[test]
    fn roundtrip_all_tiers() {
        for tier in [Tier::Free, Tier::Monthly, Tier::Yearly, Tier::Founding] {
            let ac = generate(tier, 365, SECRET);
            let (t, d) = validate(&ac.code, SECRET).expect("roundtrip");
            assert_eq!(t, tier);
            assert_eq!(d, 365);
        }
    }

    #[test]
    fn consecutive_codes_differ() {
        let a = generate(Tier::Monthly, 30, SECRET);
        let b = generate(Tier::Monthly, 30, SECRET);
        assert_ne!(a.code, b.code);
    }

    #[test]
    fn bad_checksum_rejected() {
        let ac = generate(Tier::Yearly, 365, SECRET);
        // Flip the last checksum char to a different alphabet char.
        let mut bad = ac.code.clone();
        let last = bad.pop().expect("nonempty code");
        bad.push(if last == 'A' { 'B' } else { 'A' });
        assert_eq!(validate(&bad, SECRET), Err(ActivationError::BadChecksum));
    }

    #[test]
    fn tampered_tier_rejected() {
        // Swap the tier segment to another valid tier: the checksum no
        // longer matches, so it must fail.
        let ac = generate(Tier::Monthly, 30, SECRET);
        let bad = ac.code.replacen("TRV1-MO-", "TRV1-YR-", 1);
        assert_eq!(validate(&bad, SECRET), Err(ActivationError::BadChecksum));
    }

    #[test]
    fn bad_format_rejected() {
        for bad in [
            "garbage",
            "",
            "TRV1-MO",
            "TRV1-MO-ABCDEF",       // missing checksum segment
            "TRV2-MO-ABCDEF-GH12",  // wrong prefix
            "TRV1-MO-ABCDE-GH12",   // short random segment
            "TRV1-MO-ABCDEFG-GH12", // long random segment
            "TRV1-MO-ABCDEF-GH1",   // short checksum segment
            "TRV1-MO-ABC*EF-GH12",  // illegal char in random segment
            "TRV1-MO-ABCDEF-GH1!",  // illegal char in checksum segment
        ] {
            assert_eq!(
                validate(bad, SECRET),
                Err(ActivationError::BadFormat),
                "input: {bad:?}"
            );
        }
    }

    #[test]
    fn unknown_tier_rejected() {
        assert_eq!(
            validate("TRV1-XX-ABCDEF-GH12", SECRET),
            Err(ActivationError::UnknownTier)
        );
    }

    #[test]
    fn wrong_secret_rejected() {
        let ac = generate(Tier::Monthly, 30, SECRET);
        assert_eq!(
            validate(&ac.code, OTHER_SECRET),
            Err(ActivationError::BadChecksum)
        );
    }

    #[test]
    fn reuse_rejected() {
        let ac = generate(Tier::Monthly, 30, SECRET);
        let mut registry = CodeRegistry::new();
        assert_eq!(redeem(&ac.code, SECRET, &mut registry), Ok((Tier::Monthly, 30)));
        assert!(registry.is_used(&ac.code));
        assert!(!registry.mark_used(&ac.code)); // already used -> false
        assert_eq!(
            redeem(&ac.code, SECRET, &mut registry),
            Err(ActivationError::AlreadyUsed)
        );
    }

    #[test]
    fn redeem_validates_before_marking() {
        let mut registry = CodeRegistry::new();
        // Well-formed segments, but the checksum does not match the body.
        assert_eq!(
            redeem("TRV1-MO-ABCDEF-GHAB", SECRET, &mut registry),
            Err(ActivationError::BadChecksum)
        );
        // A failed redemption must not poison the registry.
        assert!(!registry.is_used("TRV1-MO-ABCDEF-GHAB"));
    }

    #[test]
    fn validation_is_case_and_whitespace_forgiving() {
        let ac = generate(Tier::Yearly, 365, SECRET);
        let sloppy = format!("  {}  ", ac.code.to_ascii_lowercase());
        let (tier, days) = validate(&sloppy, SECRET).expect("forgiving parse");
        assert_eq!(tier, Tier::Yearly);
        assert_eq!(days, 365);
        // Redemption is forgiving too, and dedupes across casings.
        let mut registry = CodeRegistry::new();
        assert!(redeem(&sloppy, SECRET, &mut registry).is_ok());
        assert_eq!(
            redeem(&ac.code, SECRET, &mut registry),
            Err(ActivationError::AlreadyUsed)
        );
    }

    #[test]
    fn duration_clamped_to_max() {
        let ac = generate(Tier::Yearly, 10_000, SECRET);
        assert_eq!(ac.duration_days, MAX_DURATION_DAYS);
        let (_, days) = validate(&ac.code, SECRET).expect("roundtrip");
        assert_eq!(days, MAX_DURATION_DAYS);
    }

    #[test]
    fn duration_boundaries_roundtrip() {
        for days in [0, 1, 30, 365, MAX_DURATION_DAYS] {
            let ac = generate(Tier::Yearly, days, SECRET);
            let (_, d) = validate(&ac.code, SECRET).expect("roundtrip");
            assert_eq!(d, days, "days={days}");
        }
    }
}
