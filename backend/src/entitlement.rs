//! Signed, non-bypassable entitlements for the TRV Network.
//!
//! ## The hole this closes
//!
//! [`crate::paywall`] evaluates *policy* over caller-supplied
//! [`Tier`](crate::subscriptions::Tier) and
//! [`VerificationStatus`](crate::subscriptions::VerificationStatus).
//! A caller — or a modified client — can simply *claim* any tier, so
//! those inputs are never proof of anything. This module adds
//! *provenance*: an [`Entitlement`] can only be obtained by verifying
//! an issuer-signed receipt with [`verify_receipt`]. There is no public
//! constructor, no `From` impl, and no setter — the fields are private
//! and the only path in is signature verification against the issuer's
//! public key.
//!
//! ## Receipt format (v1, 86 bytes, integers little-endian)
//!
//! ```text
//! [0..4]   magic "TRVE"
//! [4]      version = 1
//! [5]      tier discriminant (0=Free, 1=Monthly, 2=Yearly, 3=Founding)
//! [6..14]  issued_at, unix seconds
//! [14..22] expires_at, unix seconds
//! [22..86] Ed25519 signature over bytes [0..22]
//! ```
//!
//! Fixed length, versioned, canonical. Anything else fails closed.
//!
//! ## Trust model — read before relying on this
//!
//! - The issuer private key is NEVER on the device. Only the issuer
//!   public key is embedded in the app.
//! - Verification is pure local Ed25519 ([`trv_core::crypto::ed25519`]) —
//!   no network calls, no billing SDKs.
//! - [`verify_receipt`] proves *provenance* (the issuer really signed
//!   this). [`Entitlement::check`] additionally enforces *expiry*.
//!   Use [`verify_and_check`] for both in one step.
//! - A modified client can still skip calling these functions entirely:
//!   on-device checks raise the bar substantially but are not remote
//!   attestation. Same honesty note as [`crate::paywall`].
//! - The Ed25519 implementation is handwritten and **not externally
//!   audited** (see [`trv_core::crypto::ed25519`]). Do not treat this
//!   as production-grade until an independent audit exists.

use trv_core::crypto::ed25519;

use crate::subscriptions::Tier;

/// Receipt magic bytes: "TRVE".
pub const RECEIPT_MAGIC: [u8; 4] = *b"TRVE";
/// Current receipt format version.
pub const RECEIPT_VERSION: u8 = 1;
/// Total receipt length in bytes: 22-byte payload + 64-byte signature.
pub const RECEIPT_LEN: usize = 86;

/// Length of the signed payload (everything before the signature).
const PAYLOAD_LEN: usize = 22;

/// A verified entitlement: proof that the issuer granted `tier` until
/// `expires_at` (unix seconds).
///
/// Fields are private on purpose — the only way to obtain one is
/// [`verify_receipt`]. Never construct entitlement state from
/// caller-supplied tier values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entitlement {
    tier: Tier,
    expires_at: u64,
}

impl Entitlement {
    /// The granted subscription tier.
    pub fn tier(self) -> Tier {
        self.tier
    }

    /// Unix timestamp (seconds) when the entitlement lapses.
    pub fn expires_at(self) -> u64 {
        self.expires_at
    }

    /// Fail-closed liveness check.
    ///
    /// Returns `Ok(self)` only while `now < expires_at`. Any expiry —
    /// or an unreadable system clock — is denied, never default-allowed.
    pub fn check(self) -> Result<Self, EntitlementError> {
        let now = now_secs()?;
        if now >= self.expires_at {
            return Err(EntitlementError::Expired);
        }
        Ok(self)
    }
}

/// Everything that can go wrong while verifying a receipt.
///
/// Variants are deliberately coarse: callers learn *that* verification
/// failed, not which byte was wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntitlementError {
    /// Receipt is not exactly [`RECEIPT_LEN`] bytes.
    BadLength,
    /// Magic bytes do not match [`RECEIPT_MAGIC`].
    BadMagic,
    /// Version byte is not [`RECEIPT_VERSION`].
    BadVersion,
    /// Tier discriminant is unknown.
    BadTier,
    /// `expires_at <= issued_at`, or issuing failed the same check.
    BadTimes,
    /// Ed25519 signature does not verify.
    BadSignature,
    /// Receipt is well-formed and genuine but past `expires_at`.
    Expired,
    /// System clock unreadable; denied rather than default-allowed.
    ClockUnavailable,
}

impl core::fmt::Display for EntitlementError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            EntitlementError::BadLength => "malformed receipt: bad length",
            EntitlementError::BadMagic => "malformed receipt: bad magic",
            EntitlementError::BadVersion => "malformed receipt: unsupported version",
            EntitlementError::BadTier => "malformed receipt: unknown tier",
            EntitlementError::BadTimes => "malformed receipt: invalid validity window",
            EntitlementError::BadSignature => "receipt signature invalid",
            EntitlementError::Expired => "entitlement expired",
            EntitlementError::ClockUnavailable => "system clock unavailable",
        };
        f.write_str(s)
    }
}

impl std::error::Error for EntitlementError {}

/// Current unix time in seconds. Fails closed when the clock is broken.
fn now_secs() -> Result<u64, EntitlementError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| EntitlementError::ClockUnavailable)
}

fn encode_tier(tier: Tier) -> u8 {
    match tier {
        Tier::Free => 0,
        Tier::Monthly => 1,
        Tier::Yearly => 2,
        Tier::Founding => 3,
    }
}

fn decode_tier(byte: u8) -> Option<Tier> {
    match byte {
        0 => Some(Tier::Free),
        1 => Some(Tier::Monthly),
        2 => Some(Tier::Yearly),
        3 => Some(Tier::Founding),
        _ => None,
    }
}

/// Issue (sign) a receipt. **Issuer-side only** — the seed must never
/// leave the issuer's signing environment.
///
/// Fails closed when `expires_at <= issued_at`.
pub fn issue(
    issuer_seed: &[u8; 32],
    tier: Tier,
    issued_at: u64,
    expires_at: u64,
) -> Result<Vec<u8>, EntitlementError> {
    if expires_at <= issued_at {
        return Err(EntitlementError::BadTimes);
    }
    let (secret, public) = ed25519::generate(issuer_seed);
    let mut receipt = Vec::with_capacity(RECEIPT_LEN);
    receipt.extend_from_slice(&RECEIPT_MAGIC);
    receipt.push(RECEIPT_VERSION);
    receipt.push(encode_tier(tier));
    receipt.extend_from_slice(&issued_at.to_le_bytes());
    receipt.extend_from_slice(&expires_at.to_le_bytes());
    debug_assert_eq!(receipt.len(), PAYLOAD_LEN);
    let sig = ed25519::sign(&secret, &public, &receipt);
    // `secret` is drop-wiped by `SecretKey`'s Drop impl.
    receipt.extend_from_slice(sig.as_bytes());
    debug_assert_eq!(receipt.len(), RECEIPT_LEN);
    Ok(receipt)
}

/// Verify a receipt's provenance against the issuer public key.
///
/// Checks length, magic, version, tier, validity window, and the Ed25519
/// signature — in that order, failing closed at the first problem. This
/// proves the issuer signed the receipt; it does NOT check expiry — use
/// [`Entitlement::check`] or [`verify_and_check`] for that.
pub fn verify_receipt(
    issuer_pubkey: &[u8; 32],
    receipt: &[u8],
) -> Result<Entitlement, EntitlementError> {
    if receipt.len() != RECEIPT_LEN {
        return Err(EntitlementError::BadLength);
    }
    let magic: [u8; 4] = receipt[0..4]
        .try_into()
        .map_err(|_| EntitlementError::BadLength)?;
    if magic != RECEIPT_MAGIC {
        return Err(EntitlementError::BadMagic);
    }
    if receipt[4] != RECEIPT_VERSION {
        return Err(EntitlementError::BadVersion);
    }
    let tier = decode_tier(receipt[5]).ok_or(EntitlementError::BadTier)?;
    let issued_at = u64::from_le_bytes(
        receipt[6..14]
            .try_into()
            .map_err(|_| EntitlementError::BadLength)?,
    );
    let expires_at = u64::from_le_bytes(
        receipt[14..22]
            .try_into()
            .map_err(|_| EntitlementError::BadLength)?,
    );
    if expires_at <= issued_at {
        return Err(EntitlementError::BadTimes);
    }
    let public = ed25519::PublicKey::from_bytes(*issuer_pubkey);
    let sig_bytes: [u8; 64] = receipt[22..86]
        .try_into()
        .map_err(|_| EntitlementError::BadLength)?;
    let sig = ed25519::Signature::from_bytes(sig_bytes);
    // The signature covers the full 22-byte canonical payload, so tier,
    // issued_at, and expires_at cannot be altered without invalidating it.
    if !ed25519::verify(&public, &receipt[..PAYLOAD_LEN], &sig) {
        return Err(EntitlementError::BadSignature);
    }
    Ok(Entitlement { tier, expires_at })
}

/// Verify provenance **and** expiry in one step. The recommended entry
/// point for gating features.
pub fn verify_and_check(
    issuer_pubkey: &[u8; 32],
    receipt: &[u8],
) -> Result<Entitlement, EntitlementError> {
    verify_receipt(issuer_pubkey, receipt)?.check()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixed issuer seed for tests only — never a real key.
    const ISSUER_SEED: [u8; 32] = *b"test-issuer-seed-000000000000000";
    const OTHER_SEED: [u8; 32] = *b"attacker-seed-000000000000000000";

    fn issuer_pubkey() -> [u8; 32] {
        let (_, public) = ed25519::generate(&ISSUER_SEED);
        *public.as_bytes()
    }

    fn valid_receipt() -> Vec<u8> {
        let now = now_secs().expect("test clock");
        issue(&ISSUER_SEED, Tier::Monthly, now, now + 30 * 86_400)
            .expect("test issuance")
    }

    #[test]
    fn valid_receipt_accepted() {
        let receipt = valid_receipt();
        assert_eq!(receipt.len(), RECEIPT_LEN);
        let ent = verify_receipt(&issuer_pubkey(), &receipt).expect("valid");
        assert_eq!(ent.tier(), Tier::Monthly);
        assert!(ent.expires_at() > now_secs().expect("test clock"));
        // check() passes while unexpired.
        ent.check().expect("unexpired");
    }

    #[test]
    fn verify_and_check_accepts_valid() {
        let receipt = valid_receipt();
        let ent = verify_and_check(&issuer_pubkey(), &receipt).expect("valid");
        assert_eq!(ent.tier(), Tier::Monthly);
    }

    #[test]
    fn forged_receipt_rejected() {
        // Signed by a different key: provenance fails.
        let now = now_secs().expect("test clock");
        let forged = issue(&OTHER_SEED, Tier::Founding, now, now + 30 * 86_400)
            .expect("forged issuance");
        assert_eq!(
            verify_receipt(&issuer_pubkey(), &forged),
            Err(EntitlementError::BadSignature)
        );
    }

    #[test]
    fn expired_receipt_rejected() {
        let now = now_secs().expect("test clock");
        let receipt = issue(&ISSUER_SEED, Tier::Yearly, now - 60 * 86_400, now - 3_600)
            .expect("test issuance");
        // Provenance is genuine...
        let ent = verify_receipt(&issuer_pubkey(), &receipt).expect("genuine");
        assert_eq!(ent.tier(), Tier::Yearly);
        // ...but the entitlement is dead.
        assert_eq!(ent.check(), Err(EntitlementError::Expired));
        assert_eq!(
            verify_and_check(&issuer_pubkey(), &receipt),
            Err(EntitlementError::Expired)
        );
    }

    #[test]
    fn tampered_tier_rejected() {
        let mut receipt = valid_receipt();
        // Flip the tier byte (Monthly -> Yearly); signature no longer matches.
        receipt[5] = encode_tier(Tier::Yearly);
        assert_eq!(
            verify_receipt(&issuer_pubkey(), &receipt),
            Err(EntitlementError::BadSignature)
        );
    }

    #[test]
    fn tampered_expiry_rejected() {
        let mut receipt = valid_receipt();
        // Extend the expiry: signature covers it, so this must fail.
        receipt[14] ^= 0xFF;
        assert_eq!(
            verify_receipt(&issuer_pubkey(), &receipt),
            Err(EntitlementError::BadSignature)
        );
    }

    #[test]
    fn tampered_signature_rejected() {
        let mut receipt = valid_receipt();
        receipt[30] ^= 0x01;
        assert_eq!(
            verify_receipt(&issuer_pubkey(), &receipt),
            Err(EntitlementError::BadSignature)
        );
    }

    #[test]
    fn unknown_tier_discriminant_rejected() {
        // Valid signature over an unknown tier byte: decode fails closed.
        let now = now_secs().expect("test clock");
        let mut payload = Vec::with_capacity(PAYLOAD_LEN);
        payload.extend_from_slice(&RECEIPT_MAGIC);
        payload.push(RECEIPT_VERSION);
        payload.push(9); // unknown tier
        payload.extend_from_slice(&now.to_le_bytes());
        payload.extend_from_slice(&(now + 86_400).to_le_bytes());
        let (secret, public) = ed25519::generate(&ISSUER_SEED);
        let sig = ed25519::sign(&secret, &public, &payload);
        let mut receipt = payload;
        receipt.extend_from_slice(sig.as_bytes());
        assert_eq!(
            verify_receipt(&issuer_pubkey(), &receipt),
            Err(EntitlementError::BadTier)
        );
    }

    #[test]
    fn bad_magic_rejected() {
        let mut receipt = valid_receipt();
        receipt[0] = b'X';
        assert_eq!(
            verify_receipt(&issuer_pubkey(), &receipt),
            Err(EntitlementError::BadMagic)
        );
    }

    #[test]
    fn bad_version_rejected() {
        let mut receipt = valid_receipt();
        receipt[4] = 2;
        assert_eq!(
            verify_receipt(&issuer_pubkey(), &receipt),
            Err(EntitlementError::BadVersion)
        );
    }

    #[test]
    fn bad_length_rejected() {
        let receipt = valid_receipt();
        assert_eq!(
            verify_receipt(&issuer_pubkey(), &receipt[..RECEIPT_LEN - 1]),
            Err(EntitlementError::BadLength)
        );
        let mut long = receipt.clone();
        long.push(0);
        assert_eq!(
            verify_receipt(&issuer_pubkey(), &long),
            Err(EntitlementError::BadLength)
        );
        assert_eq!(
            verify_receipt(&issuer_pubkey(), &[]),
            Err(EntitlementError::BadLength)
        );
    }

    #[test]
    fn bad_times_rejected_at_issue_and_verify() {
        let now = now_secs().expect("test clock");
        // Issuing refuses an inverted window.
        assert_eq!(
            issue(&ISSUER_SEED, Tier::Monthly, now, now),
            Err(EntitlementError::BadTimes)
        );
        assert_eq!(
            issue(&ISSUER_SEED, Tier::Monthly, now + 1, now),
            Err(EntitlementError::BadTimes)
        );
        // A hand-built receipt with expires_at <= issued_at fails even
        // with a valid signature.
        let mut payload = Vec::with_capacity(PAYLOAD_LEN);
        payload.extend_from_slice(&RECEIPT_MAGIC);
        payload.push(RECEIPT_VERSION);
        payload.push(encode_tier(Tier::Monthly));
        payload.extend_from_slice(&now.to_le_bytes());
        payload.extend_from_slice(&now.to_le_bytes()); // expires == issued
        let (secret, public) = ed25519::generate(&ISSUER_SEED);
        let sig = ed25519::sign(&secret, &public, &payload);
        let mut receipt = payload;
        receipt.extend_from_slice(sig.as_bytes());
        assert_eq!(
            verify_receipt(&issuer_pubkey(), &receipt),
            Err(EntitlementError::BadTimes)
        );
    }

    #[test]
    fn all_tiers_round_trip() {
        let now = now_secs().expect("test clock");
        for tier in [Tier::Free, Tier::Monthly, Tier::Yearly, Tier::Founding] {
            let receipt = issue(&ISSUER_SEED, tier, now, now + 86_400).expect("issue");
            let ent = verify_receipt(&issuer_pubkey(), &receipt).expect("verify");
            assert_eq!(ent.tier(), tier);
        }
    }

    #[test]
    fn error_display_is_stable() {
        // Display strings must not leak receipt contents.
        let msg = format!("{}", EntitlementError::BadSignature);
        assert!(!msg.is_empty());
        assert_eq!(format!("{}", EntitlementError::Expired), "entitlement expired");
    }
}
