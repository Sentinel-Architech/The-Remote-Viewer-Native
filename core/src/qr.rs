//! Authenticated contact exchange via QR.
//!
//! ## Why sign, not encrypt
//!
//! When Alice shows a QR code and Bob scans it, there is no pre-shared
//! key: Bob is a stranger whose key Alice has never seen, so
//! "encrypting" the QR payload *to Bob* is impossible at scan time.
//! Any QR "encryption" here would be obfuscation — the old
//! `ScrambleQr` reverse-and-invert transform was exactly that, and it
//! has been removed outright (it was documented as pre-production
//! obfuscation, never a security property).
//!
//! The correct model is **sign, don't encrypt**: the QR carries a
//! contact card — the owner's Ed25519 identity public key plus
//! human-readable fields — and the owner's signature over all of it.
//! Bob verifies the signature against the embedded public key. If it
//! checks out, Bob holds a *verified* identity key for Alice: the card
//! could only have been produced by whoever holds Alice's secret key.
//! Both sides then run [`crate::transport::establish_auth`] to open
//! the real encrypted channel. Secrecy comes from the transport, not
//! the QR.
//!
//! ## What's in a card (and what's not)
//!
//! A QR code on a phone screen can be photographed by anyone nearby,
//! so a card carries **public information only**: identity public
//! key, display name, `Username@RV.com`-style handle, issue
//! timestamp. No secrets ever go into a QR payload.
//!
//! ## Replay and freshness
//!
//! Cards carry an issue timestamp, but there is no trusted on-device
//! clock, so timestamps are *informational*. [`verify_exchange`]
//! enforces a caller-supplied maximum card age and rejects duplicate
//! scans within a session; callers that need stronger freshness
//! should re-issue cards per encounter.
//!
//! This module produces and consumes the QR *payload bytes* only —
//! it does not render QR images or touch the camera.
//!
//! Like the rest of `trv_core::crypto`, the Ed25519 implementation
//! used here has not had an independent audit. Do not rely on this
//! for production identity until that audit happens.

use std::collections::HashSet;

use crate::crypto::ed25519::{self, PublicKey, SecretKey, Signature};

/// Magic bytes opening every QR contact payload.
const QR_MAGIC: &[u8; 4] = b"TRVQ";
/// Payload format version.
const QR_VERSION: u8 = 0x01;
/// Maximum QR payload size in bytes (real QR capacity limits).
pub const MAX_QR_BYTES: usize = 4096;
/// Maximum display-name length in Unicode characters.
pub const MAX_NAME_CHARS: usize = 32;
/// Maximum handle length in characters (handles are ASCII-only).
pub const MAX_HANDLE_CHARS: usize = 48;
/// Domain-separation prefix for the signed bytes.
const SIGN_DOMAIN: &[u8] = b"TRV-CONTACT-CARD-v1";

/// Failures for contact-card signing, parsing, and exchange.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QrError {
    /// Payload exceeds [`MAX_QR_BYTES`].
    TooLarge,
    /// Magic bytes do not match.
    BadMagic,
    /// Unsupported payload version.
    BadVersion,
    /// Payload ends before all fields are read.
    Truncated,
    /// Bytes remain after the final field.
    TrailingGarbage,
    /// Ed25519 signature does not verify.
    BadSignature,
    /// Display name is empty, overlong, or not valid UTF-8.
    InvalidName,
    /// Handle is empty, overlong, not valid UTF-8, or uses characters
    /// outside `[a-z0-9._-]`.
    InvalidHandle,
    /// The scanned card is the scanner's own card.
    SelfCard,
    /// The scanned card is older than the allowed maximum age.
    Expired,
    /// This peer's card was already scanned in this session.
    Duplicate,
}

impl std::fmt::Display for QrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            QrError::TooLarge => "QR payload exceeds 4KB",
            QrError::BadMagic => "QR payload has bad magic bytes",
            QrError::BadVersion => "QR payload has unsupported version",
            QrError::Truncated => "QR payload is truncated",
            QrError::TrailingGarbage => "QR payload has trailing garbage",
            QrError::BadSignature => "contact card signature invalid",
            QrError::InvalidName => "display name invalid",
            QrError::InvalidHandle => "handle invalid",
            QrError::SelfCard => "scanned card is our own",
            QrError::Expired => "contact card expired",
            QrError::Duplicate => "contact card already scanned",
        };
        f.write_str(s)
    }
}

impl std::error::Error for QrError {}

/// A signed contact card: the QR payload's semantic content.
///
/// All fields are public information — nothing secret may ever be
/// placed in a card. The signature authenticates the whole card and
/// is verified with the embedded identity key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContactCard {
    identity: PublicKey,
    display_name: String,
    handle: String,
    issued_at: u64,
    signature: Signature,
}

impl ContactCard {
    /// Sign a new contact card.
    ///
    /// `public` must be the public key matching `secret`; there is no
    /// public-from-secret derivation in the crypto API, so the caller
    /// (who holds the keypair) passes both. Fails closed on invalid
    /// name/handle.
    pub fn sign(
        secret: &SecretKey,
        public: &PublicKey,
        display_name: &str,
        handle: &str,
        issued_at: u64,
    ) -> Result<Self, QrError> {
        validate_name(display_name)?;
        validate_handle(handle)?;
        let signature = ed25519::sign(
            secret,
            public,
            &signing_input(public, display_name, handle, issued_at),
        );
        Ok(ContactCard {
            identity: *public,
            display_name: display_name.to_owned(),
            handle: handle.to_owned(),
            issued_at,
            signature,
        })
    }

    /// Verify field constraints and the Ed25519 signature.
    ///
    /// Fails closed on any violation. Re-validates the fields so that
    /// even a card assembled outside [`ContactCard::sign`] cannot pass
    /// with out-of-policy values.
    pub fn verify(&self) -> Result<(), QrError> {
        validate_name(&self.display_name)?;
        validate_handle(&self.handle)?;
        if !ed25519::verify(&self.identity, &self.signing_bytes(), &self.signature) {
            return Err(QrError::BadSignature);
        }
        Ok(())
    }

    /// The exact bytes covered by the signature.
    fn signing_bytes(&self) -> Vec<u8> {
        signing_input(
            &self.identity,
            &self.display_name,
            &self.handle,
            self.issued_at,
        )
    }

    /// Serialize to the QR payload byte format.
    ///
    /// Layout: `magic(4) || version(1) || identity(32) || name_len(1)
    /// || name || handle_len(1) || handle || issued_at(8 BE) ||
    /// signature(64)`. Name/handle lengths are byte counts; validation
    /// guarantees they fit in one byte each.
    pub fn to_qr_bytes(&self) -> Vec<u8> {
        let name = self.display_name.as_bytes();
        let handle = self.handle.as_bytes();
        // 32 display-name chars * 4 bytes/char = 128 max; 48-byte
        // ASCII handle max. Both fit in a u8 length prefix.
        debug_assert!(name.len() <= 128);
        debug_assert!(handle.len() <= MAX_HANDLE_CHARS);
        let mut out = Vec::with_capacity(4 + 1 + 32 + 1 + name.len() + 1 + handle.len() + 8 + 64);
        out.extend_from_slice(QR_MAGIC);
        out.push(QR_VERSION);
        out.extend_from_slice(self.identity.as_bytes());
        out.push(name.len() as u8);
        out.extend_from_slice(name);
        out.push(handle.len() as u8);
        out.extend_from_slice(handle);
        out.extend_from_slice(&self.issued_at.to_be_bytes());
        out.extend_from_slice(self.signature.as_bytes());
        out
    }

    /// Parse **and** verify a scanned QR payload.
    ///
    /// Fails closed on oversize input, bad magic/version, truncation,
    /// trailing garbage, invalid fields, or a bad signature. A
    /// returned card is fully verified — there is no parse-without-
    /// verify path, so callers cannot accidentally trust an
    /// unauthenticated card.
    pub fn from_qr_bytes(bytes: &[u8]) -> Result<Self, QrError> {
        if bytes.len() > MAX_QR_BYTES {
            return Err(QrError::TooLarge);
        }
        let mut cur = bytes;

        if cur.len() < QR_MAGIC.len() {
            return Err(QrError::Truncated);
        }
        if &cur[..QR_MAGIC.len()] != QR_MAGIC {
            return Err(QrError::BadMagic);
        }
        cur = &cur[QR_MAGIC.len()..];

        if cur.is_empty() {
            return Err(QrError::Truncated);
        }
        if cur[0] != QR_VERSION {
            return Err(QrError::BadVersion);
        }
        cur = &cur[1..];

        if cur.len() < 32 {
            return Err(QrError::Truncated);
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&cur[..32]);
        cur = &cur[32..];

        if cur.is_empty() {
            return Err(QrError::Truncated);
        }
        let name_len = cur[0] as usize;
        cur = &cur[1..];
        if cur.len() < name_len {
            return Err(QrError::Truncated);
        }
        let display_name =
            core::str::from_utf8(&cur[..name_len]).map_err(|_| QrError::InvalidName)?;
        cur = &cur[name_len..];

        if cur.is_empty() {
            return Err(QrError::Truncated);
        }
        let handle_len = cur[0] as usize;
        cur = &cur[1..];
        if cur.len() < handle_len {
            return Err(QrError::Truncated);
        }
        let handle =
            core::str::from_utf8(&cur[..handle_len]).map_err(|_| QrError::InvalidHandle)?;
        cur = &cur[handle_len..];

        if cur.len() < 8 {
            return Err(QrError::Truncated);
        }
        let mut ts = [0u8; 8];
        ts.copy_from_slice(&cur[..8]);
        let issued_at = u64::from_be_bytes(ts);
        cur = &cur[8..];

        // The signature must be exactly the last 64 bytes.
        if cur.len() < 64 {
            return Err(QrError::Truncated);
        }
        if cur.len() > 64 {
            return Err(QrError::TrailingGarbage);
        }
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&cur[..64]);

        let card = ContactCard {
            identity: PublicKey::from_bytes(id),
            display_name: display_name.to_owned(),
            handle: handle.to_owned(),
            issued_at,
            signature: Signature::from_bytes(sig),
        };
        card.verify()?;
        Ok(card)
    }

    /// The verified identity public key on this card.
    pub fn identity(&self) -> PublicKey {
        self.identity
    }

    /// The display name on this card.
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    /// The `Username@RV.com`-style handle on this card.
    pub fn handle(&self) -> &str {
        &self.handle
    }

    /// The card's issue timestamp (informational; no trusted clock).
    pub fn issued_at(&self) -> u64 {
        self.issued_at
    }
}

/// Canonical bytes covered by a card signature.
fn signing_input(
    identity: &PublicKey,
    display_name: &str,
    handle: &str,
    issued_at: u64,
) -> Vec<u8> {
    let name = display_name.as_bytes();
    let handle_b = handle.as_bytes();
    let mut out = Vec::with_capacity(
        SIGN_DOMAIN.len() + 32 + 1 + name.len() + 1 + handle_b.len() + 8,
    );
    out.extend_from_slice(SIGN_DOMAIN);
    out.extend_from_slice(identity.as_bytes());
    out.push(name.len() as u8);
    out.extend_from_slice(name);
    out.push(handle_b.len() as u8);
    out.extend_from_slice(handle_b);
    out.extend_from_slice(&issued_at.to_be_bytes());
    out
}

fn validate_name(name: &str) -> Result<(), QrError> {
    if name.is_empty() || name.chars().count() > MAX_NAME_CHARS {
        return Err(QrError::InvalidName);
    }
    Ok(())
}

fn validate_handle(handle: &str) -> Result<(), QrError> {
    if handle.is_empty() || handle.chars().count() > MAX_HANDLE_CHARS {
        return Err(QrError::InvalidHandle);
    }
    let ok = handle
        .bytes()
        .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'));
    if !ok {
        return Err(QrError::InvalidHandle);
    }
    Ok(())
}

/// Verify a scanned QR payload as a contact-exchange step.
///
/// Parses and signature-verifies `scanned`, then rejects:
/// - our own card (`SelfCard`),
/// - cards older than `max_age_secs` relative to `now` (`Expired`),
/// - cards already seen in this session (`Duplicate`, tracked in
///   `seen` by identity key).
///
/// Returns the peer's **verified** identity public key, ready for
/// [`crate::transport::establish_auth`]. Timestamps are informational
/// (no trusted on-device clock); a card stamped in the future is
/// treated as fresh rather than rejected.
pub fn verify_exchange(
    own: &ContactCard,
    scanned: &[u8],
    now: u64,
    max_age_secs: u64,
    seen: &mut HashSet<[u8; 32]>,
) -> Result<PublicKey, QrError> {
    let peer = ContactCard::from_qr_bytes(scanned)?;
    if peer.identity == own.identity {
        return Err(QrError::SelfCard);
    }
    if now.saturating_sub(peer.issued_at) > max_age_secs {
        return Err(QrError::Expired);
    }
    if !seen.insert(*peer.identity.as_bytes()) {
        return Err(QrError::Duplicate);
    }
    Ok(peer.identity)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ed25519::generate;

    fn keypair(seed_byte: u8) -> (SecretKey, PublicKey) {
        generate(&[seed_byte; 32])
    }

    fn card(seed_byte: u8, name: &str, handle: &str, issued_at: u64) -> ContactCard {
        let (sk, pk) = keypair(seed_byte);
        ContactCard::sign(&sk, &pk, name, handle, issued_at).expect("test card must sign")
    }

    #[test]
    fn sign_verify_round_trip() {
        let c = card(1, "Alice", "alice.rv", 1_000);
        assert!(c.verify().is_ok());
        assert_eq!(c.display_name(), "Alice");
        assert_eq!(c.handle(), "alice.rv");
        assert_eq!(c.issued_at(), 1_000);
    }

    #[test]
    fn qr_bytes_round_trip() {
        let c = card(2, "Bella Martínez", "bella_99", 42);
        let bytes = c.to_qr_bytes();
        let back = ContactCard::from_qr_bytes(&bytes).expect("round trip");
        assert_eq!(back, c);
        assert!(bytes.len() <= MAX_QR_BYTES);
    }

    #[test]
    fn tampered_name_fails_verify() {
        let mut c = card(3, "Alice", "alice", 7);
        c.display_name = "Alic3".to_owned();
        assert_eq!(c.verify(), Err(QrError::BadSignature));
    }

    #[test]
    fn tampered_signature_fails_verify() {
        let mut c = card(4, "Alice", "alice", 7);
        let mut sig = *c.signature.as_bytes();
        sig[0] ^= 0x01;
        c.signature = Signature::from_bytes(sig);
        assert_eq!(c.verify(), Err(QrError::BadSignature));
    }

    #[test]
    fn tampered_payload_byte_fails_parse() {
        let c = card(5, "Alice", "alice", 7);
        let mut bytes = c.to_qr_bytes();
        // Flip a byte inside the display name region.
        let idx = bytes.iter().position(|&b| b == b'A').unwrap();
        bytes[idx] ^= 0x20;
        assert_eq!(
            ContactCard::from_qr_bytes(&bytes),
            Err(QrError::BadSignature)
        );
    }

    #[test]
    fn bad_handle_charset_rejected() {
        for bad in [
            "Alice",           // uppercase
            "alice!",          // punctuation
            "alice bob",       // space
            "alice@rv",        // at-sign
            "alicé",           // non-ASCII
            "alice/rv",        // slash
        ] {
            let (sk, pk) = keypair(6);
            assert_eq!(
                ContactCard::sign(&sk, &pk, "Alice", bad, 0),
                Err(QrError::InvalidHandle),
                "handle {:?} should be rejected",
                bad
            );
        }
        // Allowed set passes.
        for good in ["alice", "alice.rv", "alice_rv-99", "a.b_c-d0"] {
            let (sk, pk) = keypair(6);
            assert!(
                ContactCard::sign(&sk, &pk, "Alice", good, 0).is_ok(),
                "handle {:?} should be accepted",
                good
            );
        }
    }

    #[test]
    fn oversized_name_rejected() {
        let (sk, pk) = keypair(7);
        let ok_name: String = "a".repeat(MAX_NAME_CHARS);
        let big_name: String = "a".repeat(MAX_NAME_CHARS + 1);
        assert!(ContactCard::sign(&sk, &pk, &ok_name, "alice", 0).is_ok());
        assert_eq!(
            ContactCard::sign(&sk, &pk, &big_name, "alice", 0),
            Err(QrError::InvalidName)
        );
        // Multi-byte chars count as chars, not bytes.
        let wide_ok: String = "é".repeat(MAX_NAME_CHARS);
        assert!(ContactCard::sign(&sk, &pk, &wide_ok, "alice", 0).is_ok());
    }

    #[test]
    fn oversized_handle_rejected() {
        let (sk, pk) = keypair(8);
        let ok: String = "a".repeat(MAX_HANDLE_CHARS);
        let big: String = "a".repeat(MAX_HANDLE_CHARS + 1);
        assert!(ContactCard::sign(&sk, &pk, "Alice", &ok, 0).is_ok());
        assert_eq!(
            ContactCard::sign(&sk, &pk, "Alice", &big, 0),
            Err(QrError::InvalidHandle)
        );
    }

    #[test]
    fn empty_name_and_handle_rejected() {
        let (sk, pk) = keypair(9);
        assert_eq!(
            ContactCard::sign(&sk, &pk, "", "alice", 0),
            Err(QrError::InvalidName)
        );
        assert_eq!(
            ContactCard::sign(&sk, &pk, "Alice", "", 0),
            Err(QrError::InvalidHandle)
        );
    }

    #[test]
    fn oversize_payload_rejected() {
        let big = vec![0u8; MAX_QR_BYTES + 1];
        assert_eq!(
            ContactCard::from_qr_bytes(&big),
            Err(QrError::TooLarge)
        );
    }

    #[test]
    fn malformed_payload_table() {
        let c = card(10, "Alice", "alice", 100);
        let good = c.to_qr_bytes();

        // Bad magic.
        let mut bad = good.clone();
        bad[0] ^= 0xFF;
        assert_eq!(ContactCard::from_qr_bytes(&bad), Err(QrError::BadMagic));

        // Bad version.
        let mut bad = good.clone();
        bad[4] = 0x02;
        assert_eq!(ContactCard::from_qr_bytes(&bad), Err(QrError::BadVersion));

        // Truncation at several cut points.
        for cut in [0, 3, 4, 5, 10, 37, 38, 50, good.len() - 65, good.len() - 1] {
            assert_eq!(
                ContactCard::from_qr_bytes(&good[..cut]),
                Err(QrError::Truncated),
                "cut at {} should be Truncated",
                cut
            );
        }

        // Trailing garbage.
        let mut bad = good.clone();
        bad.push(0x00);
        assert_eq!(
            ContactCard::from_qr_bytes(&bad),
            Err(QrError::TrailingGarbage)
        );

        // Empty input.
        assert_eq!(
            ContactCard::from_qr_bytes(&[]),
            Err(QrError::Truncated)
        );
    }

    #[test]
    fn non_utf8_name_rejected() {
        let c = card(11, "Alice", "alice", 100);
        let mut bytes = c.to_qr_bytes();
        // name_len is at offset 4+1+32 = 37; name starts at 38.
        bytes[38] = 0xFF; // invalid UTF-8 lead byte
        assert_eq!(
            ContactCard::from_qr_bytes(&bytes),
            Err(QrError::InvalidName)
        );
    }

    #[test]
    fn self_card_rejected() {
        let own = card(12, "Me", "me", 1_000);
        let mut seen = HashSet::new();
        let bytes = own.to_qr_bytes();
        assert_eq!(
            verify_exchange(&own, &bytes, 1_500, 3_600, &mut seen),
            Err(QrError::SelfCard)
        );
    }

    #[test]
    fn expired_card_rejected() {
        let own = card(13, "Me", "me", 0);
        let peer = card(14, "Bob", "bob", 1_000);
        let bytes = peer.to_qr_bytes();

        // Fresh: age 500 <= max 3600.
        let mut seen = HashSet::new();
        assert!(verify_exchange(&own, &bytes, 1_500, 3_600, &mut seen).is_ok());

        // Boundary: age exactly max_age passes.
        let mut seen = HashSet::new();
        assert!(verify_exchange(&own, &bytes, 4_600, 3_600, &mut seen).is_ok());

        // One second over: rejected.
        let mut seen = HashSet::new();
        assert_eq!(
            verify_exchange(&own, &bytes, 4_601, 3_600, &mut seen),
            Err(QrError::Expired)
        );
    }

    #[test]
    fn duplicate_scan_rejected() {
        let own = card(15, "Me", "me", 0);
        let peer = card(16, "Bob", "bob", 500);
        let bytes = peer.to_qr_bytes();
        let mut seen = HashSet::new();
        assert!(verify_exchange(&own, &bytes, 900, 3_600, &mut seen).is_ok());
        assert_eq!(
            verify_exchange(&own, &bytes, 901, 3_600, &mut seen),
            Err(QrError::Duplicate)
        );
    }

    #[test]
    fn verified_key_matches_signer() {
        let own = card(17, "Me", "me", 0);
        let (peer_sk, peer_pk) = keypair(18);
        let peer =
            ContactCard::sign(&peer_sk, &peer_pk, "Bob", "bob", 500).expect("sign");
        let mut seen = HashSet::new();
        let got = verify_exchange(&own, &peer.to_qr_bytes(), 900, 3_600, &mut seen)
            .expect("exchange");
        assert_eq!(got, peer_pk);
        assert_eq!(got, peer.identity());
    }

    #[test]
    fn forged_card_with_attacker_key_fails_for_victim() {
        // Attacker Mallory makes a card claiming Bob's name/handle but
        // signed with Mallory's own key: it verifies (self-consistent)
        // but the identity key is Mallory's, not Bob's — the exchange
        // binds to the KEY, so it cannot impersonate Bob's key.
        let own = card(19, "Me", "me", 0);
        let (_bob_sk, bob_pk) = keypair(20);
        let (mallory_sk, mallory_pk) = keypair(21);
        let forged = ContactCard::sign(&mallory_sk, &mallory_pk, "Bob", "bob", 500)
            .expect("sign");
        let mut seen = HashSet::new();
        let got = verify_exchange(&own, &forged.to_qr_bytes(), 900, 3_600, &mut seen)
            .expect("self-consistent card verifies");
        assert_eq!(got, mallory_pk);
        assert_ne!(got, bob_pk, "must not bind to Bob's key");
    }

    #[test]
    fn error_display_messages() {
        // Every variant renders without panicking.
        for e in [
            QrError::TooLarge,
            QrError::BadMagic,
            QrError::BadVersion,
            QrError::Truncated,
            QrError::TrailingGarbage,
            QrError::BadSignature,
            QrError::InvalidName,
            QrError::InvalidHandle,
            QrError::SelfCard,
            QrError::Expired,
            QrError::Duplicate,
        ] {
            let s = format!("{}", e);
            assert!(!s.is_empty());
        }
    }
}
