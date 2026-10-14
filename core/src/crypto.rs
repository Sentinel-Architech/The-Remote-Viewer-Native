//! Minimal on-device crypto stubs.
//!
//! Real Ed25519/age wiring lands here later behind this stable API.
//! Nothing leaves the device.
//!
//! SECURITY WARNING — the stub key derivation below
//! (`public[i] = secret[i].rotate_left(3) ^ 0xA5`) is REVERSIBLE and
//! NOT secure: anyone holding a public key can trivially recover the
//! secret key by applying `rotate_right(3) ^ 0xA5`. It exists only as
//! a deterministic placeholder so the API shape is stable. It MUST be
//! replaced by real Ed25519 (e.g. ed25519-dalek, MIT/Apache-2.0 — an
//! external crate, intentionally not implemented here) before any
//! production use, key exchange, or anything adversarial.

/// Pure-Rust Ed25519 (RFC 8032), std-only.
///
/// NOT externally audited — see the module docs. Used for activation
/// codes (issuer signatures). The older [`Keypair`] stub above remains
/// for device identity and is unchanged by this module.
pub mod ed25519;

use std::time::{SystemTime, UNIX_EPOCH};

/// 32-byte secret key. Never serialized off-device.
///
/// Best-effort zeroization: [`Drop`] overwrites the bytes in place
/// with [`core::ptr::write_volatile`] so the compiler cannot elide
/// the wipe. This is best-effort only — copies (e.g. from
/// [`Clone`]), compiler spills, and swap can retain key material;
/// real key-hygiene still requires the production Ed25519 backend.
pub struct SecretKey([u8; 32]);

impl Clone for SecretKey {
    fn clone(&self) -> Self {
        SecretKey(self.0)
    }
}

impl SecretKey {
    /// Raw bytes for future in-memory signing use. Never leaves the device.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key material: logs and panic messages must not
        // leak secrets.
        f.write_str("SecretKey(<redacted>)")
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        // Best-effort zeroization. write_volatile keeps the compiler
        // from optimizing the overwrite away.
        for b in self.0.iter_mut() {
            // SAFETY: `b` is a valid, uniquely-borrowed byte; the
            // volatile write targets exactly that location.
            unsafe {
                core::ptr::write_volatile(b, 0u8);
            }
        }
    }
}

/// 32-byte public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PublicKey([u8; 32]);

/// Device-local keypair.
///
/// `Debug` is redacted: the secret half prints as `<redacted>` so key
/// material never lands in logs or panic messages.
pub struct Keypair {
    pub secret: SecretKey,
    pub public: PublicKey,
}

impl Clone for Keypair {
    fn clone(&self) -> Self {
        Keypair {
            secret: self.secret.clone(),
            public: self.public,
        }
    }
}

impl std::fmt::Debug for Keypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let public_hex: String = self
            .public
            .0
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        f.debug_struct("Keypair")
            .field("secret", &"<redacted>")
            .field("public", &public_hex)
            .finish()
    }
}

fn xorshift64(mut x: u64) -> u64 {
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    x
}

/// 64-bit FNV-1a hash of `data`.
///
/// A small, deterministic, dependency-free integrity hash shared by
/// core modules (QR scramble tags, air-gap checks). This is an
/// *integrity* primitive — not a MAC, not a password hash, not
/// collision-resistant against motivated adversaries. Real
/// authentication (age/Ed25519) lands behind the stable crypto API
/// later; this function keeps its signature so call sites migrate
/// cleanly.
pub fn fnv1a64(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in data {
        h = h.wrapping_mul(0x100_0000_01b3) ^ u64::from(*b);
    }
    h
}

/// Lowercase hex of [`fnv1a64`] (16 chars). Convenience for tags and
/// wire formats; same integrity caveats as [`fnv1a64`].
pub fn fnv1a64_hex(data: &[u8]) -> String {
    format!("{:016x}", fnv1a64(data))
}

impl Keypair {
    /// Generate a device-local keypair. No network, no keyserver.
    pub fn generate() -> Self {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| {
                d.subsec_nanos() as u64
                    ^ d.as_secs().wrapping_mul(0x9E37_79B9_7F4A_7C15)
            })
            .unwrap_or(0x243F_6A88_85A3_08D3);
        let mut s = seed;
        let mut secret = [0u8; 32];
        for chunk in secret.chunks_mut(8) {
            s = xorshift64(s.wrapping_add(0x9E37_79B9_7F4A_7C15));
            chunk.copy_from_slice(&s.to_le_bytes());
        }
        // STUB public derivation — REVERSIBLE, NOT real Ed25519, NOT
        // secure. public[i] = secret[i].rotate_left(3) ^ 0xA5 means the
        // secret is recoverable from the public key with
        // rotate_right(3) ^ 0xA5. Replace with ed25519-dalek
        // (MIT/Apache-2.0) before any production use.
        let mut public = [0u8; 32];
        for (i, b) in secret.iter().enumerate() {
            public[i] = b.rotate_left(3) ^ 0xA5;
        }
        Keypair {
            secret: SecretKey(secret),
            public: PublicKey(public),
        }
    }

    /// Hex of the public key (chain address material).
    pub fn public_hex(&self) -> String {
        self.public
            .0
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_key_exposes_32_raw_bytes() {
        let keypair = Keypair::generate();
        assert_eq!(keypair.secret.as_bytes().len(), 32);
    }

    #[test]
    fn public_key_derives_deterministically_from_secret() {
        // STUB rule: public[i] = secret[i].rotate_left(3) ^ 0xA5.
        // Guard this invariant so the real Ed25519 wiring must
        // intentionally change it, not silently.
        let keypair = Keypair::generate();
        let secret = keypair.secret.as_bytes();
        for (i, b) in keypair.public.0.iter().enumerate() {
            assert_eq!(*b, secret[i].rotate_left(3) ^ 0xA5, "byte {}", i);
        }
    }

    #[test]
    fn public_hex_is_64_lowercase_hex_chars() {
        let keypair = Keypair::generate();
        let hex = keypair.public_hex();
        assert_eq!(hex.len(), 64);
        assert!(hex
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn public_hex_round_trips_public_bytes() {
        let keypair = Keypair::generate();
        let hex = keypair.public_hex();
        let bytes: Vec<u8> = hex
            .as_bytes()
            .chunks(2)
            .map(|pair| {
                let hi = (pair[0] as char).to_digit(16).unwrap();
                let lo = (pair[1] as char).to_digit(16).unwrap();
                (hi * 16 + lo) as u8
            })
            .collect();
        assert_eq!(bytes.as_slice(), &keypair.public.0);
    }

    #[test]
    fn keypair_clone_and_public_copy_preserve_keys() {
        let keypair = Keypair::generate();
        let cloned = keypair.clone();
        assert_eq!(cloned.public, keypair.public);
        assert_eq!(cloned.secret.as_bytes(), keypair.secret.as_bytes());
        let copied: PublicKey = keypair.public;
        assert_eq!(copied, keypair.public);
    }

    #[test]
    fn debug_never_leaks_secret_material() {
        let keypair = Keypair::generate();
        let secret_dbg = format!("{:?}", keypair.secret);
        let pair_dbg = format!("{:?}", keypair);
        // The redaction marker must appear...
        assert!(secret_dbg.contains("<redacted>"));
        assert!(pair_dbg.contains("<redacted>"));
        // ...and the secret bytes must not appear in hex form.
        let secret_hex: String = keypair
            .secret
            .as_bytes()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        assert!(!secret_dbg.contains(&secret_hex));
        assert!(!pair_dbg.contains(&secret_hex));
        // Public key hex is NOT secret and stays visible.
        assert!(pair_dbg.contains(&keypair.public_hex()));
    }

    #[test]
    fn fnv1a64_empty_input_is_offset_basis() {
        assert_eq!(fnv1a64(b""), 0xcbf2_9ce4_8422_2325);
    }

    #[test]
    fn fnv1a64_is_deterministic_and_sensitive_to_input() {
        assert_eq!(fnv1a64(b"contact key material"), fnv1a64(b"contact key material"));
        assert_ne!(fnv1a64(b"hello"), fnv1a64(b"hellp"));
    }

    #[test]
    fn fnv1a64_hex_is_16_lowercase_hex() {
        let hex = fnv1a64_hex(b"hello");
        assert_eq!(hex.len(), 16);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert_eq!(hex, format!("{:016x}", fnv1a64(b"hello")));
    }
}
