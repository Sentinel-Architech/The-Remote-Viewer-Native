//! Minimal on-device crypto.
//!
//! Device identity keypairs are real Ed25519 (RFC 8032, pure Rust,
//! std-only — see [`ed25519`]), generated from OS entropy. Key
//! generation FAILS CLOSED when the OS CSPRNG is unavailable: there
//! is no time/PID-based fallback anywhere in this crate.
//!
//! SECURITY NOTE: the Ed25519 implementation is handwritten and NOT
//! externally audited. Do not use for production sales or
//! adversarial settings until an independent audit is complete.

/// Pure-Rust Ed25519 (RFC 8032), std-only.
///
/// NOT externally audited — see the module docs. Used for activation
/// codes (issuer signatures) and device identity keypairs.
pub mod ed25519;

/// ChaCha20-Poly1305 authenticated encryption (RFC 8439), std-only.
///
/// NOT externally audited — see the module docs. Used for the
/// profile vault at rest.
pub mod chacha20poly1305;

/// PBKDF2-HMAC-SHA512 key derivation (RFC 8018), std-only.
///
/// NOT externally audited — see the module docs. Used to derive the
/// profile-vault encryption key from a user passphrase.
pub mod pbkdf2;

use std::io::Read;

/// Error from [`Keypair::generate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeypairError {
    /// The OS CSPRNG (`/dev/urandom`) was unavailable. Generation
    /// fails closed rather than falling back to weak entropy.
    EntropyUnavailable,
}

impl std::fmt::Display for KeypairError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeypairError::EntropyUnavailable => {
                f.write_str("OS entropy unavailable; refusing to generate a weak keypair")
            }
        }
    }
}

impl std::error::Error for KeypairError {}

/// 32-byte secret key. Never serialized off-device.
///
/// Best-effort zeroization: [`Drop`] overwrites the bytes in place
/// with [`core::ptr::write_volatile`] so the compiler cannot elide
/// the wipe. This is best-effort only — copies (e.g. from
/// [`Clone`]), compiler spills, and swap can retain key material.
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

/// 64-bit FNV-1a hash of `data`.
///
/// A small, deterministic, dependency-free integrity hash available
/// to core modules for lightweight integrity checks. This is an
/// *integrity* primitive — not a MAC, not a password hash, not
/// collision-resistant against motivated adversaries. Real
/// authentication (Ed25519) lands behind the stable crypto API;
/// this function keeps its signature so call sites migrate cleanly.
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
    /// Generate a device-local keypair with real Ed25519. No network,
    /// no keyserver.
    ///
    /// Entropy comes from the OS CSPRNG (`/dev/urandom`). If it is
    /// unavailable, generation FAILS with
    /// [`KeypairError::EntropyUnavailable`] rather than falling back
    /// to time/PID-based entropy. A keypair generated from weak
    /// entropy is worse than no keypair at all.
    pub fn generate() -> Result<Self, KeypairError> {
        let mut seed = [0u8; 32];
        let mut f = std::fs::File::open("/dev/urandom")
            .map_err(|_| KeypairError::EntropyUnavailable)?;
        f.read_exact(&mut seed)
            .map_err(|_| KeypairError::EntropyUnavailable)?;
        let (secret, public) = ed25519::generate(&seed);
        // Wipe the stack copy of the raw seed; the ed25519 SecretKey
        // owns its own zeroizing copy.
        for b in seed.iter_mut() {
            // SAFETY: `b` is a valid, uniquely-borrowed byte; the
            // volatile write targets exactly that location.
            unsafe {
                core::ptr::write_volatile(b, 0u8);
            }
        }
        Ok(Keypair {
            secret: SecretKey(*secret.as_bytes()),
            public: PublicKey(*public.as_bytes()),
        })
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
        let keypair = Keypair::generate().expect("test env provides /dev/urandom");
        assert_eq!(keypair.secret.as_bytes().len(), 32);
    }

    #[test]
    fn public_key_is_real_ed25519_not_reversible_stub() {
        // The old stub derived public[i] = secret[i].rotate_left(3) ^ 0xA5,
        // which let anyone recover the secret from the public key.
        // The real Ed25519 public key must NOT follow that rule, and
        // must verify signatures made by the secret key.
        let keypair = Keypair::generate().expect("test env provides /dev/urandom");
        let secret = keypair.secret.as_bytes();
        let stub_matches = keypair
            .public
            .0
            .iter()
            .enumerate()
            .all(|(i, b)| *b == secret[i].rotate_left(3) ^ 0xA5);
        assert!(!stub_matches, "public key still follows the reversible stub rule");
        // Real Ed25519: the keypair must sign/verify.
        let ed_sec = ed25519::SecretKey::from_seed(*secret);
        let ed_pub = ed25519::PublicKey::from_bytes(keypair.public.0);
        let sig = ed25519::sign(&ed_sec, &ed_pub, b"sentinel");
        assert!(ed25519::verify(&ed_pub, b"sentinel", &sig));
        assert!(!ed25519::verify(&ed_pub, b"tampered", &sig));
    }

    #[test]
    fn public_hex_is_64_lowercase_hex_chars() {
        let keypair = Keypair::generate().expect("test env provides /dev/urandom");
        let hex = keypair.public_hex();
        assert_eq!(hex.len(), 64);
        assert!(hex
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn public_hex_round_trips_public_bytes() {
        let keypair = Keypair::generate().expect("test env provides /dev/urandom");
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
        let keypair = Keypair::generate().expect("test env provides /dev/urandom");
        let cloned = keypair.clone();
        assert_eq!(cloned.public, keypair.public);
        assert_eq!(cloned.secret.as_bytes(), keypair.secret.as_bytes());
        let copied: PublicKey = keypair.public;
        assert_eq!(copied, keypair.public);
    }

    #[test]
    fn debug_never_leaks_secret_material() {
        let keypair = Keypair::generate().expect("test env provides /dev/urandom");
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
