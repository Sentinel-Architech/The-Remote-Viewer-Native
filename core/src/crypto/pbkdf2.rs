//! PBKDF2-HMAC-SHA512 password-based key derivation (RFC 8018 §5.2).
//!
//! Pure Rust, std-only. Used to derive the profile-vault encryption
//! key from a user passphrase.
//!
//! NOT externally audited — like the rest of `trv_core::crypto`, this
//! module is implemented from the RFCs and cross-checked against
//! independent implementations (Python `hashlib`), but it has not had
//! an independent cryptographic audit. Do not rely on it for
//! production secrets until that audit happens.

use super::ed25519::sha512;

/// HMAC-SHA512 (RFC 2104).
///
/// SHA-512's block size is 128 bytes. Keys longer than a block are
/// hashed first, per the RFC.
pub fn hmac_sha512(key: &[u8], msg: &[u8]) -> [u8; 64] {
    const BLOCK: usize = 128;
    let mut k0 = [0u8; BLOCK];
    if key.len() > BLOCK {
        k0[..64].copy_from_slice(&sha512::digest(key));
    } else {
        k0[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k0[i];
        opad[i] ^= k0[i];
    }
    let mut inner = Vec::with_capacity(BLOCK + msg.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(msg);
    let inner_hash = sha512::digest(&inner);
    // Best-effort: drop the padded key copies as soon as they are used.
    // (The caller-owned `key` slice is not ours to wipe.)
    for b in k0.iter_mut() {
        // SAFETY: `b` is a valid, uniquely-borrowed byte.
        unsafe {
            core::ptr::write_volatile(b, 0u8);
        }
    }
    let mut outer = Vec::with_capacity(BLOCK + 64);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&inner_hash);
    let out = sha512::digest(&outer);
    // Wipe key-equivalent material: the pads, plus the `outer` buffer
    // which holds a verbatim copy of `opad`. (`k0` is wiped above.)
    for b in ipad
        .iter_mut()
        .chain(opad.iter_mut())
        .chain(outer.iter_mut())
    {
        // SAFETY: `b` is a valid, uniquely-borrowed byte.
        unsafe {
            core::ptr::write_volatile(b, 0u8);
        }
    }
    out
}

/// Error from [`pbkdf2_sha512`] on invalid parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KdfError {
    /// Iteration count must be at least 1.
    ZeroIterations,
    /// Requested output is empty or exceeds the RFC 8018 limit
    /// ((2^32 − 1) · 64 bytes).
    BadOutputLen,
}

impl std::fmt::Display for KdfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KdfError::ZeroIterations => write!(f, "PBKDF2 iterations must be >= 1"),
            KdfError::BadOutputLen => write!(f, "PBKDF2 output length out of range"),
        }
    }
}

impl std::error::Error for KdfError {}

/// PBKDF2 with HMAC-SHA512 (RFC 8018 §5.2).
///
/// Derives `out_len` bytes from `password` and `salt` using
/// `iterations` rounds. Returns [`KdfError`] on invalid parameters
/// instead of panicking.
pub fn pbkdf2_sha512(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    out_len: usize,
) -> Result<Vec<u8>, KdfError> {
    if iterations == 0 {
        return Err(KdfError::ZeroIterations);
    }
    // RFC 8018 §5.2: dkLen <= (2^32 - 1) * hLen. Compare in u64 so the
    // bound itself never overflows on 32-bit targets.
    let max_len = u64::from(u32::MAX) * 64;
    if out_len == 0 || (out_len as u64) > max_len {
        return Err(KdfError::BadOutputLen);
    }
    // U_1 = PRF(password, salt || INT_32_BE(i)); U_j = PRF(password, U_{j-1}).
    let blocks = out_len.div_ceil(64);
    let mut out = Vec::with_capacity(out_len);
    let mut salt_block = Vec::with_capacity(salt.len() + 4);
    for i in 1..=blocks as u32 {
        salt_block.clear();
        salt_block.extend_from_slice(salt);
        salt_block.extend_from_slice(&i.to_be_bytes());
        let mut u = hmac_sha512(password, &salt_block);
        let mut t = u;
        for _ in 1..iterations {
            u = hmac_sha512(password, &u);
            for j in 0..64 {
                t[j] ^= u[j];
            }
        }
        // Wipe the last chaining value before it is dropped.
        for b in u.iter_mut() {
            // SAFETY: `b` is a valid, uniquely-borrowed byte.
            unsafe {
                core::ptr::write_volatile(b, 0u8);
            }
        }
        out.extend_from_slice(&t);
        for b in t.iter_mut() {
            // SAFETY: `b` is a valid, uniquely-borrowed byte.
            unsafe {
                core::ptr::write_volatile(b, 0u8);
            }
        }
    }
    out.truncate(out_len);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hex-decode helper (test-only).
    fn hex(s: &str) -> Vec<u8> {
        assert!(s.len() % 2 == 0);
        s.as_bytes()
            .chunks(2)
            .map(|p| {
                let hi = (p[0] as char).to_digit(16).unwrap();
                let lo = (p[1] as char).to_digit(16).unwrap();
                (hi * 16 + lo) as u8
            })
            .collect()
    }

    // Vectors generated with Python's hashlib.pbkdf2_hmac (independent
    // implementation) — see the module docs for why these are trusted
    // over hand transcription.

    #[test]
    fn vector_rfc_style_1_iter() {
        let dk = pbkdf2_sha512(b"password", b"salt", 1, 64).unwrap();
        assert_eq!(
            dk,
            hex("867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce")
        );
    }

    #[test]
    fn vector_rfc_style_2_iter() {
        let dk = pbkdf2_sha512(b"password", b"salt", 2, 64).unwrap();
        assert_eq!(
            dk,
            hex("e1d9c16aa681708a45f5c7c4e215ceb66e011a2e9f0040713f18aefdb866d53cf76cab2868a39b9f7840edce4fef5a82be67335c77a6068e04112754f27ccf4e")
        );
    }

    #[test]
    fn vector_long_password_4096_iter() {
        let dk = pbkdf2_sha512(
            b"passwordPASSWORDpassword",
            b"saltSALTsaltSALT",
            4096,
            64,
        )
        .unwrap();
        assert_eq!(
            dk,
            hex("0697a650f36d9436cce4b2da03b8425695b5e85a0886ea5cd8c001f0ad05bea96f8f379da22de48858a63c7ba442d79757b9d5864316dc281408c4db18502f6d")
        );
    }

    #[test]
    fn vector_multiblock_output() {
        // dkLen = 100 exercises the multi-block path (64 + 36).
        let dk = pbkdf2_sha512(b"trv-vault-test", b"pepper16bytes....", 100, 100).unwrap();
        assert_eq!(dk.len(), 100);
        assert_eq!(
            dk,
            hex("ccb22db49f0042452f5acb61a16e444b90720a9df9e741e045e230c437475558189ea1266d27bb098eb63e0439060b5ecb21cefc68d0af0bc6dfd203db4b37da3f02dd29adab124e68c5f8f761595b1a5890456d36c18528495fc65cb4cf94bbfea00a6d")
        );
    }

    #[test]
    fn output_len_truncates_last_block() {
        let full = pbkdf2_sha512(b"pw", b"s", 5, 64).unwrap();
        let short = pbkdf2_sha512(b"pw", b"s", 5, 37).unwrap();
        assert_eq!(short, &full[..37]);
    }

    #[test]
    fn different_passwords_salts_iterations_differ() {
        let a = pbkdf2_sha512(b"pw1", b"salt", 10, 32).unwrap();
        let b = pbkdf2_sha512(b"pw2", b"salt", 10, 32).unwrap();
        let c = pbkdf2_sha512(b"pw1", b"other", 10, 32).unwrap();
        let d = pbkdf2_sha512(b"pw1", b"salt", 11, 32).unwrap();
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
    }

    #[test]
    fn zero_iterations_is_an_error() {
        assert_eq!(
            pbkdf2_sha512(b"pw", b"salt", 0, 32).unwrap_err(),
            KdfError::ZeroIterations
        );
    }

    #[test]
    fn bad_output_len_is_an_error() {
        assert_eq!(
            pbkdf2_sha512(b"pw", b"salt", 1, 0).unwrap_err(),
            KdfError::BadOutputLen
        );
    }

    #[test]
    fn hmac_is_deterministic_and_key_sensitive() {
        let a = hmac_sha512(b"key", b"message");
        let b = hmac_sha512(b"key", b"message");
        let c = hmac_sha512(b"other", b"message");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 64);
    }
}
