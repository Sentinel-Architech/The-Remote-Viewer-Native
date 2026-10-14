//! ChaCha20-Poly1305 authenticated encryption (RFC 8439 §2.8).
//!
//! Pure Rust, std-only. 256-bit keys, 96-bit nonces, 128-bit tags.
//!
//! NOT externally audited — like the rest of `trv_core::crypto`, this
//! module is implemented from the RFC and cross-checked against two
//! independent implementations (a from-scratch Python reference and
//! pycryptodome, which agree with each other and reproduce the RFC's
//! published authentication tag), but it has not had an independent
//! cryptographic audit. Do not rely on it for production secrets
//! until that audit happens.
//!
//! Design note: the IETF 96-bit-nonce variant (RFC 8439) is used, not
//! XChaCha20. Random nonces are safe here because every vault save
//! also draws a fresh random PBKDF2 salt, so the (key, nonce) pair is
//! never reused even if a nonce collided.

/// Error from [`decrypt`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadError {
    /// Poly1305 tag mismatch: wrong key/nonce, tampered ciphertext,
    /// or corrupted file. Nothing is decrypted on this path.
    AuthenticationFailed,
}

impl std::fmt::Display for AeadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AeadError::AuthenticationFailed => {
                write!(f, "authentication failed (wrong key or tampered data)")
            }
        }
    }
}

impl std::error::Error for AeadError {}

fn quarter_round(a: usize, b: usize, c: usize, d: usize, x: &mut [u32; 16]) {
    x[a] = x[a].wrapping_add(x[b]);
    x[d] ^= x[a];
    x[d] = x[d].rotate_left(16);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] ^= x[c];
    x[b] = x[b].rotate_left(12);
    x[a] = x[a].wrapping_add(x[b]);
    x[d] ^= x[a];
    x[d] = x[d].rotate_left(8);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] ^= x[c];
    x[b] = x[b].rotate_left(7);
}

/// One ChaCha20 block (RFC 8439 §2.3): 64 bytes of keystream for
/// `counter`, or the Poly1305 one-time key when `counter == 0`.
fn chacha_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut st = [0u32; 16];
    st[0] = 0x61707865;
    st[1] = 0x3320646e;
    st[2] = 0x79622d32;
    st[3] = 0x6b206574;
    for (i, chunk) in key.chunks_exact(4).enumerate() {
        st[4 + i] = u32::from_le_bytes(chunk.try_into().unwrap());
    }
    st[12] = counter;
    for (i, chunk) in nonce.chunks_exact(4).enumerate() {
        st[13 + i] = u32::from_le_bytes(chunk.try_into().unwrap());
    }
    let mut w = st;
    for _ in 0..10 {
        quarter_round(0, 4, 8, 12, &mut w);
        quarter_round(1, 5, 9, 13, &mut w);
        quarter_round(2, 6, 10, 14, &mut w);
        quarter_round(3, 7, 11, 15, &mut w);
        quarter_round(0, 5, 10, 15, &mut w);
        quarter_round(1, 6, 11, 12, &mut w);
        quarter_round(2, 7, 8, 13, &mut w);
        quarter_round(3, 4, 9, 14, &mut w);
    }
    let mut out = [0u8; 64];
    for (i, chunk) in out.chunks_exact_mut(4).enumerate() {
        chunk.copy_from_slice(&w[i].wrapping_add(st[i]).to_le_bytes());
    }
    out
}

/// XOR `data` with the ChaCha20 keystream starting at `counter`.
fn chacha_xor(key: &[u8; 32], counter: u32, nonce: &[u8; 12], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut ctr = counter;
    for chunk in data.chunks(64) {
        let ks = chacha_block(key, ctr, nonce);
        ctr = ctr.wrapping_add(1);
        for (i, b) in chunk.iter().enumerate() {
            out.push(b ^ ks[i]);
        }
    }
    out
}

/// Poly1305 one-time authenticator (RFC 8439 §2.5).
///
/// 26-bit limbs in u64 (donna-style). The `r` clamp is applied at the
/// byte level first (`r &= 0x0ffffffc0ffffffc0ffffffc0fffffff`), exactly
/// as the RFC pseudocode, so there is no doubt about which bits are
/// cleared.
fn poly1305(key: &[u8; 32], msg: &[u8]) -> [u8; 16] {
    // Clamp r at the byte level, per RFC 8439 §2.5.
    let mut rb = [0u8; 16];
    rb.copy_from_slice(&key[..16]);
    rb[3] &= 0x0f;
    rb[7] &= 0x0f;
    rb[11] &= 0x0f;
    rb[15] &= 0x0f;
    rb[4] &= 0xfc;
    rb[8] &= 0xfc;
    rb[12] &= 0xfc;
    let t = u128::from_le_bytes(rb);
    let r = [
        (t & 0x3ffffff) as u64,
        ((t >> 26) & 0x3ffffff) as u64,
        ((t >> 52) & 0x3ffffff) as u64,
        ((t >> 78) & 0x3ffffff) as u64,
        ((t >> 104) & 0x3ffffff) as u64,
    ];
    let s1 = r[1] * 5;
    let s2 = r[2] * 5;
    let s3 = r[3] * 5;
    let s4 = r[4] * 5;

    let mut h = [0u64; 5];
    let mut off = 0;
    while off < msg.len() {
        let blen = core::cmp::min(16, msg.len() - off);
        // h += block (little-endian) plus the 2^(8*blen) padding bit.
        let mut tb = [0u8; 16];
        tb[..blen].copy_from_slice(&msg[off..off + blen]);
        let bt = u128::from_le_bytes(tb);
        h[0] += (bt & 0x3ffffff) as u64;
        h[1] += ((bt >> 26) & 0x3ffffff) as u64;
        h[2] += ((bt >> 52) & 0x3ffffff) as u64;
        h[3] += ((bt >> 78) & 0x3ffffff) as u64;
        h[4] += ((bt >> 104) & 0x3ffffff) as u64;
        let bit = 8 * blen;
        h[bit / 26] += 1u64 << (bit % 26);
        // h *= r  (mod 2^130 - 5), partial carry.
        // Bounds: h_i < 2^27, r_i < 2^26, s_i < 2^29, so each d_i < 2^59.
        let d0 = h[0] * r[0] + h[1] * s4 + h[2] * s3 + h[3] * s2 + h[4] * s1;
        let d1 = h[0] * r[1] + h[1] * r[0] + h[2] * s4 + h[3] * s3 + h[4] * s2;
        let d2 = h[0] * r[2] + h[1] * r[1] + h[2] * r[0] + h[3] * s4 + h[4] * s3;
        let d3 = h[0] * r[3] + h[1] * r[2] + h[2] * r[1] + h[3] * r[0] + h[4] * s4;
        let d4 = h[0] * r[4] + h[1] * r[3] + h[2] * r[2] + h[3] * r[1] + h[4] * r[0];
        let mut c: u64;
        h[0] = d0 & 0x3ffffff;
        c = d0 >> 26;
        h[1] = (d1 + c) & 0x3ffffff;
        c = (d1 + c) >> 26;
        h[2] = (d2 + c) & 0x3ffffff;
        c = (d2 + c) >> 26;
        h[3] = (d3 + c) & 0x3ffffff;
        c = (d3 + c) >> 26;
        h[4] = (d4 + c) & 0x3ffffff;
        c = (d4 + c) >> 26;
        h[0] += c * 5;
        c = h[0] >> 26;
        h[0] &= 0x3ffffff;
        h[1] += c;
        off += blen;
    }

    // Full carry, then conditional subtract p = 2^130 - 5.
    let mut c = h[1] >> 26;
    h[1] &= 0x3ffffff;
    h[2] += c;
    c = h[2] >> 26;
    h[2] &= 0x3ffffff;
    h[3] += c;
    c = h[3] >> 26;
    h[3] &= 0x3ffffff;
    h[4] += c;
    c = h[4] >> 26;
    h[4] &= 0x3ffffff;
    h[0] += c * 5;
    c = h[0] >> 26;
    h[0] &= 0x3ffffff;
    h[1] += c;
    // g = h + 5 - 2^130; borrow out of the top limb means h < p.
    let mut g = [0u64; 5];
    g[0] = h[0] + 5;
    c = g[0] >> 26;
    g[0] &= 0x3ffffff;
    g[1] = h[1] + c;
    c = g[1] >> 26;
    g[1] &= 0x3ffffff;
    g[2] = h[2] + c;
    c = g[2] >> 26;
    g[2] &= 0x3ffffff;
    g[3] = h[3] + c;
    c = g[3] >> 26;
    g[3] &= 0x3ffffff;
    let g4 = h[4] + c;
    let borrow = u64::from(g4 < (1u64 << 26));
    g[4] = g4.wrapping_sub(1u64 << 26) & 0x3ffffff;
    // borrow == 0 (h >= p): use g. borrow == 1 (h < p): use h.
    let mask = borrow.wrapping_sub(1);
    for i in 0..5 {
        h[i] = (h[i] & !mask) | (g[i] & mask);
    }
    // Serialize h (< 2^130) as 128-bit LE, add s, reduce mod 2^128.
    let h128: u128 =
        h[0] as u128 | ((h[1] as u128) << 26) | ((h[2] as u128) << 52) | ((h[3] as u128) << 78)
            | ((h[4] as u128) << 104);
    let s = u128::from_le_bytes(key[16..32].try_into().unwrap());
    h128.wrapping_add(s).to_le_bytes()
}

/// Constant-time 16-byte equality for tag comparison.
///
/// No early exit on secret data: the loop always runs 16 iterations
/// and the result is a single boolean.
fn ct_eq(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

fn pad16_len(len: usize) -> usize {
    (16 - (len % 16)) % 16
}

/// Encrypt `plaintext` with `key`/`nonce`, authenticating `aad`.
///
/// Returns `ciphertext || tag` (tag is the final 16 bytes).
/// The Poly1305 one-time key comes from the counter-0 block and the
/// keystream starts at counter 1, per RFC 8439 §2.8.
pub fn encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    let otk_full = chacha_block(key, 0, nonce);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&otk_full[..32]);
    // Wipe the full block copy; `otk` is used below then dropped.
    let mut otk_full = otk_full;
    for b in otk_full.iter_mut() {
        // SAFETY: `b` is a valid, uniquely-borrowed byte.
        unsafe {
            core::ptr::write_volatile(b, 0u8);
        }
    }
    let ct = chacha_xor(key, 1, nonce, plaintext);
    let mut mac_data = Vec::with_capacity(
        aad.len() + pad16_len(aad.len()) + ct.len() + pad16_len(ct.len()) + 16,
    );
    mac_data.extend_from_slice(aad);
    mac_data.extend(std::iter::repeat(0u8).take(pad16_len(aad.len())));
    mac_data.extend_from_slice(&ct);
    mac_data.extend(std::iter::repeat(0u8).take(pad16_len(ct.len())));
    mac_data.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    mac_data.extend_from_slice(&(ct.len() as u64).to_le_bytes());
    let tag = poly1305(&otk, &mac_data);
    for b in otk.iter_mut() {
        // SAFETY: `b` is a valid, uniquely-borrowed byte.
        unsafe {
            core::ptr::write_volatile(b, 0u8);
        }
    }
    let mut out = Vec::with_capacity(ct.len() + 16);
    out.extend_from_slice(&ct);
    out.extend_from_slice(&tag);
    out
}

/// Decrypt `ciphertext_and_tag` (as produced by [`encrypt`]).
///
/// The tag is verified in constant time BEFORE any decryption.
/// On mismatch returns [`AeadError::AuthenticationFailed`] and no
/// plaintext is produced or returned.
pub fn decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
) -> Result<Vec<u8>, AeadError> {
    if ciphertext_and_tag.len() < 16 {
        return Err(AeadError::AuthenticationFailed);
    }
    let (ct, tag_bytes) = ciphertext_and_tag.split_at(ciphertext_and_tag.len() - 16);
    let mut tag = [0u8; 16];
    tag.copy_from_slice(tag_bytes);
    let otk_full = chacha_block(key, 0, nonce);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&otk_full[..32]);
    // Wipe the full block copy, like `encrypt` does; `otk` is wiped below.
    let mut otk_full = otk_full;
    for b in otk_full.iter_mut() {
        // SAFETY: `b` is a valid, uniquely-borrowed byte.
        unsafe {
            core::ptr::write_volatile(b, 0u8);
        }
    }
    let mut mac_data = Vec::with_capacity(
        aad.len() + pad16_len(aad.len()) + ct.len() + pad16_len(ct.len()) + 16,
    );
    mac_data.extend_from_slice(aad);
    mac_data.extend(std::iter::repeat(0u8).take(pad16_len(aad.len())));
    mac_data.extend_from_slice(ct);
    mac_data.extend(std::iter::repeat(0u8).take(pad16_len(ct.len())));
    mac_data.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    mac_data.extend_from_slice(&(ct.len() as u64).to_le_bytes());
    let expected = poly1305(&otk, &mac_data);
    for b in otk.iter_mut() {
        // SAFETY: `b` is a valid, uniquely-borrowed byte.
        unsafe {
            core::ptr::write_volatile(b, 0u8);
        }
    }
    if !ct_eq(&expected, &tag) {
        return Err(AeadError::AuthenticationFailed);
    }
    Ok(chacha_xor(key, 1, nonce, ct))
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

    fn arr32(v: &[u8]) -> [u8; 32] {
        v.try_into().unwrap()
    }
    fn arr12(v: &[u8]) -> [u8; 12] {
        v.try_into().unwrap()
    }

    // The vectors below were cross-checked between a from-scratch
    // Python RFC 8439 implementation and pycryptodome (independent
    // implementations that agree with each other and reproduce the
    // RFC's published authentication tag for §2.8.2).

    #[test]
    fn rfc_8439_section_2_8_2_vector() {
        let key = arr32(&hex(
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        ));
        let nonce = arr12(&hex("070000004041424344454647"));
        let aad = hex("50515253c0c1c2c3c4c5c6c7");
        let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let out = encrypt(&key, &nonce, &aad, pt);
        let (ct, tag) = out.split_at(out.len() - 16);
        // Ciphertext verified against two independent implementations;
        // tag matches the RFC's published value exactly.
        assert_eq!(
            hex::encode(ct),
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116"
        );
        assert_eq!(hex::encode(tag), "1ae10b594f09e26a7e902ecbd0600691");
        // And it decrypts.
        assert_eq!(decrypt(&key, &nonce, &aad, &out).unwrap(), pt);
    }

    #[test]
    fn random_vector_0() {
        let key = arr32(&hex(
            "8bb27ea8152ca24158b7c17b321481d4892db2d996c1cb32a92def5039b0ee9a",
        ));
        let nonce = arr12(&hex("b08c255cda22d00e87ae239d"));
        let aad = hex("8005f45e79dce86e24f19abfc5ca736c2e");
        let pt = hex("457d26a52c7d261f631c46e0b4e6e465d806347e98dacb61e761b1d552d91d30c9699ef3bd1b2b542278598b6e186a63ce6f3db3996f9b140fff4472b417fefc");
        let out = encrypt(&key, &nonce, &aad, &pt);
        let (ct, tag) = out.split_at(out.len() - 16);
        assert_eq!(
            hex::encode(ct),
            "2387333b359cfc31bd8da97f59573c1a7175e83f072faee888b7ca8c074d57e1006f2a2d794aeb834681dd163074cfb55ae108e849ddd935b3a310c800c0d38d"
        );
        assert_eq!(hex::encode(tag), "9f6c1de4ac5164a8eb268a49e2783144");
        assert_eq!(decrypt(&key, &nonce, &aad, &out).unwrap(), pt);
    }

    #[test]
    fn random_vector_1() {
        let key = arr32(&hex(
            "5b001de9e6ecdb8256f042b9cb4839023eaa5241226684774694e36d7058c034",
        ));
        let nonce = arr12(&hex("2cd6e60cbca1b56a94334772"));
        let aad = hex("62005b97ca915e2d9b403732ed0f0b7c1c");
        let pt = hex("fd4a1620c72f0fac9d356ca78bd4e51d2758857ed59943a5ae95d0e1c2927d3f9c45771e3d491433b8bd25a613bbd52cf6465a700715b3a23e8725d527408f84");
        let out = encrypt(&key, &nonce, &aad, &pt);
        let (ct, tag) = out.split_at(out.len() - 16);
        assert_eq!(
            hex::encode(ct),
            "fed48908a7fbdea7d0f5208f3e89dc2f6656909eaaa7f19bfbc2aa7ab885d566a43366e5eea072fd9e547c8f4f4470ae5724a8d67530799afd9867531c88336b"
        );
        assert_eq!(hex::encode(tag), "7122e8822b9004ee77f4033814132174");
        assert_eq!(decrypt(&key, &nonce, &aad, &out).unwrap(), pt);
    }

    #[test]
    fn empty_plaintext_and_aad() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let out = encrypt(&key, &nonce, b"", b"");
        assert_eq!(out.len(), 16); // tag only
        assert_eq!(hex::encode(&out), "4eb972c9a8fb3a1b382bb4d36f5ffad1");
        assert_eq!(decrypt(&key, &nonce, b"", &out).unwrap(), b"");
    }

    #[test]
    fn roundtrip_various_lengths() {
        let key = [7u8; 32];
        let nonce = [9u8; 12];
        for len in [0usize, 1, 15, 16, 17, 63, 64, 65, 200] {
            let pt: Vec<u8> = (0..len).map(|i| (i * 31 + 7) as u8).collect();
            let aad = b"associated";
            let out = encrypt(&key, &nonce, aad, &pt);
            assert_eq!(out.len(), len + 16);
            assert_eq!(decrypt(&key, &nonce, aad, &out).unwrap(), pt);
        }
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let mut out = encrypt(&key, &nonce, b"aad", b"secret message here!!");
        out[0] ^= 0x01;
        assert_eq!(
            decrypt(&key, &nonce, b"aad", &out).unwrap_err(),
            AeadError::AuthenticationFailed
        );
    }

    #[test]
    fn tampered_tag_rejected() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let mut out = encrypt(&key, &nonce, b"aad", b"secret message here!!");
        let n = out.len();
        out[n - 1] ^= 0x80;
        assert_eq!(
            decrypt(&key, &nonce, b"aad", &out).unwrap_err(),
            AeadError::AuthenticationFailed
        );
    }

    #[test]
    fn wrong_key_rejected() {
        let mut key = [1u8; 32];
        let nonce = [2u8; 12];
        let out = encrypt(&key, &nonce, b"aad", b"data");
        key[0] ^= 0x01;
        assert_eq!(
            decrypt(&key, &nonce, b"aad", &out).unwrap_err(),
            AeadError::AuthenticationFailed
        );
    }

    #[test]
    fn wrong_nonce_rejected() {
        let key = [1u8; 32];
        let mut nonce = [2u8; 12];
        let out = encrypt(&key, &nonce, b"aad", b"data");
        nonce[11] ^= 0x01;
        assert_eq!(
            decrypt(&key, &nonce, b"aad", &out).unwrap_err(),
            AeadError::AuthenticationFailed
        );
    }

    #[test]
    fn wrong_aad_rejected() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let out = encrypt(&key, &nonce, b"aad", b"data");
        assert_eq!(
            decrypt(&key, &nonce, b"other-aad", &out).unwrap_err(),
            AeadError::AuthenticationFailed
        );
    }

    #[test]
    fn truncated_input_rejected() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        assert_eq!(
            decrypt(&key, &nonce, b"aad", b"short").unwrap_err(),
            AeadError::AuthenticationFailed
        );
    }

    #[test]
    fn ct_eq_behaves() {
        assert!(ct_eq(&[0u8; 16], &[0u8; 16]));
        let mut b = [0u8; 16];
        b[15] = 1;
        assert!(!ct_eq(&[0u8; 16], &b));
    }

    /// Local hex encoder (the crate has no hex dependency).
    mod hex {
        pub fn encode(bytes: &[u8]) -> String {
            bytes.iter().map(|b| format!("{:02x}", b)).collect()
        }
    }
}
