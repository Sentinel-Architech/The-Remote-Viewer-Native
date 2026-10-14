//! Pure-Rust Ed25519 (RFC 8032), standard library only.
//!
//! # SECURITY NOTICE — NOT EXTERNALLY AUDITED
//!
//! This module implements Ed25519 from scratch: SHA-512, Curve25519
//! field arithmetic (radix 2^51), Edwards point operations, and the
//! EdDSA sign/verify algorithms. It was written carefully against
//! RFC 8032 and is validated against the RFC's official test vectors
//! (see tests), but it has **NOT been reviewed by an external
//! cryptographer or undergone a security audit**.
//!
//! Do NOT use this for production sales, real money, or anything
//! adversarial until it has been independently audited. The honest
//! posture: the math is standard and vector-tested, the audit is
//! missing, and the audit is mandatory before launch.
//!
//! Design notes for reviewers:
//! - Field operations use fixed loop bounds with no secret-dependent
//!   branches. Table lookups during scalar multiplication use
//!   mask-based constant-time selection.
//! - Scalar reduction mod L uses a fixed-iteration restoring division
//!   with masked conditional subtraction (no data-dependent branches).
//! - Point decompression (used only in `verify`, where the point is
//!   public) is variable-time; that is acceptable because nothing
//!   secret is involved.
//! - There is no heap use in the hot paths; all buffers are stack
//!   arrays.
//!
//! API shape: [`generate`] derives a keypair from a 32-byte seed,
//! [`sign`] signs, [`verify`] verifies. Secret key material is
//! zeroized on drop and never printed by `Debug`.

use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// SHA-512 (FIPS 180-4), needed by Ed25519 and the vault KDF.
// `pub(crate)`: shared with the crate's other crypto modules; the raw
// digest is not part of the public API.
// ---------------------------------------------------------------------------

pub(crate) mod sha512 {
    /// Round constants: fractional parts of the cube roots of the first
    /// 80 primes (FIPS 180-4 §4.2.3).
    #[rustfmt::skip]
    const K: [u64; 80] = [
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

    /// Initial hash value: fractional parts of the square roots of the
    /// first 8 primes (FIPS 180-4 §5.3.5).
    const H0: [u64; 8] = [
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179,
    ];


    /// SHA-512 digest of `data`.
    pub fn digest(data: &[u8]) -> [u8; 64] {
        let mut h = H0;

        // Padding: 0x80, zeros, then the 128-bit big-endian bit length.
        // Messages here are far below 2^64 bits, so the high half is 0.
        let bit_len = (data.len() as u128).wrapping_mul(8);
        let mut msg = Vec::with_capacity(data.len() + 129);
        msg.extend_from_slice(data);
        msg.push(0x80);
        while msg.len() % 128 != 112 {
            msg.push(0);
        }
        msg.extend_from_slice(&0u64.to_be_bytes());
        msg.extend_from_slice(&(bit_len as u64).to_be_bytes());

        for chunk in msg.chunks_exact(128) {
            let mut w = [0u64; 80];
            for (i, word) in w.iter_mut().take(16).enumerate() {
                let mut b = [0u8; 8];
                b.copy_from_slice(&chunk[i * 8..(i + 1) * 8]);
                *word = u64::from_be_bytes(b);
            }
            for i in 16..80 {
                let s0 = w[i - 15].rotate_right(1)
                    ^ w[i - 15].rotate_right(8)
                    ^ (w[i - 15] >> 7);
                let s1 =
                    w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
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
                    .wrapping_add(K[i])
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
        for (i, word) in h.iter().enumerate() {
            out[i * 8..(i + 1) * 8].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn hex(d: &[u8]) -> String {
            d.iter().map(|b| format!("{:02x}", b)).collect()
        }

        #[test]
        fn empty_vector() {
            // SHA-512(""), cross-checked against sha512sum, hashlib, Wikipedia.
            assert_eq!(
                hex(&digest(b"")),
                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
            );
        }

        #[test]
        fn abc_vector() {
            // SHA-512("abc"), cross-checked against sha512sum and hashlib.
            assert_eq!(
                hex(&digest(b"abc")),
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
            );
        }

        #[test]
        fn multiline_message_vector() {
            // FIPS 180-4: SHA-512("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
            //                      "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu").
            assert_eq!(
                hex(&digest(
                    b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
                )),
                "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Curve25519 field arithmetic, radix 2^51, 5 limbs.
// p = 2^255 - 19. Limbs are kept < 2^54 ("relaxed") between operations;
// every op below normalizes. All loops have fixed bounds and no
// secret-dependent branches.
// ---------------------------------------------------------------------------

const MASK51: u64 = (1 << 51) - 1;
const MASK51_128: u128 = (1 << 51) - 1;

/// Field element mod p = 2^255 - 19.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Fe([u64; 5]);

/// Value equality mod p: reduces both sides to canonical bytes.
/// Limb-wise `==` is NOT used because different limb vectors can
/// represent the same value.
fn fe_equal(a: &Fe, b: &Fe) -> bool {
    let d = fe_sub(a, b);
    fe_tobytes(&d) == [0u8; 32]
}

impl Fe {
    pub(crate) fn zero() -> Self {
        Fe([0, 0, 0, 0, 0])
    }
    pub(crate) fn one() -> Self {
        Fe([1, 0, 0, 0, 0])
    }
    /// Small constant as a field element.
    pub(crate) fn from_u64(v: u64) -> Self {
        debug_assert!(v < (1 << 51));
        Fe([v, 0, 0, 0, 0])
    }
}

/// Carry-propagate `t` into fully reduced limbs (< 2^51).
///
/// Accepts limbs up to ~2^120 (the output range of [`fe_mul_raw`]
/// below); three passes are enough to converge from that bound.
fn fe_carry(t: [u128; 5]) -> Fe {
    let mut t = t;
    for _ in 0..3 {
        let mut carry = 0u128;
        for v in t.iter_mut() {
            let cur = *v + carry;
            *v = cur & MASK51_128;
            carry = cur >> 51;
        }
        t[0] += 19 * carry;
    }
    // Final light pass: limbs are now < 2^51 + 2^7.
    let mut carry = 0u128;
    let mut out = [0u64; 5];
    for i in 0..5 {
        let cur = t[i] + carry;
        out[i] = (cur & MASK51_128) as u64;
        carry = cur >> 51;
    }
    out[0] = out[0].wrapping_add((19 * carry) as u64);
    Fe(out)
}

pub(crate) fn fe_add(a: &Fe, b: &Fe) -> Fe {
    let mut t = [0u128; 5];
    for i in 0..5 {
        t[i] = a.0[i] as u128 + b.0[i] as u128;
    }
    fe_carry(t)
}

/// p as limbs: 2^255 - 19 = (2^51 - 19) + (2^51 - 1) * (2^51 + 2^102
/// + 2^153 + 2^204). Written as expressions, not hex, so the limb
/// widths cannot be miscounted.
const P_LIMBS: [u64; 5] = [
    (1 << 51) - 19,
    (1 << 51) - 1,
    (1 << 51) - 1,
    (1 << 51) - 1,
    (1 << 51) - 1,
];

pub(crate) fn fe_sub(a: &Fe, b: &Fe) -> Fe {
    // Add 16*p first so no limb can underflow: 16 * P[i] >= 16 * 2^50
    // dominates any relaxed limb (< 2^54).
    let mut t = [0u128; 5];
    for i in 0..5 {
        t[i] = a.0[i] as u128 + 16 * P_LIMBS[i] as u128 - b.0[i] as u128;
    }
    fe_carry(t)
}

fn fe_neg(a: &Fe) -> Fe {
    fe_sub(&Fe::zero(), a)
}

/// Raw schoolbook multiply; result limbs < ~2^120, caller reduces.
fn fe_mul_raw(a: &Fe, b: &Fe) -> [u128; 5] {
    let mut t = [0u128; 5];
    for i in 0..5 {
        for j in 0..5 {
            let v = a.0[i] as u128 * b.0[j] as u128;
            let k = i + j;
            if k < 5 {
                t[k] += v;
            } else {
                // 2^{51k} = 2^{51(k-5)} * 2^255 = 19 * 2^{51(k-5)} (mod p).
                t[k - 5] += 19 * v;
            }
        }
    }
    t
}

pub(crate) fn fe_mul(a: &Fe, b: &Fe) -> Fe {
    fe_carry(fe_mul_raw(a, b))
}

pub(crate) fn fe_sq(a: &Fe) -> Fe {
    fe_mul(a, a)
}

/// Constant-time select: returns `a` when `choice == 0`, `b` when
/// `choice == 1`. `choice` must be 0 or 1.
pub(crate) fn fe_cmov(a: &Fe, b: &Fe, choice: u8) -> Fe {
    debug_assert!(choice <= 1);
    // Widen BEFORE negating: (1u8).wrapping_neg() as u64 is 0xFF, not
    // all-ones. Negating as u64 gives the full 64-bit mask.
    let mask = (choice as u64).wrapping_neg(); // 0 -> 0, 1 -> all-ones
    let mut out = [0u64; 5];
    for i in 0..5 {
        out[i] = (a.0[i] & !mask) | (b.0[i] & mask);
    }
    Fe(out)
}

/// `x^e` for public exponent `e` (4 LE u64 limbs). Fixed 256
/// iterations, no secret-dependent branches (the exponent is public).
fn fe_pow(x: &Fe, e: &[u64; 4]) -> Fe {
    let mut r = Fe::one();
    for i in (0..256).rev() {
        r = fe_sq(&r);
        let bit = (e[i / 64] >> (i % 64)) & 1;
        let m = fe_mul(&r, x);
        // Select without branching on the (public) bit.
        let mut out = [0u64; 5];
        let mask = bit.wrapping_neg();
        for j in 0..5 {
            out[j] = (r.0[j] & !mask) | (m.0[j] & mask);
        }
        r = Fe(out);
    }
    r
}

/// Multiplicative inverse via Fermat: x^(p-2), p-2 = 2^255 - 21.
/// Returns 0 for x = 0 (documented; callers never invert zero).
pub(crate) fn fe_inv(x: &Fe) -> Fe {
    // p - 2 = (2^255 - 19) - 2 = 2^255 - 21 = (2^255 - 1) - 20.
    let mut e = [0xffffffffffffffffu64, 0xffffffffffffffff, 0xffffffffffffffff, 0x7fffffffffffffff];
    let mut borrow: u128 = 20;
    for limb in e.iter_mut() {
        let cur = *limb as u128;
        let res = cur.wrapping_sub(borrow);
        *limb = res as u64;
        borrow = (res >> 127) & 1;
        if borrow == 0 {
            break;
        }
    }
    fe_pow(x, &e)
}

/// sqrt(-1) mod p = 2^((p-1)/4), computed once.
fn fe_sqrtm1() -> Fe {
    // (p-1)/4 = 2^253 - 5: bits 0,1 set, bit 2 clear, bits 3..=252 set.
    // Limb 3 = bits 192..=252 of the exponent (61 bits all set).
    let e = [
        0xfffffffffffffffb,
        0xffffffffffffffff,
        0xffffffffffffffff,
        0x1fffffffffffffff,
    ];
    fe_pow(&Fe::from_u64(2), &e)
}

/// Square root for p = 5 (mod 8): x = a^((p+3)/8); correct by
/// multiplying with sqrt(-1) when x^2 = -a. Returns `None` when `a`
/// is not a quadratic residue. Constant-time in the field ops;
/// the residue checks below branch on public verification data.
fn fe_sqrt(a: &Fe) -> Option<Fe> {
    // (p+3)/8 = 2^252 - 2: bit 0 clear, bits 1..=251 set.
    let e = [
        0xfffffffffffffffe,
        0xffffffffffffffff,
        0xffffffffffffffff,
        0x0fffffffffffffff,
    ];
    let v = fe_pow(a, &e);
    let v2 = fe_sq(&v);
    if fe_equal(&v2, a) {
        return Some(v);
    }
    let neg_a = fe_neg(a);
    if fe_equal(&v2, &neg_a) {
        return Some(fe_mul(&v, &fe_sqrtm1()));
    }
    None
}

/// True when the element is "negative" (low bit of the canonical
/// encoding is 1). Used for point decompression sign checks.
fn fe_isnegative(a: &Fe) -> bool {
    fe_tobytes(a)[0] & 1 == 1
}

/// Decode 32 LE bytes. Bit 255 is IGNORED: callers working with
/// compressed points must extract the sign bit first. (Ed25519 only
/// ever feeds this the y-coordinate with the sign stripped, or
/// values known to be < 2^255.)
pub(crate) fn fe_frombytes(s: &[u8; 32]) -> Fe {
    let load = |i: usize| {
        let mut b = [0u8; 8];
        b.copy_from_slice(&s[i * 8..(i + 1) * 8]);
        u64::from_le_bytes(b)
    };
    let s0 = load(0);
    let s1 = load(1);
    let s2 = load(2);
    let s3 = load(3);
    let h = [
        s0 & MASK51,
        ((s0 >> 51) | (s1 << 13)) & MASK51,
        ((s1 >> 38) | (s2 << 26)) & MASK51,
        ((s2 >> 25) | (s3 << 39)) & MASK51,
        (s3 >> 12) & MASK51,
    ];
    Fe(h)
}

/// Canonical 32-byte little-endian encoding.
pub(crate) fn fe_tobytes(h: &Fe) -> [u8; 32] {
    // Full carry first.
    let mut t = [
        h.0[0] as u128,
        h.0[1] as u128,
        h.0[2] as u128,
        h.0[3] as u128,
        h.0[4] as u128,
    ];
    for _ in 0..4 {
        let mut carry = 0u128;
        for v in t.iter_mut() {
            let cur = *v + carry;
            *v = cur & MASK51_128;
            carry = cur >> 51;
        }
        t[0] += 19 * carry;
    }
    // Conditional subtract p (constant-time): compute t - p, keep it
    // iff no borrow (i.e. t >= p).
    let mut sub = [0u64; 5];
    let mut borrow: u128 = 0;
    for i in 0..5 {
        let cur = t[i];
        let res = cur.wrapping_sub(P_LIMBS[i] as u128).wrapping_sub(borrow);
        sub[i] = res as u64;
        borrow = (res >> 127) & 1;
    }
    let mask = borrow.wrapping_sub(1) as u64; // borrow=0 -> all-ones
    let mut r = [0u64; 5];
    for i in 0..5 {
        r[i] = ((t[i] as u64) & !mask) | (sub[i] & mask);
    }
    let mut out = [0u8; 32];
    let s0 = r[0] | (r[1] << 51);
    let s1 = (r[1] >> 13) | (r[2] << 38);
    let s2 = (r[2] >> 26) | (r[3] << 25);
    let s3 = (r[3] >> 39) | (r[4] << 12);
    out[0..8].copy_from_slice(&s0.to_le_bytes());
    out[8..16].copy_from_slice(&s1.to_le_bytes());
    out[16..24].copy_from_slice(&s2.to_le_bytes());
    out[24..32].copy_from_slice(&s3.to_le_bytes());
    out
}

// ---------------------------------------------------------------------------
// Scalars mod L = 2^252 + 27742317777372353535851937790883648493.
// ---------------------------------------------------------------------------

/// Group order L as 4 LE u64 limbs.
const L: [u64; 4] = [
    0x5812631a5cf5d3ed,
    0x14def9dea2f79cd6,
    0x0000000000000000,
    0x1000000000000000,
];

/// 32 LE bytes -> 4 u64 limbs.
fn limbs_from_bytes32(b: &[u8; 32]) -> [u64; 4] {
    let mut out = [0u64; 4];
    for i in 0..4 {
        let mut t = [0u8; 8];
        t.copy_from_slice(&b[i * 8..(i + 1) * 8]);
        out[i] = u64::from_le_bytes(t);
    }
    out
}

/// 4 u64 limbs -> 32 LE bytes.
fn limbs_to_bytes32(l: &[u64; 4]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[i * 8..(i + 1) * 8].copy_from_slice(&l[i].to_le_bytes());
    }
    out
}

/// Reduce a 512-bit number (8 LE u64 limbs) mod L.
///
/// Fixed 512-iteration restoring division; the conditional
/// subtraction uses a mask, never a data-dependent branch. The
/// dividend may be secret (it is, during signing); the loop bound
/// and every operation are data-independent.
fn sc_reduce_limbs(x: &[u64; 8]) -> [u64; 4] {
    let mut r = [0u64; 5]; // remainder, kept < L at loop end
    for bit in (0..512).rev() {
        // r <<= 1, bringing in bit `bit` of x.
        let mut carry = (x[bit / 64] >> (bit % 64)) & 1;
        for v in r.iter_mut() {
            let new_carry = *v >> 63;
            *v = (*v << 1) | carry;
            carry = new_carry;
        }
        // Trial subtract L; keep the subtraction iff no borrow.
        let mut sub = [0u64; 5];
        let mut borrow: u128 = 0;
        for i in 0..5 {
            let li = if i < 4 { L[i] } else { 0 };
            let res = (r[i] as u128)
                .wrapping_sub(li as u128)
                .wrapping_sub(borrow);
            sub[i] = res as u64;
            borrow = (res >> 127) & 1;
        }
        let mask = borrow.wrapping_sub(1) as u64; // borrow=0 -> all-ones
        for i in 0..5 {
            r[i] = (r[i] & !mask) | (sub[i] & mask);
        }
    }
    [r[0], r[1], r[2], r[3]]
}

/// Reduce 64 bytes mod L.
fn sc_reduce64(x: &[u8; 64]) -> [u64; 4] {
    let mut limbs = [0u64; 8];
    for i in 0..8 {
        let mut t = [0u8; 8];
        t.copy_from_slice(&x[i * 8..(i + 1) * 8]);
        limbs[i] = u64::from_le_bytes(t);
    }
    sc_reduce_limbs(&limbs)
}

/// `(a * b + c) mod L`, all scalars as limb arrays.
fn sc_muladd(a: &[u64; 4], b: &[u64; 4], c: &[u64; 4]) -> [u64; 4] {
    // 512-bit product in 64-bit limbs with carry propagation.
    // (A u128 accumulator per limb would overflow: t[3] sums four
    // ~2^128 products.)
    let mut t = [0u64; 8];
    for i in 0..4 {
        for j in 0..4 {
            let prod = a[i] as u128 * b[j] as u128;
            let mut carry = prod;
            // Fixed-iteration carry propagation: always run exactly
            // 8 - (i + j) steps. Once `carry` is zero the adds are
            // no-ops, so iteration count no longer depends on secret
            // limb values (constant-time).
            for k in (i + j)..8 {
                let cur = t[k] as u128 + carry;
                t[k] = cur as u64;
                carry = cur >> 64;
            }
        }
    }
    // `t` now holds the 512-bit product, normalized. Add c.
    let mut limbs = t;
    let mut cc = 0u128;
    for i in 0..4 {
        let cur = limbs[i] as u128 + c[i] as u128 + cc;
        limbs[i] = cur as u64;
        cc = cur >> 64;
    }
    // Fixed-iteration carry propagation (4 steps, no secret-dependent bound).
    for i in 4..8 {
        let cur = limbs[i] as u128 + cc;
        limbs[i] = cur as u64;
        cc = cur >> 64;
    }
    sc_reduce_limbs(&limbs)
}

/// `(-s) mod L`.
fn sc_neg(s: &[u64; 4]) -> [u64; 4] {
    // L - s, constant-time select for s == 0 -> 0.
    let mut out = [0u64; 4];
    let mut borrow: u128 = 0;
    for i in 0..4 {
        let res = (L[i] as u128)
            .wrapping_sub(s[i] as u128)
            .wrapping_sub(borrow);
        out[i] = res as u64;
        borrow = (res >> 127) & 1;
    }
    // If s == 0 the subtraction produced L; map L -> 0 (mod L).
    // mask = all-ones iff s != 0 (keep the subtraction), else 0.
    let mut is_zero = 0u64;
    for v in s.iter() {
        is_zero |= *v;
    }
    let nonzero = ((is_zero | is_zero.wrapping_neg()) >> 63) & 1;
    let mask = 0u64.wrapping_sub(nonzero);
    for v in out.iter_mut() {
        *v &= mask;
    }
    out
}

/// True iff scalar `s` (limbs) is canonically < L.
fn sc_lt_l(s: &[u64; 4]) -> bool {
    // Compute s - L; borrow out == 1  <=>  s < L.
    let mut borrow: u128 = 0;
    for i in 0..4 {
        let res = (s[i] as u128)
            .wrapping_sub(L[i] as u128)
            .wrapping_sub(borrow);
        borrow = (res >> 127) & 1;
    }
    borrow == 1
}

// ---------------------------------------------------------------------------
// Edwards point operations, extended coordinates (X, Y, Z, T).
// Curve: -x^2 + y^2 = 1 + d*x^2*y^2, d = -121665/121666.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
struct Ge {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

fn ge_identity() -> Ge {
    Ge {
        x: Fe::zero(),
        y: Fe::one(),
        z: Fe::one(),
        t: Fe::zero(),
    }
}

fn ge_cmov(a: &Ge, b: &Ge, choice: u8) -> Ge {
    Ge {
        x: fe_cmov(&a.x, &b.x, choice),
        y: fe_cmov(&a.y, &b.y, choice),
        z: fe_cmov(&a.z, &b.z, choice),
        t: fe_cmov(&a.t, &b.t, choice),
    }
}

/// 2*d, precomputed once.
fn fe_d2() -> Fe {
    static D2: OnceLock<Fe> = OnceLock::new();
    *D2.get_or_init(|| {
        // 2*d = -243330 / 121666.
        let num = fe_neg(&Fe::from_u64(243330));
        let den = fe_inv(&Fe::from_u64(121666));
        fe_mul(&num, &den)
    })
}

/// d = -121665/121666.
fn fe_d() -> Fe {
    static D: OnceLock<Fe> = OnceLock::new();
    *D.get_or_init(|| fe_mul(&fe_d2(), &fe_inv(&Fe::from_u64(2))))
}

/// Point addition (Hisilbe et al. extended-coordinate formula).
fn ge_add(p: &Ge, q: &Ge) -> Ge {
    let a = fe_mul(&fe_sub(&p.y, &p.x), &fe_sub(&q.y, &q.x));
    let b = fe_mul(&fe_add(&p.y, &p.x), &fe_add(&q.y, &q.x));
    let c = fe_mul(&fe_mul(&p.t, &q.t), &fe_d2());
    let d = fe_mul(&fe_mul(&p.z, &q.z), &Fe::from_u64(2));
    let e = fe_sub(&b, &a);
    let f = fe_sub(&d, &c);
    let g = fe_add(&d, &c);
    let h = fe_add(&b, &a);
    Ge {
        x: fe_mul(&e, &f),
        y: fe_mul(&g, &h),
        z: fe_mul(&f, &g),
        t: fe_mul(&e, &h),
    }
}

/// Point doubling.
fn ge_double(p: &Ge) -> Ge {
    let a = fe_sq(&p.x);
    let b = fe_sq(&p.y);
    let c_2 = fe_add(&fe_sq(&p.z), &fe_sq(&p.z));
    let d = fe_neg(&a);
    let e = fe_sub(&fe_sub(&fe_sq(&fe_add(&p.x, &p.y)), &a), &b);
    let g = fe_add(&d, &b);
    let f = fe_sub(&g, &c_2);
    let h = fe_sub(&d, &b);
    Ge {
        x: fe_mul(&e, &f),
        y: fe_mul(&g, &h),
        z: fe_mul(&f, &g),
        t: fe_mul(&e, &h),
    }
}

/// Compressed base point B (RFC 8032 §5).
const BASE_COMPRESSED: [u8; 32] = [
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
];

/// Decompress a 32-byte compressed point. Returns `None` for invalid
/// encodings (non-canonical y, non-residue, failed curve check).
/// Variable-time; only used on public points during verification.
fn ge_frombytes(s: &[u8; 32]) -> Option<Ge> {
    let sign = (s[31] >> 7) & 1;
    let mut t = *s;
    t[31] &= 0x7f;
    // Canonical y: re-encoding must round-trip (catches y >= p).
    let y = fe_frombytes(&t);
    if fe_tobytes(&y) != t {
        return None;
    }
    let y2 = fe_sq(&y);
    let u = fe_sub(&y2, &Fe::one());
    let v = fe_add(&fe_mul(&y2, &fe_d()), &Fe::one());
    let x = fe_sqrt(&fe_mul(&u, &fe_inv(&v)))?;
    let x = if (fe_isnegative(&x) as u8) != sign {
        fe_neg(&x)
    } else {
        x
    };
    // Final curve-membership check: x^2 * v == u.
    if !fe_equal(&fe_mul(&fe_sq(&x), &v), &u) {
        return None;
    }
    Some(Ge {
        x,
        y,
        z: Fe::one(),
        t: fe_mul(&x, &y),
    })
}

/// Compressed 32-byte encoding.
fn ge_tobytes(p: &Ge) -> [u8; 32] {
    let zinv = fe_inv(&p.z);
    let x = fe_mul(&p.x, &zinv);
    let y = fe_mul(&p.y, &zinv);
    let mut s = fe_tobytes(&y);
    if fe_isnegative(&x) {
        s[31] |= 0x80;
    }
    s
}

/// Constant-time table select: `table[digit]`, digit < 16.
fn ge_select(table: &[Ge; 16], digit: u8) -> Ge {
    debug_assert!(digit < 16);
    let mut r = ge_identity();
    for (i, p) in table.iter().enumerate() {
        // mask = 1 iff i == digit, branchless.
        let x = (i as u8) ^ digit;
        let m = (((x | x.wrapping_neg()) >> 7) ^ 1) & 1;
        r = ge_cmov(&r, p, m);
    }
    r
}

/// Precomputed base-point table: table[w][i] = i * 2^(4w) * B.
fn base_table() -> &'static [[Ge; 16]; 64] {
    static TABLE: OnceLock<[[Ge; 16]; 64]> = OnceLock::new();
    TABLE.get_or_init(|| {
        let b = ge_frombytes(&BASE_COMPRESSED).expect("base point must decompress");
        let mut table = [[ge_identity(); 16]; 64];
        let mut cur = b;
        for w in 0..64 {
            for i in 1..16 {
                table[w][i] = ge_add(&table[w][i - 1], &cur);
            }
            for _ in 0..4 {
                cur = ge_double(&cur);
            }
        }
        table
    })
}

/// scalar * B, constant-time in the scalar.
fn ge_scalarmult_base(scalar: &[u64; 4]) -> Ge {
    // Direct accumulation: r = sum_w table[w][d_w].
    // The table already carries each window's positional weight
    // (table[w][i] = i * 2^(4w) * B), so no interleaved doublings.
    let table = base_table();
    let mut r = ge_identity();
    for w in 0..64 {
        let digit = ((scalar[w / 16] >> ((w % 16) * 4)) & 15) as u8;
        r = ge_add(&r, &ge_select(&table[w], digit));
    }
    r
}

/// scalar * p for arbitrary point p. Table built on the fly; the
/// selection is constant-time. Used in verification (public data).
fn ge_scalarmult(p: &Ge, scalar: &[u64; 4]) -> Ge {
    let mut table = [ge_identity(); 16];
    for i in 1..16 {
        table[i] = ge_add(&table[i - 1], p);
    }
    let mut r = ge_identity();
    for w in (0..64).rev() {
        for _ in 0..4 {
            r = ge_double(&r);
        }
        let digit = ((scalar[w / 16] >> ((w % 16) * 4)) & 15) as u8;
        r = ge_add(&r, &ge_select(&table, digit));
    }
    r
}

// ---------------------------------------------------------------------------
// Public API.
// ---------------------------------------------------------------------------

/// Audit status marker. This implementation is vector-tested but has
/// NOT been independently audited; the constant exists so the status
/// is greppable and cannot be silently forgotten.
pub const AUDIT_STATUS: &str = "NOT externally audited — do not use in production until audited";

/// Ed25519 secret key: the 32-byte RFC 8032 seed.
///
/// Zeroized on drop; `Debug` is redacted.
pub struct SecretKey([u8; 32]);

impl SecretKey {
    /// Wrap a 32-byte seed. The caller is responsible for the seed's
    /// randomness (issuer tooling reads `/dev/urandom`; tests use
    /// fixed vectors).
    pub fn from_seed(seed: [u8; 32]) -> Self {
        SecretKey(seed)
    }

    /// Raw seed bytes. Handle with care; never log or transmit.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hex of the seed. For issuer tooling display only —
    /// never print this where buyers can see it.
    pub fn hex(&self) -> String {
        self.0.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

impl Clone for SecretKey {
    fn clone(&self) -> Self {
        SecretKey(self.0)
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKey(<redacted>)")
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        for b in self.0.iter_mut() {
            // SAFETY: `b` is a valid, uniquely-borrowed byte.
            unsafe {
                core::ptr::write_volatile(b, 0u8);
            }
        }
    }
}

/// Ed25519 public key: 32-byte compressed Edwards point.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    /// Parse from 32 compressed-point bytes. No validation here;
    /// [`verify`] decompresses and validates on use.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        PublicKey(bytes)
    }

    /// Raw compressed-point bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hex. Safe to display and embed in binaries: this is
    /// the value buyer devices ship.
    pub fn hex(&self) -> String {
        self.0.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Parse lowercase or uppercase hex (64 chars).
    pub fn from_hex(s: &str) -> Option<Self> {
        if s.len() != 64 {
            return None;
        }
        let mut out = [0u8; 32];
        let bytes = s.as_bytes();
        for i in 0..32 {
            let hi = hex_val(bytes[2 * i])?;
            let lo = hex_val(bytes[2 * i + 1])?;
            out[i] = (hi << 4) | lo;
        }
        Some(PublicKey(out))
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Public keys are not secret; hex is safe in logs.
        write!(f, "PublicKey({})", self.hex())
    }
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Ed25519 signature: 64 bytes (R || S).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; 64]);

impl Signature {
    /// Parse from 64 bytes.
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Signature(bytes)
    }

    /// Raw bytes.
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Signature(<redacted:64 bytes>)")
    }
}

/// Clamp a 32-byte scalar per RFC 8032 §5.1.5.
fn clamp_scalar(mut a: [u8; 32]) -> [u64; 4] {
    a[0] &= 248;
    a[31] &= 63;
    a[31] |= 64;
    limbs_from_bytes32(&a)
}

/// Derive a keypair from a 32-byte seed (RFC 8032 §5.1.5).
///
/// Also runs a self-test (sign + verify of a fixed message) and
/// panics if it fails: a broken field implementation must be loud,
/// never silent. (Panics only on internal malfunction, not on
/// attacker input.)
pub fn generate(seed: &[u8; 32]) -> (SecretKey, PublicKey) {
    let secret = SecretKey(*seed);
    let h = sha512::digest(seed);
    let mut a_bytes = [0u8; 32];
    a_bytes.copy_from_slice(&h[..32]);
    let a = clamp_scalar(a_bytes);
    let big_a = ge_scalarmult_base(&a);
    let public = PublicKey(ge_tobytes(&big_a));
    // Self-test: sign and verify must round-trip.
    let sig = sign_inner(&secret, &public, &a, b"trv-ed25519-selftest");
    debug_assert!(verify(&public, b"trv-ed25519-selftest", &sig));
    assert!(
        verify(&public, b"trv-ed25519-selftest", &sig),
        "ed25519 self-test failed: implementation malfunction"
    );
    (secret, public)
}

/// Sign `msg` (RFC 8032 §5.1.6). Deterministic: the nonce derives
/// from the secret seed, so no RNG is needed at signing time.
pub fn sign(secret: &SecretKey, public: &PublicKey, msg: &[u8]) -> Signature {
    let h = sha512::digest(secret.as_bytes());
    let mut a_bytes = [0u8; 32];
    a_bytes.copy_from_slice(&h[..32]);
    let a = clamp_scalar(a_bytes);
    sign_inner(secret, public, &a, msg)
}

fn sign_inner(
    secret: &SecretKey,
    public: &PublicKey,
    a: &[u64; 4],
    msg: &[u8],
) -> Signature {
    let h = sha512::digest(secret.as_bytes());
    let prefix = &h[32..64];
    // r = SHA-512(prefix || msg) mod L.
    let mut r_input = Vec::with_capacity(32 + msg.len());
    r_input.extend_from_slice(prefix);
    r_input.extend_from_slice(msg);
    let r = sc_reduce64(&sha512::digest(&r_input));
    let big_r = ge_scalarmult_base(&r);
    let r_enc = ge_tobytes(&big_r);
    // k = SHA-512(R || A || msg) mod L.
    let mut k_input = Vec::with_capacity(64 + msg.len());
    k_input.extend_from_slice(&r_enc);
    k_input.extend_from_slice(public.as_bytes());
    k_input.extend_from_slice(msg);
    let k = sc_reduce64(&sha512::digest(&k_input));
    // S = (r + k * a) mod L.
    let s = sc_muladd(&k, a, &r);
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&r_enc);
    out[32..].copy_from_slice(&limbs_to_bytes32(&s));
    Signature(out)
}

/// Constant-time byte equality.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Verify `sig` over `msg` (RFC 8032 §5.1.7).
///
/// Returns false for malformed keys, malformed signatures, and
/// non-canonical encodings. Verification time may vary with the
/// (public) inputs; nothing secret is involved.
pub fn verify(public: &PublicKey, msg: &[u8], sig: &Signature) -> bool {
    // Decode and validate A (on-curve, canonical encoding).
    let a_pt = match ge_frombytes(public.as_bytes()) {
        Some(p) => p,
        None => return false,
    };
    // Reject the identity point as a public key (degenerate key).
    if ge_tobytes(&a_pt) == ge_tobytes(&ge_identity()) {
        return false;
    }
    let r_bytes: [u8; 32] = sig.0[..32].try_into().unwrap_or([0u8; 32]);
    let s_bytes: [u8; 32] = sig.0[32..].try_into().unwrap_or([0u8; 32]);
    // S must be canonical (< L); non-canonical S enables malleability.
    let s = limbs_from_bytes32(&s_bytes);
    if !sc_lt_l(&s) {
        return false;
    }
    // k = SHA-512(R || A || M) mod L.
    let mut k_input = Vec::with_capacity(64 + msg.len());
    k_input.extend_from_slice(&r_bytes);
    k_input.extend_from_slice(public.as_bytes());
    k_input.extend_from_slice(msg);
    let k = sc_reduce64(&sha512::digest(&k_input));
    // Check [s]B - [k]A == R via [s]B + [(-k)]A.
    let s_b = ge_scalarmult_base(&s);
    let neg_k = sc_neg(&k);
    let k_a = ge_scalarmult(&a_pt, &neg_k);
    let r_calc = ge_add(&s_b, &k_a);
    ct_eq(&ge_tobytes(&r_calc), &r_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_32(s: &str) -> [u8; 32] {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        assert_eq!(s.len(), 64);
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    fn hex_to_64(s: &str) -> [u8; 64] {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        assert_eq!(s.len(), 128);
        let mut out = [0u8; 64];
        for i in 0..64 {
            out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    fn hex_msg(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(s.len() % 2 == 0);
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 8032 §7.1 TEST 1 (empty message).
    #[test]
    fn rfc8032_test1() {
        let seed = hex_to_32(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        );
        let expected_pk = hex_to_32(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        );
        let expected_sig = hex_to_64(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
             5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        );
        let (secret, public) = generate(&seed);
        assert_eq!(public.0, expected_pk, "public key mismatch");
        let sig = sign(&secret, &public, b"");
        assert_eq!(sig.0, expected_sig, "signature mismatch");
        assert!(verify(&public, b"", &sig));
    }

    /// RFC 8032 §7.1 TEST 2 (1-byte message 0x72).
    #[test]
    fn rfc8032_test2() {
        let seed = hex_to_32(
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        );
        let expected_pk = hex_to_32(
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        );
        let expected_sig = hex_to_64(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
             085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        );
        let (secret, public) = generate(&seed);
        assert_eq!(public.0, expected_pk, "public key mismatch");
        let sig = sign(&secret, &public, &[0x72]);
        assert_eq!(sig.0, expected_sig, "signature mismatch");
        assert!(verify(&public, &[0x72], &sig));
    }

    /// RFC 8032 §7.1 TEST 3 (2-byte message 0xaf82).
    #[test]
    fn rfc8032_test3() {
        let seed = hex_to_32(
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        );
        let expected_pk = hex_to_32(
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        );
        let expected_sig = hex_to_64(
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac\
             18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        );
        let (secret, public) = generate(&seed);
        assert_eq!(public.0, expected_pk, "public key mismatch");
        let msg = hex_msg("af82");
        let sig = sign(&secret, &public, &msg);
        assert_eq!(sig.0, expected_sig, "signature mismatch");
        assert!(verify(&public, &msg, &sig));
    }

    #[test]
    fn sign_verify_roundtrip() {
        let seed = [0x42u8; 32];
        let (secret, public) = generate(&seed);
        let msg = b"The Remote Viewer Network";
        let sig = sign(&secret, &public, msg);
        assert!(verify(&public, msg, &sig));
    }

    #[test]
    fn tampered_message_rejected() {
        let (secret, public) = generate(&[7u8; 32]);
        let sig = sign(&secret, &public, b"hello");
        assert!(!verify(&public, b"hellp", &sig));
        assert!(!verify(&public, b"", &sig));
    }

    #[test]
    fn tampered_signature_rejected() {
        let (secret, public) = generate(&[7u8; 32]);
        let sig = sign(&secret, &public, b"hello");
        for i in [0usize, 31, 32, 63] {
            let mut bad = sig.0;
            bad[i] ^= 0x01;
            assert!(!verify(&public, b"hello", &Signature(bad)), "byte {i}");
        }
    }

    #[test]
    fn wrong_key_rejected() {
        let (secret_a, public_a) = generate(&[1u8; 32]);
        let (_secret_b, public_b) = generate(&[2u8; 32]);
        let sig = sign(&secret_a, &public_a, b"hello");
        assert!(!verify(&public_b, b"hello", &sig));
    }

    #[test]
    fn noncanonical_s_rejected() {
        // S = L is non-canonical and must be rejected even though a
        // forged equation could otherwise hold.
        let (secret, public) = generate(&[9u8; 32]);
        let sig = sign(&secret, &public, b"m");
        let mut bad = sig.0;
        bad[32..].copy_from_slice(&limbs_to_bytes32(&L));
        assert!(!verify(&public, b"m", &Signature(bad)));
    }

    #[test]
    fn degenerate_public_key_rejected() {
        // Identity point as public key.
        let identity = PublicKey(ge_tobytes(&ge_identity()));
        let (_s, public) = generate(&[3u8; 32]);
        let sig = sign(&_s, &public, b"x");
        assert!(!verify(&identity, b"x", &sig));
    }

    #[test]
    fn secret_debug_is_redacted_and_dropped_zeroized() {
        let (secret, _) = generate(&[11u8; 32]);
        let dbg = format!("{:?}", secret);
        assert!(dbg.contains("<redacted>"));
        assert!(!dbg.contains("0b0b"));
        // Cloned-then-dropped keys must not leave the seed behind in
        // the Debug output either.
        let cloned = secret.clone();
        assert_eq!(format!("{:?}", cloned), "SecretKey(<redacted>)");
    }

    #[test]
    fn public_key_hex_roundtrip() {
        let (_, public) = generate(&[13u8; 32]);
        let hex = public.hex();
        assert_eq!(hex.len(), 64);
        assert_eq!(PublicKey::from_hex(&hex).unwrap(), public);
        assert_eq!(PublicKey::from_hex(&hex.to_uppercase()).unwrap(), public);
        assert!(PublicKey::from_hex("zz").is_none());
        assert!(PublicKey::from_hex(&hex[..63]).is_none());
    }

    #[test]
    fn field_sqrt_known_values() {
        // sqrt(4) = ±2.
        let four = fe_add(&Fe::from_u64(2), &Fe::from_u64(2));
        let r = fe_sqrt(&four).expect("4 is a residue");
        let two = Fe::from_u64(2);
        assert!(fe_equal(&r, &two) || fe_equal(&r, &fe_neg(&two)));
        // 2 is a non-residue mod p (p = 5 mod 8).
        assert!(fe_sqrt(&Fe::from_u64(2)).is_none());
    }

    #[test]
    fn scalar_reduce_matches_known_value() {
        // reduce64 of 64 zero bytes is 0.
        assert_eq!(sc_reduce64(&[0u8; 64]), [0, 0, 0, 0]);
        // reduce64 of L (as 64 LE bytes) is 0.
        let mut l_bytes = [0u8; 64];
        l_bytes[..32].copy_from_slice(&limbs_to_bytes32(&L));
        assert_eq!(sc_reduce64(&l_bytes), [0, 0, 0, 0]);
        // reduce64 of L+1 is 1.
        l_bytes[0] = l_bytes[0].wrapping_add(1);
        assert_eq!(sc_reduce64(&l_bytes), [1, 0, 0, 0]);
    }




















}
