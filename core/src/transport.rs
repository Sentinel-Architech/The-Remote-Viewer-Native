//! Encrypted node-to-node transport.
//!
//! Pure Rust, std-only. Ephemeral X25519 (RFC 7748) key exchange over
//! the Curve25519 field arithmetic shared with
//! [`crate::crypto::ed25519`] (no duplicated field code), HKDF-style
//! session-key derivation from HMAC-SHA512, and ChaCha20-Poly1305
//! (RFC 8439) encrypted frames with sequence-bound nonces, a replay
//! window, and direction-bound authentication.
//!
//! NOT externally audited — like the rest of `trv_core::crypto`, this
//! module is implemented from the RFCs and cross-checked against an
//! independent implementation (a from-scratch Python Montgomery ladder
//! that agrees on the RFC 7748 test vector), but it has not had an
//! independent cryptographic audit. Do not rely on it for production
//! secrets until that audit happens.
//!
//! ## Handshake (ephemeral-ephemeral, no static keys)
//!
//! ```text
//! initiator -> responder:  32-byte ephemeral public key (hello)
//! responder -> initiator:  32-byte ephemeral public key (response)
//! ```
//!
//! Both sides compute `shared = X25519(eph_secret, peer_eph_public)`
//! and derive identical session keys via HKDF-SHA512 over a
//! transcript-bound info string (`b"TRV-TRANSPORT-v1" || e_init ||
//! e_resp`). An all-zero peer key or an all-zero shared secret fails
//! the handshake instead of producing a weak channel.
//!
//! ## Channel
//!
//! Each direction gets its own 32-byte key, so a frame sealed for one
//! direction can never be reflected into the other (the AAD also binds
//! the direction label). Nonces are 96-bit: a 4-byte per-session
//! random prefix followed by an 8-byte big-endian sequence counter.
//! The receiver keeps a 64-entry sliding window: replays and frames
//! older than the window are rejected. The transmit counter fails
//! closed at `u64::MAX` rather than wrapping.

use crate::crypto::chacha20poly1305;
use crate::crypto::ed25519::{
    fe_add, fe_cmov, fe_frombytes, fe_inv, fe_mul, fe_sq, fe_sub, fe_tobytes, Fe,
};
use crate::crypto::pbkdf2::hmac_sha512;

/// Errors from the transport layer. All failures are closed: no
/// partial plaintext is ever produced on an error path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    /// The OS CSPRNG (`/dev/urandom`) was unavailable. Fails closed
    /// rather than falling back to weak entropy.
    EntropyUnavailable,
    /// Peer hello was all zeros, or the handshake produced an
    /// all-zero shared secret (low-order/contributory failure).
    BadPeerKey,
    /// Frame is shorter than nonce (12) + tag (16).
    FrameTooShort,
    /// Poly1305 tag mismatch: wrong key, wrong nonce, tampered
    /// frame, or wrong direction. Nothing is decrypted.
    AuthenticationFailed,
    /// Sequence number already seen, or older than the 64-entry
    /// replay window.
    ReplayDetected,
    /// Transmit sequence counter reached `u64::MAX`. Rekey instead
    /// of wrapping.
    SequenceExhausted,
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportError::EntropyUnavailable => {
                f.write_str("OS entropy unavailable; refusing to build a weak channel")
            }
            TransportError::BadPeerKey => f.write_str("bad peer key or degenerate shared secret"),
            TransportError::FrameTooShort => f.write_str("frame too short"),
            TransportError::AuthenticationFailed => {
                f.write_str("frame authentication failed (wrong key or tampered data)")
            }
            TransportError::ReplayDetected => f.write_str("replayed or stale frame rejected"),
            TransportError::SequenceExhausted => {
                f.write_str("sequence counter exhausted; rekey required")
            }
        }
    }
}

impl std::error::Error for TransportError {}

/// Best-effort in-place wipe, matching the codebase's `SecretKey`
/// pattern: `write_volatile` keeps the compiler from eliding it.
fn wipe(bytes: &mut [u8]) {
    for b in bytes.iter_mut() {
        // SAFETY: `b` is a valid, uniquely-borrowed byte.
        unsafe {
            core::ptr::write_volatile(b, 0u8);
        }
    }
}

/// 32 bytes of OS entropy, or [`TransportError::EntropyUnavailable`].
/// No time/PID fallback — a channel built on weak entropy is worse
/// than no channel at all.
fn random32() -> Result<[u8; 32], TransportError> {
    use std::io::Read;
    let mut b = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut b))
        .map_err(|_| TransportError::EntropyUnavailable)?;
    Ok(b)
}

/// X25519 base point: u = 9.
const BASE_POINT: [u8; 32] = {
    let mut b = [0u8; 32];
    b[0] = 9;
    b
};

/// X25519 Diffie-Hellman (RFC 7748 §5).
///
/// Computes `clamp(scalar) * u` on the Montgomery curve, reusing the
/// 5×51-bit field arithmetic from [`crate::crypto::ed25519`] — no
/// duplicated field code. The ladder is constant-time in the field
/// operations (`fe_cmov` selects without branching on secret bits).
fn x25519(scalar: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    // RFC 7748 scalar clamping: clear bits 0,1,2 and 255, set bit 254.
    let mut e = *scalar;
    e[0] &= 248;
    e[31] &= 127;
    e[31] |= 64;
    // Decode u, masking bit 255 per RFC 7748.
    let mut ub = *u;
    ub[31] &= 0x7f;
    let x1 = fe_frombytes(&ub);
    // A24 = (486662 - 2) / 4 = 121665.
    let a24 = Fe::from_u64(121665);
    let mut x2 = Fe::one();
    let mut z2 = Fe::zero();
    let mut x3 = x1;
    let mut z3 = Fe::one();
    let mut swap: u8 = 0;
    for t in (0..255).rev() {
        let k_t = (e[t >> 3] >> (t & 7)) & 1;
        swap ^= k_t;
        // cswap(swap, x2, x3); cswap(swap, z2, z3).
        // fe_cmov(a, b, 0) == a, fe_cmov(a, b, 1) == b.
        let nx2 = fe_cmov(&x2, &x3, swap);
        let nx3 = fe_cmov(&x3, &x2, swap);
        let nz2 = fe_cmov(&z2, &z3, swap);
        let nz3 = fe_cmov(&z3, &z2, swap);
        x2 = nx2;
        x3 = nx3;
        z2 = nz2;
        z3 = nz3;
        swap = k_t;
        // Montgomery ladder step (RFC 7748 pseudocode).
        let a = fe_add(&x2, &z2);
        let aa = fe_sq(&a);
        let b = fe_sub(&x2, &z2);
        let bb = fe_sq(&b);
        let ed = fe_sub(&aa, &bb);
        let c = fe_add(&x3, &z3);
        let d = fe_sub(&x3, &z3);
        let da = fe_mul(&d, &a);
        let cb = fe_mul(&c, &b);
        x3 = fe_sq(&fe_add(&da, &cb));
        let dmcb = fe_sub(&da, &cb);
        z3 = fe_mul(&x1, &fe_sq(&dmcb));
        x2 = fe_mul(&aa, &bb);
        z2 = fe_mul(&ed, &fe_add(&aa, &fe_mul(&a24, &ed)));
    }
    // Final cswap, then affine x = x2 * z2^-1.
    let nx2 = fe_cmov(&x2, &x3, swap);
    let nx3 = fe_cmov(&x3, &x2, swap);
    let nz2 = fe_cmov(&z2, &z3, swap);
    let nz3 = fe_cmov(&z3, &z2, swap);
    x2 = nx2;
    x3 = nx3;
    z2 = nz2;
    z3 = nz3;
    let _ = x3;
    let _ = z3;
    fe_tobytes(&fe_mul(&x2, &fe_inv(&z2)))
}

/// HKDF-Extract (RFC 5869 §2.1) with HMAC-SHA512: `PRK = HMAC(salt, ikm)`.
fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 64] {
    hmac_sha512(salt, ikm)
}

/// HKDF-Expand (RFC 5869 §2.3) with HMAC-SHA512, writing `out.len()`
/// bytes. `T(0)` is empty; `T(i) = HMAC(PRK, T(i-1) || info || i)`.
fn hkdf_expand(prk: &[u8; 64], info: &[u8], out: &mut [u8]) {
    let mut t = [0u8; 64];
    let mut t_len = 0usize;
    let mut pos = 0usize;
    let mut ctr: u8 = 1;
    while pos < out.len() {
        let mut msg = Vec::with_capacity(t_len + info.len() + 1);
        msg.extend_from_slice(&t[..t_len]);
        msg.extend_from_slice(info);
        msg.push(ctr);
        let ti = hmac_sha512(prk, &msg);
        wipe(&mut msg);
        let take = (out.len() - pos).min(64);
        out[pos..pos + take].copy_from_slice(&ti[..take]);
        pos += take;
        t = ti;
        t_len = 64;
        ctr = ctr.wrapping_add(1);
    }
    wipe(&mut t);
}

/// Domain separation for the handshake KDF.
const KDF_INFO_PREFIX: &[u8] = b"TRV-TRANSPORT-v1";
/// AAD binding the initiator→responder direction.
const AAD_I2R: &[u8] = b"TRV-CHAN-v1:I2R";
/// AAD binding the responder→initiator direction.
const AAD_R2I: &[u8] = b"TRV-CHAN-v1:R2I";

/// Reject an all-zero peer hello before it can produce a degenerate
/// shared secret.
fn check_peer_key(peer: &[u8; 32]) -> Result<(), TransportError> {
    if peer == &[0u8; 32] {
        return Err(TransportError::BadPeerKey);
    }
    Ok(())
}

/// An encrypted, replay-protected channel between two nodes.
///
/// Each direction uses its own 32-byte key and AAD label, so frames
/// cannot be reflected. Nonces are `4-byte session prefix || 8-byte
/// big-endian sequence`. Receiving enforces a 64-entry sliding
/// window: replays and stale frames are rejected.
///
/// Key material is wiped on drop; `Debug` is redacted.
pub struct Channel {
    tx_key: [u8; 32],
    rx_key: [u8; 32],
    tx_prefix: [u8; 4],
    rx_prefix: [u8; 4],
    tx_aad: &'static [u8],
    rx_aad: &'static [u8],
    tx_seq: u64,
    /// Highest received sequence. Bit `i` of `rx_seen` marks sequence
    /// `rx_highest - i` as received (bit 0 == `rx_highest` itself).
    rx_highest: u64,
    rx_seen: u64,
}

impl std::fmt::Debug for Channel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Channel")
            .field("tx_key", &"<redacted>")
            .field("rx_key", &"<redacted>")
            .field("tx_seq", &self.tx_seq)
            .field("rx_highest", &self.rx_highest)
            .finish()
    }
}

impl Drop for Channel {
    fn drop(&mut self) {
        wipe(&mut self.tx_key);
        wipe(&mut self.rx_key);
    }
}

impl Channel {
    /// Seal `plaintext` into a frame: `nonce(12) || ciphertext || tag`.
    ///
    /// Fails closed with [`TransportError::SequenceExhausted`] if the
    /// transmit counter is exhausted (rekey instead of wrapping).
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, TransportError> {
        if self.tx_seq == u64::MAX {
            return Err(TransportError::SequenceExhausted);
        }
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&self.tx_prefix);
        nonce[4..].copy_from_slice(&self.tx_seq.to_be_bytes());
        let ct = chacha20poly1305::encrypt(&self.tx_key, &nonce, self.tx_aad, plaintext);
        self.tx_seq += 1;
        let mut frame = Vec::with_capacity(12 + ct.len());
        frame.extend_from_slice(&nonce);
        frame.extend_from_slice(&ct);
        Ok(frame)
    }

    /// Open a frame produced by the peer's [`Channel::seal`].
    ///
    /// Rejects replays, stale frames, wrong-direction frames, and
    /// tampered frames. No plaintext is produced on any error path.
    pub fn open(&mut self, frame: &[u8]) -> Result<Vec<u8>, TransportError> {
        if frame.len() < 12 + 16 {
            return Err(TransportError::FrameTooShort);
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&frame[..12]);
        if nonce[..4] != self.rx_prefix {
            return Err(TransportError::AuthenticationFailed);
        }
        let mut seq_bytes = [0u8; 8];
        seq_bytes.copy_from_slice(&nonce[4..]);
        let seq = u64::from_be_bytes(seq_bytes);
        if !self.rx_accept(seq) {
            return Err(TransportError::ReplayDetected);
        }
        // The sequence is part of the nonce, so a forged sequence
        // fails the tag check even if it passed the window test.
        match chacha20poly1305::decrypt(&self.rx_key, &nonce, self.rx_aad, &frame[12..]) {
            Ok(pt) => {
                self.rx_mark(seq);
                Ok(pt)
            }
            Err(_) => Err(TransportError::AuthenticationFailed),
        }
    }

    /// Window test: true if `seq` is new (or a fresh high), false if
    /// already seen or older than the 64-entry window.
    fn rx_accept(&self, seq: u64) -> bool {
        if seq > self.rx_highest {
            return true;
        }
        let behind = self.rx_highest - seq;
        if behind >= 64 {
            return false;
        }
        (self.rx_seen >> behind) & 1 == 0
    }

    /// Record a successfully authenticated `seq`. Call only after
    /// the tag verifies.
    fn rx_mark(&mut self, seq: u64) {
        if seq > self.rx_highest {
            let shift = seq - self.rx_highest;
            self.rx_seen = if shift >= 64 { 0 } else { self.rx_seen << shift };
            // Bit 0 always marks the (new) highest itself.
            self.rx_seen |= 1;
            self.rx_highest = seq;
        } else {
            let behind = self.rx_highest - seq;
            // `rx_accept` guarantees `behind < 64` here.
            if behind < 64 {
                self.rx_seen |= 1u64 << behind;
            }
        }
    }

    #[cfg(test)]
    fn corrupt_rx_key(&mut self) {
        self.rx_key[0] ^= 0xff;
    }
}

/// Build the two role-specific channels from one handshake.
///
/// `e_init`/`e_resp` are the ephemeral publics in transcript order.
/// Fails with [`TransportError::BadPeerKey`] on a degenerate
/// (all-zero) shared secret.
fn derive_channels(
    shared: &[u8; 32],
    e_init: &[u8; 32],
    e_resp: &[u8; 32],
    is_initiator: bool,
) -> Result<Channel, TransportError> {
    if shared == &[0u8; 32] {
        return Err(TransportError::BadPeerKey);
    }
    let prk = hkdf_extract(&[0u8; 64], shared);
    let mut info = Vec::with_capacity(KDF_INFO_PREFIX.len() + 64);
    info.extend_from_slice(KDF_INFO_PREFIX);
    info.extend_from_slice(e_init);
    info.extend_from_slice(e_resp);
    // OKM layout: k_i2r(32) || k_r2i(32) || prefix_i2r(4) || prefix_r2i(4).
    let mut okm = [0u8; 72];
    hkdf_expand(&prk, &info, &mut okm);
    let mut k_i2r = [0u8; 32];
    let mut k_r2i = [0u8; 32];
    let mut p_i2r = [0u8; 4];
    let mut p_r2i = [0u8; 4];
    k_i2r.copy_from_slice(&okm[..32]);
    k_r2i.copy_from_slice(&okm[32..64]);
    p_i2r.copy_from_slice(&okm[64..68]);
    p_r2i.copy_from_slice(&okm[68..72]);
    wipe(&mut okm);
    let (tx_key, rx_key, tx_prefix, rx_prefix, tx_aad, rx_aad) = if is_initiator {
        (k_i2r, k_r2i, p_i2r, p_r2i, AAD_I2R, AAD_R2I)
    } else {
        (k_r2i, k_i2r, p_r2i, p_i2r, AAD_R2I, AAD_I2R)
    };
    Ok(Channel {
        tx_key,
        rx_key,
        tx_prefix,
        rx_prefix,
        tx_aad,
        rx_aad,
        tx_seq: 0,
        rx_highest: 0,
        rx_seen: 0,
    })
}

/// Initiator side of the ephemeral handshake. Consumed by
/// [`finish`](InitiatorHandshake::finish); the ephemeral secret is
/// wiped afterwards.
pub struct InitiatorHandshake {
    secret: [u8; 32],
    public: [u8; 32],
}

impl std::fmt::Debug for InitiatorHandshake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InitiatorHandshake")
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl Drop for InitiatorHandshake {
    fn drop(&mut self) {
        wipe(&mut self.secret);
    }
}

impl InitiatorHandshake {
    /// Generate a fresh ephemeral keypair from OS entropy.
    pub fn new() -> Result<Self, TransportError> {
        let secret = random32()?;
        let public = x25519(&secret, &BASE_POINT);
        Ok(Self { secret, public })
    }

    /// The 32-byte hello to send the responder.
    pub fn hello(&self) -> [u8; 32] {
        self.public
    }

    /// Complete the handshake with the responder's 32-byte response,
    /// returning the initiator's [`Channel`].
    pub fn finish(mut self, peer_response: &[u8; 32]) -> Result<Channel, TransportError> {
        check_peer_key(peer_response)?;
        let shared = x25519(&self.secret, peer_response);
        wipe(&mut self.secret);
        derive_channels(&shared, &self.public, peer_response, true)
    }
}

/// Responder side of the ephemeral handshake. Consumed by
/// [`respond`](ResponderHandshake::respond); the ephemeral secret is
/// wiped afterwards.
pub struct ResponderHandshake {
    secret: [u8; 32],
    public: [u8; 32],
}

impl std::fmt::Debug for ResponderHandshake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResponderHandshake")
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl Drop for ResponderHandshake {
    fn drop(&mut self) {
        wipe(&mut self.secret);
    }
}

impl ResponderHandshake {
    /// Generate a fresh ephemeral keypair from OS entropy.
    pub fn new() -> Result<Self, TransportError> {
        let secret = random32()?;
        let public = x25519(&secret, &BASE_POINT);
        Ok(Self { secret, public })
    }

    /// Process the initiator's 32-byte hello. Returns the
    /// responder's [`Channel`] and the 32-byte response to send back.
    pub fn respond(
        mut self,
        peer_hello: &[u8; 32],
    ) -> Result<(Channel, [u8; 32]), TransportError> {
        check_peer_key(peer_hello)?;
        let shared = x25519(&self.secret, peer_hello);
        wipe(&mut self.secret);
        let channel = derive_channels(&shared, peer_hello, &self.public, false)?;
        Ok((channel, self.public))
    }
}

/// Run both handshake roles in-process. Returns
/// `(initiator_channel, responder_channel)`.
///
/// Convenience for loopback use and tests; over a real link, send
/// [`InitiatorHandshake::hello`] and the responder's response bytes
/// between the two sides instead.
pub fn establish() -> Result<(Channel, Channel), TransportError> {
    let init = InitiatorHandshake::new()?;
    let resp = ResponderHandshake::new()?;
    let hello = init.hello();
    let (rchan, response) = resp.respond(&hello)?;
    let ichan = init.finish(&response)?;
    Ok((ichan, rchan))
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

    #[test]
    fn x25519_matches_rfc7748_test_vector() {
        // RFC 7748 §6.1: X25519(0x09..00, 0x09..00).
        // Cross-checked 2026-10-14 against an independent from-scratch
        // Python Montgomery-ladder implementation (Python big ints, not
        // the 5x51 limbs used here); both agree with the RFC value.
        let mut scalar = [0u8; 32];
        scalar[0] = 9;
        let mut u = [0u8; 32];
        u[0] = 9;
        let out = x25519(&scalar, &u);
        assert_eq!(
            out,
            arr32(&hex(
                "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"
            ))
        );
    }

    #[test]
    fn x25519_matches_independent_python_vectors() {
        // Random vectors generated 2026-10-14 by the independent
        // Python implementation (see module docs); the Rust ladder
        // must reproduce them exactly.
        let cases = [
            (
                "de099f9359bfc4e9a80268c395236ee7436d29f5bbb16a68af41357a60a144ab",
                "4715ceb1ee389bd2e0015e401418df5285f6cf5e60741074150d8f9fff47f596",
                "cbbbd0ff00e7b5e60c1fbc5f7e50faa443517c7fea4cff61693dfff1e2f6eb75",
            ),
            (
                "0c5054d08d4bab094be297a2bae4113e3daad7391579a0ec560f0a8295301220",
                "772dfe2d4417533c543203f762bedb7379a294cb428e445022b33bafbec84a82",
                "960dac9841fbcc4308e54e8fa55c98dbb3664effa6240d14a630df9e61d04061",
            ),
            (
                "1dba98b6d99d89bfa436e32edeeec9c3e98b4d2a759a7314ffc2a91f3a6382bf",
                "01329ee8cca7d6fdddbe4e04bee5e79118a56b0ebac4f405afbb236b2319a547",
                "0e517342faf7a8a52151ecbc025f3aebb0541b50a4a2e0da083ee8ab32a5be26",
            ),
        ];
        for (s, u, expected) in cases {
            let out = x25519(&arr32(&hex(s)), &arr32(&hex(u)));
            assert_eq!(out, arr32(&hex(expected)), "scalar {s}");
        }
    }

    #[test]
    fn x25519_dh_commutes() {
        // X25519(a, X25519(b, G)) == X25519(b, X25519(a, G)).
        let a = random32().unwrap();
        let b = random32().unwrap();
        let pa = x25519(&a, &BASE_POINT);
        let pb = x25519(&b, &BASE_POINT);
        assert_eq!(x25519(&a, &pb), x25519(&b, &pa));
    }

    #[test]
    fn handshake_round_trip_both_directions() {
        let (mut ichan, mut rchan) = establish().unwrap();
        for i in 0..5u8 {
            let msg_i = format!("initiator message {i}").into_bytes();
            let frame = ichan.seal(&msg_i).unwrap();
            assert_eq!(rchan.open(&frame).unwrap(), msg_i);
            let msg_r = format!("responder message {i}").into_bytes();
            let frame = rchan.seal(&msg_r).unwrap();
            assert_eq!(ichan.open(&frame).unwrap(), msg_r);
        }
        // Empty plaintext round-trips too.
        let frame = ichan.seal(b"").unwrap();
        assert_eq!(rchan.open(&frame).unwrap(), b"");
    }

    #[test]
    fn tampered_frame_rejected() {
        let (mut ichan, mut rchan) = establish().unwrap();
        let frame = ichan.seal(b"secret plans").unwrap();
        // Tamper the nonce.
        let mut f1 = frame.clone();
        f1[3] ^= 0x01;
        assert_eq!(
            rchan.open(&f1),
            Err(TransportError::AuthenticationFailed)
        );
        // Tamper the ciphertext body.
        let mut f2 = frame.clone();
        let mid = 12 + (f2.len() - 12 - 16) / 2;
        f2[mid] ^= 0x80;
        assert_eq!(
            rchan.open(&f2),
            Err(TransportError::AuthenticationFailed)
        );
        // Tamper the tag.
        let mut f3 = frame.clone();
        let last = f3.len() - 1;
        f3[last] ^= 0x01;
        assert_eq!(
            rchan.open(&f3),
            Err(TransportError::AuthenticationFailed)
        );
        // Truncated frame.
        assert_eq!(
            rchan.open(&frame[..20]),
            Err(TransportError::FrameTooShort)
        );
        // The untampered frame still opens afterwards.
        assert_eq!(rchan.open(&frame).unwrap(), b"secret plans");
    }

    #[test]
    fn replayed_frame_rejected() {
        let (mut ichan, mut rchan) = establish().unwrap();
        let frame = ichan.seal(b"once").unwrap();
        assert_eq!(rchan.open(&frame).unwrap(), b"once");
        // Exact replay.
        assert_eq!(rchan.open(&frame), Err(TransportError::ReplayDetected));
        // Out-of-order delivery within the window is accepted, then
        // replaying any of them is rejected.
        let f0 = ichan.seal(b"m0").unwrap();
        let f1 = ichan.seal(b"m1").unwrap();
        let f2 = ichan.seal(b"m2").unwrap();
        assert_eq!(rchan.open(&f2).unwrap(), b"m2");
        assert_eq!(rchan.open(&f0).unwrap(), b"m0");
        assert_eq!(rchan.open(&f0), Err(TransportError::ReplayDetected));
        assert_eq!(rchan.open(&f1).unwrap(), b"m1");
        assert_eq!(rchan.open(&f1), Err(TransportError::ReplayDetected));
        assert_eq!(rchan.open(&f2), Err(TransportError::ReplayDetected));
    }

    #[test]
    fn stale_frame_outside_window_rejected() {
        let (mut ichan, mut rchan) = establish().unwrap();
        let first = ichan.seal(b"first").unwrap();
        assert_eq!(rchan.open(&first).unwrap(), b"first");
        // Advance the receiver's window 70 frames past `first`.
        for i in 0..70u8 {
            let f = ichan.seal(&[i]).unwrap();
            rchan.open(&f).unwrap();
        }
        // `first` (seq 0) is now more than 64 behind the highest.
        assert_eq!(rchan.open(&first), Err(TransportError::ReplayDetected));
    }

    #[test]
    fn wrong_key_fails() {
        // Frames from an unrelated channel pair must not open.
        let (mut ichan_a, _rchan_a) = establish().unwrap();
        let (_ichan_b, mut rchan_b) = establish().unwrap();
        let frame = ichan_a.seal(b"for A only").unwrap();
        assert_eq!(
            rchan_b.open(&frame),
            Err(TransportError::AuthenticationFailed)
        );
        // Corrupting one side's receive key breaks the channel.
        let (mut ichan, mut rchan) = establish().unwrap();
        rchan.corrupt_rx_key();
        let frame = ichan.seal(b"hello").unwrap();
        assert_eq!(
            rchan.open(&frame),
            Err(TransportError::AuthenticationFailed)
        );
    }

    #[test]
    fn mitm_hello_produces_unusable_channel() {
        // Attacker swaps the responder's hello: the initiator
        // completes a handshake with the attacker, so the real
        // responder's frames no longer authenticate.
        let init = InitiatorHandshake::new().unwrap();
        let attacker = ResponderHandshake::new().unwrap();
        let (_achan, evil_response) = attacker.respond(&init.hello()).unwrap();
        let mut ichan = init.finish(&evil_response).unwrap();
        let (_real_r, mut real_rchan) = establish().unwrap();
        let frame = real_rchan.seal(b"real").unwrap();
        assert_eq!(
            ichan.open(&frame),
            Err(TransportError::AuthenticationFailed)
        );
    }

    #[test]
    fn reflection_rejected() {
        // A frame sealed by a channel must not open on that same
        // channel: direction keys and AAD differ per direction.
        let (mut ichan, _rchan) = establish().unwrap();
        let frame = ichan.seal(b"loopback").unwrap();
        assert_eq!(
            ichan.open(&frame),
            Err(TransportError::AuthenticationFailed)
        );
    }

    #[test]
    fn zero_peer_hello_rejected() {
        let init = InitiatorHandshake::new().unwrap();
        assert_eq!(
            init.finish(&[0u8; 32]).unwrap_err(),
            TransportError::BadPeerKey
        );
        let resp = ResponderHandshake::new().unwrap();
        assert!(resp.respond(&[0u8; 32]).is_err());
    }

    #[test]
    fn hkdf_expand_is_deterministic_and_sized() {
        let prk = hkdf_extract(&[0u8; 64], b"test ikm");
        let mut o1 = [0u8; 100];
        let mut o2 = [0u8; 100];
        hkdf_expand(&prk, b"info", &mut o1);
        hkdf_expand(&prk, b"info", &mut o2);
        assert_eq!(o1, o2);
        let mut o3 = [0u8; 100];
        hkdf_expand(&prk, b"other info", &mut o3);
        assert_ne!(o1, o3);
        // Multi-block output differs per block (counter domain separation).
        assert_ne!(&o1[..64], &o1[64..]);
    }

    #[test]
    fn debug_never_leaks_key_material() {
        let (ichan, _) = establish().unwrap();
        let dbg = format!("{:?}", ichan);
        assert!(dbg.contains("<redacted>"));
        let tx_hex: String = ichan
            .tx_key
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        assert!(!dbg.contains(&tx_hex));
    }
}
