//! Username@RV.com encrypted email over a blind relay.
//!
//! Privacy model, in plain words:
//!
//! * **Nobody in the middle learns anything.** The relay that moves packets
//!   sees only opaque 32-byte routing tags — never sender addresses,
//!   recipient addresses, subjects, bodies, or timestamps. All of that is
//!   inside the ChaCha20-Poly1305 sealed box, which only the recipient's
//!   long-term X25519 key can open.
//! * **The sender proves who they are inside the box.** The inner content
//!   carries the sender's Ed25519 identity public key and a signature over
//!   the whole message. The relay never sees the sender at all.
//! * **Routing tags are unlinkable by the relay.** A recipient generates a
//!   random 32-byte tag secret, publishes `SHA-512(domain || secret)[..32]`
//!   as their routing tag for an epoch, and later proves ownership by
//!   presenting the secret. The relay derives the tag from the presented
//!   proof and drains that queue — a wrong proof derives a different,
//!   almost-surely-empty tag, so there is no oracle telling anyone whether
//!   a tag exists.
//! * **Sealed-box key exchange.** Each email uses a fresh ephemeral X25519
//!   keypair; the symmetric key comes from HKDF-SHA512 over the DH shared
//!   secret with a mail-specific info string. Ephemeral secrets and the raw
//!   shared secret are wiped after use. Low-order and all-zero peer points
//!   are rejected before the key schedule (small-subgroup confinement).
//!
//! What this module does NOT do: no network sockets, no SMTP interop, no
//! attachments, no folders UI, no key server. `BlindRelay` is the pure
//! routing-table logic; real I/O plugs in later. Like the rest of
//! `trv_core`, this has not had an independent cryptographic audit — do not
//! rely on it for production secrets until that happens.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::time::Duration;

use crate::crypto::chacha20poly1305::{decrypt, encrypt, AeadError};
use crate::crypto::ed25519;
use crate::ratelimit::RateLimiter;
use crate::transport::{
    hkdf_expand, hkdf_extract, is_low_order, random32, x25519, BASE_POINT, TransportError,
};

/// Email domain. Fixed: every address ends here.
const DOMAIN: &str = "rv.com";
/// Max username length in bytes (charset is ASCII-only, so bytes == chars).
const MAX_USERNAME: usize = 32;
/// Max subject length in characters.
const MAX_SUBJECT_CHARS: usize = 200;
/// Max body length in bytes.
const MAX_BODY_BYTES: usize = 65_536;
/// Max total relay-packet size in bytes (80 KiB).
const MAX_PACKET_BYTES: usize = 81_920;
/// Max queued packets per routing tag; oldest are dropped beyond this.
const MAX_QUEUE: usize = 100;
/// Packet magic.
const MAGIC: &[u8; 4] = b"TRVM";
/// Packet format version.
const VERSION: u8 = 0x01;
/// Inner-content format version.
const INNER_VERSION: u8 = 0x01;
/// HKDF info string for the sealed-box key schedule.
const KDF_INFO: &[u8] = b"TRV-MAIL-v1:sealed-box";
/// Domain separation for the inner-content signature.
const SIGN_DOMAIN: &[u8] = b"TRV-MAIL-v1:inner-sign";
/// Domain separation for routing-tag derivation.
const TAG_DOMAIN: &[u8] = b"TRV-MAIL-v1:routing-tag";

/// Errors for the mail module. All fail closed; no partial state leaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailError {
    /// Address failed validation (charset, length, or domain).
    BadAddress,
    /// Inner Ed25519 signature did not verify.
    BadSignature,
    /// AEAD authentication failed (wrong key or tampered ciphertext).
    DecryptFailed,
    /// Packet or inner content failed structural parsing.
    Malformed,
    /// A size cap was exceeded (subject, body, or packet).
    TooLarge,
    /// Inner recipient did not match the expected address.
    WrongRecipient,
    /// Relay rate limiter rejected the submission.
    RateLimited,
    /// OS entropy was unavailable.
    EntropyUnavailable,
    /// Recipient/ephemeral X25519 point was all-zero or low-order.
    LowOrderKey,
}

impl fmt::Display for MailError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            MailError::BadAddress => "invalid rv.com address",
            MailError::BadSignature => "sender signature invalid",
            MailError::DecryptFailed => "envelope authentication failed",
            MailError::Malformed => "malformed mail packet",
            MailError::TooLarge => "mail size limit exceeded",
            MailError::WrongRecipient => "envelope recipient mismatch",
            MailError::RateLimited => "relay rate limit exceeded",
            MailError::EntropyUnavailable => "OS entropy unavailable",
            MailError::LowOrderKey => "rejected weak X25519 point",
        };
        f.write_str(s)
    }
}

impl std::error::Error for MailError {}

impl From<TransportError> for MailError {
    fn from(_: TransportError) -> Self {
        MailError::EntropyUnavailable
    }
}

impl From<AeadError> for MailError {
    fn from(_: AeadError) -> Self {
        MailError::DecryptFailed
    }
}

/// Volatile wipe for secret buffers.
fn wipe(b: &mut [u8]) {
    for x in b.iter_mut() {
        // SAFETY: `x` is a valid, uniquely-borrowed byte.
        unsafe {
            core::ptr::write_volatile(x, 0u8);
        }
    }
}

fn hex_lower(b: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push(H[(x >> 4) as usize] as char);
        s.push(H[(x & 15) as usize] as char);
    }
    s
}

// ---------------------------------------------------------------------------
// Addresses
// ---------------------------------------------------------------------------

/// A `username@rv.com` address. Usernames are 1–32 chars from
/// `[a-z0-9._-]`; the domain is fixed. Uppercase and anything outside the
/// charset is rejected — fail closed, no silent normalization.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RvAddress {
    username: String,
}

impl RvAddress {
    /// Parse and validate `username@rv.com`.
    pub fn parse(s: &str) -> Result<Self, MailError> {
        let (user, domain) = s.split_once('@').ok_or(MailError::BadAddress)?;
        if domain != DOMAIN {
            return Err(MailError::BadAddress);
        }
        if user.is_empty() || user.len() > MAX_USERNAME {
            return Err(MailError::BadAddress);
        }
        let ok = user
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'));
        if !ok {
            return Err(MailError::BadAddress);
        }
        Ok(RvAddress {
            username: user.to_string(),
        })
    }

    /// The username part.
    pub fn username(&self) -> &str {
        &self.username
    }

    fn as_bytes(&self) -> &[u8] {
        self.username.as_bytes()
    }
}

impl fmt::Display for RvAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.username, DOMAIN)
    }
}

// ---------------------------------------------------------------------------
// Long-term mail keys (X25519)
// ---------------------------------------------------------------------------

/// A recipient's long-term X25519 secret. Never serialized; `Debug` is
/// redacted.
pub struct MailSecretKey([u8; 32]);

/// A recipient's long-term X25519 public key. This is what senders seal
/// to; it can be published (e.g. alongside a contact card).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MailPublicKey([u8; 32]);

impl MailSecretKey {
    /// Generate a fresh keypair secret from OS entropy.
    pub fn generate() -> Result<Self, MailError> {
        Ok(MailSecretKey(random32()?))
    }

    /// Derive the public key.
    pub fn public(&self) -> MailPublicKey {
        MailPublicKey(x25519(&self.0, &BASE_POINT))
    }
}

// Redacted Debug: the secret never appears in debug output.
impl fmt::Debug for MailSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MailSecretKey([redacted])")
    }
}

impl MailPublicKey {
    /// Wrap 32 raw bytes as a public key.
    pub fn from_bytes(b: [u8; 32]) -> Self {
        MailPublicKey(b)
    }

    /// Raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Reject weak X25519 points before they enter the key schedule.
fn check_point(p: &[u8; 32]) -> Result<(), MailError> {
    if *p == [0u8; 32] || is_low_order(p) {
        return Err(MailError::LowOrderKey);
    }
    Ok(())
}

/// Derive the 32-byte sealed-box key from a DH shared secret.
fn kdf_box_key(shared: &[u8; 32]) -> [u8; 32] {
    let mut prk = hkdf_extract(&[0u8; 64], shared);
    let mut key = [0u8; 32];
    hkdf_expand(&prk, KDF_INFO, &mut key);
    wipe(&mut prk);
    key
}

// ---------------------------------------------------------------------------
// Inner content: what gets encrypted
// ---------------------------------------------------------------------------

/// Canonical bytes the sender's Ed25519 key signs. Length-prefixed so the
/// encoding is unambiguous.
fn sign_bytes(
    sender: &RvAddress,
    recipient: &RvAddress,
    subject: &str,
    body: &str,
    timestamp: u64,
    sender_id_pub: &[u8; 32],
) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(SIGN_DOMAIN);
    for part in [sender.as_bytes(), recipient.as_bytes()] {
        v.extend_from_slice(&(part.len() as u32).to_be_bytes());
        v.extend_from_slice(part);
    }
    v.extend_from_slice(&(subject.len() as u32).to_be_bytes());
    v.extend_from_slice(subject.as_bytes());
    v.extend_from_slice(&(body.len() as u32).to_be_bytes());
    v.extend_from_slice(body.as_bytes());
    v.extend_from_slice(&timestamp.to_be_bytes());
    v.extend_from_slice(sender_id_pub);
    v
}

/// Serialize the signed inner content for encryption.
#[allow(clippy::too_many_arguments)]
fn serialize_inner(
    sender: &RvAddress,
    recipient: &RvAddress,
    subject: &str,
    body: &str,
    timestamp: u64,
    sender_id_pub: &[u8; 32],
    sig: &[u8; 64],
) -> Vec<u8> {
    let mut v = Vec::new();
    v.push(INNER_VERSION);
    for part in [sender.as_bytes(), recipient.as_bytes()] {
        v.extend_from_slice(&(part.len() as u16).to_be_bytes());
        v.extend_from_slice(part);
    }
    v.extend_from_slice(&timestamp.to_be_bytes());
    v.extend_from_slice(&(subject.len() as u32).to_be_bytes());
    v.extend_from_slice(subject.as_bytes());
    v.extend_from_slice(&(body.len() as u32).to_be_bytes());
    v.extend_from_slice(body.as_bytes());
    v.extend_from_slice(sender_id_pub);
    v.extend_from_slice(sig);
    v
}

/// Parsed, signature-verified inner content.
struct ParsedInner {
    sender: RvAddress,
    recipient: RvAddress,
    subject: String,
    body: String,
    timestamp: u64,
    sender_id_pub: [u8; 32],
}

/// Advance `cur` by `n` bytes, fail closed on truncation.
fn take<'a>(cur: &mut &'a [u8], n: usize) -> Result<&'a [u8], MailError> {
    if cur.len() < n {
        return Err(MailError::Malformed);
    }
    let (h, t) = cur.split_at(n);
    *cur = t;
    Ok(h)
}

fn parse_inner(pt: &[u8]) -> Result<ParsedInner, MailError> {
    let mut cur: &[u8] = pt;

    if take(&mut cur, 1)?[0] != INNER_VERSION {
        return Err(MailError::Malformed);
    }
    let sn = u16::from_be_bytes(take(&mut cur, 2)?.try_into().unwrap()) as usize;
    if sn == 0 || sn > MAX_USERNAME {
        return Err(MailError::Malformed);
    }
    let sender_raw = take(&mut cur, sn)?;
    let rn = u16::from_be_bytes(take(&mut cur, 2)?.try_into().unwrap()) as usize;
    if rn == 0 || rn > MAX_USERNAME {
        return Err(MailError::Malformed);
    }
    let recip_raw = take(&mut cur, rn)?;
    let timestamp = u64::from_be_bytes(take(&mut cur, 8)?.try_into().unwrap());
    let sl = u32::from_be_bytes(take(&mut cur, 4)?.try_into().unwrap()) as usize;
    if sl > 4 * MAX_SUBJECT_CHARS {
        return Err(MailError::Malformed);
    }
    let subj_raw = take(&mut cur, sl)?;
    let bl = u32::from_be_bytes(take(&mut cur, 4)?.try_into().unwrap()) as usize;
    if bl > MAX_BODY_BYTES {
        return Err(MailError::Malformed);
    }
    let body_raw = take(&mut cur, bl)?;
    let id_pub: [u8; 32] = take(&mut cur, 32)?.try_into().unwrap();
    let sig: [u8; 64] = take(&mut cur, 64)?.try_into().unwrap();
    if !cur.is_empty() {
        return Err(MailError::Malformed);
    }

    let sender_str = core::str::from_utf8(sender_raw).map_err(|_| MailError::Malformed)?;
    let recip_str = core::str::from_utf8(recip_raw).map_err(|_| MailError::Malformed)?;
    let subject = core::str::from_utf8(subj_raw).map_err(|_| MailError::Malformed)?;
    let body = core::str::from_utf8(body_raw).map_err(|_| MailError::Malformed)?;
    if subject.chars().count() > MAX_SUBJECT_CHARS {
        return Err(MailError::Malformed);
    }
    // Rebuild full addresses for charset validation.
    let mut sfull = String::with_capacity(sender_str.len() + 1 + DOMAIN.len());
    sfull.push_str(sender_str);
    sfull.push('@');
    sfull.push_str(DOMAIN);
    let mut rfull = String::with_capacity(recip_str.len() + 1 + DOMAIN.len());
    rfull.push_str(recip_str);
    rfull.push('@');
    rfull.push_str(DOMAIN);
    let sender = RvAddress::parse(&sfull).map_err(|_| MailError::Malformed)?;
    let recipient = RvAddress::parse(&rfull).map_err(|_| MailError::Malformed)?;

    // Verify the sender's signature over the canonical bytes.
    let msg = sign_bytes(&sender, &recipient, subject, body, timestamp, &id_pub);
    let pk = ed25519::PublicKey::from_bytes(id_pub);
    let signature = ed25519::Signature::from_bytes(sig);
    if !ed25519::verify(&pk, &msg, &signature) {
        return Err(MailError::BadSignature);
    }

    Ok(ParsedInner {
        sender,
        recipient,
        subject: subject.to_string(),
        body: body.to_string(),
        timestamp,
        sender_id_pub: id_pub,
    })
}

// ---------------------------------------------------------------------------
// Sealed envelope
// ---------------------------------------------------------------------------

/// An opened, verified email.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedEmail {
    /// Sender address (inside the sealed box; the relay never saw it).
    pub sender: RvAddress,
    /// Recipient address (matches the `expected` passed to [`open`]).
    pub recipient: RvAddress,
    /// Subject line.
    pub subject: String,
    /// Body text.
    pub body: String,
    /// Sender-supplied timestamp (informational; no trusted clock).
    pub timestamp: u64,
    /// The sender's Ed25519 identity key; the inner signature verified
    /// against this key.
    pub sender_id: [u8; 32],
}

/// Seal an email for `recipient_pub`, addressed for `routing_tag`.
///
/// The sender's identity is proven INSIDE the box via Ed25519 signature;
/// the relay sees only the opaque routing tag, the ephemeral X25519
/// public key, nonce, and ciphertext.
#[allow(clippy::too_many_arguments)]
pub fn seal(
    sender: &RvAddress,
    recipient: &RvAddress,
    subject: &str,
    body: &str,
    timestamp: u64,
    sender_id_secret: &ed25519::SecretKey,
    sender_id_public: &ed25519::PublicKey,
    recipient_pub: &MailPublicKey,
    routing_tag: &[u8; 32],
) -> Result<Vec<u8>, MailError> {
    if subject.chars().count() > MAX_SUBJECT_CHARS {
        return Err(MailError::TooLarge);
    }
    if body.len() > MAX_BODY_BYTES {
        return Err(MailError::TooLarge);
    }
    check_point(&recipient_pub.0)?;

    // Sign the canonical inner content with the sender's identity key.
    let msg = sign_bytes(
        sender,
        recipient,
        subject,
        body,
        timestamp,
        sender_id_public.as_bytes(),
    );
    let sig = ed25519::sign(sender_id_secret, sender_id_public, &msg);
    let mut inner = serialize_inner(
        sender,
        recipient,
        subject,
        body,
        timestamp,
        sender_id_public.as_bytes(),
        sig.as_bytes(),
    );

    // Ephemeral X25519 keypair; DH against the recipient's long-term key.
    let mut eph = random32()?;
    let eph_pub = x25519(&eph, &BASE_POINT);
    let mut shared = x25519(&eph, &recipient_pub.0);
    wipe(&mut eph);
    if shared == [0u8; 32] {
        wipe(&mut shared);
        wipe(&mut inner);
        return Err(MailError::LowOrderKey);
    }
    let mut key = kdf_box_key(&shared);
    wipe(&mut shared);

    let full_nonce = random32()?;
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&full_nonce[..12]);

    // AAD binds the ciphertext to the ephemeral public key.
    let ct = encrypt(&key, &nonce, &eph_pub, &inner);
    wipe(&mut key);
    wipe(&mut inner);

    let packet = RelayPacket {
        tag: *routing_tag,
        eph_pub,
        nonce,
        ciphertext: ct,
    };
    let raw = packet.encode();
    if raw.len() > MAX_PACKET_BYTES {
        return Err(MailError::TooLarge);
    }
    Ok(raw)
}

/// Open a sealed email. `expected` must match the inner recipient address
/// or the packet is rejected — a misdelivered envelope fails closed even
/// when the key is right.
pub fn open(
    raw: &[u8],
    recipient_secret: &MailSecretKey,
    expected: &RvAddress,
) -> Result<OpenedEmail, MailError> {
    let packet = RelayPacket::decode(raw)?;
    check_point(&packet.eph_pub)?;

    let mut shared = x25519(&recipient_secret.0, &packet.eph_pub);
    if shared == [0u8; 32] {
        wipe(&mut shared);
        return Err(MailError::LowOrderKey);
    }
    let mut key = kdf_box_key(&shared);
    wipe(&mut shared);

    let mut pt = decrypt(&key, &packet.nonce, &packet.eph_pub, &packet.ciphertext)?;
    wipe(&mut key);
    let inner = parse_inner(&pt)?;
    wipe(&mut pt);

    if inner.recipient != *expected {
        return Err(MailError::WrongRecipient);
    }
    Ok(OpenedEmail {
        sender: inner.sender,
        recipient: inner.recipient,
        subject: inner.subject,
        body: inner.body,
        timestamp: inner.timestamp,
        sender_id: inner.sender_id_pub,
    })
}

// ---------------------------------------------------------------------------
// Relay packet: what the blind relay moves
// ---------------------------------------------------------------------------

/// The unit the relay stores and forwards. Layout:
///
/// `TRVM || 0x01 || tag(32) || eph_pub(32) || nonce(12) || ct_len(4 BE) || ct`
///
/// The tag is opaque to the relay; everything after it is the sealed box.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayPacket {
    /// Opaque 32-byte routing tag. The relay maps this to a queue and
    /// learns nothing else.
    pub tag: [u8; 32],
    /// Ephemeral X25519 public key (random per email).
    pub eph_pub: [u8; 32],
    /// ChaCha20-Poly1305 nonce.
    pub nonce: [u8; 12],
    /// Sealed inner content.
    pub ciphertext: Vec<u8>,
}

/// Encoded header length: 4 + 1 + 32 + 32 + 12 + 4.
const PACKET_HEADER: usize = 85;

impl RelayPacket {
    /// Encode to the wire format.
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(PACKET_HEADER + self.ciphertext.len());
        v.extend_from_slice(MAGIC);
        v.push(VERSION);
        v.extend_from_slice(&self.tag);
        v.extend_from_slice(&self.eph_pub);
        v.extend_from_slice(&self.nonce);
        v.extend_from_slice(&(self.ciphertext.len() as u32).to_be_bytes());
        v.extend_from_slice(&self.ciphertext);
        v
    }

    /// Parse and validate. Fail closed on any structural problem.
    pub fn decode(raw: &[u8]) -> Result<Self, MailError> {
        if raw.len() > MAX_PACKET_BYTES {
            return Err(MailError::TooLarge);
        }
        if raw.len() < PACKET_HEADER {
            return Err(MailError::Malformed);
        }
        if &raw[0..4] != MAGIC {
            return Err(MailError::Malformed);
        }
        if raw[4] != VERSION {
            return Err(MailError::Malformed);
        }
        let mut tag = [0u8; 32];
        tag.copy_from_slice(&raw[5..37]);
        let mut eph_pub = [0u8; 32];
        eph_pub.copy_from_slice(&raw[37..69]);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&raw[69..81]);
        let ct_len =
            u32::from_be_bytes(raw[81..85].try_into().unwrap()) as usize;
        if ct_len > MAX_PACKET_BYTES {
            return Err(MailError::Malformed);
        }
        let total = PACKET_HEADER
            .checked_add(ct_len)
            .ok_or(MailError::Malformed)?;
        if raw.len() != total {
            // Truncation or trailing garbage: fail closed either way.
            return Err(MailError::Malformed);
        }
        Ok(RelayPacket {
            tag,
            eph_pub,
            nonce,
            ciphertext: raw[PACKET_HEADER..].to_vec(),
        })
    }
}

// ---------------------------------------------------------------------------
// Routing tags: unlinkable mailbox names
// ---------------------------------------------------------------------------

/// A recipient's unlinkable mailbox for one epoch.
///
/// The recipient generates a random 32-byte secret, publishes
/// `tag = SHA-512(TAG_DOMAIN || secret)[..32]`, and keeps the secret.
/// Senders address packets to the tag; the relay cannot link the tag to
/// any address. To collect, the recipient presents the secret as proof;
/// the relay re-derives the tag and drains that queue.
pub struct RoutingTag {
    tag: [u8; 32],
    secret: [u8; 32],
}

impl RoutingTag {
    /// Generate a fresh tag + secret from OS entropy.
    pub fn generate() -> Result<Self, MailError> {
        let secret = random32()?;
        Ok(Self {
            tag: Self::derive(&secret),
            secret,
        })
    }

    /// Derive the public tag from a secret (also used by the relay to
    /// check collection proofs).
    pub fn derive(secret: &[u8; 32]) -> [u8; 32] {
        let mut input = Vec::with_capacity(TAG_DOMAIN.len() + 32);
        input.extend_from_slice(TAG_DOMAIN);
        input.extend_from_slice(secret);
        let d = ed25519::sha512::digest(&input);
        let mut tag = [0u8; 32];
        tag.copy_from_slice(&d[..32]);
        tag
    }

    /// The public routing tag to publish.
    pub fn tag(&self) -> &[u8; 32] {
        &self.tag
    }

    /// The secret proof, presented at collection time.
    pub fn secret(&self) -> &[u8; 32] {
        &self.secret
    }
}

// ---------------------------------------------------------------------------
// Blind relay: pure routing-table logic, no sockets
// ---------------------------------------------------------------------------

/// The TRV-native blind relay: an in-memory map from opaque routing tags
/// to packet queues. It never sees addresses, subjects, bodies, or
/// senders — only tags, ephemeral keys, nonces, and ciphertext.
///
/// Spam posture: submissions are rate-limited per routing tag with cost
/// proportional to packet size (1 unit per 16 KiB, minimum 1), so flooding
/// one mailbox with maximum-size packets burns the attacker's budget fast.
/// Operators expecting adversarial load should additionally front this
/// with proof-of-work or a micropayment gate — the `with_limits`
/// constructor exposes the knobs.
pub struct BlindRelay {
    queues: HashMap<[u8; 32], VecDeque<Vec<u8>>>,
    limiter: RateLimiter,
}

impl BlindRelay {
    /// Default relay: 10 submission-units/second per tag, 5-minute bans,
    /// 10k tracked tags.
    pub fn new() -> Self {
        Self::with_limits(10, 300, 10_000)
    }

    /// Relay with explicit rate-limit knobs.
    pub fn with_limits(threshold: u32, ban_secs: u64, max_tracked: usize) -> Self {
        BlindRelay {
            queues: HashMap::new(),
            limiter: RateLimiter::with_limits(
                threshold,
                Duration::from_secs(ban_secs),
                max_tracked,
            ),
        }
    }

    /// Validate and queue a raw packet. Malformed packets are rejected;
    /// over-limit submitters are rejected; queues are capped at
    /// [`MAX_QUEUE`] with oldest-first eviction.
    pub fn submit(&mut self, raw: &[u8]) -> Result<(), MailError> {
        let packet = RelayPacket::decode(raw)?;
        // Size-proportional cost: bigger packets burn more budget.
        let charge = 1 + (raw.len() / 16_384) as u32;
        let key = hex_lower(&packet.tag);
        for _ in 0..charge {
            if !self.limiter.handle_request(&key) {
                return Err(MailError::RateLimited);
            }
        }
        let q = self.queues.entry(packet.tag).or_default();
        q.push_back(raw.to_vec());
        while q.len() > MAX_QUEUE {
            q.pop_front();
        }
        Ok(())
    }

    /// Collect and drain the queue for a routing tag, proving ownership
    /// with the tag secret. A wrong proof derives a different,
    /// almost-surely-empty tag — the caller cannot distinguish "wrong
    /// proof" from "no such mailbox": no oracle.
    pub fn collect(&mut self, proof: &[u8; 32]) -> Vec<Vec<u8>> {
        let tag = RoutingTag::derive(proof);
        match self.queues.remove(&tag) {
            Some(q) => q.into_iter().collect(),
            None => Vec::new(),
        }
    }

    /// Queued packet count for a tag (monitoring; the tag itself is
    /// already public to anyone the recipient shared it with).
    pub fn queue_len(&self, tag: &[u8; 32]) -> usize {
        self.queues.get(tag).map(|q| q.len()).unwrap_or(0)
    }
}

impl Default for BlindRelay {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> RvAddress {
        RvAddress::parse(s).unwrap()
    }

    fn id_keypair() -> (ed25519::SecretKey, ed25519::PublicKey) {
        let seed = random32().unwrap();
        ed25519::generate(&seed)
    }

    fn mail_keypair() -> (MailSecretKey, MailPublicKey) {
        let sk = MailSecretKey::generate().unwrap();
        let pk = sk.public();
        (sk, pk)
    }

    #[allow(clippy::too_many_arguments)]
    fn seal_test(
        sender: &RvAddress,
        recipient: &RvAddress,
        subject: &str,
        body: &str,
        ids: &ed25519::SecretKey,
        idp: &ed25519::PublicKey,
        rpub: &MailPublicKey,
        tag: &[u8; 32],
    ) -> Vec<u8> {
        seal(sender, recipient, subject, body, 1_700_000_000, ids, idp, rpub, tag).unwrap()
    }

    #[test]
    fn address_good_table() {
        for s in [
            "alice@rv.com",
            "a@rv.com",
            "a.b-c_d9@rv.com",
            "user.name-1_2@rv.com",
            "01234567890123456789012345678901@rv.com", // 32 chars
        ] {
            assert!(RvAddress::parse(s).is_ok(), "should parse: {}", s);
        }
    }

    #[test]
    fn address_bad_table() {
        let long = "a".repeat(33) + "@rv.com";
        for s in [
            "",
            "alice",
            "alice@",
            "@rv.com",
            "alice@RV.com",      // uppercase domain
            "Alice@rv.com",      // uppercase user
            "alice@gmail.com",   // wrong domain
            "alice@rv.com.evil", // domain suffix trick
            "al ice@rv.com",     // space
            "ali!ce@rv.com",     // bad char
            "alice@@rv.com",     // double @
            long.as_str(),       // 33 chars
        ] {
            assert!(RvAddress::parse(s).is_err(), "should reject: {}", s);
        }
    }

    #[test]
    fn address_display_roundtrip() {
        let a = addr("bob.smith_99@rv.com");
        assert_eq!(a.to_string(), "bob.smith_99@rv.com");
        assert_eq!(RvAddress::parse(&a.to_string()).unwrap(), a);
        assert_eq!(a.username(), "bob.smith_99");
    }

    #[test]
    fn seal_open_roundtrip() {
        let sender = addr("alice@rv.com");
        let recipient = addr("bob@rv.com");
        let (ids, idp) = id_keypair();
        let (rsk, rpub) = mail_keypair();
        let rtag = RoutingTag::generate().unwrap();
        let raw = seal_test(
            &sender, &recipient, "hello", "meet at dawn",
            &ids, &idp, &rpub, rtag.tag(),
        );
        let opened = open(&raw, &rsk, &recipient).unwrap();
        assert_eq!(opened.sender, sender);
        assert_eq!(opened.recipient, recipient);
        assert_eq!(opened.subject, "hello");
        assert_eq!(opened.body, "meet at dawn");
        assert_eq!(opened.timestamp, 1_700_000_000);
        assert_eq!(opened.sender_id, *idp.as_bytes());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let sender = addr("alice@rv.com");
        let recipient = addr("bob@rv.com");
        let (ids, idp) = id_keypair();
        let (rsk, rpub) = mail_keypair();
        let rtag = RoutingTag::generate().unwrap();
        let mut raw = seal_test(&sender, &recipient, "s", "b", &ids, &idp, &rpub, rtag.tag());
        let last = raw.len() - 1;
        raw[last] ^= 0x01;
        assert_eq!(open(&raw, &rsk, &recipient), Err(MailError::DecryptFailed));
    }

    #[test]
    fn tampered_eph_pub_fails_via_aad() {
        let sender = addr("alice@rv.com");
        let recipient = addr("bob@rv.com");
        let (ids, idp) = id_keypair();
        let (rsk, rpub) = mail_keypair();
        let rtag = RoutingTag::generate().unwrap();
        let mut raw = seal_test(&sender, &recipient, "s", "b", &ids, &idp, &rpub, rtag.tag());
        raw[40] ^= 0x01; // inside eph_pub; also bound as AAD
        assert_eq!(open(&raw, &rsk, &recipient), Err(MailError::DecryptFailed));
    }

    #[test]
    fn wrong_recipient_key_cannot_open() {
        let sender = addr("alice@rv.com");
        let recipient = addr("bob@rv.com");
        let (ids, idp) = id_keypair();
        let (_rsk, rpub) = mail_keypair();
        let (wrong_sk, _) = mail_keypair();
        let rtag = RoutingTag::generate().unwrap();
        let raw = seal_test(&sender, &recipient, "s", "b", &ids, &idp, &rpub, rtag.tag());
        assert_eq!(
            open(&raw, &wrong_sk, &recipient),
            Err(MailError::DecryptFailed)
        );
    }

    #[test]
    fn wrong_expected_address_fails_closed() {
        let sender = addr("alice@rv.com");
        let recipient = addr("bob@rv.com");
        let other = addr("mallory@rv.com");
        let (ids, idp) = id_keypair();
        let (rsk, rpub) = mail_keypair();
        let rtag = RoutingTag::generate().unwrap();
        let raw = seal_test(&sender, &recipient, "s", "b", &ids, &idp, &rpub, rtag.tag());
        assert_eq!(open(&raw, &rsk, &other), Err(MailError::WrongRecipient));
    }

    #[test]
    fn mismatched_sender_keypair_fails_signature() {
        // Sign with A's secret but claim B's public: verification must fail.
        let sender = addr("alice@rv.com");
        let recipient = addr("bob@rv.com");
        let (ids_a, _) = id_keypair();
        let (_, idp_b) = id_keypair();
        let (rsk, rpub) = mail_keypair();
        let rtag = RoutingTag::generate().unwrap();
        let raw = seal(
            &sender, &recipient, "s", "b", 1, &ids_a, &idp_b, &rpub, rtag.tag(),
        )
        .unwrap();
        assert_eq!(open(&raw, &rsk, &recipient), Err(MailError::BadSignature));
    }

    #[test]
    fn low_order_recipient_point_rejected() {
        let sender = addr("alice@rv.com");
        let recipient = addr("bob@rv.com");
        let (ids, idp) = id_keypair();
        let rtag = RoutingTag::generate().unwrap();
        // All-zero point.
        let zero = MailPublicKey::from_bytes([0u8; 32]);
        assert_eq!(
            seal(&sender, &recipient, "s", "b", 1, &ids, &idp, &zero, rtag.tag()),
            Err(MailError::LowOrderKey)
        );
        // u = 1: a genuine low-order X25519 point.
        let mut one = [0u8; 32];
        one[0] = 1;
        let low = MailPublicKey::from_bytes(one);
        assert_eq!(
            seal(&sender, &recipient, "s", "b", 1, &ids, &idp, &low, rtag.tag()),
            Err(MailError::LowOrderKey)
        );
    }

    #[test]
    fn oversized_subject_rejected() {
        let sender = addr("alice@rv.com");
        let recipient = addr("bob@rv.com");
        let (ids, idp) = id_keypair();
        let (_, rpub) = mail_keypair();
        let rtag = RoutingTag::generate().unwrap();
        let big: String = "x".repeat(201);
        assert_eq!(
            seal(&sender, &recipient, &big, "b", 1, &ids, &idp, &rpub, rtag.tag()),
            Err(MailError::TooLarge)
        );
        // Exactly 200 chars is fine.
        let ok: String = "y".repeat(200);
        assert!(seal(&sender, &recipient, &ok, "b", 1, &ids, &idp, &rpub, rtag.tag()).is_ok());
    }

    #[test]
    fn oversized_body_rejected() {
        let sender = addr("alice@rv.com");
        let recipient = addr("bob@rv.com");
        let (ids, idp) = id_keypair();
        let (_, rpub) = mail_keypair();
        let rtag = RoutingTag::generate().unwrap();
        let big = "z".repeat(MAX_BODY_BYTES + 1);
        assert_eq!(
            seal(&sender, &recipient, "s", &big, 1, &ids, &idp, &rpub, rtag.tag()),
            Err(MailError::TooLarge)
        );
    }

    #[test]
    fn malformed_packet_table() {
        let sender = addr("alice@rv.com");
        let recipient = addr("bob@rv.com");
        let (ids, idp) = id_keypair();
        let (_, rpub) = mail_keypair();
        let rtag = RoutingTag::generate().unwrap();
        let raw = seal_test(&sender, &recipient, "s", "b", &ids, &idp, &rpub, rtag.tag());

        // Bad magic.
        let mut m = raw.clone();
        m[0] = b'X';
        assert_eq!(RelayPacket::decode(&m), Err(MailError::Malformed));
        // Bad version.
        let mut m = raw.clone();
        m[4] = 0x02;
        assert_eq!(RelayPacket::decode(&m), Err(MailError::Malformed));
        // Truncations at several cut points.
        for cut in [0usize, 10, 84, 85, 100, raw.len() - 1] {
            assert_eq!(
                RelayPacket::decode(&raw[..cut]),
                Err(MailError::Malformed),
                "cut at {}",
                cut
            );
        }
        // Trailing garbage.
        let mut m = raw.clone();
        m.push(0x00);
        assert_eq!(RelayPacket::decode(&m), Err(MailError::Malformed));
        // Lying ct_len (claims more than present).
        let mut m = raw.clone();
        let claimed = (m.len() as u32) + 100;
        m[81..85].copy_from_slice(&claimed.to_be_bytes());
        assert_eq!(RelayPacket::decode(&m), Err(MailError::Malformed));
        // Empty.
        assert_eq!(RelayPacket::decode(&[]), Err(MailError::Malformed));
        // Oversize.
        assert_eq!(
            RelayPacket::decode(&vec![0u8; MAX_PACKET_BYTES + 1]),
            Err(MailError::TooLarge)
        );
        // Round-trip through encode/decode.
        let p = RelayPacket::decode(&raw).unwrap();
        assert_eq!(p.encode(), raw);
    }

    #[test]
    fn relay_submit_collect_roundtrip() {
        let sender = addr("alice@rv.com");
        let recipient = addr("bob@rv.com");
        let (ids, idp) = id_keypair();
        let (rsk, rpub) = mail_keypair();
        let rtag = RoutingTag::generate().unwrap();
        let raw = seal_test(&sender, &recipient, "hey", "packet one", &ids, &idp, &rpub, rtag.tag());
        let raw2 = seal_test(&sender, &recipient, "hey2", "packet two", &ids, &idp, &rpub, rtag.tag());

        let mut relay = BlindRelay::new();
        relay.submit(&raw).unwrap();
        relay.submit(&raw2).unwrap();
        assert_eq!(relay.queue_len(rtag.tag()), 2);

        let got = relay.collect(rtag.secret());
        assert_eq!(got.len(), 2);
        // Drained: second collect is empty.
        assert!(relay.collect(rtag.secret()).is_empty());

        let opened = open(&got[0], &rsk, &recipient).unwrap();
        assert_eq!(opened.body, "packet one");
        let opened2 = open(&got[1], &rsk, &recipient).unwrap();
        assert_eq!(opened2.body, "packet two");
    }

    #[test]
    fn wrong_proof_gives_no_oracle() {
        let mut relay = BlindRelay::new();
        // Never-used tag: empty.
        let fresh = random32().unwrap();
        assert!(relay.collect(&fresh).is_empty());
        // Submit one real packet, then collect with a wrong proof: also empty,
        // indistinguishable from the never-used case.
        let sender = addr("alice@rv.com");
        let recipient = addr("bob@rv.com");
        let (ids, idp) = id_keypair();
        let (_, rpub) = mail_keypair();
        let rtag = RoutingTag::generate().unwrap();
        let raw = seal_test(&sender, &recipient, "s", "b", &ids, &idp, &rpub, rtag.tag());
        relay.submit(&raw).unwrap();
        let wrong = random32().unwrap();
        assert!(relay.collect(&wrong).is_empty());
        // The real mailbox is untouched.
        assert_eq!(relay.queue_len(rtag.tag()), 1);
    }

    #[test]
    fn queue_cap_evicts_oldest() {
        let sender = addr("alice@rv.com");
        let recipient = addr("bob@rv.com");
        let (ids, idp) = id_keypair();
        let (_, rpub) = mail_keypair();
        let rtag = RoutingTag::generate().unwrap();
        // Rate limiter with a huge budget so only the cap is exercised.
        let mut relay = BlindRelay::with_limits(1_000_000, 1, 100_000);
        for i in 0..(MAX_QUEUE + 5) {
            let raw = seal_test(
                &sender, &recipient, "s", &format!("msg {}", i),
                &ids, &idp, &rpub, rtag.tag(),
            );
            relay.submit(&raw).unwrap();
        }
        assert_eq!(relay.queue_len(rtag.tag()), MAX_QUEUE);
    }

    #[test]
    fn relay_rejects_malformed_submit() {
        let mut relay = BlindRelay::new();
        assert_eq!(relay.submit(b"garbage"), Err(MailError::Malformed));
        assert_eq!(relay.submit(&[]), Err(MailError::Malformed));
    }

    #[test]
    fn rate_limit_trips() {
        let sender = addr("alice@rv.com");
        let recipient = addr("bob@rv.com");
        let (ids, idp) = id_keypair();
        let (_, rpub) = mail_keypair();
        let rtag = RoutingTag::generate().unwrap();
        // Tiny budget: 2 units/second.
        let mut relay = BlindRelay::with_limits(2, 60, 100);
        for _ in 0..2 {
            let raw = seal_test(&sender, &recipient, "s", "b", &ids, &idp, &rpub, rtag.tag());
            relay.submit(&raw).unwrap();
        }
        let raw = seal_test(&sender, &recipient, "s", "b", &ids, &idp, &rpub, rtag.tag());
        assert_eq!(relay.submit(&raw), Err(MailError::RateLimited));
    }

    #[test]
    fn routing_tag_derive_is_deterministic() {
        let secret = random32().unwrap();
        assert_eq!(RoutingTag::derive(&secret), RoutingTag::derive(&secret));
        let other = random32().unwrap();
        assert_ne!(RoutingTag::derive(&secret), RoutingTag::derive(&other));
    }

    #[test]
    fn relay_sees_no_plaintext() {
        // The relay's whole view of a packet must contain no address,
        // subject, or body bytes. Sliding-window scan, like the HYDRA test.
        let sender = addr("alice@rv.com");
        let recipient = addr("bob@rv.com");
        let subject = "secret-subject-xyz-123";
        let body = "secret-body-abc-789-unique";
        let (ids, idp) = id_keypair();
        let (_, rpub) = mail_keypair();
        let rtag = RoutingTag::generate().unwrap();
        let raw = seal_test(&sender, &recipient, subject, body, &ids, &idp, &rpub, rtag.tag());

        let needles: &[&[u8]] = &[
            b"alice@rv.com",
            b"bob@rv.com",
            b"alice",
            b"bob",
            subject.as_bytes(),
            body.as_bytes(),
        ];
        for needle in needles {
            // Sliding window: does `needle` appear anywhere in `raw`?
            let found = raw
                .windows(needle.len())
                .any(|w| w == *needle);
            assert!(!found, "relay-visible bytes leak: {:?}", needle);
        }
    }

    #[test]
    fn mail_secret_debug_is_redacted() {
        let sk = MailSecretKey::generate().unwrap();
        let d = format!("{:?}", sk);
        assert!(!d.contains(&hex_lower(&sk.0)));
        assert!(d.contains("redacted"));
    }

    #[test]
    fn error_display_coverage() {
        for e in [
            MailError::BadAddress,
            MailError::BadSignature,
            MailError::DecryptFailed,
            MailError::Malformed,
            MailError::TooLarge,
            MailError::WrongRecipient,
            MailError::RateLimited,
            MailError::EntropyUnavailable,
            MailError::LowOrderKey,
        ] {
            let s = format!("{}", e);
            assert!(!s.is_empty());
            let _: &dyn std::error::Error = &e;
        }
    }
}
