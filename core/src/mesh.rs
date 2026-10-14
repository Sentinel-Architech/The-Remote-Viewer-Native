//! Peer-to-peer mesh networking core: link framing, channel
//! orchestration, local discovery, offline queueing, walkie-talkie
//! voice, and blind-relay onion routing.
//!
//! Pure Rust, std-only. The core NEVER touches sockets: every network
//! byte flows through the [`Transport`](crate::transport::Transport)
//! trait, implemented by the platform. All bytes crossing that trait
//! are already-encrypted sealed frames or onion packets — plaintext
//! never reaches the transport (see the trait's hard invariant).
//!
//! ## Zero-delay live path
//!
//! Real-time communication (chat, calls, voice) moves with ZERO
//! artificial delay: [`MeshNode::send_data`] seals and hands the frame
//! to the transport synchronously, and [`MeshNode::poll`] drains every
//! pending inbound frame in a tight loop with no sleeps, timers, or
//! batching. The [`OfflineQueue`] exists ONLY for peers that are
//! unreachable — it is never a delay mechanism for the live path.
//!
//! ## Walkie-talkie fallback
//!
//! When peers are too far for a direct real-time link, voice messages
//! fall back to push-to-talk store-and-forward: [`MeshNode::send_voice`]
//! chunks audio (opaque bytes — the platform encodes, e.g. Opus),
//! seals each chunk with the same [`SecureChannel`](crate::transport::SecureChannel)
//! encryption as everything else, and queues chunks while the peer is
//! unreachable. Chunks reassemble on arrival; the receiver gets a
//! [`MeshEvent::VoiceMessageComplete`] with the full audio.
//!
//! ## Blind relay (scaffold)
//!
//! [`OnionPacket`] implements 2+ hop onion routing: each relay learns
//! only the next hop and sees an opaque blob — never the sender,
//! recipient, or content. The relay *network* (node selection,
//! incentives, wide-area routing) is future work; this module is the
//! protocol design plus the core seal/open logic, fully tested.
//!
//! NOT externally audited. Do not rely on this for production secrets
//! until the independent cryptographic audit happens.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};

use crate::crypto::chacha20poly1305;
use crate::crypto::ed25519::PublicKey;
use crate::qr::{self, ContactCard};
use crate::transport::{
    self, AdvertError, IdentityKey, InitiatorHandshake, PeerAdvert, PeerId, PeerStatus,
    SecureChannel, Transport, REKEY_BLOB_LEN,
};

/// Errors from the mesh layer. All failures are closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MeshError {
    /// OS entropy unavailable.
    EntropyUnavailable,
    /// Link frame failed structural checks.
    MalformedLink,
    /// Unknown link-frame kind byte.
    UnknownLinkKind,
    /// Link frame exceeds [`MAX_LINK_FRAME`].
    OversizedFrame,
    /// The peer is not a pinned contact (QR-paired). Handshakes from
    /// strangers are ignored, never answered.
    UnknownPeer,
    /// No established channel to this peer yet.
    ChannelNotReady,
    /// The offline queue file is corrupt (it was quarantined).
    QueueCorrupt,
    /// Per-peer or total queue caps hit; message dropped, sender told.
    QueueFull,
    /// Voice chunk or assembled message exceeds caps.
    VoiceTooLarge,
    /// Onion packet failed structural or cryptographic checks.
    RelayFailed,
    /// A QR pairing attempt failed.
    PairFailed,
}

impl std::fmt::Display for MeshError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            MeshError::EntropyUnavailable => "OS entropy unavailable",
            MeshError::MalformedLink => "malformed link frame",
            MeshError::UnknownLinkKind => "unknown link-frame kind",
            MeshError::OversizedFrame => "link frame too large",
            MeshError::UnknownPeer => "peer is not a pinned contact",
            MeshError::ChannelNotReady => "no channel to peer yet",
            MeshError::QueueCorrupt => "offline queue was corrupt (quarantined)",
            MeshError::QueueFull => "offline queue full",
            MeshError::VoiceTooLarge => "voice message too large",
            MeshError::RelayFailed => "onion packet rejected",
            MeshError::PairFailed => "QR pairing failed",
        };
        f.write_str(s)
    }
}

impl std::error::Error for MeshError {}

impl From<AdvertError> for MeshError {
    fn from(_: AdvertError) -> Self {
        MeshError::PairFailed
    }
}

impl From<qr::QrError> for MeshError {
    fn from(_: qr::QrError) -> Self {
        MeshError::PairFailed
    }
}

// =====================================================================
// Link framing
// =====================================================================

/// Magic opening every link frame on the wire.
const LINK_MAGIC: &[u8; 4] = b"TRVL";
/// Link protocol version.
const LINK_VERSION: u8 = 0x01;
/// Maximum link frame: 64 KiB. Voice chunks are 4 KiB; onion layers add
/// modest overhead. Anything bigger is refused, not truncated.
pub const MAX_LINK_FRAME: usize = 65536;

/// Link-frame kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum LinkKind {
    HandshakeHello = 0x01,
    HandshakeResponse = 0x02,
    Data = 0x03,
    RekeyOffer = 0x04,
    RekeyAccept = 0x05,
    Voice = 0x06,
}

impl LinkKind {
    fn from_u8(b: u8) -> Result<Self, MeshError> {
        match b {
            0x01 => Ok(LinkKind::HandshakeHello),
            0x02 => Ok(LinkKind::HandshakeResponse),
            0x03 => Ok(LinkKind::Data),
            0x04 => Ok(LinkKind::RekeyOffer),
            0x05 => Ok(LinkKind::RekeyAccept),
            0x06 => Ok(LinkKind::Voice),
            _ => Err(MeshError::UnknownLinkKind),
        }
    }
}

/// Encode a link frame: `TRVL(4) || version(1) || kind(1) || len_be(4) || payload`.
fn encode_link(kind: LinkKind, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(10 + payload.len());
    out.extend_from_slice(LINK_MAGIC);
    out.push(LINK_VERSION);
    out.push(kind as u8);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Decode a link frame. Fails closed on any structural problem.
fn decode_link(bytes: &[u8]) -> Result<(LinkKind, Vec<u8>), MeshError> {
    if bytes.len() > MAX_LINK_FRAME {
        return Err(MeshError::OversizedFrame);
    }
    if bytes.len() < 10 {
        return Err(MeshError::MalformedLink);
    }
    if &bytes[..4] != LINK_MAGIC {
        return Err(MeshError::MalformedLink);
    }
    if bytes[4] != LINK_VERSION {
        return Err(MeshError::MalformedLink);
    }
    let kind = LinkKind::from_u8(bytes[5])?;
    let mut len = [0u8; 4];
    len.copy_from_slice(&bytes[6..10]);
    let len = u32::from_be_bytes(len) as usize;
    if bytes.len() != 10 + len {
        return Err(MeshError::MalformedLink);
    }
    Ok((kind, bytes[10..].to_vec()))
}

// =====================================================================
// Offline queue: encrypted, persistent, expiring
// =====================================================================

/// Magic for the queue file.
const QUEUE_MAGIC: &[u8; 4] = b"TRVQ";
/// Queue file version.
const QUEUE_VERSION: u8 = 0x01;
/// Queued messages live this long, then the sender is notified of
/// non-delivery. 7 days: long enough for peers to wander back into
/// proximity, short enough to bound storage.
pub const QUEUE_TTL_SECS: u64 = 7 * 24 * 3600;
/// Per-peer cap: bounds memory and disk against a runaway sender.
pub const MAX_QUEUED_PER_PEER: usize = 500;
/// Total queue cap across all peers.
pub const MAX_QUEUED_TOTAL: usize = 5000;
/// AAD binding queue ciphertext to this format.
const QUEUE_AAD: &[u8] = b"TRV-OFFLINE-QUEUE-v1";

/// What kind of payload a queued entry carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QueueKind {
    Data = 0x01,
    Voice = 0x02,
}

impl QueueKind {
    fn from_u8(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(QueueKind::Data),
            0x02 => Some(QueueKind::Voice),
            _ => None,
        }
    }
}

/// One queued outbound message.
#[derive(Debug, Clone)]
pub struct QueuedMessage {
    /// Intended recipient.
    pub peer: PeerId,
    /// Data or voice.
    kind: QueueKind,
    /// Caller-supplied enqueue time (Unix seconds).
    pub enqueued_at: u64,
    /// 16-byte id for sender notification on expiry.
    pub id: [u8; 16],
    /// The sealed payload bytes (link-frame payload, already encrypted).
    pub payload: Vec<u8>,
}

/// Encrypted-at-rest persistent queue for unreachable peers.
///
/// The whole queue file is one ChaCha20-Poly1305 ciphertext under a
/// caller-supplied 32-byte device key. Writes are atomic
/// (temp + fsync + rename). A corrupt file is quarantined, never
/// silently dropped.
pub struct OfflineQueue {
    path: PathBuf,
    key: [u8; 32],
    entries: Vec<QueuedMessage>,
}

impl std::fmt::Debug for OfflineQueue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OfflineQueue")
            .field("path", &self.path)
            .field("entries", &self.entries.len())
            .finish()
    }
}

impl OfflineQueue {
    /// Open (or create) the queue at `dir/queue.trvqueue`, decrypting
    /// with `key`. A corrupt file is quarantined to
    /// `queue.trvqueue.corrupt-<nanos>` and the queue starts empty.
    pub fn open(dir: &Path, key: &[u8; 32]) -> Result<Self, MeshError> {
        let path = dir.join("queue.trvqueue");
        let mut q = Self {
            path,
            key: *key,
            entries: Vec::new(),
        };
        if q.path.exists() {
            match Self::load_file(&q.path, &q.key) {
                Ok(entries) => q.entries = entries,
                Err(_) => {
                    let stamp = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_nanos())
                        .unwrap_or(0);
                    let quarantine = q.path.with_extension(format!("corrupt-{stamp}"));
                    let _ = std::fs::rename(&q.path, &quarantine);
                    q.entries = Vec::new();
                }
            }
        }
        Ok(q)
    }

    fn load_file(path: &Path, key: &[u8; 32]) -> Result<Vec<QueuedMessage>, MeshError> {
        let bytes = std::fs::read(path).map_err(|_| MeshError::QueueCorrupt)?;
        if bytes.len() < 4 + 1 + 12 + 16 {
            return Err(MeshError::QueueCorrupt);
        }
        if &bytes[..4] != QUEUE_MAGIC || bytes[4] != QUEUE_VERSION {
            return Err(MeshError::QueueCorrupt);
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&bytes[5..17]);
        let pt = chacha20poly1305::decrypt(key, &nonce, QUEUE_AAD, &bytes[17..])
            .map_err(|_| MeshError::QueueCorrupt)?;
        Self::parse_entries(&pt)
    }

    fn parse_entries(pt: &[u8]) -> Result<Vec<QueuedMessage>, MeshError> {
        if pt.len() < 4 {
            return Err(MeshError::QueueCorrupt);
        }
        let mut n = [0u8; 4];
        n.copy_from_slice(&pt[..4]);
        let count = u32::from_be_bytes(n) as usize;
        if count > MAX_QUEUED_TOTAL {
            return Err(MeshError::QueueCorrupt);
        }
        let mut entries = Vec::with_capacity(count);
        let mut pos = 4;
        for _ in 0..count {
            // peer(32) || kind(1) || enqueued_at(8) || id(16) || len(4) || payload
            if pt.len() < pos + 32 + 1 + 8 + 16 + 4 {
                return Err(MeshError::QueueCorrupt);
            }
            let mut peer = [0u8; 32];
            peer.copy_from_slice(&pt[pos..pos + 32]);
            pos += 32;
            let kind = QueueKind::from_u8(pt[pos]).ok_or(MeshError::QueueCorrupt)?;
            pos += 1;
            let mut ts = [0u8; 8];
            ts.copy_from_slice(&pt[pos..pos + 8]);
            let enqueued_at = u64::from_be_bytes(ts);
            pos += 8;
            let mut id = [0u8; 16];
            id.copy_from_slice(&pt[pos..pos + 16]);
            pos += 16;
            let mut lb = [0u8; 4];
            lb.copy_from_slice(&pt[pos..pos + 4]);
            let len = u32::from_be_bytes(lb) as usize;
            pos += 4;
            if len > MAX_LINK_FRAME || pt.len() < pos + len {
                return Err(MeshError::QueueCorrupt);
            }
            let payload = pt[pos..pos + len].to_vec();
            pos += len;
            entries.push(QueuedMessage {
                peer: PeerId(peer),
                kind,
                enqueued_at,
                id,
                payload,
            });
        }
        if pos != pt.len() {
            return Err(MeshError::QueueCorrupt);
        }
        Ok(entries)
    }

    fn persist(&self) -> Result<(), MeshError> {
        let mut pt = Vec::new();
        pt.extend_from_slice(&(self.entries.len() as u32).to_be_bytes());
        for e in &self.entries {
            pt.extend_from_slice(e.peer.as_bytes());
            pt.push(e.kind as u8);
            pt.extend_from_slice(&e.enqueued_at.to_be_bytes());
            pt.extend_from_slice(&e.id);
            pt.extend_from_slice(&(e.payload.len() as u32).to_be_bytes());
            pt.extend_from_slice(&e.payload);
        }
        let mut nonce = [0u8; 12];
        {
            use std::io::Read;
            std::fs::File::open("/dev/urandom")
                .and_then(|mut f| f.read_exact(&mut nonce))
                .map_err(|_| MeshError::EntropyUnavailable)?;
        }
        let ct = chacha20poly1305::encrypt(&self.key, &nonce, QUEUE_AAD, &pt);
        let mut out = Vec::with_capacity(17 + ct.len());
        out.extend_from_slice(QUEUE_MAGIC);
        out.push(QUEUE_VERSION);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let tmp = self.path.with_extension("tmp");
        {
            use std::io::Write;
            let mut f = std::fs::File::create(&tmp).map_err(|_| MeshError::QueueCorrupt)?;
            f.write_all(&out).map_err(|_| MeshError::QueueCorrupt)?;
            f.sync_all().map_err(|_| MeshError::QueueCorrupt)?;
        }
        std::fs::rename(&tmp, &self.path).map_err(|_| MeshError::QueueCorrupt)?;
        Ok(())
    }

    /// Queue a payload for an unreachable peer. The payload is stored
    /// RAW (it is sealed at flush time, exactly once); at rest it is
    /// protected by the queue cipher. Fails when the per-peer or total
    /// caps are hit (the sender must be told).
    pub fn enqueue(
        &mut self,
        peer: &PeerId,
        id: &[u8; 16],
        payload: Vec<u8>,
        is_voice: bool,
        now_secs: u64,
    ) -> Result<(), MeshError> {
        self.enqueue_at(peer, id, payload, is_voice, now_secs)
    }

    /// [`OfflineQueue::enqueue`] with an explicit enqueue timestamp
    /// (used when re-queueing after a failed flush, preserving the
    /// original time for expiry accounting).
    pub fn enqueue_at(
        &mut self,
        peer: &PeerId,
        id: &[u8; 16],
        payload: Vec<u8>,
        is_voice: bool,
        enqueued_at: u64,
    ) -> Result<(), MeshError> {
        if payload.len() > MAX_LINK_FRAME {
            return Err(MeshError::OversizedFrame);
        }
        let per_peer = self.entries.iter().filter(|e| &e.peer == peer).count();
        if per_peer >= MAX_QUEUED_PER_PEER || self.entries.len() >= MAX_QUEUED_TOTAL {
            return Err(MeshError::QueueFull);
        }
        self.entries.push(QueuedMessage {
            peer: *peer,
            kind: if is_voice { QueueKind::Voice } else { QueueKind::Data },
            enqueued_at,
            id: *id,
            payload,
        });
        self.persist()
    }

    /// Remove and return everything queued for `peer`, oldest first.
    /// The caller transmits each immediately (zero-delay flush).
    pub fn drain_for_peer(&mut self, peer: &PeerId) -> Vec<QueuedMessage> {
        let mut out = Vec::new();
        let mut rest = Vec::new();
        for e in self.entries.drain(..) {
            if &e.peer == peer {
                out.push(e);
            } else {
                rest.push(e);
            }
        }
        self.entries = rest;
        let _ = self.persist();
        out
    }

    /// Remove and return entries older than [`QUEUE_TTL_SECS`]. The
    /// caller notifies the sender of non-delivery for each.
    pub fn collect_expired(&mut self, now_secs: u64) -> Vec<QueuedMessage> {
        let mut expired = Vec::new();
        let mut rest = Vec::new();
        for e in self.entries.drain(..) {
            if now_secs.saturating_sub(e.enqueued_at) > QUEUE_TTL_SECS {
                expired.push(e);
            } else {
                rest.push(e);
            }
        }
        self.entries = rest;
        let _ = self.persist();
        expired
    }

    /// Number of queued entries (for tests/monitoring).
    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }
}

// =====================================================================
// Walkie-talkie voice: chunked, encrypted, store-and-forward
// =====================================================================

/// Maximum audio bytes per voice chunk (fits comfortably in one link frame).
pub const MAX_VOICE_CHUNK: usize = 4096;
/// Maximum assembled voice message: ~1 MiB (about a minute of Opus).
pub const MAX_VOICE_TOTAL: usize = 1024 * 1024;
/// Maximum concurrent voice reassemblies per node (bounds memory).
const MAX_VOICE_ASSEMBLIES: usize = 16;

/// One chunk of a push-to-talk voice message. Audio bytes are opaque
/// to the core (the platform encodes, e.g. Opus); they travel sealed
/// inside the [`SecureChannel`](crate::transport::SecureChannel) like
/// every other payload, and queue identically when the peer is
/// unreachable.
///
/// Wire: `msg_id(16) || seq_be(4) || total_be(4) || audio_len_be(4) || audio`.
#[derive(Debug, Clone)]
pub struct VoiceChunk {
    /// 16-byte id binding all chunks of one voice message.
    pub msg_id: [u8; 16],
    /// This chunk's index.
    pub seq: u32,
    /// Total chunks in the message.
    pub total: u32,
    /// Opaque encoded audio bytes.
    pub audio: Vec<u8>,
}

impl VoiceChunk {
    /// Serialize. Fails closed on oversize audio or nonsense counts.
    pub fn to_bytes(&self) -> Result<Vec<u8>, MeshError> {
        if self.audio.len() > MAX_VOICE_CHUNK || self.total == 0 || self.seq >= self.total {
            return Err(MeshError::VoiceTooLarge);
        }
        if (self.total as usize) * MAX_VOICE_CHUNK > MAX_VOICE_TOTAL {
            return Err(MeshError::VoiceTooLarge);
        }
        let mut out = Vec::with_capacity(28 + self.audio.len());
        out.extend_from_slice(&self.msg_id);
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.total.to_be_bytes());
        out.extend_from_slice(&(self.audio.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.audio);
        Ok(out)
    }

    /// Parse. Fails closed on any structural problem.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MeshError> {
        if bytes.len() < 28 {
            return Err(MeshError::MalformedLink);
        }
        let mut msg_id = [0u8; 16];
        msg_id.copy_from_slice(&bytes[..16]);
        let mut b4 = [0u8; 4];
        b4.copy_from_slice(&bytes[16..20]);
        let seq = u32::from_be_bytes(b4);
        b4.copy_from_slice(&bytes[20..24]);
        let total = u32::from_be_bytes(b4);
        b4.copy_from_slice(&bytes[24..28]);
        let audio_len = u32::from_be_bytes(b4) as usize;
        if bytes.len() != 28 + audio_len || audio_len > MAX_VOICE_CHUNK {
            return Err(MeshError::MalformedLink);
        }
        if total == 0 || seq >= total || (total as usize) * MAX_VOICE_CHUNK > MAX_VOICE_TOTAL {
            return Err(MeshError::VoiceTooLarge);
        }
        Ok(Self {
            msg_id,
            seq,
            total,
            audio: bytes[28..].to_vec(),
        })
    }
}

/// Reassembly state for one inbound voice message.
struct VoiceAssembly {
    total: u32,
    chunks: Vec<Option<Vec<u8>>>,
    received: u32,
}

// =====================================================================
// Blind relay: onion-routed store-and-forward (protocol scaffold)
// =====================================================================

/// AAD binding onion layers to this format.
const ONION_AAD: &[u8] = b"TRV-ONION-v1";
/// Maximum onion hops (2 required minimum per spec; 4 cap bounds work).
pub const MAX_ONION_HOPS: usize = 4;
/// Maximum plaintext message inside an onion packet.
pub const MAX_ONION_MESSAGE: usize = 32768;
/// Next-hop value meaning "this layer is the final delivery".
const ONION_FINAL: [u8; 32] = [0u8; 32];

/// One relay hop: where to send next, and the hop's X25519 onion key
/// (published in its [`PeerAdvert`]).
#[derive(Debug, Clone)]
pub struct RelayHop {
    /// The relay's identity.
    pub peer: PeerId,
    /// The relay's X25519 onion public key.
    pub onion_pub: [u8; 32],
}

/// What a relay (or final recipient) does with an onion packet.
#[derive(Debug)]
pub enum RelayAction {
    /// Forward the inner packet to the next hop. The relay learns
    /// NOTHING else: not the sender, not the recipient, not the content.
    Forward {
        /// Next hop's identity.
        next: PeerId,
        /// Opaque inner packet bytes.
        packet: Vec<u8>,
    },
    /// This node is the final recipient.
    Deliver {
        /// Original sender's identity (sealed inside the innermost layer).
        sender: PeerId,
        /// The plaintext message.
        message: Vec<u8>,
    },
}

/// 12 random bytes, or [`MeshError::EntropyUnavailable`].
fn random12() -> Result<[u8; 12], MeshError> {
    let b = transport::random32().map_err(|_| MeshError::EntropyUnavailable)?;
    let mut out = [0u8; 12];
    out.copy_from_slice(&b[..12]);
    Ok(out)
}

/// Seal one onion layer: `eph_pub(32) || nonce(12) || ct`, where `ct`
/// is ChaCha20-Poly1305 over `next_hop(32) || inner` under
/// `X25519(eph_secret, hop_pub)`. Fresh ephemeral per layer.
fn seal_onion_layer(
    hop_pub: &[u8; 32],
    next: &[u8; 32],
    inner: &[u8],
) -> Result<Vec<u8>, MeshError> {
    let secret = transport::random32().map_err(|_| MeshError::EntropyUnavailable)?;
    let eph_pub = transport::x25519(&secret, &transport::BASE_POINT);
    let key = transport::x25519(&secret, hop_pub);
    // Wipe the local ephemeral secret copy.
    let mut secret = secret;
    transport::wipe(&mut secret);
    let nonce = random12()?;
    let mut pt = Vec::with_capacity(32 + inner.len());
    pt.extend_from_slice(next);
    pt.extend_from_slice(inner);
    let ct = chacha20poly1305::encrypt(&key, &nonce, ONION_AAD, &pt);
    let mut out = Vec::with_capacity(44 + ct.len());
    out.extend_from_slice(&eph_pub);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Namespace for onion packet construction.
pub struct OnionPacket;

impl OnionPacket {
    /// Build a 2+ hop onion packet. `path` is ordered [first relay,
    /// ..., last relay]; the last relay forwards to `recipient`.
    /// The innermost layer is sealed to the recipient's onion key and
    /// carries `sender || message`; every relay layer carries only
    /// `next_hop || inner_blob`.
    pub fn build(
        message: &[u8],
        sender: &PeerId,
        recipient: &PeerId,
        recipient_onion_pub: &[u8; 32],
        path: &[RelayHop],
    ) -> Result<Vec<u8>, MeshError> {
        if message.len() > MAX_ONION_MESSAGE {
            return Err(MeshError::VoiceTooLarge);
        }
        if path.len() < 2 || path.len() > MAX_ONION_HOPS {
            return Err(MeshError::RelayFailed);
        }
        // Innermost: sealed to the recipient; next == FINAL.
        let mut inner_pt = Vec::with_capacity(32 + message.len());
        inner_pt.extend_from_slice(sender.as_bytes());
        inner_pt.extend_from_slice(message);
        let mut packet = seal_onion_layer(recipient_onion_pub, &ONION_FINAL, &inner_pt)?;
        // Wrap in relay layers, inside out. The last relay's next hop
        // is the recipient; earlier relays point at the next relay.
        let mut next = *recipient.as_bytes();
        for hop in path.iter().rev() {
            packet = seal_onion_layer(&hop.onion_pub, &next, &packet)?;
            next = *hop.peer.as_bytes();
        }
        Ok(packet)
    }
}

/// Peel one onion layer with this node's onion secret. Returns what to
/// do next. The caller forwards [`RelayAction::Forward`] packets via
/// its [`Transport`] and delivers [`RelayAction::Deliver`] locally.
///
/// Privacy invariant: a relay's view is exactly `(next_hop, opaque_blob)`.
/// It learns nothing about the sender, the final recipient, or the
/// content — the tests assert this by byte-scanning the relay's view.
pub fn relay_open(onion_secret: &[u8; 32], packet: &[u8]) -> Result<RelayAction, MeshError> {
    if packet.len() < 32 + 12 + 16 {
        return Err(MeshError::RelayFailed);
    }
    let mut eph_pub = [0u8; 32];
    eph_pub.copy_from_slice(&packet[..32]);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&packet[32..44]);
    let key = transport::x25519(onion_secret, &eph_pub);
    let pt = chacha20poly1305::decrypt(&key, &nonce, ONION_AAD, &packet[44..])
        .map_err(|_| MeshError::RelayFailed)?;
    if pt.len() < 32 {
        return Err(MeshError::RelayFailed);
    }
    let mut next = [0u8; 32];
    next.copy_from_slice(&pt[..32]);
    if next == ONION_FINAL {
        // Final delivery: inner is sender(32) || message.
        if pt.len() < 64 {
            return Err(MeshError::RelayFailed);
        }
        let mut sender = [0u8; 32];
        sender.copy_from_slice(&pt[32..64]);
        Ok(RelayAction::Deliver {
            sender: PeerId(sender),
            message: pt[64..].to_vec(),
        })
    } else {
        Ok(RelayAction::Forward {
            next: PeerId(next),
            packet: pt[32..].to_vec(),
        })
    }
}

// =====================================================================
// MeshNode: the orchestration layer
// =====================================================================

/// A pinned contact: someone we QR-paired with and trust.
#[derive(Debug, Clone)]
struct Contact {
    public: PublicKey,
    display_name: String,
}

/// What [`MeshNode::poll`] reports. The platform turns these into UI
/// updates, notifications, and sender callbacks.
#[derive(Debug)]
pub enum MeshEvent {
    /// A secure channel to the peer is ready (handshake or rekey done).
    /// Any queued messages were flushed immediately.
    ChannelReady(PeerId),
    /// A handshake or rekey exchange failed. Fail closed; retry is the
    /// caller's decision.
    ChannelFailed(PeerId),
    /// Link-layer payload bytes arrived for the peer. Hand them to the
    /// conversation layer (e.g. `Router::deliver_frame`) via
    /// [`MeshNode::take_inbound`].
    DataReceived(PeerId),
    /// One voice chunk arrived (for progress UI).
    VoiceChunkReceived {
        /// Who sent it.
        peer: PeerId,
        /// Which voice message.
        msg_id: [u8; 16],
        /// Chunk index / total.
        seq: u32,
        /// Chunk index / total.
        total: u32,
    },
    /// A full voice message reassembled.
    VoiceMessageComplete {
        /// Who sent it.
        peer: PeerId,
        /// Voice message id.
        msg_id: [u8; 16],
        /// The complete opaque audio bytes.
        audio: Vec<u8>,
    },
    /// A queued message expired undelivered: tell the sender.
    MessageExpired {
        /// Intended recipient.
        peer: PeerId,
        /// The expired message id.
        id: [u8; 16],
    },
    /// A new peer advert passed verification.
    PeerDiscovered(PeerId),
    /// A rekey completed; the channel moved to a fresh key epoch.
    Rekeyed(PeerId),
}

/// Maximum age of a cached discovery advert (5 minutes); the platform
/// re-beacons continuously.
const DISCOVERY_MAX_AGE_SECS: u64 = 300;
/// Maximum age of a QR contact card for pairing (24 hours).
pub const QR_MAX_AGE_SECS: u64 = 24 * 3600;

/// The mesh node: owns the identity, drives handshakes and rekeys over
/// the [`Transport`], routes sealed frames, queues for offline peers,
/// and reassembles walkie-talkie voice.
///
/// The node holds NO sockets and makes NO syscalls except
/// `/dev/urandom` (entropy, fails closed) and queue-file I/O. Time is
/// always caller-supplied (`now_secs`): there is no trusted on-device
/// clock.
pub struct MeshNode {
    identity: IdentityKey,
    own_id: PeerId,
    transport: Box<dyn Transport>,
    contacts: HashMap<PeerId, Contact>,
    channels: HashMap<PeerId, SecureChannel>,
    pending_handshakes: HashMap<PeerId, InitiatorHandshake>,
    pending_rekeys: HashMap<PeerId, transport::RekeyOffer>,
    /// Decrypted link payloads awaiting the UI, per peer.
    inbound: HashMap<PeerId, VecDeque<Vec<u8>>>,
    queue: OfflineQueue,
    onion_secret: [u8; 32],
    onion_pub: [u8; 32],
    discovery: HashMap<PeerId, (PeerAdvert, u64)>,
    voice_assembly: HashMap<(PeerId, [u8; 16]), VoiceAssembly>,
    qr_seen: HashSet<[u8; 32]>,
    own_card: Option<ContactCard>,
}

impl std::fmt::Debug for MeshNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeshNode")
            .field("own_id", &self.own_id)
            .field("contacts", &self.contacts.len())
            .field("channels", &self.channels.len())
            .finish()
    }
}

impl Drop for MeshNode {
    fn drop(&mut self) {
        transport::wipe(&mut self.onion_secret);
    }
}

impl MeshNode {
    /// Create a node. `transport` is the platform's byte pipe;
    /// `queue_dir`/`queue_key` back the encrypted offline queue.
    /// Generates a fresh X25519 onion keypair for blind-relay layers.
    pub fn new(
        identity: IdentityKey,
        transport: Box<dyn Transport>,
        queue_dir: &Path,
        queue_key: &[u8; 32],
    ) -> Result<Self, MeshError> {
        let own_id = PeerId::from_public(identity.public());
        let queue = OfflineQueue::open(queue_dir, queue_key)?;
        let onion_secret = transport::random32().map_err(|_| MeshError::EntropyUnavailable)?;
        let onion_pub = transport::x25519(&onion_secret, &transport::BASE_POINT);
        Ok(Self {
            identity,
            own_id,
            transport,
            contacts: HashMap::new(),
            channels: HashMap::new(),
            pending_handshakes: HashMap::new(),
            pending_rekeys: HashMap::new(),
            inbound: HashMap::new(),
            queue,
            onion_secret,
            onion_pub,
            discovery: HashMap::new(),
            voice_assembly: HashMap::new(),
            qr_seen: HashSet::new(),
            own_card: None,
        })
    }

    /// This node's identity.
    pub fn own_id(&self) -> PeerId {
        self.own_id
    }

    /// This node's X25519 onion public key (published in adverts).
    pub fn onion_pub(&self) -> &[u8; 32] {
        &self.onion_pub
    }

    /// Reachability of a peer, per the platform transport.
    pub fn peer_status(&self, peer: &PeerId) -> PeerStatus {
        self.transport.peer_status(peer)
    }

    /// True when a live secure channel exists to the peer.
    pub fn has_channel(&self, peer: &PeerId) -> bool {
        self.channels.contains_key(peer)
    }

    /// Display name of a pinned contact, if known.
    pub fn contact_name(&self, peer: &PeerId) -> Option<&str> {
        self.contacts.get(peer).map(|c| c.display_name.as_str())
    }

    // ---- contacts & QR pairing ----

    /// Set our own contact card, signing it with the identity key,
    /// and return its QR payload bytes for display. The card is what
    /// other users scan to pair with us.
    pub fn set_own_card(
        &mut self,
        display_name: &str,
        handle: &str,
        issued_at: u64,
    ) -> Result<Vec<u8>, MeshError> {
        let public = *self.identity.public();
        let card = ContactCard::sign_with(
            &public,
            display_name,
            handle,
            issued_at,
            &|msg| self.identity.sign(msg),
        )?;
        let bytes = card.to_qr_bytes();
        self.own_card = Some(card);
        Ok(bytes)
    }

    /// Install a pre-signed own contact card (signed by the owner with
    /// the identity secret) and return its QR payload bytes.
    pub fn set_own_card_bytes(&mut self, card_bytes: &[u8]) -> Result<Vec<u8>, MeshError> {
        let card = ContactCard::from_qr_bytes(card_bytes)?;
        card.verify()?;
        // The card must claim our own identity.
        if card.identity().as_bytes() != self.own_id.as_bytes() {
            return Err(MeshError::PairFailed);
        }
        self.own_card = Some(card);
        Ok(card_bytes.to_vec())
    }

    /// Pair via QR: verify the scanned card against our own card and
    /// pin the peer as a contact. Returns the peer's [`PeerId`].
    /// Duplicate scans in this session are rejected.
    pub fn pair_via_qr(
        &mut self,
        scanned: &[u8],
        now_secs: u64,
    ) -> Result<PeerId, MeshError> {
        let own = self.own_card.as_ref().ok_or(MeshError::PairFailed)?;
        let peer_pub = qr::verify_exchange(own, scanned, now_secs, QR_MAX_AGE_SECS, &mut self.qr_seen)?;
        let peer_id = PeerId::from_public(&peer_pub);
        // Pull display name from the verified card for the contact book.
        let card = ContactCard::from_qr_bytes(scanned)?;
        self.contacts.insert(
            peer_id,
            Contact {
                public: peer_pub,
                display_name: card.display_name().to_string(),
            },
        );
        Ok(peer_id)
    }

    /// Pin a contact directly (peer id + public key + name).
    pub fn add_contact(&mut self, peer: PeerId, public: PublicKey, display_name: &str) {
        self.contacts.insert(
            peer,
            Contact {
                public,
                display_name: display_name.to_string(),
            },
        );
    }

    /// This node's signed discovery advert bytes, for the platform to
    /// beacon over UDP/mDNS. Signed with the identity key; carries
    /// public info only.
    pub fn advert_bytes(
        &self,
        display_name: &str,
        handle: &str,
        now_secs: u64,
    ) -> Result<Vec<u8>, MeshError> {
        let public = *self.identity.public();
        let advert = PeerAdvert::sign_with(
            &public,
            display_name,
            handle,
            &self.onion_pub,
            now_secs,
            &|msg| self.identity.sign(msg),
        )?;
        Ok(advert.to_bytes())
    }

    // ---- channels ----

    /// Begin (or re-begin) the authenticated handshake with a pinned
    /// contact. The hello goes out immediately; the channel completes
    /// when the response arrives in [`MeshNode::poll`].
    pub fn open_channel(&mut self, peer: &PeerId) -> Result<(), MeshError> {
        let contact = self.contacts.get(peer).ok_or(MeshError::UnknownPeer)?;
        if self.channels.contains_key(peer) || self.pending_handshakes.contains_key(peer) {
            return Ok(()); // already up or in flight
        }
        let hs = InitiatorHandshake::new().map_err(|_| MeshError::EntropyUnavailable)?;
        let hello = hs.hello_auth(&self.identity, &contact.public);
        let frame = encode_link(LinkKind::HandshakeHello, &hello);
        self.transport
            .send_frame(peer, &frame)
            .map_err(|_| MeshError::ChannelNotReady)?;
        self.pending_handshakes.insert(*peer, hs);
        Ok(())
    }

    /// Send sealed bytes to a peer with ZERO artificial delay: if a
    /// channel is ready the frame is sealed and handed to the
    /// transport synchronously. If the peer is unreachable (no
    /// channel), the frame is encrypted-at-rest in the offline queue.
    pub fn send_data(&mut self, peer: &PeerId, bytes: &[u8], now_secs: u64) -> Result<(), MeshError> {
        // Fast path first: live channel → immediate send. This branch
        // performs no allocation-heavy work before the send and never
        // waits on anything: zero artificial delay on the live path.
        if let Some(ch) = self.channels.get_mut(peer) {
            let frame = ch.seal(bytes).map_err(|_| MeshError::ChannelNotReady)?;
            let link = encode_link(LinkKind::Data, &frame);
            match self.transport.send_frame(peer, &link) {
                Ok(()) => return Ok(()),
                Err(_) => {
                    // Hand-off failed: peer went unreachable mid-send.
                    // Queue the RAW bytes (not the link frame) so the
                    // flush path seals exactly once.
                    let mut id = [0u8; 16];
                    Self::fill_id(&mut id)?;
                    self.queue.enqueue(peer, &id, bytes.to_vec(), false, now_secs)?;
                    return Ok(());
                }
            }
        }
        // No channel: try to open one opportunistically for pinned
        // contacts, and queue meanwhile. Queueing here is NOT a delay
        // mechanism — it only happens because the peer is unreachable.
        if self.contacts.contains_key(peer)
            && !self.pending_handshakes.contains_key(peer)
            && self.transport.peer_status(peer) != PeerStatus::Offline
        {
            let _ = self.open_channel(peer);
        }
        let mut id = [0u8; 16];
        Self::fill_id(&mut id)?;
        // Seal now with a queue-local ephemeral? No — queue the
        // *plaintext-ready* link payload is wrong: it must be sealed.
        // Without a channel we cannot seal; queue the raw bytes and
        // seal at flush time. Document the invariant: queued payloads
        // are encrypted at rest by the queue cipher.
        self.queue.enqueue(peer, &id, bytes.to_vec(), false, now_secs)?;
        Ok(())
    }

    /// Send one walkie-talkie voice chunk. Same zero-delay / queue
    /// policy as [`MeshNode::send_data`].
    pub fn send_voice(&mut self, peer: &PeerId, chunk: &VoiceChunk, now_secs: u64) -> Result<(), MeshError> {
        let bytes = chunk.to_bytes()?;
        if let Some(ch) = self.channels.get_mut(peer) {
            let frame = ch.seal(&bytes).map_err(|_| MeshError::ChannelNotReady)?;
            let link = encode_link(LinkKind::Voice, &frame);
            match self.transport.send_frame(peer, &link) {
                Ok(()) => return Ok(()),
                Err(_) => {
                    let mut id = [0u8; 16];
                    Self::fill_id(&mut id)?;
                    self.queue.enqueue(peer, &id, bytes, true, now_secs)?;
                    return Ok(());
                }
            }
        }
        if self.contacts.contains_key(peer)
            && !self.pending_handshakes.contains_key(peer)
            && self.transport.peer_status(peer) != PeerStatus::Offline
        {
            let _ = self.open_channel(peer);
        }
        let mut id = [0u8; 16];
        Self::fill_id(&mut id)?;
        self.queue.enqueue(peer, &id, bytes, true, now_secs)?;
        Ok(())
    }

    fn fill_id(id: &mut [u8; 16]) -> Result<(), MeshError> {
        use std::io::Read;
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(id))
            .map_err(|_| MeshError::EntropyUnavailable)
    }

    /// Take inbound link-layer payloads buffered for `peer`. The UI
    /// calls this when a chat opens (or each pump for the active peer)
    /// and feeds each to the conversation layer.
    pub fn take_inbound(&mut self, peer: &PeerId) -> Vec<Vec<u8>> {
        self.inbound.remove(peer).map(|q| q.into()).unwrap_or_default()
    }

    /// Queued entry count (tests).
    #[cfg(test)]
    fn queue_len(&self) -> usize {
        self.queue.len()
    }

    /// Drain all pending network activity: inbound frames, discovery,
    /// rekey triggers, queue expiry. Processes everything available
    /// RIGHT NOW — no sleeps, no batching timers, no artificial delay.
    pub fn poll(&mut self, now_secs: u64) -> Vec<MeshEvent> {
        let mut events = Vec::new();
        // 1. Drain inbound frames (tight loop, non-blocking).
        while let Some((from, bytes)) = self.transport.recv_frame() {
            self.handle_link_frame(&from, &bytes, now_secs, &mut events);
        }
        // 2. Discovery sweep.
        for advert in self.transport.discover_peers() {
            let pid = advert.peer_id();
            if pid == self.own_id {
                continue;
            }
            let fresh = now_secs.saturating_sub(advert.issued_at()) <= DISCOVERY_MAX_AGE_SECS;
            if !fresh {
                continue;
            }
            let is_new = !self.discovery.contains_key(&pid);
            self.discovery.insert(pid, (advert, now_secs));
            if is_new {
                events.push(MeshEvent::PeerDiscovered(pid));
            }
        }
        // 3. Rekey triggers.
        let peers: Vec<PeerId> = self.channels.keys().copied().collect();
        for peer in peers {
            if self.pending_rekeys.contains_key(&peer) {
                continue;
            }
            let needs = self.channels.get(&peer).map(|c| c.needs_rekey(now_secs)).unwrap_or(false);
            if !needs {
                continue;
            }
            let contact = match self.contacts.get(&peer) {
                Some(c) => c,
                None => continue,
            };
            let (offer, blob) = match self.channels.get(&peer).unwrap().begin_rekey(&self.identity, &contact.public) {
                Ok(v) => v,
                Err(_) => continue,
            };
            // Simultaneous-offer tie-break is enforced on receipt;
            // sending our offer is always safe.
            let link = encode_link(LinkKind::RekeyOffer, &blob);
            if self.transport.send_frame(&peer, &link).is_ok() {
                self.pending_rekeys.insert(peer, offer);
            }
        }
        // 4. Queue expiry → sender notification events.
        for expired in self.queue.collect_expired(now_secs) {
            events.push(MeshEvent::MessageExpired {
                peer: expired.peer,
                id: expired.id,
            });
        }
        events
    }

    /// Handle one inbound link frame. All failures are closed and
    /// silent: no error is ever sent back to the network (that would
    /// be an oracle).
    fn handle_link_frame(
        &mut self,
        from: &PeerId,
        bytes: &[u8],
        now_secs: u64,
        events: &mut Vec<MeshEvent>,
    ) {
        let (kind, payload) = match decode_link(bytes) {
            Ok(v) => v,
            Err(_) => return,
        };
        match kind {
            LinkKind::HandshakeHello => self.on_hello(from, &payload, now_secs, events),
            LinkKind::HandshakeResponse => self.on_response(from, &payload, now_secs, events),
            LinkKind::Data => self.on_data(from, &payload, events),
            LinkKind::RekeyOffer => self.on_rekey_offer(from, &payload, now_secs, events),
            LinkKind::RekeyAccept => self.on_rekey_accept(from, &payload, now_secs, events),
            LinkKind::Voice => self.on_voice(from, &payload, events),
        }
    }

    fn on_hello(&mut self, from: &PeerId, payload: &[u8], now_secs: u64, events: &mut Vec<MeshEvent>) {
        // Strangers are ignored: no response, no state, no event.
        let contact = match self.contacts.get(from) {
            Some(c) => c.clone(),
            None => return,
        };
        if payload.len() != transport::AUTH_HELLO_LEN {
            return;
        }
        let mut blob = [0u8; transport::AUTH_HELLO_LEN];
        blob.copy_from_slice(payload);
        let responder = match transport::ResponderHandshake::new() {
            Ok(r) => r,
            Err(_) => return,
        };
        let (channel, response) = match responder.respond_auth(&blob, &contact.public, &self.identity) {
            Ok(v) => v,
            Err(_) => return, // tampered/forged hello: fail closed, silent
        };
        let link = encode_link(LinkKind::HandshakeResponse, &response);
        if self.transport.send_frame(from, &link).is_err() {
            return;
        }
        self.channels.insert(*from, SecureChannel::from_channel(channel, *from, now_secs));
        self.flush_queue(from);
        events.push(MeshEvent::ChannelReady(*from));
    }

    fn on_response(&mut self, from: &PeerId, payload: &[u8], now_secs: u64, events: &mut Vec<MeshEvent>) {
        let contact = match self.contacts.get(from) {
            Some(c) => c.clone(),
            None => return,
        };
        let hs = match self.pending_handshakes.remove(from) {
            Some(h) => h,
            None => return, // unsolicited response: ignore
        };
        if payload.len() != transport::AUTH_HELLO_LEN {
            events.push(MeshEvent::ChannelFailed(*from));
            return;
        }
        let mut blob = [0u8; transport::AUTH_HELLO_LEN];
        blob.copy_from_slice(payload);
        let channel = match hs.finish_auth(&blob, &contact.public, self.identity.public()) {
            Ok(c) => c,
            Err(_) => {
                events.push(MeshEvent::ChannelFailed(*from));
                return;
            }
        };
        self.channels.insert(*from, SecureChannel::from_channel(channel, *from, now_secs));
        self.flush_queue(from);
        events.push(MeshEvent::ChannelReady(*from));
    }

    fn on_data(&mut self, from: &PeerId, payload: &[u8], events: &mut Vec<MeshEvent>) {
        let ch = match self.channels.get_mut(from) {
            Some(c) => c,
            None => return, // no channel: data before handshake is dropped
        };
        match ch.open(payload) {
            Ok(pt) => {
                self.inbound.entry(*from).or_default().push_back(pt);
                events.push(MeshEvent::DataReceived(*from));
            }
            Err(_) => {} // replay/tamper: fail closed, silent
        }
    }

    fn on_rekey_offer(&mut self, from: &PeerId, payload: &[u8], now_secs: u64, events: &mut Vec<MeshEvent>) {
        let contact = match self.contacts.get(from) {
            Some(c) => c.clone(),
            None => return,
        };
        let ch = match self.channels.get(from) {
            Some(c) => c,
            None => return,
        };
        // Simultaneous-offer tie-break: the smaller PeerId keeps its
        // offer; the larger accepts. Deterministic, no extra round trip.
        if self.pending_rekeys.contains_key(from) && self.own_id.0 < from.0 {
            return;
        }
        if payload.len() != REKEY_BLOB_LEN {
            return;
        }
        let mut blob = [0u8; REKEY_BLOB_LEN];
        blob.copy_from_slice(payload);
        let (new_ch, accept) = match ch.accept_rekey(&blob, &self.identity, &contact.public, now_secs) {
            Ok(v) => v,
            Err(_) => return, // forged offer: fail closed, keep old channel
        };
        let link = encode_link(LinkKind::RekeyAccept, &accept);
        if self.transport.send_frame(from, &link).is_err() {
            return;
        }
        self.pending_rekeys.remove(from);
        self.channels.insert(*from, new_ch);
        events.push(MeshEvent::Rekeyed(*from));
    }

    fn on_rekey_accept(&mut self, from: &PeerId, payload: &[u8], now_secs: u64, events: &mut Vec<MeshEvent>) {
        let contact = match self.contacts.get(from) {
            Some(c) => c.clone(),
            None => return,
        };
        let offer = match self.pending_rekeys.remove(from) {
            Some(o) => o,
            None => return, // unsolicited accept: ignore
        };
        let ch = match self.channels.get(from) {
            Some(c) => c,
            None => return,
        };
        if payload.len() != REKEY_BLOB_LEN {
            events.push(MeshEvent::ChannelFailed(*from));
            return;
        }
        let mut blob = [0u8; REKEY_BLOB_LEN];
        blob.copy_from_slice(payload);
        match ch.finish_rekey(&offer, &blob, &self.identity, &contact.public, now_secs) {
            Ok(new_ch) => {
                self.channels.insert(*from, new_ch);
                events.push(MeshEvent::Rekeyed(*from));
            }
            Err(_) => events.push(MeshEvent::ChannelFailed(*from)),
        }
    }

    fn on_voice(&mut self, from: &PeerId, payload: &[u8], events: &mut Vec<MeshEvent>) {
        let ch = match self.channels.get_mut(from) {
            Some(c) => c,
            None => return,
        };
        let pt = match ch.open(payload) {
            Ok(v) => v,
            Err(_) => return,
        };
        let chunk = match VoiceChunk::from_bytes(&pt) {
            Ok(c) => c,
            Err(_) => return,
        };
        events.push(MeshEvent::VoiceChunkReceived {
            peer: *from,
            msg_id: chunk.msg_id,
            seq: chunk.seq,
            total: chunk.total,
        });
        let key = (*from, chunk.msg_id);
        if !self.voice_assembly.contains_key(&key) {
            if self.voice_assembly.len() >= MAX_VOICE_ASSEMBLIES {
                return; // bound memory: drop, sender retries
            }
            self.voice_assembly.insert(
                key,
                VoiceAssembly {
                    total: chunk.total,
                    chunks: vec![None; chunk.total as usize],
                    received: 0,
                },
            );
        }
        let asm = match self.voice_assembly.get_mut(&key) {
            Some(a) => a,
            None => return,
        };
        if chunk.total != asm.total || (chunk.seq as usize) >= asm.chunks.len() {
            return;
        }
        if asm.chunks[chunk.seq as usize].is_none() {
            asm.chunks[chunk.seq as usize] = Some(chunk.audio);
            asm.received += 1;
        }
        if asm.received == asm.total {
            let mut audio = Vec::new();
            for c in asm.chunks.iter().flatten() {
                audio.extend_from_slice(c);
            }
            self.voice_assembly.remove(&key);
            events.push(MeshEvent::VoiceMessageComplete {
                peer: *from,
                msg_id: chunk.msg_id,
                audio,
            });
        }
    }

    /// Flush queued messages the moment a channel is ready — zero
    /// delay: queued bytes go out immediately on connect.
    ///
    /// Queued payloads are always RAW bytes (never already-sealed
    /// link frames): they are sealed here, exactly once, with the
    /// fresh channel. At rest they were protected by the queue cipher.
    fn flush_queue(&mut self, peer: &PeerId) {
        let queued = self.queue.drain_for_peer(peer);
        for q in queued {
            let link = match q.kind {
                QueueKind::Data => {
                    match self.channels.get_mut(peer).map(|ch| ch.seal(&q.payload)) {
                        Some(Ok(frame)) => encode_link(LinkKind::Data, &frame),
                        _ => continue,
                    }
                }
                QueueKind::Voice => {
                    // Validate the chunk shape before sealing.
                    if VoiceChunk::from_bytes(&q.payload).is_err() {
                        continue;
                    }
                    match self.channels.get_mut(peer).map(|ch| ch.seal(&q.payload)) {
                        Some(Ok(frame)) => encode_link(LinkKind::Voice, &frame),
                        _ => continue,
                    }
                }
            };
            // Best effort: a failed flush re-queues the ORIGINAL raw
            // payload at the back (so the next flush seals exactly
            // once), preserving the original enqueue time for expiry.
            if self.transport.send_frame(peer, &link).is_err() {
                let _ = self.queue.enqueue_at(
                    peer,
                    &q.id,
                    q.payload,
                    q.kind == QueueKind::Voice,
                    q.enqueued_at,
                );
                break;
            }
        }
    }
}

#[cfg(test)]
#[path = "mesh_tests.rs"]
mod mesh_tests;
