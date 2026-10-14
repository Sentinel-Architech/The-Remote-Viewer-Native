//! Authenticated person-to-person messaging.
//!
//! Pure Rust, std-only. A small framed message protocol layered over
//! the authenticated transport [`Channel`](crate::transport::Channel):
//! text messages, delivery receipts, and typing indicators, with
//! per-conversation peer pinning, message-ID deduplication, and size
//! caps. Everything fails closed.
//!
//! NOT externally audited — like the rest of `trv_core::crypto` and
//! `trv_core::transport`, the framing and conversation logic here are
//! implemented from first principles and unit-tested, but no
//! independent cryptographic or security audit has happened. Do not
//! rely on this for production secrets until that audit happens.
//!
//! ## Trust model
//!
//! A [`Conversation`] is built on a [`Channel`](crate::transport::Channel)
//! PLUS the two long-term Ed25519 identity public keys: our own and
//! the peer's, pinned at creation. Every received frame must claim
//! exactly the pinned peer as sender and us as recipient, or it fails
//! closed. The pinned identities MUST come from the authenticated
//! handshake ([`establish_auth`](crate::transport::establish_auth))
//! — or an equivalent out-of-band pinned exchange. The unauthenticated
//! [`establish`](crate::transport::establish) handshake yields no
//! identity keys at all, so there is nothing trustworthy to pin: any
//! binding invented on top of it authenticates nobody, and a
//! man-in-the-middle who completes that handshake speaks as whoever
//! the victim pinned. This module enforces the binding at its API
//! boundary (the constructor demands both identities) and at runtime
//! (sender/recipient checks on every frame); it cannot retroactively
//! authenticate a channel that was never bound.
//!
//! ## Scope
//!
//! Protocol + conversation logic only. No sockets, no DHT, no push
//! notifications, no group chats, no media attachments, no UI. The
//! network I/O plugs in later: `send_*` returns sealed frame bytes to
//! transmit, `receive_frame` consumes received frame bytes and returns
//! any reply bytes (delivery receipts) to transmit back.

use crate::crypto::ed25519::PublicKey;
use crate::transport::{Channel, TransportError};
use std::collections::VecDeque;

/// Errors from the messaging layer. All failures are closed: no
/// message is accepted, logged, or acted on along any error path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessagingError {
    /// The OS CSPRNG (`/dev/urandom`) was unavailable, so no message
    /// ID could be minted. Fails closed rather than reusing IDs.
    EntropyUnavailable,
    /// The system clock was unavailable or before the Unix epoch, so
    /// no timestamp could be minted.
    ClockUnavailable,
    /// Frame failed structural checks: short header, bad magic,
    /// length mismatch, trailing garbage, or a kind/payload shape
    /// violation. Nothing is accepted.
    MalformedFrame,
    /// Frame declares a protocol version this code does not speak.
    /// Refused rather than guessed at.
    UnknownVersion,
    /// Frame declares an unknown message kind.
    UnknownMessageKind,
    /// Text payload exceeds [`MAX_TEXT_BYTES`], on send or receive.
    OversizedPayload,
    /// Frame's claimed sender is not the pinned peer identity.
    WrongSender,
    /// Frame is not addressed to our identity.
    WrongRecipient,
    /// A Text payload was not valid UTF-8.
    InvalidText,
    /// The transport layer rejected the frame (bad tag, replay,
    /// truncated frame, exhausted sequence, ...). See
    /// [`TransportError`].
    Transport(TransportError),
}

impl std::fmt::Display for MessagingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MessagingError::EntropyUnavailable => {
                f.write_str("OS entropy unavailable; refusing to mint a message ID")
            }
            MessagingError::ClockUnavailable => {
                f.write_str("system clock unavailable; refusing to timestamp")
            }
            MessagingError::MalformedFrame => f.write_str("malformed message frame"),
            MessagingError::UnknownVersion => f.write_str("unknown protocol version"),
            MessagingError::UnknownMessageKind => f.write_str("unknown message kind"),
            MessagingError::OversizedPayload => f.write_str("message payload too large"),
            MessagingError::WrongSender => {
                f.write_str("frame sender is not the pinned peer identity")
            }
            MessagingError::WrongRecipient => f.write_str("frame is not addressed to us"),
            MessagingError::InvalidText => f.write_str("text payload is not valid UTF-8"),
            MessagingError::Transport(e) => write!(f, "transport error: {e}"),
        }
    }
}

impl std::error::Error for MessagingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            MessagingError::Transport(e) => Some(e),
            _ => None,
        }
    }
}

impl From<TransportError> for MessagingError {
    fn from(e: TransportError) -> Self {
        MessagingError::Transport(e)
    }
}

/// Wire magic: every message frame starts with these bytes.
const MAGIC: &[u8; 4] = b"TRVM";
/// The only protocol version this code speaks.
const PROTOCOL_VERSION: u8 = 0x01;
/// Header length: magic(4) + version(1) + kind(1) + sender(32) +
/// recipient(32) + msg_id(16) + timestamp(8) + payload_len(4).
const HEADER_LEN: usize = 98;
/// Maximum text payload: 8 KiB.
pub const MAX_TEXT_BYTES: usize = 8192;
/// Delivery-receipt payload is exactly the acked message ID.
const RECEIPT_PAYLOAD_LEN: usize = 16;
/// Typing indicators carry no payload.
const TYPING_PAYLOAD_LEN: usize = 0;
/// How many recent message IDs are remembered for deduplication.
const MAX_SEEN_IDS: usize = 1024;

/// The kinds of messages the protocol carries. Text + receipts are
/// the core; typing indicators are best-effort presence hints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageKind {
    /// Human text, UTF-8, at most [`MAX_TEXT_BYTES`] bytes.
    Text,
    /// Acknowledgement of a received text. Payload is the 16-byte ID
    /// of the message being acknowledged.
    DeliveryReceipt,
    /// "Peer is typing" hint. No payload; never logged to history.
    TypingIndicator,
}

impl MessageKind {
    fn as_u8(self) -> u8 {
        match self {
            MessageKind::Text => 0x01,
            MessageKind::DeliveryReceipt => 0x02,
            MessageKind::TypingIndicator => 0x03,
        }
    }

    fn from_u8(b: u8) -> Result<Self, MessagingError> {
        match b {
            0x01 => Ok(MessageKind::Text),
            0x02 => Ok(MessageKind::DeliveryReceipt),
            0x03 => Ok(MessageKind::TypingIndicator),
            _ => Err(MessagingError::UnknownMessageKind),
        }
    }
}

/// A parsed message: the plaintext inside one sealed frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    kind: MessageKind,
    sender: [u8; 32],
    recipient: [u8; 32],
    id: [u8; 16],
    timestamp: u64,
    payload: Vec<u8>,
}

impl Message {
    /// The message kind.
    pub fn kind(&self) -> MessageKind {
        self.kind
    }
    /// Claimed sender identity (32-byte Ed25519 public key).
    pub fn sender(&self) -> &[u8; 32] {
        &self.sender
    }
    /// Intended recipient identity (32-byte Ed25519 public key).
    pub fn recipient(&self) -> &[u8; 32] {
        &self.recipient
    }
    /// Unique 16-byte message ID.
    pub fn id(&self) -> &[u8; 16] {
        &self.id
    }
    /// Unix-seconds timestamp minted by the sender. Informational
    /// only: there is no trusted time source, so skew is not
    /// enforced. Ordering and dedup use message IDs and the
    /// transport's sequence numbers, not this field.
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }
    /// Raw payload bytes.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
    /// The text of a [`MessageKind::Text`] message. Fails closed if
    /// called on another kind or if the payload is not UTF-8 (the
    /// parser already rejects the latter; this re-checks cheaply).
    pub fn text(&self) -> Result<&str, MessagingError> {
        if self.kind != MessageKind::Text {
            return Err(MessagingError::MalformedFrame);
        }
        std::str::from_utf8(&self.payload).map_err(|_| MessagingError::InvalidText)
    }
}

/// Serialize a message to its wire form:
/// `magic || version || kind || sender || recipient || id ||
/// timestamp_be || payload_len_be || payload`.
fn serialize(msg: &Message) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + msg.payload.len());
    out.extend_from_slice(MAGIC);
    out.push(PROTOCOL_VERSION);
    out.push(msg.kind.as_u8());
    out.extend_from_slice(&msg.sender);
    out.extend_from_slice(&msg.recipient);
    out.extend_from_slice(&msg.id);
    out.extend_from_slice(&msg.timestamp.to_be_bytes());
    out.extend_from_slice(&(msg.payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&msg.payload);
    out
}

/// Parse and validate wire bytes. Fails closed on anything unexpected:
/// short reads, bad magic, unknown version/kind, length mismatches,
/// trailing garbage, oversized or misshapen payloads, non-UTF-8 text.
fn parse(bytes: &[u8]) -> Result<Message, MessagingError> {
    if bytes.len() < HEADER_LEN {
        return Err(MessagingError::MalformedFrame);
    }
    if &bytes[..4] != MAGIC {
        return Err(MessagingError::MalformedFrame);
    }
    if bytes[4] != PROTOCOL_VERSION {
        return Err(MessagingError::UnknownVersion);
    }
    let kind = MessageKind::from_u8(bytes[5])?;
    let mut sender = [0u8; 32];
    sender.copy_from_slice(&bytes[6..38]);
    let mut recipient = [0u8; 32];
    recipient.copy_from_slice(&bytes[38..70]);
    let mut id = [0u8; 16];
    id.copy_from_slice(&bytes[70..86]);
    let mut ts = [0u8; 8];
    ts.copy_from_slice(&bytes[86..94]);
    let timestamp = u64::from_be_bytes(ts);
    let mut len = [0u8; 4];
    len.copy_from_slice(&bytes[94..98]);
    let payload_len = u32::from_be_bytes(len) as usize;

    // Fail fast on absurd lengths before slicing.
    if payload_len > MAX_TEXT_BYTES {
        return Err(MessagingError::OversizedPayload);
    }
    let total = HEADER_LEN
        .checked_add(payload_len)
        .ok_or(MessagingError::MalformedFrame)?;
    if bytes.len() != total {
        // Truncated payload or trailing garbage: reject either way.
        return Err(MessagingError::MalformedFrame);
    }
    // Kind-specific payload shapes.
    match kind {
        MessageKind::Text => {
            std::str::from_utf8(&bytes[HEADER_LEN..total])
                .map_err(|_| MessagingError::InvalidText)?;
        }
        MessageKind::DeliveryReceipt => {
            if payload_len != RECEIPT_PAYLOAD_LEN {
                return Err(MessagingError::MalformedFrame);
            }
        }
        MessageKind::TypingIndicator => {
            if payload_len != TYPING_PAYLOAD_LEN {
                return Err(MessagingError::MalformedFrame);
            }
        }
    }
    Ok(Message {
        kind,
        sender,
        recipient,
        id,
        timestamp,
        payload: bytes[HEADER_LEN..total].to_vec(),
    })
}

/// 16 bytes of OS entropy for message IDs, or
/// [`MessagingError::EntropyUnavailable`]. No weak fallback — an ID
/// collision would break deduplication.
fn random16() -> Result<[u8; 16], MessagingError> {
    use std::io::Read;
    let mut b = [0u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut b))
        .map_err(|_| MessagingError::EntropyUnavailable)?;
    Ok(b)
}

/// Current Unix time in seconds, or [`MessagingError::ClockUnavailable`].
fn now_unix() -> Result<u64, MessagingError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| MessagingError::ClockUnavailable)
}

/// Delivery state of an outgoing text message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageStatus {
    /// Sealed and handed to the network layer; no receipt yet.
    Sent,
    /// The peer's delivery receipt arrived.
    Delivered,
}

/// One entry in the conversation log.
#[derive(Debug, Clone)]
pub struct StoredMessage {
    /// The parsed message.
    pub message: Message,
    /// True if we sent it, false if the peer did.
    pub outgoing: bool,
    /// Delivery state. Incoming messages are always
    /// [`MessageStatus::Delivered`] (they reached us); outgoing
    /// messages move `Sent -> Delivered` when the receipt arrives.
    pub status: MessageStatus,
}

/// What [`Conversation::receive_frame`] produced for one frame.
#[derive(Debug, PartialEq, Eq)]
pub enum Received {
    /// A new text from the peer. `receipt_frame` is the sealed
    /// delivery receipt — hand it to the network layer to send back.
    /// The receipt is protocol traffic and is NOT added to history.
    Text {
        message: Message,
        receipt_frame: Vec<u8>,
    },
    /// A delivery receipt for one of our outgoing messages.
    /// Unknown IDs are ignored (no status change) but still reported.
    Receipt {
        acked_id: [u8; 16],
    },
    /// A typing-indicator hint from the peer. Never logged.
    Typing,
    /// A frame whose message ID was already seen: dropped silently,
    /// no history change, no receipt re-sent.
    Duplicate,
}

/// An authenticated one-to-one conversation.
///
/// Binds an encrypted [`Channel`] to the two pinned Ed25519 identity
/// keys. The bindings MUST come from the authenticated handshake
/// ([`establish_auth`](crate::transport::establish_auth)): that is
/// the only path that proves the peer owns the pinned key. There is
/// deliberately no constructor that omits them.
pub struct Conversation {
    channel: Channel,
    own_id: [u8; 32],
    peer_id: [u8; 32],
    history: Vec<StoredMessage>,
    /// Recently seen message IDs, oldest first, capped at
    /// [`MAX_SEEN_IDS`]. Guards against a buggy or malicious peer
    /// re-sealing the same logical message under fresh transport
    /// sequence numbers (exact frame replays never reach us — the
    /// channel's replay window rejects those first).
    seen: VecDeque<[u8; 16]>,
}

impl std::fmt::Debug for Conversation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Conversation")
            .field("channel", &self.channel)
            .field("own_id", &self.own_id)
            .field("peer_id", &self.peer_id)
            .field("history_len", &self.history.len())
            .field("seen_len", &self.seen.len())
            .finish()
    }
}

impl Conversation {
    /// Bind a channel to the pinned identities. `own_id` is this
    /// device's long-term identity public key; `peer_id` is the
    /// peer's, pinned during the authenticated handshake. Every frame
    /// received afterwards must claim exactly `peer_id` as sender and
    /// `own_id` as recipient.
    pub fn new(channel: Channel, own_id: &PublicKey, peer_id: &PublicKey) -> Self {
        Self {
            channel,
            own_id: *own_id.as_bytes(),
            peer_id: *peer_id.as_bytes(),
            history: Vec::new(),
            seen: VecDeque::new(),
        }
    }

    /// Our pinned identity.
    pub fn own_id(&self) -> &[u8; 32] {
        &self.own_id
    }

    /// The peer's pinned identity.
    pub fn peer_id(&self) -> &[u8; 32] {
        &self.peer_id
    }

    /// The in-memory ordered conversation log (texts only; receipts
    /// and typing hints are protocol traffic and are not logged).
    pub fn history(&self) -> &[StoredMessage] {
        &self.history
    }

    /// Delivery status of an outgoing message by ID, or `None` if no
    /// outgoing message with that ID exists.
    pub fn message_status(&self, id: &[u8; 16]) -> Option<MessageStatus> {
        self.history
            .iter()
            .find(|s| s.outgoing && &s.message.id == id)
            .map(|s| s.status)
    }

    /// Build, log, and seal a text message. Returns the sealed frame
    /// bytes to transmit. Rejects payloads over [`MAX_TEXT_BYTES`].
    pub fn send_text(&mut self, text: &str) -> Result<Vec<u8>, MessagingError> {
        if text.len() > MAX_TEXT_BYTES {
            return Err(MessagingError::OversizedPayload);
        }
        let msg = Message {
            kind: MessageKind::Text,
            sender: self.own_id,
            recipient: self.peer_id,
            id: random16()?,
            timestamp: now_unix()?,
            payload: text.as_bytes().to_vec(),
        };
        let frame = self.channel.seal(&serialize(&msg))?;
        self.remember(&msg.id);
        self.history.push(StoredMessage {
            message: msg,
            outgoing: true,
            status: MessageStatus::Sent,
        });
        Ok(frame)
    }

    /// Seal a typing-indicator hint. Best-effort presence; the peer
    /// is not required to act on it, and it is never logged.
    pub fn send_typing(&mut self) -> Result<Vec<u8>, MessagingError> {
        let msg = Message {
            kind: MessageKind::TypingIndicator,
            sender: self.own_id,
            recipient: self.peer_id,
            id: random16()?,
            timestamp: now_unix()?,
            payload: Vec::new(),
        };
        let frame = self.channel.seal(&serialize(&msg))?;
        self.remember(&msg.id);
        Ok(frame)
    }

    /// Open, validate, and dispatch one received frame.
    ///
    /// The transport layer runs first (authentication, replay
    /// window), then the messaging checks: structure, version, kind,
    /// pinned sender, addressed recipient, and message-ID
    /// deduplication. A received text is logged and answered with a
    /// delivery receipt whose sealed bytes are returned for
    /// transmission.
    pub fn receive_frame(&mut self, frame: &[u8]) -> Result<Received, MessagingError> {
        let plaintext = self.channel.open(frame)?;
        let msg = parse(&plaintext)?;
        if msg.sender != self.peer_id {
            return Err(MessagingError::WrongSender);
        }
        if msg.recipient != self.own_id {
            return Err(MessagingError::WrongRecipient);
        }
        if self.seen.contains(&msg.id) {
            return Ok(Received::Duplicate);
        }
        self.remember(&msg.id);
        match msg.kind {
            MessageKind::Text => {
                let receipt = self.build_receipt(&msg.id)?;
                let receipt_frame = self.channel.seal(&serialize(&receipt))?;
                self.history.push(StoredMessage {
                    message: msg.clone(),
                    outgoing: false,
                    status: MessageStatus::Delivered,
                });
                Ok(Received::Text {
                    message: msg,
                    receipt_frame,
                })
            }
            MessageKind::DeliveryReceipt => {
                let mut acked_id = [0u8; 16];
                acked_id.copy_from_slice(&msg.payload);
                // Mark delivered if we sent it; unknown IDs are
                // ignored rather than erroring (a receipt can arrive
                // after history was trimmed, or be spurious).
                if let Some(stored) = self
                    .history
                    .iter_mut()
                    .find(|s| s.outgoing && s.message.id == acked_id)
                {
                    stored.status = MessageStatus::Delivered;
                }
                Ok(Received::Receipt { acked_id })
            }
            MessageKind::TypingIndicator => Ok(Received::Typing),
        }
    }

    /// Build (but do not log or seal) a delivery receipt for `id`.
    fn build_receipt(&self, id: &[u8; 16]) -> Result<Message, MessagingError> {
        Ok(Message {
            kind: MessageKind::DeliveryReceipt,
            sender: self.own_id,
            recipient: self.peer_id,
            id: random16()?,
            timestamp: now_unix()?,
            payload: id.to_vec(),
        })
    }

    /// Record a message ID for deduplication, evicting the oldest
    /// when the cap is reached.
    fn remember(&mut self, id: &[u8; 16]) {
        if self.seen.len() >= MAX_SEEN_IDS {
            self.seen.pop_front();
        }
        self.seen.push_back(*id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{establish, establish_auth, IdentityKey};

    /// Two conversations over a mutually authenticated channel, with
    /// identities pinned exactly as `establish_auth` proved them.
    fn authed_pair() -> (Conversation, Conversation) {
        let id_a = IdentityKey::generate(&[0xA1u8; 32]);
        let id_b = IdentityKey::generate(&[0xB2u8; 32]);
        let (chan_a, chan_b) = establish_auth(&id_a, &id_b).unwrap();
        let a = Conversation::new(chan_a, id_a.public(), id_b.public());
        let b = Conversation::new(chan_b, id_b.public(), id_a.public());
        (a, b)
    }

    /// Seal arbitrary (possibly malicious) messaging bytes through a
    /// live channel, bypassing the `Conversation` send path — the way
    /// a compromised or buggy peer endpoint would emit them.
    fn seal_raw(channel: &mut Channel, msg: &Message) -> Vec<u8> {
        channel.seal(&serialize(msg)).unwrap()
    }

    fn raw_text(sender: &[u8; 32], recipient: &[u8; 32], text: &[u8]) -> Message {
        Message {
            kind: MessageKind::Text,
            sender: *sender,
            recipient: *recipient,
            id: [0x55u8; 16],
            timestamp: 1_700_000_000,
            payload: text.to_vec(),
        }
    }

    #[test]
    fn text_round_trip_over_auth_channel() {
        let (mut a, mut b) = authed_pair();
        let frame = a.send_text("hello from A").unwrap();
        match b.receive_frame(&frame).unwrap() {
            Received::Text { message, .. } => {
                assert_eq!(message.kind(), MessageKind::Text);
                assert_eq!(message.text().unwrap(), "hello from A");
                assert_eq!(message.sender(), a.own_id());
                assert_eq!(message.recipient(), b.own_id());
                assert!(message.timestamp() > 0);
                // B logged it as incoming + delivered. The receipt is
                // protocol traffic, not history.
                assert_eq!(b.history().len(), 1);
                assert!(!b.history()[0].outgoing);
                assert_eq!(b.history()[0].status, MessageStatus::Delivered);
            }
            other => panic!("expected Text, got {other:?}"),
        }
        // A logged the outgoing message as sent.
        assert_eq!(a.history().len(), 1);
        assert!(a.history()[0].outgoing);
        assert_eq!(a.history()[0].status, MessageStatus::Sent);
        // Empty text round-trips.
        let frame = b.send_text("").unwrap();
        match a.receive_frame(&frame).unwrap() {
            Received::Text { message, .. } => assert_eq!(message.text().unwrap(), ""),
            other => panic!("expected Text, got {other:?}"),
        }
    }

    #[test]
    fn receipt_flow_marks_delivered() {
        let (mut a, mut b) = authed_pair();
        let frame = a.send_text("ping").unwrap();
        let sent_id = *a.history()[0].message.id();
        assert_eq!(a.message_status(&sent_id), Some(MessageStatus::Sent));

        let receipt_frame = match b.receive_frame(&frame).unwrap() {
            Received::Text { receipt_frame, .. } => receipt_frame,
            other => panic!("expected Text, got {other:?}"),
        };
        // A consumes the receipt: status flips Sent -> Delivered.
        match a.receive_frame(&receipt_frame).unwrap() {
            Received::Receipt { acked_id } => assert_eq!(acked_id, sent_id),
            other => panic!("expected Receipt, got {other:?}"),
        }
        assert_eq!(a.message_status(&sent_id), Some(MessageStatus::Delivered));

        // A receipt for an ID we never sent is ignored, not an error.
        // (Sealed by d so the sender/recipient bindings check out for c.)
        let (mut c, mut d) = authed_pair();
        let bogus = Message {
            kind: MessageKind::DeliveryReceipt,
            sender: *d.own_id(),
            recipient: *d.peer_id(),
            id: [0x99u8; 16],
            timestamp: 1,
            payload: [0xABu8; 16].to_vec(),
        };
        let frame = seal_raw(d_channel(&mut d), &bogus);
        match c.receive_frame(&frame).unwrap() {
            Received::Receipt { acked_id } => assert_eq!(acked_id, [0xABu8; 16]),
            other => panic!("expected Receipt, got {other:?}"),
        }
        assert!(c.history().is_empty());
    }

    // Helper: reach the inner channel of a Conversation for tests.
    // (Only used to craft adversarial frames; the public API never
    // exposes it.)
    fn d_channel(c: &mut Conversation) -> &mut Channel {
        &mut c.channel
    }

    #[test]
    fn wrong_sender_rejected() {
        let (mut a, mut b) = authed_pair();
        let id_evil = IdentityKey::generate(&[0xE1u8; 32]);
        // A frame sealed through the live channel but claiming a
        // different sender than the pinned peer.
        let evil = raw_text(
            id_evil.public().as_bytes(),
            b.own_id(),
            b"i am totally your peer",
        );
        let frame = seal_raw(d_channel(&mut a), &evil);
        assert_eq!(
            b.receive_frame(&frame),
            Err(MessagingError::WrongSender)
        );
        assert!(b.history().is_empty());
    }

    #[test]
    fn wrong_recipient_rejected() {
        let (mut a, mut b) = authed_pair();
        let id_stranger = IdentityKey::generate(&[0xE2u8; 32]);
        // Correct pinned sender, but addressed to someone else.
        let misdirected = raw_text(
            a.own_id(),
            id_stranger.public().as_bytes(),
            b"not for you",
        );
        let frame = seal_raw(d_channel(&mut a), &misdirected);
        assert_eq!(
            b.receive_frame(&frame),
            Err(MessagingError::WrongRecipient)
        );
        assert!(b.history().is_empty());
    }

    #[test]
    fn duplicate_message_id_deduped() {
        let (mut a, mut b) = authed_pair();
        // Same logical message sealed twice: distinct transport
        // frames (fresh nonces/sequences), same message ID. The
        // channel's replay window cannot catch this — only the
        // conversation-level dedup can.
        let msg = raw_text(a.own_id(), b.own_id(), b"send twice");
        let f1 = seal_raw(d_channel(&mut a), &msg);
        let f2 = seal_raw(d_channel(&mut a), &msg);
        assert_ne!(f1, f2);
        match b.receive_frame(&f1).unwrap() {
            Received::Text { .. } => {}
            other => panic!("expected Text, got {other:?}"),
        }
        assert_eq!(b.history().len(), 1);
        // Second copy: dropped silently — no new history, no receipt.
        match b.receive_frame(&f2).unwrap() {
            Received::Duplicate => {}
            other => panic!("expected Duplicate, got {other:?}"),
        }
        assert_eq!(b.history().len(), 1);
    }

    #[test]
    fn oversized_text_rejected() {
        let (mut a, mut b) = authed_pair();
        // Exactly at the cap is fine.
        let ok = "x".repeat(MAX_TEXT_BYTES);
        let frame = a.send_text(&ok).unwrap();
        match b.receive_frame(&frame).unwrap() {
            Received::Text { message, .. } => {
                assert_eq!(message.payload().len(), MAX_TEXT_BYTES)
            }
            other => panic!("expected Text, got {other:?}"),
        }
        // One byte over fails closed on send...
        let big = "x".repeat(MAX_TEXT_BYTES + 1);
        assert_eq!(
            a.send_text(&big),
            Err(MessagingError::OversizedPayload)
        );
        // ...and on receive, if a hostile peer crafts it by hand.
        let mut evil = raw_text(a.own_id(), b.own_id(), b"");
        evil.payload = vec![0x41u8; MAX_TEXT_BYTES + 1];
        let frame = seal_raw(d_channel(&mut a), &evil);
        assert_eq!(
            b.receive_frame(&frame),
            Err(MessagingError::OversizedPayload)
        );
    }

    #[test]
    fn malformed_frames_rejected() {
        let (mut x, mut y) = authed_pair();
        let good = x.send_text("probe").unwrap();
        // Learn the valid plaintext once, before any closures borrow
        // the conversations.
        let good_pt = y.channel.open(&good).unwrap();
        assert!(good_pt.len() >= HEADER_LEN);

        // Minimal header builder for the structural cases.
        let header = |kind: u8, payload_len: u32| -> Vec<u8> {
            let mut h = vec![0u8; HEADER_LEN];
            h[..4].copy_from_slice(MAGIC);
            h[4] = PROTOCOL_VERSION;
            h[5] = kind;
            h[94..98].copy_from_slice(&payload_len.to_be_bytes());
            h
        };
        // Seal hand-built plaintext through x's channel; feed it to y.
        // (Closures borrow x and y mutably; nothing touches them
        // directly afterwards.)
        let mut seal = |pt: &[u8]| x.channel.seal(pt).unwrap();
        let mut recv = |f: Vec<u8>| y.receive_frame(&f);

        // Truncated header.
        assert_eq!(recv(seal(&[0u8; 10])), Err(MessagingError::MalformedFrame));
        // Bad magic.
        let mut pt = good_pt.clone();
        pt[0] = b'X';
        assert_eq!(recv(seal(&pt)), Err(MessagingError::MalformedFrame));
        // Unknown version.
        let mut pt = header(0x01, 0);
        pt[4] = 0x7F;
        assert_eq!(recv(seal(&pt)), Err(MessagingError::UnknownVersion));
        // Unknown kind.
        assert_eq!(
            recv(seal(&header(0x7F, 0))),
            Err(MessagingError::UnknownMessageKind)
        );
        // Declared length longer than the actual bytes.
        assert_eq!(
            recv(seal(&header(0x01, 100))),
            Err(MessagingError::MalformedFrame)
        );
        // Trailing garbage after the payload.
        let mut pt = good_pt.clone();
        pt.push(0xFF);
        assert_eq!(recv(seal(&pt)), Err(MessagingError::MalformedFrame));
        // Non-UTF8 text payload ("probe" is 5 bytes; poison two).
        let mut pt = good_pt.clone();
        pt[HEADER_LEN] = 0xFF;
        pt[HEADER_LEN + 1] = 0xFE;
        assert_eq!(recv(seal(&pt)), Err(MessagingError::InvalidText));
        // Receipt with wrong payload length.
        assert_eq!(
            recv(seal(&header(0x02, 4))),
            Err(MessagingError::MalformedFrame)
        );
        // Typing indicator carrying a payload.
        let mut pt = header(0x03, 1);
        pt.push(0x00);
        assert_eq!(recv(seal(&pt)), Err(MessagingError::MalformedFrame));
        // Bytes that are not a transport frame at all.
        assert!(matches!(
            recv(good[..5].to_vec()),
            Err(MessagingError::Transport(_))
        ));
    }

    #[test]
    fn unauthenticated_channel_has_no_trustworthy_binding() {
        // establish() yields channels but NO identity keys — only
        // ephemeral X25519 publics. Conversation::new demands pinned
        // Ed25519 identities for both ends, which only the
        // authenticated handshake (or an equivalent pinned exchange)
        // can supply. Any binding invented on top of an
        // unauthenticated channel is unverifiable: here the caller
        // pins the ATTACKER's key as "peer", and a frame claiming the
        // real peer's identity then fails closed instead of being
        // trusted — the binding is enforced, never assumed.
        let id_attacker = IdentityKey::generate(&[0xF1u8; 32]);
        let id_real_peer = IdentityKey::generate(&[0xF2u8; 32]);
        let id_own = IdentityKey::generate(&[0xF3u8; 32]);

        let (ch_a, mut ch_b) = establish().unwrap();
        let mut convo = Conversation::new(ch_a, id_own.public(), id_attacker.public());

        let forged = raw_text(
            id_real_peer.public().as_bytes(),
            id_own.public().as_bytes(),
            b"trust me",
        );
        let frame = seal_raw(&mut ch_b, &forged);
        assert_eq!(
            convo.receive_frame(&frame),
            Err(MessagingError::WrongSender)
        );
    }

    #[test]
    fn typing_indicator_round_trip() {
        let (mut a, mut b) = authed_pair();
        let frame = a.send_typing().unwrap();
        match b.receive_frame(&frame).unwrap() {
            Received::Typing => {}
            other => panic!("expected Typing, got {other:?}"),
        }
        // Typing hints are never logged.
        assert!(b.history().is_empty());
    }

    #[test]
    fn replayed_transport_frame_rejected_before_messaging() {
        let (mut a, mut b) = authed_pair();
        let frame = a.send_text("once").unwrap();
        match b.receive_frame(&frame).unwrap() {
            Received::Text { .. } => {}
            other => panic!("expected Text, got {other:?}"),
        }
        // Exact replay: the channel's replay window rejects it before
        // any messaging logic runs.
        assert!(matches!(
            b.receive_frame(&frame),
            Err(MessagingError::Transport(TransportError::ReplayDetected))
        ));
    }

    #[test]
    fn error_display_and_source() {
        let e: MessagingError = MessagingError::WrongSender.into();
        let _ = e;
        let te = MessagingError::Transport(TransportError::ReplayDetected);
        assert!(std::error::Error::source(&te).is_some());
        assert!(format!("{te}").contains("transport error"));
        assert!(format!("{}", MessagingError::OversizedPayload).contains("too large"));
    }
}
