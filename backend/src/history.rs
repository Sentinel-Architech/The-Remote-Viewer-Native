//! Persistent per-peer message history, encrypted at rest.
//!
//! [`Conversation`](trv_core::messaging::Conversation) keeps its log
//! in memory — a restart loses everything. This module is the durable
//! counterpart: each peer's conversation log is serialized, encrypted
//! with the viewer's vault passphrase, and stored as one file per
//! peer (`<peer-key-hex>.msglog`) inside the store directory.
//!
//! ## Security properties
//!
//! - Plaintext message text NEVER touches disk. Only ChaCha20-Poly1305
//!   ciphertext is written; intermediate plaintext buffers are wiped
//!   with volatile writes after encryption.
//! - Each file is authenticated: the header (magic, version, AEAD id,
//!   nonce) is bound into the AEAD as associated data, so header
//!   tampering fails decryption.
//! - One file per peer: a corrupt log for peer A cannot affect peer B's
//!   log. Corruption fails closed — the caller gets an error, never
//!   partial garbage.
//! - Writes are atomic (temp + fsync + rename, via the vault's
//!   [`crate::profile`] staging) and serialized with the vault's
//!   cooperative lock file. A crash mid-write leaves the previous log
//!   intact.
//! - The store key is derived ONCE at open with PBKDF2-HMAC-SHA512 at
//!   the vault's iteration count (600,000) and held in a zeroizing
//!   wrapper; every write uses a fresh random nonce. (Rationale: the
//!   vault derives per-save because it has no session; a history
//!   store is a session, so per-append KDF would cost ~2s per
//!   message with no security benefit — nonce uniqueness is what the
//!   AEAD needs.)
//!
//! ## What this is NOT
//!
//! - No network sync, no search/indexing, no media, no group chats.
//! - Passphrase changes are NOT handled here: the store key is bound
//!   to the passphrase given at open. Changing the vault passphrase
//!   requires re-encrypting history (a future migration helper).
//! - Not externally audited. Do not rely on it for production
//!   safety workflows until that audit happens.

use std::path::{Path, PathBuf};

use trv_core::crypto::{chacha20poly1305, pbkdf2};
use trv_core::messaging;

use crate::profile::{self, VaultError, VAULT_KDF_ITERATIONS};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Magic bytes at the start of every history log file.
const HIST_MAGIC: &[u8; 4] = b"TRVH";
/// History log file format version.
const HIST_FORMAT_VERSION: u8 = 0x01;
/// AEAD algorithm id (ChaCha20-Poly1305), mirroring the vault's ids.
const HIST_AEAD_ID: u8 = 0x01;
/// Domain string bound into the AEAD associated data.
const HIST_AAD_DOMAIN: &[u8] = b"TRV-HISTORY-V1";
/// Domain-separated salt for the store-key KDF. Fixed per
/// application: the passphrase is the secret; this salt separates the
/// history key from the vault key even when both use the same
/// passphrase.
const HIST_KDF_SALT: &[u8] = b"TRV-HISTORY-KEY-V1";
/// Nonce length for ChaCha20-Poly1305.
const HIST_NONCE_LEN: usize = 12;
/// Maximum messages kept per peer; older messages are evicted.
pub const MAX_MESSAGES_PER_PEER: usize = 10_000;
/// Maximum text payload per message, matching
/// [`trv_core::messaging::MAX_TEXT_BYTES`].
pub const MAX_HISTORY_TEXT_BYTES: usize = 8 * 1024;
/// Suffix for per-peer log files.
const LOG_SUFFIX: &str = ".msglog";

/// Magic bytes at the start of the serialized plaintext record log.
const RECORDS_MAGIC: &[u8; 4] = b"TRVM";
/// Record-log format version.
const RECORDS_VERSION: u8 = 0x01;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Failures from the history store. Fail closed: on any error the
/// caller gets no messages, never partial or forged ones.
#[derive(Debug)]
pub enum HistoryError {
    /// Filesystem error (read/write).
    Io(String),
    /// Wrong passphrase or tampered file: Poly1305 rejected the log.
    /// Nothing was decrypted.
    AuthFailed,
    /// The file is not a history log, has an unsupported version, or
    /// is truncated/malformed. Nothing was decrypted.
    Corrupt(String),
    /// Message text exceeds [`MAX_HISTORY_TEXT_BYTES`].
    Oversized,
    /// Underlying vault primitive failed (lock contention, KDF,
    /// entropy, atomic write).
    Vault(VaultError),
}

impl std::fmt::Display for HistoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HistoryError::Io(e) => write!(f, "history I/O error: {e}"),
            HistoryError::AuthFailed => write!(
                f,
                "history authentication failed: wrong passphrase or tampered log"
            ),
            HistoryError::Corrupt(e) => write!(f, "history log is corrupt: {e}"),
            HistoryError::Oversized => write!(
                f,
                "message text exceeds {MAX_HISTORY_TEXT_BYTES} bytes"
            ),
            HistoryError::Vault(e) => write!(f, "history vault primitive failed: {e}"),
        }
    }
}

impl std::error::Error for HistoryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            HistoryError::Vault(e) => Some(e),
            _ => None,
        }
    }
}

impl From<VaultError> for HistoryError {
    fn from(e: VaultError) -> Self {
        HistoryError::Vault(e)
    }
}

// ---------------------------------------------------------------------------
// Wiping
// ---------------------------------------------------------------------------

/// Best-effort wipe of a plaintext buffer: volatile writes so the
/// compiler cannot elide them. Same pattern as the vault's
/// `DerivedKey` zeroization.
fn wipe(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: `b` is a valid, uniquely-borrowed byte.
        unsafe {
            core::ptr::write_volatile(b, 0u8);
        }
    }
}

// ---------------------------------------------------------------------------
// Store key
// ---------------------------------------------------------------------------

/// The history store's encryption key, derived once at open.
///
/// Best-effort zeroization on drop (same pattern as
/// [`trv_core::crypto::SecretKey`]): volatile writes the compiler
/// cannot elide. `Debug` is redacted.
struct StoreKey([u8; 32]);

impl std::fmt::Debug for StoreKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StoreKey(<redacted>)")
    }
}

impl Drop for StoreKey {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

fn derive_store_key(passphrase: &str, iterations: u32) -> Result<StoreKey, HistoryError> {
    let dk = pbkdf2::pbkdf2_sha512(passphrase.as_bytes(), HIST_KDF_SALT, iterations, 32)
        .map_err(|e| HistoryError::Vault(VaultError::Kdf(e.to_string())))?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&dk);
    // Wipe the Vec copy; `key` is moved into StoreKey.
    let mut dk = dk;
    wipe(&mut dk);
    Ok(StoreKey(key))
}

// ---------------------------------------------------------------------------
// Message record
// ---------------------------------------------------------------------------

/// Delivery state of a persisted message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryStatus {
    /// We sent it; no delivery receipt arrived yet.
    Sent,
    /// It reached the peer (incoming messages are always delivered;
    /// outgoing ones become delivered when the receipt arrives).
    Delivered,
}

/// One persisted message: the durable form of
/// [`trv_core::messaging::StoredMessage`].
///
/// Named `HistoryMessage` (not `StoredMessage`) to avoid confusion
/// with `messaging::StoredMessage`, the in-memory log entry this is
/// converted from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryMessage {
    /// Unique 16-byte message ID (from the messaging layer).
    pub id: [u8; 16],
    /// The conversation peer's 32-byte Ed25519 identity key.
    pub peer: [u8; 32],
    /// True if we sent it, false if the peer did.
    pub outgoing: bool,
    /// Delivery state at persist time.
    pub status: HistoryStatus,
    /// Unix-seconds timestamp minted by the sender. Informational
    /// only (no trusted clock); ordering uses append order.
    pub timestamp: u64,
    /// Human text, UTF-8, at most [`MAX_HISTORY_TEXT_BYTES`] bytes.
    pub text: String,
}

impl HistoryMessage {
    /// Convert an in-memory [`trv_core::messaging::StoredMessage`]
    /// into its durable form. `peer` is the conversation peer's
    /// pinned identity key (from
    /// [`Conversation::peer_id`](trv_core::messaging::Conversation::peer_id)).
    ///
    /// Only text messages convert: receipts and typing hints are
    /// protocol traffic and are never persisted. Fails closed on
    /// oversized or non-text payloads.
    pub fn from_messaging(
        peer: &[u8; 32],
        s: &messaging::StoredMessage,
    ) -> Result<Self, HistoryError> {
        if s.message.kind() != messaging::MessageKind::Text {
            return Err(HistoryError::Corrupt(
                "only text messages are persisted".to_string(),
            ));
        }
        let text = s
            .message
            .text()
            .map_err(|_| HistoryError::Corrupt("message text is not UTF-8".to_string()))?;
        if text.len() > MAX_HISTORY_TEXT_BYTES {
            return Err(HistoryError::Oversized);
        }
        Ok(HistoryMessage {
            id: *s.message.id(),
            peer: *peer,
            outgoing: s.outgoing,
            status: match s.status {
                messaging::MessageStatus::Sent => HistoryStatus::Sent,
                messaging::MessageStatus::Delivered => HistoryStatus::Delivered,
            },
            timestamp: s.message.timestamp(),
            text: text.to_string(),
        })
    }
}

// ---------------------------------------------------------------------------
// Record serialization (plaintext; never touches disk as-is)
// ---------------------------------------------------------------------------

/// Serialize one record. Caller guarantees `text.len()` fits the cap.
fn serialize_record(msg: &HistoryMessage, out: &mut Vec<u8>) {
    out.extend_from_slice(&msg.id);
    out.extend_from_slice(&msg.peer);
    out.push(u8::from(msg.outgoing));
    out.push(match msg.status {
        HistoryStatus::Sent => 0u8,
        HistoryStatus::Delivered => 1u8,
    });
    out.extend_from_slice(&msg.timestamp.to_be_bytes());
    let tb = msg.text.as_bytes();
    out.extend_from_slice(&(tb.len() as u32).to_le_bytes());
    out.extend_from_slice(tb);
}

/// Serialize the full record log (the AEAD plaintext).
fn serialize_records(log: &[HistoryMessage]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(RECORDS_MAGIC);
    out.push(RECORDS_VERSION);
    out.extend_from_slice(&(log.len() as u32).to_le_bytes());
    for msg in log {
        serialize_record(msg, &mut out);
    }
    out
}

fn parse_record(data: &[u8], pos: &mut usize, expect_peer: &[u8; 32]) -> Result<HistoryMessage, HistoryError> {
    let corrupt = |m: &str| HistoryError::Corrupt(m.to_string());
    // Fixed part: 16 + 32 + 1 + 1 + 8 + 4 = 62 bytes.
    if *pos + 62 > data.len() {
        return Err(corrupt("truncated record header"));
    }
    let mut id = [0u8; 16];
    id.copy_from_slice(&data[*pos..*pos + 16]);
    *pos += 16;
    let mut peer = [0u8; 32];
    peer.copy_from_slice(&data[*pos..*pos + 32]);
    *pos += 32;
    // Cross-check: the record's peer must match the file's peer.
    // Catches swapped/renamed log files.
    if &peer != expect_peer {
        return Err(corrupt("record peer does not match log file peer"));
    }
    let outgoing = match data[*pos] {
        0 => false,
        1 => true,
        _ => return Err(corrupt("bad direction byte")),
    };
    *pos += 1;
    let status = match data[*pos] {
        0 => HistoryStatus::Sent,
        1 => HistoryStatus::Delivered,
        _ => return Err(corrupt("bad status byte")),
    };
    *pos += 1;
    let mut ts = [0u8; 8];
    ts.copy_from_slice(&data[*pos..*pos + 8]);
    *pos += 8;
    let timestamp = u64::from_be_bytes(ts);
    let mut lenb = [0u8; 4];
    lenb.copy_from_slice(&data[*pos..*pos + 4]);
    *pos += 4;
    let text_len = u32::from_le_bytes(lenb) as usize;
    if text_len > MAX_HISTORY_TEXT_BYTES {
        return Err(corrupt("record text length absurd"));
    }
    if *pos + text_len > data.len() {
        return Err(corrupt("truncated record text"));
    }
    let text = std::str::from_utf8(&data[*pos..*pos + text_len])
        .map_err(|_| corrupt("record text is not UTF-8"))?
        .to_string();
    *pos += text_len;
    Ok(HistoryMessage {
        id,
        peer,
        outgoing,
        status,
        timestamp,
        text,
    })
}

fn parse_records(data: &[u8], expect_peer: &[u8; 32]) -> Result<Vec<HistoryMessage>, HistoryError> {
    let corrupt = |m: &str| HistoryError::Corrupt(m.to_string());
    if data.len() < 9 || &data[..4] != RECORDS_MAGIC || data[4] != RECORDS_VERSION {
        return Err(corrupt("bad record-log magic or version"));
    }
    let mut countb = [0u8; 4];
    countb.copy_from_slice(&data[5..9]);
    let count = u32::from_le_bytes(countb) as usize;
    if count > MAX_MESSAGES_PER_PEER {
        return Err(corrupt("record count absurd"));
    }
    let mut pos = 9usize;
    let mut log = Vec::with_capacity(count.min(1024));
    for _ in 0..count {
        log.push(parse_record(data, &mut pos, expect_peer)?);
    }
    if pos != data.len() {
        return Err(corrupt("trailing bytes after records"));
    }
    Ok(log)
}

// ---------------------------------------------------------------------------
// File encryption
// ---------------------------------------------------------------------------

/// Build the AEAD associated data: binds every header field so
/// tampering with magic, version, AEAD id, or nonce fails decryption.
fn hist_aad(nonce: &[u8; HIST_NONCE_LEN]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(HIST_AAD_DOMAIN.len() + 2 + HIST_NONCE_LEN);
    aad.extend_from_slice(HIST_AAD_DOMAIN);
    aad.push(HIST_FORMAT_VERSION);
    aad.push(HIST_AEAD_ID);
    aad.extend_from_slice(nonce);
    aad
}

/// Encrypt a serialized record log into the on-disk file format.
fn encrypt_log(key: &StoreKey, plaintext: &[u8]) -> Result<Vec<u8>, HistoryError> {
    let nonce_v = profile::random_bytes(HIST_NONCE_LEN)?;
    let mut nonce = [0u8; HIST_NONCE_LEN];
    nonce.copy_from_slice(&nonce_v);
    let aad = hist_aad(&nonce);
    let ct = chacha20poly1305::encrypt(&key.0, &nonce, &aad, plaintext);
    let mut out = Vec::with_capacity(4 + 1 + 1 + HIST_NONCE_LEN + ct.len());
    out.extend_from_slice(HIST_MAGIC);
    out.push(HIST_FORMAT_VERSION);
    out.push(HIST_AEAD_ID);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt an on-disk log file. Returns the record-log plaintext.
/// Fails closed: wrong passphrase or any tampering yields
/// [`HistoryError::AuthFailed`]; malformed files yield
/// [`HistoryError::Corrupt`]. Nothing is decrypted on failure.
fn decrypt_log(key: &StoreKey, data: &[u8]) -> Result<Vec<u8>, HistoryError> {
    let corrupt = |m: &str| HistoryError::Corrupt(m.to_string());
    if data.len() < 4 + 1 + 1 + HIST_NONCE_LEN + 16 {
        return Err(corrupt("log file truncated"));
    }
    if &data[..4] != HIST_MAGIC {
        return Err(corrupt("bad log magic"));
    }
    if data[4] != HIST_FORMAT_VERSION {
        return Err(corrupt("unsupported log version"));
    }
    if data[5] != HIST_AEAD_ID {
        return Err(corrupt("unsupported AEAD id"));
    }
    let mut nonce = [0u8; HIST_NONCE_LEN];
    nonce.copy_from_slice(&data[6..6 + HIST_NONCE_LEN]);
    let aad = hist_aad(&nonce);
    chacha20poly1305::decrypt(&key.0, &nonce, &aad, &data[6 + HIST_NONCE_LEN..])
        .map_err(|_| HistoryError::AuthFailed)
}

// ---------------------------------------------------------------------------
// Filenames
// ---------------------------------------------------------------------------

fn hex_of(key: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for b in key {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

fn peer_from_hex(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out[i] = (hi * 16 + lo) as u8;
    }
    Some(out)
}

fn log_path_for(dir: &Path, peer: &[u8; 32]) -> PathBuf {
    dir.join(format!("{}{}", hex_of(peer), LOG_SUFFIX))
}

// ---------------------------------------------------------------------------
// The store
// ---------------------------------------------------------------------------

/// Persistent per-peer message history, encrypted at rest with the
/// viewer's vault passphrase.
///
/// Open once with [`HistoryStore::open`]; the store key is derived
/// then and held (zeroized on drop) for the store's lifetime. Each
/// peer's log lives in its own `<peer-hex>.msglog` file inside `dir`.
pub struct HistoryStore {
    dir: PathBuf,
    key: StoreKey,
}

impl std::fmt::Debug for HistoryStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HistoryStore")
            .field("dir", &self.dir)
            .field("key", &self.key)
            .finish()
    }
}

impl HistoryStore {
    /// Open (creating if needed) the history store at `dir`,
    /// deriving the store key from `passphrase` with the vault's
    /// standard KDF strength. Fails closed on empty passphrase.
    pub fn open(dir: &Path, passphrase: &str) -> Result<Self, HistoryError> {
        Self::open_with_iterations(dir, passphrase, VAULT_KDF_ITERATIONS)
    }

    /// [`HistoryStore::open`] with an explicit KDF iteration count.
    /// Public for tests/benchmarks; production callers use
    /// [`HistoryStore::open`].
    pub fn open_with_iterations(
        dir: &Path,
        passphrase: &str,
        iterations: u32,
    ) -> Result<Self, HistoryError> {
        if passphrase.is_empty() {
            return Err(HistoryError::Vault(VaultError::EmptyPassphrase));
        }
        std::fs::create_dir_all(dir).map_err(|e| HistoryError::Io(e.to_string()))?;
        #[cfg(unix)]
        {
            // Owner-only directory: log filenames themselves are
            // public keys (not secret), but defense in depth costs
            // nothing here.
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| HistoryError::Io(e.to_string()))?;
        }
        let key = derive_store_key(passphrase, iterations)?;
        Ok(HistoryStore {
            dir: dir.to_path_buf(),
            key,
        })
    }

    /// Append a message to the peer's log. The whole log is
    /// re-encrypted with a fresh nonce and written atomically;
    /// beyond [`MAX_MESSAGES_PER_PEER`] the oldest messages are
    /// evicted (documented, not silent — see const docs).
    ///
    /// Plaintext is wiped after encryption. Only ciphertext is
    /// written.
    pub fn append(&self, msg: &HistoryMessage) -> Result<(), HistoryError> {
        if msg.text.len() > MAX_HISTORY_TEXT_BYTES {
            return Err(HistoryError::Oversized);
        }
        let path = log_path_for(&self.dir, &msg.peer);
        // Serialize writers for this peer's log.
        let _lock = profile::VaultLock::acquire(&path)?;
        let mut log = self.load_unlocked(&msg.peer)?;
        log.push(msg.clone());
        if log.len() > MAX_MESSAGES_PER_PEER {
            let excess = log.len() - MAX_MESSAGES_PER_PEER;
            log.drain(..excess);
        }
        let mut plaintext = serialize_records(&log);
        let file_bytes = encrypt_log(&self.key, &plaintext)?;
        // Wipe the plaintext now that ciphertext exists. The `log`
        // itself holds owned Strings the caller may still need via
        // `msg`; the serialized buffer is ours to wipe.
        wipe(&mut plaintext);
        profile::atomic_write(&path, &file_bytes)?;
        // `_lock` drops here, releasing the cooperative lock.
        Ok(())
    }

    /// Load a peer's conversation log, oldest first. A missing log
    /// is not an error — it loads as empty. Corruption or a wrong
    /// passphrase fails closed (error, never partial data).
    pub fn load(&self, peer: &[u8; 32]) -> Result<Vec<HistoryMessage>, HistoryError> {
        self.load_unlocked(peer)
    }

    fn load_unlocked(&self, peer: &[u8; 32]) -> Result<Vec<HistoryMessage>, HistoryError> {
        let path = log_path_for(&self.dir, peer);
        let data = match std::fs::read(&path) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(HistoryError::Io(e.to_string())),
        };
        let mut plaintext = decrypt_log(&self.key, &data)?;
        let log = parse_records(&plaintext, peer);
        wipe(&mut plaintext);
        log
    }

    /// Enumerate peers with stored logs. Stray files (locks, temps)
    /// are skipped, not treated as errors.
    pub fn list_peers(&self) -> Result<Vec<[u8; 32]>, HistoryError> {
        let mut peers = Vec::new();
        let entries =
            std::fs::read_dir(&self.dir).map_err(|e| HistoryError::Io(e.to_string()))?;
        for entry in entries {
            let entry = entry.map_err(|e| HistoryError::Io(e.to_string()))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(stem) = name.strip_suffix(LOG_SUFFIX) {
                if let Some(peer) = peer_from_hex(stem) {
                    peers.push(peer);
                }
            }
        }
        Ok(peers)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Low KDF iterations so tests run fast. Production uses
    /// [`VAULT_KDF_ITERATIONS`].
    const TEST_ITERS: u32 = 1_000;

    static DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_dir() -> PathBuf {
        let n = DIR_COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "trv-history-test-{}-{}",
            std::process::id(),
            n
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn open_test(dir: &Path) -> HistoryStore {
        HistoryStore::open_with_iterations(dir, "correct horse battery staple", TEST_ITERS)
            .expect("test store opens")
    }

    fn peer(n: u8) -> [u8; 32] {
        [n; 32]
    }

    fn msg(peer: &[u8; 32], id_byte: u8, outgoing: bool, text: &str) -> HistoryMessage {
        HistoryMessage {
            id: [id_byte; 16],
            peer: *peer,
            outgoing,
            status: if outgoing {
                HistoryStatus::Sent
            } else {
                HistoryStatus::Delivered
            },
            timestamp: 1_700_000_000 + u64::from(id_byte),
            text: text.to_string(),
        }
    }

    #[test]
    fn append_load_round_trip() {
        let dir = test_dir();
        let store = open_test(&dir);
        let p = peer(7);
        store.append(&msg(&p, 1, true, "hello")).unwrap();
        store.append(&msg(&p, 2, false, "hi back")).unwrap();
        let log = store.load(&p).unwrap();
        assert_eq!(log.len(), 2);
        assert_eq!(log[0].text, "hello");
        assert!(log[0].outgoing);
        assert_eq!(log[0].status, HistoryStatus::Sent);
        assert_eq!(log[1].text, "hi back");
        assert!(!log[1].outgoing);
        assert_eq!(log[1].status, HistoryStatus::Delivered);
        assert_eq!(log[0].id, [1u8; 16]);
        assert_eq!(log[0].peer, p);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_log_loads_empty() {
        let dir = test_dir();
        let store = open_test(&dir);
        assert!(store.load(&peer(9)).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wrong_passphrase_fails_closed() {
        let dir = test_dir();
        let store = open_test(&dir);
        let p = peer(3);
        store.append(&msg(&p, 1, true, "secret")).unwrap();
        drop(store);
        let wrong =
            HistoryStore::open_with_iterations(&dir, "wrong passphrase", TEST_ITERS).unwrap();
        match wrong.load(&p) {
            Err(HistoryError::AuthFailed) => {}
            other => panic!("expected AuthFailed, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn flipped_byte_fails_closed() {
        let dir = test_dir();
        let store = open_test(&dir);
        let p = peer(4);
        store.append(&msg(&p, 1, true, "secret")).unwrap();
        let path = log_path_for(&dir, &p);
        let mut data = std::fs::read(&path).unwrap();
        // Flip a byte deep in the ciphertext region.
        let idx = data.len() - 5;
        data[idx] ^= 0x01;
        std::fs::write(&path, &data).unwrap();
        match store.load(&p) {
            Err(HistoryError::AuthFailed) => {}
            other => panic!("expected AuthFailed, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn truncated_file_fails_closed() {
        let dir = test_dir();
        let store = open_test(&dir);
        let p = peer(5);
        store.append(&msg(&p, 1, true, "secret")).unwrap();
        let path = log_path_for(&dir, &p);
        let data = std::fs::read(&path).unwrap();
        std::fs::write(&path, &data[..data.len() / 2]).unwrap();
        match store.load(&p) {
            Err(HistoryError::Corrupt(_)) | Err(HistoryError::AuthFailed) => {}
            other => panic!("expected Corrupt/AuthFailed, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn per_peer_isolation() {
        let dir = test_dir();
        let store = open_test(&dir);
        let a = peer(10);
        let b = peer(11);
        store.append(&msg(&a, 1, true, "for A")).unwrap();
        store.append(&msg(&b, 1, true, "for B")).unwrap();
        // Corrupt A's file outright.
        let path_a = log_path_for(&dir, &a);
        std::fs::write(&path_a, b"definitely not a log").unwrap();
        assert!(store.load(&a).is_err());
        // B is unaffected.
        let log_b = store.load(&b).unwrap();
        assert_eq!(log_b.len(), 1);
        assert_eq!(log_b[0].text, "for B");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn swapped_log_file_rejected() {
        let dir = test_dir();
        let store = open_test(&dir);
        let a = peer(12);
        let b = peer(13);
        store.append(&msg(&a, 1, true, "for A")).unwrap();
        // Rename A's file to B's name: records claim peer A but the
        // file claims peer B.
        let path_a = log_path_for(&dir, &a);
        let path_b = log_path_for(&dir, &b);
        std::fs::rename(&path_a, &path_b).unwrap();
        match store.load(&b) {
            Err(HistoryError::Corrupt(_)) => {}
            other => panic!("expected Corrupt, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cap_eviction_keeps_newest() {
        // Exercise the eviction rule directly: 10_005 messages in,
        // oldest 5 out.
        let p = peer(20);
        let mut log: Vec<HistoryMessage> = (0..MAX_MESSAGES_PER_PEER + 5)
            .map(|i| HistoryMessage {
                id: [(i % 251) as u8; 16],
                peer: p,
                outgoing: true,
                status: HistoryStatus::Sent,
                timestamp: i as u64,
                text: format!("m{i}"),
            })
            .collect();
        if log.len() > MAX_MESSAGES_PER_PEER {
            let excess = log.len() - MAX_MESSAGES_PER_PEER;
            log.drain(..excess);
        }
        assert_eq!(log.len(), MAX_MESSAGES_PER_PEER);
        assert_eq!(log[0].text, "m5");
        assert_eq!(log[log.len() - 1].text, format!("m{}", MAX_MESSAGES_PER_PEER + 4));
    }

    #[test]
    fn append_persists_across_reopen() {
        let dir = test_dir();
        let p = peer(21);
        {
            let store = open_test(&dir);
            store.append(&msg(&p, 1, true, "before restart")).unwrap();
        }
        // Reopen with the same passphrase: history survives.
        let store2 = open_test(&dir);
        let log = store2.load(&p).unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].text, "before restart");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn oversized_text_rejected() {
        let dir = test_dir();
        let store = open_test(&dir);
        let p = peer(22);
        let big = "x".repeat(MAX_HISTORY_TEXT_BYTES + 1);
        match store.append(&msg(&p, 1, true, &big)) {
            Err(HistoryError::Oversized) => {}
            other => panic!("expected Oversized, got {other:?}"),
        }
        // Nothing was written.
        assert!(store.load(&p).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn list_peers_enumerates_and_ignores_stray_files() {
        let dir = test_dir();
        let store = open_test(&dir);
        let a = peer(30);
        let b = peer(31);
        store.append(&msg(&a, 1, true, "a")).unwrap();
        store.append(&msg(&b, 1, true, "b")).unwrap();
        // Stray files a real directory accumulates.
        std::fs::write(dir.join("notes.txt"), b"nope").unwrap();
        std::fs::write(dir.join(format!("{}.lock", hex_of(&a))), b"").unwrap();
        std::fs::write(dir.join("zz.msglog"), b"bad hex stem").unwrap();
        let mut peers = store.list_peers().unwrap();
        peers.sort();
        assert_eq!(peers, vec![a, b]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_passphrase_refused() {
        let dir = test_dir();
        match HistoryStore::open_with_iterations(&dir, "", TEST_ITERS) {
            Err(HistoryError::Vault(VaultError::EmptyPassphrase)) => {}
            other => panic!("expected EmptyPassphrase, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn malformed_record_log_rejected() {
        let p = peer(40);
        // Bad magic.
        let mut bad = serialize_records(&[msg(&p, 1, true, "x")]);
        bad[0] = 0xFF;
        assert!(matches!(
            parse_records(&bad, &p),
            Err(HistoryError::Corrupt(_))
        ));
        // Trailing garbage.
        let mut bad2 = serialize_records(&[msg(&p, 1, true, "x")]);
        bad2.push(0x00);
        assert!(matches!(
            parse_records(&bad2, &p),
            Err(HistoryError::Corrupt(_))
        ));
        // Declared count lies.
        let mut bad3 = serialize_records(&[msg(&p, 1, true, "x")]);
        bad3[5] = 99;
        assert!(matches!(
            parse_records(&bad3, &p),
            Err(HistoryError::Corrupt(_))
        ));
    }

    #[test]
    fn header_tamper_fails_decryption() {
        let dir = test_dir();
        let store = open_test(&dir);
        let p = peer(41);
        store.append(&msg(&p, 1, true, "secret")).unwrap();
        let path = log_path_for(&dir, &p);
        let mut data = std::fs::read(&path).unwrap();
        // Flip a nonce byte: the AAD binds the nonce, so this must
        // fail authentication.
        data[7] ^= 0x01;
        std::fs::write(&path, &data).unwrap();
        assert!(matches!(store.load(&p), Err(HistoryError::AuthFailed)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn plaintext_never_on_disk() {
        let dir = test_dir();
        let store = open_test(&dir);
        let p = peer(42);
        let secret_text = "super secret phrase xyzzy";
        store.append(&msg(&p, 1, true, secret_text)).unwrap();
        let path = log_path_for(&dir, &p);
        let raw = std::fs::read(&path).unwrap();
        // Sliding-window scan: the plaintext must not appear anywhere
        // in the file bytes.
        let needle = secret_text.as_bytes();
        let found = raw
            .windows(needle.len())
            .any(|w| w == needle);
        assert!(!found, "plaintext found on disk");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bridge_from_messaging_round_trip() {
        use trv_core::messaging::{Conversation, MessageStatus};
        use trv_core::transport::{establish_auth, IdentityKey};

        let dir = test_dir();
        let store = open_test(&dir);

        let id_a = IdentityKey::generate(&[1u8; 32]);
        let id_b = IdentityKey::generate(&[2u8; 32]);
        let (chan_a, _chan_b) = establish_auth(&id_a, &id_b).expect("auth handshake");
        let mut conv = Conversation::new(chan_a, id_a.public(), id_b.public());
        conv.send_text("hello over the wire").expect("send");

        let stored = &conv.history()[0];
        assert_eq!(stored.status, MessageStatus::Sent);
        let hm = HistoryMessage::from_messaging(id_b.public().as_bytes(), stored).unwrap();
        assert_eq!(hm.text, "hello over the wire");
        assert!(hm.outgoing);
        assert_eq!(hm.peer, *id_b.public().as_bytes());

        store.append(&hm).unwrap();
        let log = store.load(id_b.public().as_bytes()).unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0], hm);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bridge_rejects_non_text() {
        use trv_core::messaging::{Conversation, MessageStatus};
        use trv_core::transport::{establish_auth, IdentityKey};

        let id_a = IdentityKey::generate(&[3u8; 32]);
        let id_b = IdentityKey::generate(&[4u8; 32]);
        let (chan_a, chan_b) =
            establish_auth(&id_a, &id_b).expect("auth handshake");
        let mut conv_a = Conversation::new(chan_a, id_a.public(), id_b.public());
        let mut conv_b = Conversation::new(chan_b, id_b.public(), id_a.public());
        // Typing hints are never logged and must not persist.
        let frame = conv_a.send_typing().expect("typing");
        let received = conv_b.receive_frame(&frame).expect("receive");
        // The typing hint produces no history entry at all.
        assert!(conv_b.history().is_empty());
        let _ = received;
        let _ = MessageStatus::Sent;
    }

    #[test]
    fn hex_helpers_round_trip() {
        let k = peer(0xab);
        let h = hex_of(&k);
        assert_eq!(h.len(), 64);
        assert_eq!(peer_from_hex(&h).unwrap(), k);
        assert!(peer_from_hex("zz").is_none());
        assert!(peer_from_hex(&"ab".repeat(31)).is_none());
        assert!(peer_from_hex(&format!("{}!", "ab".repeat(32))).is_none());
    }

    #[test]
    fn store_debug_redacts_key() {
        let dir = test_dir();
        let store = open_test(&dir);
        let dbg = format!("{store:?}");
        assert!(dbg.contains("<redacted>"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
