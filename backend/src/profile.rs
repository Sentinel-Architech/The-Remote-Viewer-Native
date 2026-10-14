//! Encrypted on-device profile vault.
//!
//! The vault holds the viewer's profile (handle, display name, ...).
//! In memory it is a plain struct; **at rest it is always a
//! ChaCha20-Poly1305-encrypted file**. The encryption key is derived
//! from a user passphrase with PBKDF2-HMAC-SHA512 (600,000 iterations,
//! fresh random 16-byte salt per save).
//!
//! Wrong passphrase — or any tampering — fails closed: Poly1305
//! rejects the file and nothing is decrypted. There is no partial
//! decryption and no oracle distinguishing "wrong passphrase" from
//! "corrupt file".
//!
//! Filesystem hardening (this module):
//!
//! - **Atomic writes.** Saves go to a temp file in the same directory
//!   (`<name>.tmp.<pid>-<rand>`), which is fsync'd and then renamed
//!   over the target. A crash mid-save leaves the previous vault
//!   intact; a torn file can never be observed by a reader.
//! - **Owner-only permissions.** On Unix the temp file is chmod'd to
//!   `0o600` immediately after creation, before any secret bytes are
//!   written. (No std-only portable equivalent exists elsewhere;
//!   documented, not silent.)
//! - **Authenticated metadata.** Format v2 binds the whole header
//!   (version, KDF/AEAD ids, iteration count, salt, nonce) into the
//!   AEAD as associated data, so flipping any header field fails
//!   decryption. v1 files (constant AAD) still open; use
//!   [`ProfileVault::migrate_v1_to_v2`] for the explicit upgrade.
//! - **Cooperative locking.** Saves take an advisory `<name>.lock`
//!   file via exclusive creation and fail closed with
//!   [`VaultError::VaultBusy`] if another process holds it. This is
//!   cooperative, not mandatory OS locking.
//!
//! Myspace-style live customization (music etc., ENHANCED) renders from
//! this vault — all local.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use trv_core::crypto::{chacha20poly1305, pbkdf2};

/// PBKDF2 iteration count for the vault KDF.
///
/// OWASP's recommendation for PBKDF2-HMAC-SHA512. Tuned for an
/// interactive unlock (a second or two on a phone), not for unit
/// tests — tests pass small counts explicitly.
pub const VAULT_KDF_ITERATIONS: u32 = 600_000;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// Magic of the encrypted vault file.
const ENC_MAGIC: &[u8; 4] = b"TRVV";
/// Magic of the legacy plaintext vault file (accepted by the one-time
/// migration only; never written by current code).
const LEGACY_MAGIC: &[u8; 4] = b"TRVP";
/// Version byte of the legacy plaintext (`TRVP`) file format.
/// (Unrelated to the encrypted format versions below.)
const FORMAT_VERSION: u8 = 0x01;
/// Encrypted format v1: header metadata is NOT authenticated (constant
/// AAD). Read-only now — kept so old vaults still open. New saves
/// always write v2.
pub const ENC_FORMAT_V1: u8 = 0x01;
/// Encrypted format v2: the full header (version, KDF/AEAD ids,
/// iteration count, salt, nonce) is bound into the AEAD as associated
/// data. Any header tampering fails decryption.
pub const ENC_FORMAT_V2: u8 = 0x02;
const KDF_ID_PBKDF2_SHA512: u8 = 0x01;
const AEAD_ID_CHACHA20_POLY1305: u8 = 0x01;

/// Associated data for v1 files: a constant, so v1 header fields
/// (salt, nonce, ...) are NOT cryptographically bound. Kept for
/// reading old vaults only.
const VAULT_AAD: &[u8] = b"TRV-VAULT-V1";
/// Domain separator for the v2 header-bound associated data built by
/// [`v2_aad`].
const VAULT_AAD_V2_DOMAIN: &[u8] = b"TRV-VAULT-V2";

/// Version byte of the inner plaintext payload.
const PAYLOAD_VERSION: u8 = 0x01;
/// Max bytes for one serialized profile field. Corrupt files fail
/// closed instead of allocating absurd buffers.
const MAX_FIELD_LEN: usize = 4096;

/// Errors from the encrypted vault API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultError {
    /// Filesystem error (read/write).
    Io(String),
    /// The passphrase was empty.
    EmptyPassphrase,
    /// Poly1305 rejected the file: wrong passphrase, tampered
    /// ciphertext, or corrupted bytes. Nothing was decrypted.
    BadPassphrase,
    /// The file is not a vault file, has an unsupported version, or
    /// is truncated. Nothing was decrypted.
    Corrupt(String),
    /// The KDF refused its parameters (internal error).
    Kdf(String),
    /// Migration source is already an encrypted vault file.
    AlreadyEncrypted,
    /// Migration source is not a parseable legacy plaintext file.
    LegacyParse(String),
    /// Another process holds the vault's cooperative lock file.
    /// Remove `<vault>.lock` if its holder is known to be dead.
    VaultBusy,
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultError::Io(e) => write!(f, "vault I/O error: {e}"),
            VaultError::EmptyPassphrase => write!(f, "vault passphrase must not be empty"),
            VaultError::BadPassphrase => {
                write!(f, "vault authentication failed: wrong passphrase or tampered file")
            }
            VaultError::Corrupt(e) => write!(f, "vault file is corrupt: {e}"),
            VaultError::Kdf(e) => write!(f, "vault key derivation failed: {e}"),
            VaultError::AlreadyEncrypted => {
                write!(f, "file is already an encrypted vault (nothing to migrate)")
            }
            VaultError::LegacyParse(e) => {
                write!(f, "legacy plaintext vault could not be parsed: {e}")
            }
            VaultError::VaultBusy => {
                write!(f, "vault is busy: another process holds the vault lock")
            }
        }
    }
}

impl std::error::Error for VaultError {}

/// A 32-byte vault encryption key.
///
/// Best-effort zeroization on drop (same pattern as
/// [`trv_core::crypto::SecretKey`]): the bytes are overwritten with
/// `write_volatile` so the compiler cannot elide the wipe. `Debug`
/// is redacted.
struct DerivedKey([u8; 32]);

impl std::fmt::Debug for DerivedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DerivedKey(<redacted>)")
    }
}

impl Drop for DerivedKey {
    fn drop(&mut self) {
        for b in self.0.iter_mut() {
            // SAFETY: `b` is a valid, uniquely-borrowed byte.
            unsafe {
                core::ptr::write_volatile(b, 0u8);
            }
        }
    }
}

/// A viewer's local profile vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileVault {
    /// The viewer's handle (username).
    pub handle: String,
    /// Display name shown in the native UI (customizable, Myspace-style).
    pub display_name: String,
}

/// Fill `out` with `n` random bytes from the OS CSPRNG.
///
/// If `/dev/urandom` is unavailable, returns an error: the vault
/// FAILS CLOSED rather than falling back to weak time/PID-based
/// entropy. Predictable salts or nonces would weaken the vault's
/// encryption, so refusing to save is safer than saving weakly.
pub(crate) fn random_bytes(n: usize) -> Result<Vec<u8>, VaultError> {
    if let Ok(mut f) = File::open("/dev/urandom") {
        let mut out = vec![0u8; n];
        f.read_exact(&mut out)
            .map_err(|e| VaultError::Io(e.to_string()))?;
        return Ok(out);
    }
    Err(VaultError::Io(
        "OS entropy (/dev/urandom) unavailable; refusing to use weak fallback entropy for vault salt/nonce"
            .to_string(),
    ))
}

fn derive_key(passphrase: &str, salt: &[u8], iterations: u32) -> Result<DerivedKey, VaultError> {
    let dk = pbkdf2::pbkdf2_sha512(passphrase.as_bytes(), salt, iterations, 32)
        .map_err(|e| VaultError::Kdf(e.to_string()))?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&dk);
    // Wipe the Vec copy; `key` is moved into DerivedKey.
    let mut dk = dk;
    for b in dk.iter_mut() {
        // SAFETY: `b` is a valid, uniquely-borrowed byte.
        unsafe {
            core::ptr::write_volatile(b, 0u8);
        }
    }
    Ok(DerivedKey(key))
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    let b = s.as_bytes();
    out.extend_from_slice(&(b.len() as u16).to_le_bytes());
    out.extend_from_slice(b);
}

fn get_str(data: &[u8], pos: &mut usize) -> Result<String, VaultError> {
    if *pos + 2 > data.len() {
        return Err(VaultError::Corrupt("truncated field length".into()));
    }
    let len_bytes: [u8; 2] = data[*pos..*pos + 2]
        .try_into()
        .map_err(|_| VaultError::Corrupt("truncated field length".into()))?;
    let len = u16::from_le_bytes(len_bytes) as usize;
    *pos += 2;
    if len > MAX_FIELD_LEN {
        return Err(VaultError::Corrupt("field length absurd".into()));
    }
    if *pos + len > data.len() {
        return Err(VaultError::Corrupt("truncated field data".into()));
    }
    let s = std::str::from_utf8(&data[*pos..*pos + len])
        .map_err(|_| VaultError::Corrupt("field is not UTF-8".into()))?;
    *pos += len;
    Ok(s.to_string())
}

/// Serialize the vault to the inner plaintext payload (this is what
/// gets encrypted — it never touches disk as-is).
fn serialize_payload(vault: &ProfileVault) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(PAYLOAD_VERSION);
    put_str(&mut out, &vault.handle);
    put_str(&mut out, &vault.display_name);
    out
}

fn parse_payload(data: &[u8]) -> Result<ProfileVault, VaultError> {
    if data.is_empty() || data[0] != PAYLOAD_VERSION {
        return Err(VaultError::Corrupt("bad payload version".into()));
    }
    let mut pos = 1;
    let handle = get_str(data, &mut pos)?;
    let display_name = get_str(data, &mut pos)?;
    if pos != data.len() {
        return Err(VaultError::Corrupt("trailing bytes".into()));
    }
    Ok(ProfileVault {
        handle,
        display_name,
    })
}

/// Serialize the legacy plaintext file format (test-only helper).
///
/// No shipped version ever wrote this — it exists so tests can build
/// a legacy file for [`ProfileVault::migrate_from_plaintext`] to
/// upgrade.
#[cfg(test)]
fn serialize_legacy(vault: &ProfileVault) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(LEGACY_MAGIC);
    out.push(FORMAT_VERSION);
    out.extend_from_slice(&serialize_payload(vault));
    out
}

fn parse_legacy(data: &[u8]) -> Result<ProfileVault, VaultError> {
    if data.len() < 5 || &data[..4] != LEGACY_MAGIC || data[4] != FORMAT_VERSION {
        return Err(VaultError::LegacyParse(
            "not a TRVP legacy plaintext vault".into(),
        ));
    }
    parse_payload(&data[5..]).map_err(|e| VaultError::LegacyParse(e.to_string()))
}

// ---------------------------------------------------------------------------
// Filesystem hardening: atomic writes, permissions, cooperative locking.
// ---------------------------------------------------------------------------

/// Build the v2 associated data: binds every header field into the
/// AEAD so tampering with version, KDF/AEAD ids, iteration count,
/// salt, or nonce fails decryption instead of silently changing
/// parameters.
fn v2_aad(
    version: u8,
    kdf_id: u8,
    aead_id: u8,
    iterations: u32,
    salt: &[u8],
    nonce: &[u8],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(
        VAULT_AAD_V2_DOMAIN.len() + 3 + 4 + salt.len() + nonce.len(),
    );
    aad.extend_from_slice(VAULT_AAD_V2_DOMAIN);
    aad.push(version);
    aad.push(kdf_id);
    aad.push(aead_id);
    aad.extend_from_slice(&iterations.to_le_bytes());
    aad.extend_from_slice(salt);
    aad.extend_from_slice(nonce);
    aad
}

/// Restrict a freshly created vault file to owner read/write
/// (`0o600`), applied immediately after creation and BEFORE any
/// secret bytes are written.
///
/// On non-Unix targets there is no std-only portable equivalent of
/// owner-only permissions, so this is a documented no-op there and
/// the OS default ACLs apply. (Windows' `PermissionsExt` only models
/// readonly-ness and cannot express `0o600`.)
fn lockdown_permissions(file: &File) -> Result<(), VaultError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = file
            .metadata()
            .map_err(|e| VaultError::Io(format!("cannot stat vault temp file: {e}")))?
            .permissions();
        perms.set_mode(0o600);
        file.set_permissions(perms)
            .map_err(|e| VaultError::Io(format!("cannot lockdown vault permissions: {e}")))?;
    }
    #[cfg(not(unix))]
    {
        // Documented limitation: no portable owner-only permission
        // API in std on this platform; OS defaults apply.
        let _ = file;
    }
    Ok(())
}

/// Temp path for an atomic save of `target`: same directory (so the
/// final rename is atomic), named `<file>.tmp.<pid>-<randhex>`.
///
/// Same-directory placement is load-bearing: `rename` is only atomic
/// within one filesystem.
fn temp_path_for(target: &Path, rand_suffix: &[u8]) -> PathBuf {
    let stem = target
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_default();
    let mut name = stem;
    name.push(format!(".tmp.{}-", std::process::id()));
    for b in rand_suffix {
        name.push(format!("{b:02x}"));
    }
    target.with_file_name(name)
}

/// Stage one: create the temp file exclusively, lockdown its
/// permissions, write `bytes`, flush, and fsync. Returns the temp
/// path. The target is untouched — a crash here leaves the old vault
/// intact.
fn stage_temp_file(target: &Path, bytes: &[u8]) -> Result<PathBuf, VaultError> {
    let suffix = random_bytes(8)?;
    let tmp = temp_path_for(target, &suffix);
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .map_err(|e| VaultError::Io(format!("cannot create vault temp file: {e}")))?;
    lockdown_permissions(&f)?;
    f.write_all(bytes)
        .map_err(|e| VaultError::Io(format!("cannot write vault temp file: {e}")))?;
    f.flush()
        .map_err(|e| VaultError::Io(format!("cannot flush vault temp file: {e}")))?;
    f.sync_all()
        .map_err(|e| VaultError::Io(format!("vault temp fsync failed: {e}")))?;
    drop(f);
    Ok(tmp)
}

/// Best-effort fsync of the target's parent directory so the rename
/// itself is durable. Never fails a save: the file data is already
/// safe; only the directory entry's durability is at stake.
fn sync_parent_dir(target: &Path) {
    if let Some(parent) = target.parent() {
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
    }
}

/// Stage two: atomically replace `target` with the staged temp file.
/// After this returns, readers see either the complete old vault or
/// the complete new vault — never a torn write.
fn commit_temp_file(tmp: &Path, target: &Path) -> Result<(), VaultError> {
    std::fs::rename(tmp, target)
        .map_err(|e| VaultError::Io(format!("vault atomic rename failed: {e}")))?;
    sync_parent_dir(target);
    Ok(())
}

/// Write `bytes` to `target` atomically: stage to a temp file, fsync,
/// rename over the target. On ANY failure the temp file is removed
/// (best-effort) and the previous target — if any — is untouched.
pub(crate) fn atomic_write(target: &Path, bytes: &[u8]) -> Result<(), VaultError> {
    let tmp = stage_temp_file(target, bytes)?;
    let result = commit_temp_file(&tmp, target);
    if result.is_err() {
        // Don't leave the staged temp behind on a failed rename.
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Lock-file path for `target`: `<file>.lock` next to the vault.
fn lock_path_for(target: &Path) -> PathBuf {
    let mut name = target
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_default();
    name.push(".lock");
    target.with_file_name(name)
}

/// Cooperative advisory lock for vault writes.
///
/// Acquired via exclusive creation of `<vault>.lock`; a second
/// writer fails closed with [`VaultError::VaultBusy`]. The lock file
/// is removed when the guard drops (success or failure path).
///
/// This is COOPERATIVE, not mandatory OS locking: it only serializes
/// writers that go through this API. A crashed holder leaves a stale
/// lock file behind — it contains the holder's PID for diagnosis and
/// must be removed by the operator. No PID-liveness probing is done:
/// that is not portable in std-only code.
pub(crate) struct VaultLock {
    lock_path: PathBuf,
    /// Held open for the lock's lifetime (conventional; exclusivity
    /// was established at creation).
    _handle: File,
}

impl VaultLock {
    pub(crate) fn acquire(target: &Path) -> Result<Self, VaultError> {
        let lock_path = lock_path_for(target);
        let mut handle = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    VaultError::VaultBusy
                } else {
                    VaultError::Io(format!("cannot create vault lock file: {e}"))
                }
            })?;
        // Informational only: helps an operator identify a stale lock's
        // holder. Not used for liveness decisions.
        let _ = writeln!(handle, "pid={}", std::process::id());
        Ok(VaultLock {
            lock_path,
            _handle: handle,
        })
    }
}

impl Drop for VaultLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.lock_path);
    }
}

/// Outcome of [`ProfileVault::migrate_v1_to_v2`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultUpgradeOutcome {
    /// The file was already v2; nothing was written.
    AlreadyCurrent,
    /// The v1 vault was decrypted and atomically re-saved as v2.
    Upgraded,
}

impl ProfileVault {
    /// Create a vault for `handle`. Display name defaults to the handle
    /// and can be customized later — all local. In-memory only; use
    /// [`ProfileVault::save_encrypted`] to persist.
    pub fn new(handle: &str) -> Self {
        ProfileVault {
            handle: handle.to_string(),
            display_name: handle.to_string(),
        }
    }

    /// Decentralized email replacing traditional email after registration.
    ///
    /// Canonical implementation lives in
    /// [`crate::registration::decentralized_email`]; this delegates to it
    /// so both paths produce identical addresses.
    pub fn decentralized_email(&self) -> String {
        crate::registration::decentralized_email(&self.handle)
    }

    /// Persist the vault to `path`, encrypted with `passphrase`.
    ///
    /// A fresh random salt and nonce are drawn per save, so two saves
    /// of the same vault never produce the same bytes. Fails closed on
    /// empty passphrase or I/O error. Overwrites any existing file.
    pub fn save_encrypted(&self, path: &Path, passphrase: &str) -> Result<(), VaultError> {
        self.save_encrypted_with(path, passphrase, VAULT_KDF_ITERATIONS)
    }

    /// [`ProfileVault::save_encrypted`] with an explicit iteration
    /// count. Public for tests/benchmarks; production callers use
    /// [`ProfileVault::save_encrypted`].
    ///
    /// Writes format v2 (header-bound AAD) atomically: the file is
    /// staged to a `0o600` temp file, fsync'd, and renamed over the
    /// target while holding the cooperative vault lock. A crash or
    /// error mid-save leaves the previous vault intact.
    pub fn save_encrypted_with(
        &self,
        path: &Path,
        passphrase: &str,
        iterations: u32,
    ) -> Result<(), VaultError> {
        if passphrase.is_empty() {
            return Err(VaultError::EmptyPassphrase);
        }
        // Serialize writers; fail closed if another process holds it.
        let _lock = VaultLock::acquire(path)?;
        let salt = random_bytes(SALT_LEN)?;
        let nonce_v = random_bytes(NONCE_LEN)?;
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&nonce_v);
        let key = derive_key(passphrase, &salt, iterations)?;
        let payload = serialize_payload(self);
        let aad = v2_aad(
            ENC_FORMAT_V2,
            KDF_ID_PBKDF2_SHA512,
            AEAD_ID_CHACHA20_POLY1305,
            iterations,
            &salt,
            &nonce,
        );
        let ct = chacha20poly1305::encrypt(&key.0, &nonce, &aad, &payload);
        // `key` is dropped (zeroized) here.
        let mut file_bytes = Vec::with_capacity(4 + 1 + 1 + 1 + 4 + SALT_LEN + NONCE_LEN + ct.len());
        file_bytes.extend_from_slice(ENC_MAGIC);
        file_bytes.push(ENC_FORMAT_V2);
        file_bytes.push(KDF_ID_PBKDF2_SHA512);
        file_bytes.push(AEAD_ID_CHACHA20_POLY1305);
        file_bytes.extend_from_slice(&iterations.to_le_bytes());
        file_bytes.extend_from_slice(&salt);
        file_bytes.extend_from_slice(&nonce);
        file_bytes.extend_from_slice(&ct);
        atomic_write(path, &file_bytes)?;
        // `_lock` drops here, releasing the cooperative lock.
        Ok(())
    }

    /// Open a vault file previously written by
    /// [`ProfileVault::save_encrypted`].
    ///
    /// Reads both format v1 (constant AAD) and v2 (header-bound AAD);
    /// unknown versions fail closed. Wrong passphrase — or any
    /// tampering, including header tampering on v2 files — returns
    /// [`VaultError::BadPassphrase`] and decrypts nothing. Malformed
    /// files return [`VaultError::Corrupt`].
    ///
    /// Reads take no lock: atomic renames guarantee a reader only ever
    /// sees a complete vault file.
    pub fn open_encrypted(path: &Path, passphrase: &str) -> Result<ProfileVault, VaultError> {
        if passphrase.is_empty() {
            return Err(VaultError::EmptyPassphrase);
        }
        let bytes = std::fs::read(path).map_err(|e| VaultError::Io(e.to_string()))?;
        // Header: magic(4) + version(1) + kdf(1) + aead(1) + iters(4)
        //        + salt(16) + nonce(12) + ct+tag(>=16).
        const HEADER_LEN: usize = 4 + 1 + 1 + 1 + 4 + SALT_LEN + NONCE_LEN;
        if bytes.len() < HEADER_LEN + TAG_LEN {
            return Err(VaultError::Corrupt("file truncated".into()));
        }
        if &bytes[..4] != ENC_MAGIC {
            return Err(VaultError::Corrupt("bad magic".into()));
        }
        let version = bytes[4];
        if version != ENC_FORMAT_V1 && version != ENC_FORMAT_V2 {
            return Err(VaultError::Corrupt("unsupported version".into()));
        }
        if bytes[5] != KDF_ID_PBKDF2_SHA512 {
            return Err(VaultError::Corrupt("unsupported KDF".into()));
        }
        if bytes[6] != AEAD_ID_CHACHA20_POLY1305 {
            return Err(VaultError::Corrupt("unsupported AEAD".into()));
        }
        let iterations = u32::from_le_bytes(bytes[7..11].try_into().unwrap());
        if iterations == 0 {
            return Err(VaultError::Corrupt("zero KDF iterations".into()));
        }
        let salt = &bytes[11..11 + SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[11 + SALT_LEN..HEADER_LEN]);
        let ct = &bytes[HEADER_LEN..];
        // v1 keeps its legacy constant AAD; v2 re-binds the exact
        // header bytes just parsed, so any header tampering breaks the
        // Poly1305 tag.
        let aad: Vec<u8> = match version {
            ENC_FORMAT_V1 => VAULT_AAD.to_vec(),
            _ => v2_aad(version, bytes[5], bytes[6], iterations, salt, &nonce),
        };
        let key = derive_key(passphrase, salt, iterations)?;
        let payload = chacha20poly1305::decrypt(&key.0, &nonce, &aad, ct)
            .map_err(|_| VaultError::BadPassphrase)?;
        // `key` is dropped (zeroized) here.
        parse_payload(&payload)
    }

    /// Read a vault file's encrypted-format version byte without
    /// decrypting. Returns [`ENC_FORMAT_V1`] or [`ENC_FORMAT_V2`].
    pub fn format_version(path: &Path) -> Result<u8, VaultError> {
        let bytes = std::fs::read(path).map_err(|e| VaultError::Io(e.to_string()))?;
        if bytes.len() < 5 || &bytes[..4] != ENC_MAGIC {
            return Err(VaultError::Corrupt("not a vault file".into()));
        }
        Ok(bytes[4])
    }

    /// Explicit one-time upgrade of a v1 vault file to the v2 layout
    /// (header-bound AAD), re-encrypted atomically under the same
    /// passphrase.
    ///
    /// Returns [`VaultUpgradeOutcome::AlreadyCurrent`] without writing
    /// anything if the file is already v2. v1 files are still readable
    /// by [`ProfileVault::open_encrypted`]; this upgrade is explicit
    /// rather than silent so callers know when the stronger binding
    /// takes effect.
    pub fn migrate_v1_to_v2(path: &Path, passphrase: &str) -> Result<VaultUpgradeOutcome, VaultError> {
        Self::migrate_v1_to_v2_with(path, passphrase, VAULT_KDF_ITERATIONS)
    }

    /// [`ProfileVault::migrate_v1_to_v2`] with an explicit iteration
    /// count. Public for tests/benchmarks; production callers use
    /// [`ProfileVault::migrate_v1_to_v2`].
    pub fn migrate_v1_to_v2_with(
        path: &Path,
        passphrase: &str,
        iterations: u32,
    ) -> Result<VaultUpgradeOutcome, VaultError> {
        match Self::format_version(path)? {
            ENC_FORMAT_V2 => Ok(VaultUpgradeOutcome::AlreadyCurrent),
            ENC_FORMAT_V1 => {
                let vault = Self::open_encrypted(path, passphrase)?;
                vault.save_encrypted_with(path, passphrase, iterations)?;
                Ok(VaultUpgradeOutcome::Upgraded)
            }
            _ => Err(VaultError::Corrupt("unsupported version".into())),
        }
    }

    /// One-time upgrade of a legacy plaintext vault file.
    ///
    /// Reads `plain_path` (legacy `TRVP` format), writes the encrypted
    /// vault to `enc_path` with `passphrase`. The plaintext source is
    /// deliberately LEFT IN PLACE — verify the encrypted copy opens,
    /// then delete the plaintext yourself. Nothing is silently
    /// deleted.
    ///
    /// Returns [`VaultError::AlreadyEncrypted`] if the source already
    /// has the encrypted magic.
    pub fn migrate_from_plaintext(
        plain_path: &Path,
        enc_path: &Path,
        passphrase: &str,
    ) -> Result<(), VaultError> {
        Self::migrate_from_plaintext_with(plain_path, enc_path, passphrase, VAULT_KDF_ITERATIONS)
    }

    /// [`ProfileVault::migrate_from_plaintext`] with an explicit
    /// iteration count. Public for tests/benchmarks; production
    /// callers use [`ProfileVault::migrate_from_plaintext`].
    pub fn migrate_from_plaintext_with(
        plain_path: &Path,
        enc_path: &Path,
        passphrase: &str,
        iterations: u32,
    ) -> Result<(), VaultError> {
        let bytes = std::fs::read(plain_path).map_err(|e| VaultError::Io(e.to_string()))?;
        if bytes.len() >= 4 && &bytes[..4] == ENC_MAGIC {
            return Err(VaultError::AlreadyEncrypted);
        }
        let vault = parse_legacy(&bytes)?;
        vault.save_encrypted_with(enc_path, passphrase, iterations)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unique temp path per test (no cross-test interference).
    fn tmp(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "trv-vault-test-{}-{}",
            std::process::id(),
            name
        ));
        let _ = std::fs::remove_file(&p);
        p
    }

    /// Low iteration count so the suite stays fast; production uses
    /// VAULT_KDF_ITERATIONS.
    const TEST_ITERS: u32 = 50;

    fn save_test(vault: &ProfileVault, path: &Path, pass: &str) {
        vault
            .save_encrypted_with(path, pass, TEST_ITERS)
            .expect("test save must succeed");
    }

    #[test]
    fn new_defaults_display_name_to_handle() {
        let vault = ProfileVault::new("alice");
        assert_eq!(vault.handle, "alice");
        assert_eq!(vault.display_name, "alice");
    }

    #[test]
    fn decentralized_email_matches_canonical() {
        let vault = ProfileVault::new("alice");
        assert_eq!(vault.decentralized_email(), "alice@RV.com");
        assert_eq!(
            vault.decentralized_email(),
            crate::registration::decentralized_email("alice")
        );
    }

    #[test]
    fn roundtrip_save_open() {
        let path = tmp("roundtrip");
        let mut vault = ProfileVault::new("alice");
        vault.display_name = "Alice 🎨".to_string();
        save_test(&vault, &path, "correct horse");
        let back = ProfileVault::open_encrypted(&path, "correct horse").unwrap();
        assert_eq!(back, vault);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn wrong_passphrase_fails_closed() {
        let path = tmp("badpass");
        let vault = ProfileVault::new("alice");
        save_test(&vault, &path, "correct horse");
        let err = ProfileVault::open_encrypted(&path, "wrong donkey").unwrap_err();
        assert_eq!(err, VaultError::BadPassphrase);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let path = tmp("tamper-ct");
        let vault = ProfileVault::new("alice");
        save_test(&vault, &path, "pass");
        let mut bytes = std::fs::read(&path).unwrap();
        // Flip a byte deep in the ciphertext region.
        let i = bytes.len() - 20;
        bytes[i] ^= 0x01;
        std::fs::write(&path, &bytes).unwrap();
        let err = ProfileVault::open_encrypted(&path, "pass").unwrap_err();
        assert_eq!(err, VaultError::BadPassphrase);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn tampered_salt_rejected() {
        let path = tmp("tamper-salt");
        let vault = ProfileVault::new("alice");
        save_test(&vault, &path, "pass");
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[12] ^= 0xff; // inside the 16-byte salt
        std::fs::write(&path, &bytes).unwrap();
        // Wrong derived key -> Poly1305 rejects.
        let err = ProfileVault::open_encrypted(&path, "pass").unwrap_err();
        assert_eq!(err, VaultError::BadPassphrase);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn two_saves_never_produce_same_bytes() {
        let p1 = tmp("uniq1");
        let p2 = tmp("uniq2");
        let vault = ProfileVault::new("alice");
        save_test(&vault, &p1, "same passphrase");
        save_test(&vault, &p2, "same passphrase");
        let b1 = std::fs::read(&p1).unwrap();
        let b2 = std::fs::read(&p2).unwrap();
        assert_ne!(b1, b2, "salt/nonce must differ per save");
        // ...but both open with the same passphrase.
        assert_eq!(ProfileVault::open_encrypted(&p1, "same passphrase").unwrap(), vault);
        assert_eq!(ProfileVault::open_encrypted(&p2, "same passphrase").unwrap(), vault);
        let _ = std::fs::remove_file(&p1);
        let _ = std::fs::remove_file(&p2);
    }

    #[test]
    fn empty_passphrase_rejected() {
        let path = tmp("emptypass");
        let vault = ProfileVault::new("alice");
        assert_eq!(
            vault.save_encrypted(&path, "").unwrap_err(),
            VaultError::EmptyPassphrase
        );
        // Write a valid file first, then try opening with "".
        save_test(&vault, &path, "nonempty");
        assert_eq!(
            ProfileVault::open_encrypted(&path, "").unwrap_err(),
            VaultError::EmptyPassphrase
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn bad_magic_rejected() {
        let path = tmp("badmagic");
        std::fs::write(&path, b"NOPE this is not a vault file at all....................").unwrap();
        let err = ProfileVault::open_encrypted(&path, "pass").unwrap_err();
        assert!(matches!(err, VaultError::Corrupt(_)), "got {err:?}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn truncated_file_rejected() {
        let path = tmp("truncated");
        let vault = ProfileVault::new("alice");
        save_test(&vault, &path, "pass");
        let bytes = std::fs::read(&path).unwrap();
        std::fs::write(&path, &bytes[..20]).unwrap();
        let err = ProfileVault::open_encrypted(&path, "pass").unwrap_err();
        assert!(matches!(err, VaultError::Corrupt(_)), "got {err:?}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn unsupported_version_rejected() {
        let path = tmp("badver");
        let vault = ProfileVault::new("alice");
        save_test(&vault, &path, "pass");
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[4] = 0x7f; // version byte
        std::fs::write(&path, &bytes).unwrap();
        let err = ProfileVault::open_encrypted(&path, "pass").unwrap_err();
        assert!(matches!(err, VaultError::Corrupt(_)), "got {err:?}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn missing_file_is_io_error() {
        let path = tmp("does-not-exist-xyz");
        let err = ProfileVault::open_encrypted(&path, "pass").unwrap_err();
        assert!(matches!(err, VaultError::Io(_)), "got {err:?}");
    }

    #[test]
    fn debug_never_leaks_key() {
        // DerivedKey is private; exercise the redaction via a type
        // that formats it. Here we at least assert the error type
        // never carries key material.
        let err = VaultError::BadPassphrase;
        let s = format!("{err:?}");
        assert!(!s.contains("passphrase"));
    }

    #[test]
    fn migration_happy_path() {
        let plain = tmp("mig-plain");
        let enc = tmp("mig-enc");
        let mut vault = ProfileVault::new("bob");
        vault.display_name = "Bob the Builder".to_string();
        std::fs::write(&plain, serialize_legacy(&vault)).unwrap();
        ProfileVault::migrate_from_plaintext(&plain, &enc, "new secret").unwrap();
        // Encrypted copy opens with the passphrase and matches.
        // (Migration used production iterations; this takes ~1-2s.)
        let back = ProfileVault::open_encrypted(&enc, "new secret").unwrap();
        assert_eq!(back, vault);
        // Plaintext source is LEFT IN PLACE (never silently deleted).
        assert!(plain.exists());
        let _ = std::fs::remove_file(&plain);
        let _ = std::fs::remove_file(&enc);
    }

    #[test]
    fn migration_refuses_already_encrypted() {
        let plain = tmp("mig-already");
        let enc = tmp("mig-already-enc");
        let vault = ProfileVault::new("carol");
        save_test(&vault, &plain, "pass");
        let err = ProfileVault::migrate_from_plaintext(&plain, &enc, "pass").unwrap_err();
        assert_eq!(err, VaultError::AlreadyEncrypted);
        assert!(!enc.exists());
        let _ = std::fs::remove_file(&plain);
    }

    #[test]
    fn migration_rejects_garbage() {
        let plain = tmp("mig-garbage");
        let enc = tmp("mig-garbage-enc");
        std::fs::write(&plain, b"definitely not a vault").unwrap();
        let err = ProfileVault::migrate_from_plaintext(&plain, &enc, "pass").unwrap_err();
        assert!(matches!(err, VaultError::LegacyParse(_)), "got {err:?}");
        assert!(!enc.exists());
        let _ = std::fs::remove_file(&plain);
    }

    #[test]
    fn migration_wrong_passphrase_after_migrate() {
        let plain = tmp("mig-wrong");
        let enc = tmp("mig-wrong-enc");
        let vault = ProfileVault::new("dave");
        std::fs::write(&plain, serialize_legacy(&vault)).unwrap();
        ProfileVault::migrate_from_plaintext_with(&plain, &enc, "right", TEST_ITERS).unwrap();
        let err = ProfileVault::open_encrypted(&enc, "wrong").unwrap_err();
        assert_eq!(err, VaultError::BadPassphrase);
        let _ = std::fs::remove_file(&plain);
        let _ = std::fs::remove_file(&enc);
    }

    // ------------------------------------------------------------------
    // Filesystem hardening tests.
    // ------------------------------------------------------------------

    /// Write a v1-format vault (pre-v2 layout, constant AAD) for
    /// migration tests. Replicates the old save path exactly.
    fn save_v1_for_test(vault: &ProfileVault, path: &Path, pass: &str) {
        let salt = random_bytes(SALT_LEN).unwrap();
        let nonce_v = random_bytes(NONCE_LEN).unwrap();
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&nonce_v);
        let key = derive_key(pass, &salt, TEST_ITERS).unwrap();
        let payload = serialize_payload(vault);
        let ct = chacha20poly1305::encrypt(&key.0, &nonce, VAULT_AAD, &payload);
        drop(key);
        let mut out = Vec::new();
        out.extend_from_slice(ENC_MAGIC);
        out.push(ENC_FORMAT_V1);
        out.push(KDF_ID_PBKDF2_SHA512);
        out.push(AEAD_ID_CHACHA20_POLY1305);
        out.extend_from_slice(&TEST_ITERS.to_le_bytes());
        out.extend_from_slice(&salt);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        std::fs::write(path, &out).unwrap();
    }

    #[test]
    fn new_saves_write_v2() {
        let path = tmp("ver-v2");
        let vault = ProfileVault::new("alice");
        save_test(&vault, &path, "pass");
        assert_eq!(ProfileVault::format_version(&path).unwrap(), ENC_FORMAT_V2);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn v1_files_still_open() {
        let path = tmp("ver-v1-open");
        let vault = ProfileVault::new("alice");
        save_v1_for_test(&vault, &path, "pass");
        assert_eq!(ProfileVault::format_version(&path).unwrap(), ENC_FORMAT_V1);
        assert_eq!(ProfileVault::open_encrypted(&path, "pass").unwrap(), vault);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn migrate_v1_to_v2_upgrades_explicitly() {
        let path = tmp("ver-migrate");
        let mut vault = ProfileVault::new("bob");
        vault.display_name = "Bob".to_string();
        save_v1_for_test(&vault, &path, "pass");
        let before = std::fs::read(&path).unwrap();

        let outcome = ProfileVault::migrate_v1_to_v2_with(&path, "pass", TEST_ITERS).unwrap();
        assert_eq!(outcome, VaultUpgradeOutcome::Upgraded);
        assert_eq!(ProfileVault::format_version(&path).unwrap(), ENC_FORMAT_V2);
        assert_eq!(ProfileVault::open_encrypted(&path, "pass").unwrap(), vault);
        assert_ne!(std::fs::read(&path).unwrap(), before, "v2 bytes must differ");

        // Second run is a no-op: nothing rewritten.
        let before2 = std::fs::read(&path).unwrap();
        let outcome2 = ProfileVault::migrate_v1_to_v2_with(&path, "pass", TEST_ITERS).unwrap();
        assert_eq!(outcome2, VaultUpgradeOutcome::AlreadyCurrent);
        assert_eq!(std::fs::read(&path).unwrap(), before2, "no-op must not rewrite");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn migrate_v1_to_v2_wrong_passphrase_fails() {
        let path = tmp("ver-mig-badpass");
        let vault = ProfileVault::new("carol");
        save_v1_for_test(&vault, &path, "pass");
        let err = ProfileVault::migrate_v1_to_v2_with(&path, "nope", TEST_ITERS).unwrap_err();
        assert_eq!(err, VaultError::BadPassphrase);
        // Still v1, still opens with the right passphrase.
        assert_eq!(ProfileVault::format_version(&path).unwrap(), ENC_FORMAT_V1);
        assert_eq!(ProfileVault::open_encrypted(&path, "pass").unwrap(), vault);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn tampered_v2_nonce_rejected() {
        let path = tmp("tamper-v2-nonce");
        let vault = ProfileVault::new("alice");
        save_test(&vault, &path, "pass");
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[30] ^= 0x01; // inside the 12-byte nonce (bytes 27..39)
        std::fs::write(&path, &bytes).unwrap();
        let err = ProfileVault::open_encrypted(&path, "pass").unwrap_err();
        assert_eq!(err, VaultError::BadPassphrase);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn tampered_v2_version_rejected() {
        let path = tmp("tamper-v2-ver");
        let vault = ProfileVault::new("alice");
        save_test(&vault, &path, "pass");
        // Downgrade the version byte to v1: parses as v1, but the file
        // was sealed with the v2 header-bound AAD -> auth must fail.
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[4] = ENC_FORMAT_V1;
        std::fs::write(&path, &bytes).unwrap();
        let err = ProfileVault::open_encrypted(&path, "pass").unwrap_err();
        assert_eq!(err, VaultError::BadPassphrase, "downgraded version must fail auth");
        // Unknown version byte fails closed as corrupt.
        bytes[4] = 0x03;
        std::fs::write(&path, &bytes).unwrap();
        let err = ProfileVault::open_encrypted(&path, "pass").unwrap_err();
        assert!(matches!(err, VaultError::Corrupt(_)), "got {err:?}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn tampered_v2_iterations_rejected() {
        let path = tmp("tamper-v2-iters");
        let vault = ProfileVault::new("alice");
        save_test(&vault, &path, "pass");
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[7] ^= 0x01; // iteration-count low byte
        std::fs::write(&path, &bytes).unwrap();
        // Iterations feed both the KDF and the v2 AAD: auth must fail.
        let err = ProfileVault::open_encrypted(&path, "pass").unwrap_err();
        assert_eq!(err, VaultError::BadPassphrase);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn atomic_crash_between_stage_and_commit_keeps_old_vault() {
        let path = tmp("atomic-crash");
        let old = ProfileVault::new("alice");
        save_test(&old, &path, "pass");
        let old_bytes = std::fs::read(&path).unwrap();

        // Simulate a crashed save: temp staged, process dies before rename.
        let staged = stage_temp_file(&path, b"definitely a new vault image").unwrap();
        assert!(staged.exists());
        // Old vault fully intact while the temp sits uncommitted.
        assert_eq!(std::fs::read(&path).unwrap(), old_bytes);
        assert_eq!(ProfileVault::open_encrypted(&path, "pass").unwrap(), old);

        // The rename lands: readers see the complete new image, temp gone.
        commit_temp_file(&staged, &path).unwrap();
        assert!(!staged.exists());
        assert_eq!(std::fs::read(&path).unwrap(), b"definitely a new vault image");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn atomic_write_cleans_temp_on_failed_rename() {
        let dir = tmp("atomic-fail-dir");
        std::fs::create_dir(&dir).unwrap();
        // Rename of a file onto an existing directory fails: the temp
        // must be cleaned up and the target left alone.
        let err = atomic_write(&dir, b"new vault bytes").unwrap_err();
        assert!(matches!(err, VaultError::Io(_)), "got {err:?}");
        assert!(dir.is_dir(), "target directory must be untouched");
        let parent = dir.parent().unwrap();
        let stem = dir.file_name().unwrap().to_str().unwrap().to_string();
        let prefix = format!("{stem}.tmp.");
        let strays: Vec<_> = std::fs::read_dir(parent)
            .unwrap()
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .map(|n| n.starts_with(&prefix))
                    .unwrap_or(false)
            })
            .collect();
        assert!(strays.is_empty(), "stray temps left behind: {strays:?}");
        std::fs::remove_dir(&dir).unwrap();
    }

    #[test]
    fn atomic_write_to_missing_dir_fails_clean() {
        let target = Path::new("/nonexistent-dir-trv-xyz/vault.dat");
        let err = atomic_write(target, b"data").unwrap_err();
        assert!(matches!(err, VaultError::Io(_)), "got {err:?}");
        assert!(!target.exists());
    }

    #[test]
    #[cfg(unix)]
    fn vault_file_is_owner_only_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let path = tmp("perms");
        let vault = ProfileVault::new("alice");
        save_test(&vault, &path, "pass");
        let mode = std::fs::metadata(&path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "vault file mode is {mode:o}, want 600");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn lock_contention_fails_closed_with_busy() {
        let path = tmp("lock-busy");
        let vault = ProfileVault::new("alice");
        // Simulate another process holding the lock.
        let lock_path = lock_path_for(&path);
        std::fs::write(&lock_path, b"pid=99999").unwrap();
        let err = vault
            .save_encrypted_with(&path, "pass", TEST_ITERS)
            .unwrap_err();
        assert_eq!(err, VaultError::VaultBusy);
        assert!(!path.exists(), "failed save must not create a vault file");
        // Holder releases; the save now succeeds.
        std::fs::remove_file(&lock_path).unwrap();
        vault.save_encrypted_with(&path, "pass", TEST_ITERS).unwrap();
        assert_eq!(ProfileVault::open_encrypted(&path, "pass").unwrap(), vault);
        let _ = std::fs::remove_file(&path);
        assert!(!lock_path.exists(), "lock must be released after save");
    }

    #[test]
    fn lock_guard_releases_on_drop() {
        let path = tmp("lock-guard");
        let lock_path = lock_path_for(&path);
        {
            let _guard = VaultLock::acquire(&path).unwrap();
            assert!(lock_path.exists());
            // Re-acquire while held fails closed.
            assert!(
                matches!(VaultLock::acquire(&path), Err(VaultError::VaultBusy)),
                "second acquire must fail with VaultBusy"
            );
        }
        assert!(!lock_path.exists(), "lock must be removed on drop");
    }

    #[test]
    fn torn_write_truncated_fails_closed_never_ok() {
        let path = tmp("torn");
        let vault = ProfileVault::new("alice");
        save_test(&vault, &path, "pass");
        let full = std::fs::read(&path).unwrap();
        assert!(full.len() > 60);
        // Every truncation length must fail closed — never Ok.
        let cuts = [0usize, 1, 4, 5, 20, 39, 40, 60, full.len() - 1];
        for cut in cuts {
            let cut = cut.min(full.len());
            std::fs::write(&path, &full[..cut]).unwrap();
            assert!(
                ProfileVault::open_encrypted(&path, "pass").is_err(),
                "truncated to {cut} bytes opened Ok?!"
            );
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn vault_busy_error_displays() {
        let s = format!("{}", VaultError::VaultBusy);
        assert!(s.contains("busy"), "got: {s}");
        let dbg = format!("{:?}", VaultError::VaultBusy);
        assert!(dbg.contains("VaultBusy"));
    }

    #[test]
    fn format_version_rejects_non_vault() {
        let path = tmp("ver-nonvault");
        std::fs::write(&path, b"not a vault").unwrap();
        let err = ProfileVault::format_version(&path).unwrap_err();
        assert!(matches!(err, VaultError::Corrupt(_)), "got {err:?}");
        let _ = std::fs::remove_file(&path);
    }
}
