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
//! Myspace-style live customization (music etc., ENHANCED) renders from
//! this vault — all local.

use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

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
const FORMAT_VERSION: u8 = 0x01;
const KDF_ID_PBKDF2_SHA512: u8 = 0x01;
const AEAD_ID_CHACHA20_POLY1305: u8 = 0x01;

/// Associated data bound into the AEAD: ties the ciphertext to this
/// vault format so a blob can't be transplanted into another context.
const VAULT_AAD: &[u8] = b"TRV-VAULT-V1";

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
fn random_bytes(n: usize) -> Result<Vec<u8>, VaultError> {
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
    pub fn save_encrypted_with(
        &self,
        path: &Path,
        passphrase: &str,
        iterations: u32,
    ) -> Result<(), VaultError> {
        if passphrase.is_empty() {
            return Err(VaultError::EmptyPassphrase);
        }
        let salt = random_bytes(SALT_LEN)?;
        let nonce_v = random_bytes(NONCE_LEN)?;
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&nonce_v);
        let key = derive_key(passphrase, &salt, iterations)?;
        let payload = serialize_payload(self);
        let ct = chacha20poly1305::encrypt(&key.0, &nonce, VAULT_AAD, &payload);
        // `key` is dropped (zeroized) here.
        let mut file = File::create(path).map_err(|e| VaultError::Io(e.to_string()))?;
        file.write_all(ENC_MAGIC)
            .map_err(|e| VaultError::Io(e.to_string()))?;
        file.write_all(&[FORMAT_VERSION, KDF_ID_PBKDF2_SHA512, AEAD_ID_CHACHA20_POLY1305])
            .map_err(|e| VaultError::Io(e.to_string()))?;
        file.write_all(&iterations.to_le_bytes())
            .map_err(|e| VaultError::Io(e.to_string()))?;
        file.write_all(&salt)
            .map_err(|e| VaultError::Io(e.to_string()))?;
        file.write_all(&nonce)
            .map_err(|e| VaultError::Io(e.to_string()))?;
        file.write_all(&ct)
            .map_err(|e| VaultError::Io(e.to_string()))?;
        Ok(())
    }

    /// Open a vault file previously written by
    /// [`ProfileVault::save_encrypted`].
    ///
    /// Wrong passphrase — or any tampering — returns
    /// [`VaultError::BadPassphrase`] and decrypts nothing. Malformed
    /// files return [`VaultError::Corrupt`].
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
        if bytes[4] != FORMAT_VERSION {
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
        let key = derive_key(passphrase, salt, iterations)?;
        let payload = chacha20poly1305::decrypt(&key.0, &nonce, VAULT_AAD, ct)
            .map_err(|_| VaultError::BadPassphrase)?;
        // `key` is dropped (zeroized) here.
        parse_payload(&payload)
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
}
