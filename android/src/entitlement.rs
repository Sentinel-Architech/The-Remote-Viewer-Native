//! Entitlement loading for the Android app.
//!
//! Pure logic, no NDK calls: given the app's data directory and the
//! issuer public key, read the stored receipt file and verify it. Every
//! failure mode — missing file, unreadable file, bad signature, expired
//! receipt — yields `None`, and the UI gates then fail closed (deny).
//!
//! The app calls [`load_entitlement`] once at startup with
//! `ANativeActivity.internal_data_path` and passes the result to the
//! screen/router via `set_entitlement`.

use std::path::Path;
use trv_backend::entitlement::{verify_and_check, Entitlement};

/// Receipt file name inside the app's internal data directory.
pub const RECEIPT_FILE: &str = "receipt.trve";

/// Load and verify the stored entitlement receipt.
///
/// Returns `Some(entitlement)` only when the receipt file exists, parses,
/// carries a genuine issuer signature, and is unexpired. Anything else —
/// including a forged receipt — returns `None`.
pub fn load_entitlement(data_dir: &Path, issuer_pubkey: &[u8; 32]) -> Option<Entitlement> {
    let bytes = std::fs::read(data_dir.join(RECEIPT_FILE)).ok()?;
    verify_and_check(issuer_pubkey, &bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use trv_backend::entitlement::issue;
    use trv_backend::subscriptions::Tier;

    /// Fixed issuer seed for tests only — never a real key.
    const ISSUER_SEED: [u8; 32] = *b"test-android-ent-issuer-00000000";
    const OTHER_SEED: [u8; 32] = *b"attacker-seed-android-0000000000";

    fn issuer_pubkey() -> [u8; 32] {
        let (_, public) = trv_core::crypto::ed25519::generate(&ISSUER_SEED);
        *public.as_bytes()
    }

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .expect("test clock")
    }

    fn tmp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("trv-ent-test-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("tmp dir");
        dir
    }

    fn write_receipt(dir: &Path, bytes: &[u8]) {
        std::fs::write(dir.join(RECEIPT_FILE), bytes).expect("write receipt");
    }

    #[test]
    fn valid_receipt_loads() {
        let dir = tmp_dir("valid");
        let now = now_secs();
        let receipt = issue(&ISSUER_SEED, Tier::Monthly, now, now + 30 * 86_400)
            .expect("issue");
        write_receipt(&dir, &receipt);
        let ent = load_entitlement(&dir, &issuer_pubkey()).expect("loads");
        assert_eq!(ent.tier(), Tier::Monthly);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_receipt_is_none() {
        let dir = tmp_dir("missing");
        assert!(load_entitlement(&dir, &issuer_pubkey()).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn forged_receipt_is_none() {
        // Signed by a different key: must not produce an entitlement.
        let dir = tmp_dir("forged");
        let now = now_secs();
        let forged = issue(&OTHER_SEED, Tier::Founding, now, now + 30 * 86_400)
            .expect("issue");
        write_receipt(&dir, &forged);
        assert!(load_entitlement(&dir, &issuer_pubkey()).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn expired_receipt_is_none() {
        let dir = tmp_dir("expired");
        let now = now_secs();
        let receipt = issue(&ISSUER_SEED, Tier::Yearly, now - 60 * 86_400, now - 3_600)
            .expect("issue");
        write_receipt(&dir, &receipt);
        assert!(load_entitlement(&dir, &issuer_pubkey()).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn garbage_receipt_is_none() {
        let dir = tmp_dir("garbage");
        write_receipt(&dir, b"not a receipt at all");
        assert!(load_entitlement(&dir, &issuer_pubkey()).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
