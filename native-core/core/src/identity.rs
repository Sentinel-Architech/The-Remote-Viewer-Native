//! Local-first device identity.
//!
//! Destroy = Restart: wiping keys locally is sufficient because nothing
//! ever left the device.

use crate::crypto::Keypair;

/// A Remote Viewer's on-device identity.
#[derive(Debug)]
pub struct LocalIdentity {
    keypair: Keypair,
    handle: String,
    /// Whether the viewer owns a State ID. Per spec: without a State ID,
    /// verification is ineligible (see [`verification_eligibility`]).
    has_state_id: bool,
}

impl LocalIdentity {
    /// Create a new local identity for `handle`. Fully offline.
    ///
    /// `has_state_id` records whether the viewer owns a State ID; it
    /// drives the verification-eligibility rule and nothing else.
    pub fn new(handle: &str, has_state_id: bool) -> Self {
        LocalIdentity {
            keypair: Keypair::generate(),
            handle: handle.to_string(),
            has_state_id,
        }
    }

    /// Whether the viewer owns a State ID.
    pub fn has_state_id(&self) -> bool {
        self.has_state_id
    }

    /// Verification eligibility for this identity.
    ///
    /// Mirrors the backend [`verification_eligibility`] rule so the core
    /// can gate verification locally without touching the backend crate.
    pub fn verification_status(&self) -> VerificationStatus {
        verification_eligibility(self.has_state_id)
    }

    /// The viewer's decentralized address. Local claim only.
    pub fn address(&self) -> String {
        self.keypair.public_hex()
    }

    /// The viewer's decentralized email, replacing traditional email
    /// after registration: `Username@RV.com`.
    pub fn decentralized_email(&self) -> String {
        format!("{}@RV.com", self.handle)
    }

    /// Destroy = Restart: drop keys. Nothing to wipe remotely — nothing
    /// was ever transmitted.
    pub fn destroy(self) {
        // `self` is consumed; keys die with it.
    }
}

/// Human-verification eligibility status.
///
/// Kept minimal and duplicated from the backend crate on purpose:
/// `core` must stay backend-free so it compiles as a standalone
/// on-device primitive. Both crates agree on the rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationStatus {
    /// Owns a State ID: eligible to begin background ID verification.
    Eligible,
    /// No State ID: ineligible for verification.
    Ineligible,
}

/// On-device verification-eligibility gate.
///
/// Per spec: "If Remote Viewer doesn't own a State ID then VERIFICATION
/// is ineligible."
pub fn verification_eligibility(has_state_id: bool) -> VerificationStatus {
    if has_state_id {
        VerificationStatus::Eligible
    } else {
        VerificationStatus::Ineligible
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decentralized_email_is_handle_at_rv_dot_com() {
        let id = LocalIdentity::new("skyviewer", true);
        assert_eq!(id.decentralized_email(), "skyviewer@RV.com");
        assert!(id.decentralized_email().starts_with("skyviewer"));
        assert!(id.decentralized_email().contains("@RV.com"));
    }

    #[test]
    fn verification_ineligible_without_state_id() {
        let id = LocalIdentity::new("ghost", false);
        assert!(!id.has_state_id());
        assert_eq!(id.verification_status(), VerificationStatus::Ineligible);
        assert_eq!(
            verification_eligibility(false),
            VerificationStatus::Ineligible
        );
    }

    #[test]
    fn verification_eligible_with_state_id() {
        let id = LocalIdentity::new("verified", true);
        assert!(id.has_state_id());
        assert_eq!(id.verification_status(), VerificationStatus::Eligible);
        assert_eq!(
            verification_eligibility(true),
            VerificationStatus::Eligible
        );
    }

    #[test]
    fn address_is_64_hex_char_public_key() {
        let id = LocalIdentity::new("addr", true);
        let address = id.address();
        assert_eq!(address.len(), 64);
        assert!(address.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn destroy_consumes_identity() {
        let id = LocalIdentity::new("temp", false);
        id.destroy(); // Destroy = Restart: keys die locally, nothing to wipe remotely.
    }
}
