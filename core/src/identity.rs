//! Local-first device identity.
//!
//! Destroy = Restart: wiping keys locally is sufficient because nothing
//! ever left the device.

use crate::crypto::{Keypair, KeypairError};

/// Errors for local identity operations. All local; no I/O.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityError {
    /// The handle was empty after trimming. Handles like `"@RV.com"`
    /// (empty local part) are never valid.
    InvalidHandle,
    /// The OS CSPRNG was unavailable, so no keypair could be
    /// generated. Fails closed; never falls back to weak entropy.
    EntropyUnavailable,
}

impl From<KeypairError> for IdentityError {
    fn from(e: KeypairError) -> Self {
        match e {
            KeypairError::EntropyUnavailable => IdentityError::EntropyUnavailable,
        }
    }
}

impl IdentityError {
    /// Short machine-readable label.
    pub fn label(self) -> &'static str {
        match self {
            IdentityError::InvalidHandle => "invalid-handle",
            IdentityError::EntropyUnavailable => "entropy-unavailable",
        }
    }
}

/// A Remote Viewer's on-device identity.
///
/// `Debug` is redacted: the embedded keypair prints as `<redacted>`
/// so secret key material never lands in logs or panic messages.
pub struct LocalIdentity {
    keypair: Keypair,
    handle: String,
    /// Whether the viewer owns a State ID. Per spec: without a State ID,
    /// verification is ineligible (see [`verification_eligibility`]).
    has_state_id: bool,
}

impl std::fmt::Debug for LocalIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalIdentity")
            .field("keypair", &"<redacted>")
            .field("handle", &self.handle)
            .field("has_state_id", &self.has_state_id)
            .finish()
    }
}

impl LocalIdentity {
    /// Create a new local identity for `handle`. Fully offline.
    ///
    /// The handle is trimmed; a handle that is empty after trimming
    /// is rejected with [`IdentityError::InvalidHandle`] (no more
    /// `"@RV.com"` with an empty local part).
    ///
    /// `has_state_id` records whether the viewer owns a State ID; it
    /// drives the verification-eligibility rule and nothing else.
    pub fn new(handle: &str, has_state_id: bool) -> Result<Self, IdentityError> {
        let trimmed = handle.trim();
        if trimmed.is_empty() {
            return Err(IdentityError::InvalidHandle);
        }
        Ok(LocalIdentity {
            keypair: Keypair::generate()?,
            handle: trimmed.to_string(),
            has_state_id,
        })
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
    ///
    /// Best-effort zeroization: dropping `self` runs [`Keypair`]'s
    /// field drops, and [`crate::crypto::SecretKey`]'s `Drop` impl
    /// overwrites the secret bytes in place (see its docs for the
    /// best-effort caveats).
    pub fn destroy(self) {
        // `self` is consumed; keys die with it, and SecretKey::drop
        // wipes the secret bytes on the way out.
    }
}

/// Human-verification eligibility status.
///
/// Kept minimal and duplicated from the backend crate on purpose:
/// `core` must stay backend-free so it compiles as a standalone
/// on-device primitive. Both crates agree on the rule.
///
/// Mapping to the backend's fuller lifecycle
/// (`backend::subscriptions::VerificationStatus`): core's
/// [`VerificationStatus::Unverified`] is the backend's initial state
/// for an eligible viewer; [`VerificationStatus::Ineligible`] is the
/// shared terminal "no State ID" state. The backend's `Pending` and
/// `Verified` states have no core equivalent — they are tracked
/// server-side after the viewer begins verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationStatus {
    /// Owns a State ID: unverified so far, but eligible to begin
    /// background ID verification. Matches the backend's initial
    /// state for eligible viewers.
    Unverified,
    /// No State ID: ineligible for verification.
    Ineligible,
}

/// On-device verification-eligibility gate.
///
/// Per spec: "If Remote Viewer doesn't own a State ID then VERIFICATION
/// is ineligible."
pub fn verification_eligibility(has_state_id: bool) -> VerificationStatus {
    if has_state_id {
        VerificationStatus::Unverified
    } else {
        VerificationStatus::Ineligible
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decentralized_email_is_handle_at_rv_dot_com() {
        let id = LocalIdentity::new("skyviewer", true).expect("valid handle");
        assert_eq!(id.decentralized_email(), "skyviewer@RV.com");
        assert!(id.decentralized_email().starts_with("skyviewer"));
        assert!(id.decentralized_email().contains("@RV.com"));
    }

    #[test]
    fn handle_is_trimmed_and_empty_after_trim_is_rejected() {
        let id = LocalIdentity::new("  skyviewer  ", true).expect("valid handle");
        assert_eq!(id.decentralized_email(), "skyviewer@RV.com");
        // No more "@RV.com" with an empty local part.
        assert!(matches!(
            LocalIdentity::new("", true),
            Err(IdentityError::InvalidHandle)
        ));
        assert!(matches!(
            LocalIdentity::new("   \t  ", true),
            Err(IdentityError::InvalidHandle)
        ));
        assert_eq!(IdentityError::InvalidHandle.label(), "invalid-handle");
    }

    #[test]
    fn verification_ineligible_without_state_id() {
        let id = LocalIdentity::new("ghost", false).expect("valid handle");
        assert!(!id.has_state_id());
        assert_eq!(id.verification_status(), VerificationStatus::Ineligible);
        assert_eq!(
            verification_eligibility(false),
            VerificationStatus::Ineligible
        );
    }

    #[test]
    fn verification_unverified_with_state_id() {
        let id = LocalIdentity::new("verified", true).expect("valid handle");
        assert!(id.has_state_id());
        assert_eq!(id.verification_status(), VerificationStatus::Unverified);
        assert_eq!(
            verification_eligibility(true),
            VerificationStatus::Unverified
        );
    }

    #[test]
    fn address_is_64_hex_char_public_key() {
        let id = LocalIdentity::new("addr", true).expect("valid handle");
        let address = id.address();
        assert_eq!(address.len(), 64);
        assert!(address.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn debug_never_leaks_key_material() {
        let id = LocalIdentity::new("quiet", true).expect("valid handle");
        let dbg = format!("{:?}", id);
        assert!(dbg.contains("<redacted>"));
        // The handle and flags are not secret and stay visible.
        assert!(dbg.contains("quiet"));
        assert!(dbg.contains("has_state_id"));
        // The keypair (secret AND public halves) prints redacted: the
        // conservative choice while the stub public derivation is
        // reversible (see the crypto module docs). The public
        // address remains available through address().
        assert!(!dbg.contains(&id.address()));
        assert_eq!(id.address().len(), 64);
    }

    #[test]
    fn destroy_consumes_identity() {
        let id = LocalIdentity::new("temp", false).expect("valid handle");
        id.destroy(); // Destroy = Restart: keys die locally, nothing to wipe remotely.
    }
}
