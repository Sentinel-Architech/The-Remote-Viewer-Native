//! Verification scaffolding for The Remote Viewer: ID + email flows.
//!
//! DESIGN-ONLY types. There are no verification implementations here on
//! purpose: real ID verification requires an external verification provider
//! or manual human review (see
//! `~/workspace/verification-design-2026-10-14.md`), and inventing either
//! would be dishonest. These types define the shape of the data so the
//! flows can be built against them later.
//!
//! Invariants enforced by the types (not by code that does not exist yet):
//! - ID images are referenced by vault handle only — never raw bytes here,
//!   so plaintext document scans cannot leak through this module.
//! - Every outbound transfer requires an explicit [`VerificationConsent`].
//! - Email challenge secrets live in [`EmailChallenge`] and are wiped by
//!   the holder; comparison must be constant-time at the call site.

/// Which side of the identity document was captured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocumentSide {
    /// Front of the state/federal ID.
    Front,
    /// Back of the state/federal ID.
    Back,
}

/// Opaque handle to an encrypted ID image inside the profile vault.
///
/// The bytes are never exposed through this module: capture writes them
/// straight into the vault (PBKDF2 + ChaCha20-Poly1305) and only the
/// handle travels here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultImageRef {
    /// Vault-internal identifier (meaningless outside the vault).
    pub handle: String,
    /// Which side of the document this image shows.
    pub side: DocumentSide,
    /// Unix timestamp (seconds) when the image was captured.
    pub captured_at: u64,
}

/// The identity document under verification: front + back, both required.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdDocument {
    /// Front image reference. Required.
    pub front: VaultImageRef,
    /// Back image reference. Required.
    pub back: VaultImageRef,
    /// Issuing authority as entered/selected, e.g. "Ohio BMV".
    /// Free text for now; a validated enum comes with the provider.
    pub issuer: String,
}

/// Explicit, informed consent for the one-time verification transfer.
///
/// Constructing this value is the code-level equivalent of the viewer
/// tapping "Verify my ID". No transfer may happen without one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationConsent {
    /// Who the package may be sent to (provider name or "manual-review").
    pub recipient: String,
    /// Unix timestamp (seconds) when consent was given.
    pub granted_at: u64,
    /// How long the consent (and package) stays valid, in seconds.
    pub valid_for_secs: u64,
}

/// Outcome of an ID verification decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdDecision {
    /// Identity verified; viewer is eligible for verified tiers.
    Approved,
    /// Identity rejected; reason is human-readable, never a code leak.
    Rejected,
    /// Needs a human reviewer; document package retained per policy.
    NeedsReview,
}

/// Stored record of an ID verification decision.
///
/// Only the decision is kept long-term. Document images are deleted from
/// the vault after a final decision unless the viewer opts to keep them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdVerificationRecord {
    /// The decision that was reached.
    pub decision: IdDecision,
    /// Unix timestamp (seconds) of the decision.
    pub decided_at: u64,
    /// Whether the source images were kept for re-verification.
    pub images_retained: bool,
}

/// A pending email ownership challenge.
///
/// The `code` is the one-time code in memory. It must be wiped after
/// verification, expiry, or attempt exhaustion. Comparison against user
/// input must be constant-time at the call site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailChallenge {
    /// The address being verified (already format-validated).
    pub address: String,
    /// One-time code, exactly [`EMAIL_CODE_LEN`] ASCII digits.
    /// Memory-only; never persisted.
    pub code: String,
    /// Unix timestamp (seconds) when the code expires.
    pub expires_at: u64,
    /// Remaining entry attempts.
    pub attempts_left: u8,
}

/// Length of the email one-time code in ASCII digits.
pub const EMAIL_CODE_LEN: usize = 6;

/// Lifetime of an email challenge in seconds (10 minutes).
pub const EMAIL_CODE_TTL_SECS: u64 = 600;

/// Maximum entry attempts per email challenge.
pub const EMAIL_MAX_ATTEMPTS: u8 = 5;

/// Resend cooldown between email challenges in seconds.
pub const EMAIL_RESEND_COOLDOWN_SECS: u64 = 60;

/// Email verification state for a registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmailVerificationStatus {
    /// No challenge issued yet.
    Unverified,
    /// Challenge issued, awaiting the code.
    Pending,
    /// Code accepted within its lifetime.
    Verified,
}

/// Errors for the verification flows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationError {
    /// No state/federal ID available — viewer is ineligible for
    /// ID verification (per spec).
    NoStateId,
    /// Document capture failed (camera unavailable, unreadable image).
    CaptureFailed,
    /// Front or back image missing — both are required.
    IncompleteDocument,
    /// No explicit consent for the verification transfer.
    ConsentMissing,
    /// Consent expired before the transfer completed.
    ConsentExpired,
    /// No verification provider or reviewer is reachable.
    /// Real verification cannot be faked on-device.
    ProviderUnavailable,
    /// The verification decision was negative.
    Rejected,
    /// Email challenge expired; a new code is required.
    ChallengeExpired,
    /// No attempts left; a new code is required.
    AttemptsExhausted,
    /// Submitted code did not match (attempts_left remaining after this).
    CodeMismatch {
        /// Attempts remaining after this failed try.
        attempts_left: u8,
    },
    /// Resend requested before the cooldown elapsed.
    ResendTooSoon {
        /// Seconds until a resend is allowed.
        wait_secs: u64,
    },
    /// Underlying vault/IO failure while handling verification data.
    Storage(String),
}

impl std::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerificationError::NoStateId => {
                write!(f, "no state or federal ID: not eligible for ID verification")
            }
            VerificationError::CaptureFailed => {
                write!(f, "could not capture the document image")
            }
            VerificationError::IncompleteDocument => {
                write!(f, "both front and back of the ID are required")
            }
            VerificationError::ConsentMissing => {
                write!(f, "verification transfer requires explicit consent")
            }
            VerificationError::ConsentExpired => {
                write!(f, "verification consent expired before transfer")
            }
            VerificationError::ProviderUnavailable => write!(
                f,
                "no identity verifier reachable; verification cannot be faked on-device"
            ),
            VerificationError::Rejected => write!(f, "identity verification was not approved"),
            VerificationError::ChallengeExpired => {
                write!(f, "verification code expired; request a new one")
            }
            VerificationError::AttemptsExhausted => {
                write!(f, "no attempts left; request a new code")
            }
            VerificationError::CodeMismatch { attempts_left } => write!(
                f,
                "code did not match; {attempts_left} attempt(s) remaining"
            ),
            VerificationError::ResendTooSoon { wait_secs } => {
                write!(f, "wait {wait_secs}s before requesting a new code")
            }
            VerificationError::Storage(msg) => write!(f, "verification storage error: {msg}"),
        }
    }
}

impl std::error::Error for VerificationError {}
