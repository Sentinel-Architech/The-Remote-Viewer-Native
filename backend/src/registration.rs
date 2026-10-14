//! On-device registration for The Remote Viewer.
//!
//! A traditional email is used only to verify a real person at sign-up.
//! After registration the viewer receives a decentralized encrypted
//! email: `Username@RV.com`.
//!
//! Per spec: at registration the viewer must select either Male or
//! Female — NOTHING ELSE EVER. If the viewer does not own a State ID,
//! verification is ineligible ([`Registration::verification_eligibility`]).
//! All validation is local; no network I/O.

use crate::subscriptions::{check_verification, VerificationStatus};

/// Sex selected at registration. Per spec: Male or Female only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sex {
    /// Male.
    Male,
    /// Female.
    Female,
}

impl Sex {
    /// Parse a sex selection. Anything other than "male"/"female"
    /// (case-insensitive) is rejected — NOTHING ELSE EVER.
    pub fn parse(value: &str) -> Result<Self, RegistrationError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "male" => Ok(Sex::Male),
            "female" => Ok(Sex::Female),
            _ => Err(RegistrationError::InvalidSex),
        }
    }

    /// Short machine-readable label.
    pub fn label(self) -> &'static str {
        match self {
            Sex::Male => "male",
            Sex::Female => "female",
        }
    }
}

/// The decentralized encrypted email replacing traditional email
/// after registration: `Username@RV.com`.
///
/// This is the ONE canonical address formatter. [`ProfileVault`](crate::profile::ProfileVault)
/// delegates here so every code path produces identical addresses.
///
/// The handle is used verbatim; callers must have validated it first
/// (e.g. via [`Registration::new`]'s handle rules).
pub fn decentralized_email(handle: &str) -> String {
    format!("{handle}@RV.com")
}

/// Maximum handle length in chars. Handles are stored in memory and may
/// be echoed in logs, so the length is capped.
pub const MAX_HANDLE_LEN: usize = 64;

/// Validate and normalize a handle (username).
///
/// Rules: trim; reject empty-after-trim; max [`MAX_HANDLE_LEN`] chars;
/// allow ASCII alphanumerics plus `_`, `-`, `.` — reject anything else.
fn validate_handle(handle: &str) -> Result<String, RegistrationError> {
    let trimmed = handle.trim();
    if trimmed.is_empty() {
        return Err(RegistrationError::EmptyHandle);
    }
    if trimmed.chars().count() > MAX_HANDLE_LEN {
        return Err(RegistrationError::HandleTooLong);
    }
    let ok = trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'));
    if !ok {
        return Err(RegistrationError::InvalidHandle);
    }
    Ok(trimmed.to_string())
}

/// Validate an email address beyond `contains('@')`.
///
/// Rules: exactly one `@`; non-empty local part; domain contains at
/// least one `.`; every domain label is non-empty. This is a format
/// sanity check only — it does not prove the address exists or that
/// the viewer controls it.
fn validate_email(email: &str) -> Result<String, RegistrationError> {
    let trimmed = email.trim();
    let mut parts = trimmed.split('@');
    let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
        return Err(RegistrationError::InvalidEmail);
    };
    if local.is_empty() || domain.is_empty() {
        return Err(RegistrationError::InvalidEmail);
    }
    if !domain.contains('.') || domain.split('.').any(|label| label.is_empty()) {
        return Err(RegistrationError::InvalidEmail);
    }
    Ok(trimmed.to_string())
}

/// Errors raised during registration. All local; no I/O.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationError {
    /// The handle (username) is empty or whitespace-only.
    EmptyHandle,
    /// The handle exceeds [`MAX_HANDLE_LEN`] chars.
    HandleTooLong,
    /// The handle contains characters outside `[A-Za-z0-9_.-]`.
    InvalidHandle,
    /// The email is malformed (see [`validate_email`] rules).
    InvalidEmail,
    /// Sex selection was not Male or Female.
    InvalidSex,
}

impl RegistrationError {
    /// Short machine-readable label.
    pub fn label(self) -> &'static str {
        match self {
            RegistrationError::EmptyHandle => "empty-handle",
            RegistrationError::HandleTooLong => "handle-too-long",
            RegistrationError::InvalidHandle => "invalid-handle",
            RegistrationError::InvalidEmail => "invalid-email",
            RegistrationError::InvalidSex => "invalid-sex",
        }
    }
}

/// A viewer's registration record, created fully on-device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    /// The viewer's handle (username).
    pub handle: String,
    /// Traditional email, used once to verify a real person.
    pub email: String,
    /// Sex selected at registration: Male or Female only.
    pub sex: Sex,
    /// Caller-attested State ID ownership. NOT actually verified —
    /// there is no ID-verification pipeline in this codebase; this is
    /// the viewer's own declaration. Without a real verification step,
    /// [`Registration::verification_eligibility`] only gates on the
    /// caller's claim. Real ID verification (document scan, issuer
    /// checks) is a future step.
    pub state_id_present: bool,
}

impl Registration {
    /// Validate and build a registration. Handle and email are trimmed.
    ///
    /// Fails with [`RegistrationError::EmptyHandle`] for a blank handle,
    /// [`RegistrationError::HandleTooLong`] for an over-long handle,
    /// [`RegistrationError::InvalidHandle`] for disallowed handle
    /// characters, and [`RegistrationError::InvalidEmail`] for a
    /// malformed email.
    pub fn new(
        handle: &str,
        email: &str,
        sex: Sex,
        state_id_present: bool,
    ) -> Result<Self, RegistrationError> {
        let handle = validate_handle(handle)?;
        let email = validate_email(email)?;
        Ok(Registration {
            handle,
            email,
            sex,
            state_id_present,
        })
    }

    /// Verification eligibility for this registration.
    ///
    /// Returns [`VerificationStatus::Ineligible`] when the viewer claims
    /// no State ID; otherwise returns [`VerificationStatus::Unverified`]
    /// (eligible to begin the background ID verification process).
    /// Honest caveat: `state_id_present` is caller-attested; the real
    /// ID-verification pipeline is a future step.
    pub fn verification_eligibility(&self) -> VerificationStatus {
        check_verification(self.state_id_present)
    }

    /// The decentralized encrypted email replacing traditional email
    /// after registration: `Username@RV.com`. Delegates to the
    /// canonical [`decentralized_email`] free function.
    pub fn decentralized_email(&self) -> String {
        decentralized_email(&self.handle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_registration() {
        let reg = Registration::new("alice", "alice@example.com", Sex::Female, true).unwrap();
        assert_eq!(reg.handle, "alice");
        assert_eq!(reg.email, "alice@example.com");
        assert_eq!(reg.sex, Sex::Female);
        assert_eq!(reg.decentralized_email(), "alice@RV.com");
        assert_eq!(
            reg.verification_eligibility(),
            VerificationStatus::Unverified
        );
    }

    #[test]
    fn invalid_email_rejected() {
        // Each malformed shape must fail: no '@', two '@'s, empty local
        // part, missing domain, missing dot in domain, empty domain label.
        for bad in [
            "not-an-email",
            "a@b@c.com",
            "@example.com",
            "alice@",
            "alice@examplecom",
            "alice@.com",
            "alice@example.",
            "alice@ex..com",
            "",
            "   ",
        ] {
            let err = Registration::new("alice", bad, Sex::Male, true).unwrap_err();
            assert_eq!(err, RegistrationError::InvalidEmail, "input: {bad:?}");
        }
        assert_eq!(
            RegistrationError::InvalidEmail.label(),
            "invalid-email"
        );
    }

    #[test]
    fn valid_emails_accepted_and_trimmed() {
        let reg =
            Registration::new("alice", "  alice@example.com  ", Sex::Female, true).unwrap();
        assert_eq!(reg.email, "alice@example.com");
        Registration::new("b.ob-2_x", "x.y-z@sub.example.com", Sex::Male, true).unwrap();
    }

    #[test]
    fn empty_handle_rejected() {
        let err = Registration::new("   ", "a@b.com", Sex::Male, true).unwrap_err();
        assert_eq!(err, RegistrationError::EmptyHandle);
    }

    #[test]
    fn handle_rules_enforced() {
        // Allowed chars: alphanumeric plus `_`, `-`, `.`.
        Registration::new("a_l-i.c3", "a@b.com", Sex::Male, true).unwrap();
        // Disallowed chars rejected.
        for bad in ["a b", "a!b", "a@b", "a/b", "snäck"] {
            let err = Registration::new(bad, "a@b.com", Sex::Male, true).unwrap_err();
            assert_eq!(err, RegistrationError::InvalidHandle, "input: {bad:?}");
        }
        assert_eq!(
            RegistrationError::InvalidHandle.label(),
            "invalid-handle"
        );
        // Over the 64-char cap.
        let long = "a".repeat(MAX_HANDLE_LEN + 1);
        let err = Registration::new(&long, "a@b.com", Sex::Male, true).unwrap_err();
        assert_eq!(err, RegistrationError::HandleTooLong);
        // Exactly at the cap is fine.
        let ok = "a".repeat(MAX_HANDLE_LEN);
        Registration::new(&ok, "a@b.com", Sex::Male, true).unwrap();
        assert_eq!(
            RegistrationError::HandleTooLong.label(),
            "handle-too-long"
        );
    }

    #[test]
    fn handle_is_trimmed_before_checks() {
        let reg = Registration::new("  alice  ", "a@b.com", Sex::Female, true).unwrap();
        assert_eq!(reg.handle, "alice");
        assert_eq!(reg.decentralized_email(), "alice@RV.com");
    }

    #[test]
    fn canonical_decentralized_email_free_function() {
        assert_eq!(decentralized_email("alice"), "alice@RV.com");
    }

    #[test]
    fn invalid_sex_rejected() {
        assert_eq!(Sex::parse("male"), Ok(Sex::Male));
        assert_eq!(Sex::parse("Female"), Ok(Sex::Female));
        assert_eq!(Sex::parse("other"), Err(RegistrationError::InvalidSex));
        assert_eq!(Sex::parse(""), Err(RegistrationError::InvalidSex));
        assert_eq!(Sex::parse("non-binary"), Err(RegistrationError::InvalidSex));
    }

    #[test]
    fn verification_ineligible_without_state_id() {
        let reg = Registration::new("bob", "bob@example.com", Sex::Male, false).unwrap();
        assert_eq!(
            reg.verification_eligibility(),
            VerificationStatus::Ineligible
        );
    }
}
