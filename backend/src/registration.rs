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

/// Errors raised during registration. All local; no I/O.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationError {
    /// The handle (username) is empty.
    EmptyHandle,
    /// The email does not contain '@'.
    InvalidEmail,
    /// Sex selection was not Male or Female.
    InvalidSex,
}

impl RegistrationError {
    /// Short machine-readable label.
    pub fn label(self) -> &'static str {
        match self {
            RegistrationError::EmptyHandle => "empty-handle",
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
    /// Whether the viewer owns a State ID. Without one, verification
    /// is ineligible.
    pub state_id_present: bool,
}

impl Registration {
    /// Validate and build a registration. Handle and email are trimmed.
    ///
    /// Fails with [`RegistrationError::EmptyHandle`] for a blank handle
    /// and [`RegistrationError::InvalidEmail`] when the email contains
    /// no '@'.
    pub fn new(
        handle: &str,
        email: &str,
        sex: Sex,
        state_id_present: bool,
    ) -> Result<Self, RegistrationError> {
        let handle = handle.trim().to_string();
        if handle.is_empty() {
            return Err(RegistrationError::EmptyHandle);
        }
        let email = email.trim().to_string();
        if !email.contains('@') {
            return Err(RegistrationError::InvalidEmail);
        }
        Ok(Registration {
            handle,
            email,
            sex,
            state_id_present,
        })
    }

    /// Verification eligibility for this registration.
    ///
    /// Returns [`VerificationStatus::Ineligible`] when the viewer has no
    /// State ID; otherwise returns [`VerificationStatus::Unverified`]
    /// (eligible to begin the background ID verification process).
    pub fn verification_eligibility(&self) -> VerificationStatus {
        check_verification(self.state_id_present)
    }

    /// The decentralized encrypted email replacing traditional email
    /// after registration: `Username@RV.com`.
    pub fn decentralized_email(&self) -> String {
        format!("{}@RV.com", self.handle)
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
        let err = Registration::new("alice", "not-an-email", Sex::Male, true).unwrap_err();
        assert_eq!(err, RegistrationError::InvalidEmail);
        assert_eq!(err.label(), "invalid-email");
    }

    #[test]
    fn empty_handle_rejected() {
        let err = Registration::new("   ", "a@b.com", Sex::Male, true).unwrap_err();
        assert_eq!(err, RegistrationError::EmptyHandle);
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
