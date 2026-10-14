//! Plaintext in-memory profile vault.
//!
//! NOT encrypted at rest — values are held in plain RAM. Real vault
//! encrypts notes with the device key (age wiring later); encryption
//! at rest is a future step, not a current property.
//! Myspace-style live customization (music etc., ENHANCED) renders from
//! this vault — all local.

/// A viewer's local profile vault.
#[derive(Debug, Clone)]
pub struct ProfileVault {
    /// The viewer's handle (username).
    pub handle: String,
    /// Display name shown in the native UI (customizable, Myspace-style).
    pub display_name: String,
}

impl ProfileVault {
    /// Create a vault for `handle`. Display name defaults to the handle
    /// and can be customized later — all local.
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
