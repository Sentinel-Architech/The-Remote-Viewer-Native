//! Encrypted profile vault stub.
//!
//! Real vault encrypts notes with the device key (age wiring later).
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
    pub fn decentralized_email(&self) -> String {
        format!("{}@RV.com", self.handle)
    }
}
