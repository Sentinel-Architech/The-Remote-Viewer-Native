//! NFC sharing gate for The Remote Viewer.
//!
//! Per spec: "Allow anything to be shared via NFC but only if actually
//! following each other on the Network." The rule is simple —
//! *no follow, no share.*
//!
//! A share request is authorized only when the sender follows the
//! recipient AND the recipient follows the sender (mutual follow).
//! The check is pure local computation over a follower map supplied
//! by the caller (e.g. the local on-device social graph) — no network
//! I/O happens here.

use std::collections::{HashMap, HashSet};

/// The kind of payload being shared. NFC can carry anything; the gate
/// does not discriminate by type, only by the mutual-follow rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadType {
    /// Plain text / link / note.
    Text,
    /// Image or video media.
    Media,
    /// File of any kind.
    File,
    /// Contact card / identity reference.
    Contact,
    /// Audio clip.
    Audio,
}

impl PayloadType {
    /// Short machine-readable label.
    pub fn label(self) -> &'static str {
        match self {
            PayloadType::Text => "text",
            PayloadType::Media => "media",
            PayloadType::File => "file",
            PayloadType::Contact => "contact",
            PayloadType::Audio => "audio",
        }
    }
}

/// Errors raised by the share gate. All local; no I/O.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareError {
    /// No mutual follow: at least one side does not follow the other.
    /// Per spec: no follow, no share.
    NotMutualFollow,
    /// A viewer cannot share with themselves.
    SelfShare,
    /// One of the handles is empty.
    InvalidHandle,
}

impl ShareError {
    /// Short machine-readable label.
    pub fn label(self) -> &'static str {
        match self {
            ShareError::NotMutualFollow => "not-mutual-follow",
            ShareError::SelfShare => "self-share",
            ShareError::InvalidHandle => "invalid-handle",
        }
    }
}

/// A request to share something via NFC from one viewer to another.
///
/// `follower_map` is a local social graph: handle -> set of handles
/// that handle follows. Supplied by the caller (e.g. the on-device
/// profile store); this module never performs network lookups.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareRequest {
    /// Sender's handle.
    pub from: String,
    /// Recipient's handle.
    pub to: String,
    /// What kind of payload is being shared.
    pub payload_type: PayloadType,
}

impl ShareRequest {
    /// Build a share request. Handles are trimmed; empties are
    /// rejected later by [`ShareRequest::validate`].
    pub fn new(from: &str, to: &str, payload_type: PayloadType) -> Self {
        ShareRequest {
            from: from.trim().to_string(),
            to: to.trim().to_string(),
            payload_type,
        }
    }

    /// Basic sanity check: handles must be non-empty and different.
    pub fn validate(&self) -> Result<(), ShareError> {
        if self.from.is_empty() || self.to.is_empty() {
            return Err(ShareError::InvalidHandle);
        }
        if self.from == self.to {
            return Err(ShareError::SelfShare);
        }
        Ok(())
    }

    /// Returns true only when `from` follows `to` AND `to` follows
    /// `from` in the supplied local follower map. Per spec: no follow,
    /// no share.
    ///
    /// Missing map entries count as "follows nobody", so an unknown
    /// handle can never pass the gate.
    pub fn can_share(&self, follower_map: &HashMap<String, HashSet<String>>) -> bool {
        let empty: HashSet<String> = HashSet::new();
        let from_follows = follower_map.get(&self.from).unwrap_or(&empty);
        let to_follows = follower_map.get(&self.to).unwrap_or(&empty);
        from_follows.contains(&self.to) && to_follows.contains(&self.from)
    }

    /// Evaluate the full gate: validate handles, then enforce the
    /// mutual-follow rule.
    pub fn authorize(&self, follower_map: &HashMap<String, HashSet<String>>) -> Result<(), ShareError> {
        self.validate()?;
        if !self.can_share(follower_map) {
            return Err(ShareError::NotMutualFollow);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: &[(&str, &[&str])]) -> HashMap<String, HashSet<String>> {
        let mut m: HashMap<String, HashSet<String>> = HashMap::new();
        for (who, follows) in pairs {
            m.insert(
                who.to_string(),
                follows.iter().map(|s| s.to_string()).collect(),
            );
        }
        m
    }

    #[test]
    fn mutual_follow_allows_share() {
        let followers = map(&[("alice", &["bob"]), ("bob", &["alice"])]);
        let req = ShareRequest::new("alice", "bob", PayloadType::Media);
        assert!(req.can_share(&followers));
        assert!(req.authorize(&followers).is_ok());
    }

    #[test]
    fn one_sided_follow_denied() {
        let followers = map(&[("alice", &["bob"])]);
        let req = ShareRequest::new("alice", "bob", PayloadType::File);
        assert!(!req.can_share(&followers));
        assert_eq!(req.authorize(&followers), Err(ShareError::NotMutualFollow));
    }

    #[test]
    fn unknown_handles_denied() {
        let followers = map(&[]);
        let req = ShareRequest::new("alice", "bob", PayloadType::Text);
        assert_eq!(req.authorize(&followers), Err(ShareError::NotMutualFollow));
    }

    #[test]
    fn self_share_denied() {
        let followers = map(&[("alice", &["alice"])]);
        let req = ShareRequest::new("alice", "alice", PayloadType::Contact);
        assert_eq!(req.authorize(&followers), Err(ShareError::SelfShare));
    }

    #[test]
    fn empty_handle_denied() {
        let followers = map(&[]);
        let req = ShareRequest::new("", "bob", PayloadType::Audio);
        assert_eq!(req.authorize(&followers), Err(ShareError::InvalidHandle));
    }
}
