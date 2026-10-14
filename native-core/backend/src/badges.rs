//! Special badges for digital creators on the TRV Network.
//!
//! Per user decision (2026-10-13): digital creators get special badges.
//! Badges are earned, not bought, and can be revoked for policy
//! violations. Badges are purely descriptive of a viewer's standing:
//! they connect to the existing creator economics (80% to exclusive
//! TRV creators, irreplaceable watermarks) but do not change them.
//!
//! All computation is local; no network I/O happens here.

/// A special badge a digital creator can hold on the TRV Network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Badge {
    /// Publishes original work on TRV.
    Creator,
    /// Creates exclusively for TRV. This is the badge that ties to the
    /// 80% creator economics: exclusive creators earn 80% of what they
    /// sell. Exclusive implies Creator.
    ExclusiveCreator,
    /// An identity-verified creator (passed State/federal ID checks).
    VerifiedCreator,
}

impl Badge {
    /// Short machine-readable label.
    pub fn label(self) -> &'static str {
        match self {
            Badge::Creator => "creator",
            Badge::ExclusiveCreator => "exclusive-creator",
            Badge::VerifiedCreator => "verified-creator",
        }
    }

    /// Human-readable description of what the badge means.
    pub fn description(self) -> &'static str {
        match self {
            Badge::Creator => "Publishes original work on the TRV Network.",
            Badge::ExclusiveCreator => {
                "Creates exclusively for TRV; eligible for the 80% creator share."
            }
            Badge::VerifiedCreator => {
                "Identity-verified creator; real-person status confirmed."
            }
        }
    }
}

/// The minimal facts about a viewer used to judge badge eligibility.
///
/// Kept deliberately small and honest: the caller (profile store,
/// verification flow) supplies what it knows; this module never
/// performs network lookups.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreatorProfile {
    /// Publishes original work on TRV.
    pub is_creator: bool,
    /// Creates exclusively for TRV.
    pub is_exclusive: bool,
    /// Passed identity verification.
    pub is_verified: bool,
}

impl CreatorProfile {
    /// Build an eligibility snapshot. No validation: flags are
    /// asserted by the calling store, not derived here.
    pub fn new(is_creator: bool, is_exclusive: bool, is_verified: bool) -> Self {
        CreatorProfile {
            is_creator,
            is_exclusive,
            is_verified,
        }
    }
}

/// Pure eligibility rule for `badge` given `profile`.
///
/// - Creator: must publish original work on TRV.
/// - ExclusiveCreator: must create exclusively for TRV (exclusivity
///   implies being a creator).
/// - VerifiedCreator: must be a creator AND identity-verified.
pub fn qualifies_for(badge: Badge, profile: CreatorProfile) -> bool {
    match badge {
        Badge::Creator => profile.is_creator,
        Badge::ExclusiveCreator => profile.is_creator && profile.is_exclusive,
        Badge::VerifiedCreator => profile.is_creator && profile.is_verified,
    }
}

/// A granted badge on a viewer's handle.
///
/// Badges are earned: a grant records the badge, who holds it, and
/// when it was granted (unix seconds, kept as a plain `u64` to stay
/// std-only). A badge can be revoked for policy violations; a revoked
/// badge is inactive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BadgeGrant {
    /// The badge held.
    pub badge: Badge,
    /// The viewer's handle.
    pub handle: String,
    /// When the badge was granted, unix seconds.
    pub granted_unix_secs: u64,
    /// Whether the badge has been revoked.
    pub revoked: bool,
}

impl BadgeGrant {
    /// Record a new badge grant. Handles are trimmed; empties are left
    /// to the caller to reject (badges live in the profile store).
    pub fn new(badge: Badge, handle: &str, granted_unix_secs: u64) -> Self {
        BadgeGrant {
            badge,
            handle: handle.trim().to_string(),
            granted_unix_secs,
            revoked: false,
        }
    }

    /// Revoke the badge (e.g., for a policy violation). Revocation is
    /// one-way in this model: a fresh grant is required to re-earn it.
    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    /// A badge counts only while it has not been revoked.
    pub fn is_active(&self) -> bool {
        !self.revoked
    }
}

/// All badges a `profile` currently earns, in badge order.
pub fn earned_badges(profile: CreatorProfile) -> Vec<Badge> {
    [Badge::Creator, Badge::ExclusiveCreator, Badge::VerifiedCreator]
        .into_iter()
        .filter(|b| qualifies_for(*b, profile))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn badge_labels() {
        assert_eq!(Badge::Creator.label(), "creator");
        assert_eq!(Badge::ExclusiveCreator.label(), "exclusive-creator");
        assert_eq!(Badge::VerifiedCreator.label(), "verified-creator");
    }

    #[test]
    fn badge_descriptions_non_empty() {
        for badge in [
            Badge::Creator,
            Badge::ExclusiveCreator,
            Badge::VerifiedCreator,
        ] {
            assert!(!badge.description().is_empty());
        }
    }

    #[test]
    fn non_creator_qualifies_for_nothing() {
        let p = CreatorProfile::new(false, false, false);
        assert!(earned_badges(p).is_empty());
    }

    #[test]
    fn plain_creator_gets_creator_only() {
        let p = CreatorProfile::new(true, false, false);
        assert_eq!(earned_badges(p), vec![Badge::Creator]);
    }

    #[test]
    fn exclusive_implies_creator() {
        let p = CreatorProfile::new(true, true, false);
        let earned = earned_badges(p);
        assert!(earned.contains(&Badge::Creator));
        assert!(earned.contains(&Badge::ExclusiveCreator));
        assert!(!earned.contains(&Badge::VerifiedCreator));
    }

    #[test]
    fn verified_creator_combo() {
        let p = CreatorProfile::new(true, false, true);
        assert_eq!(
            earned_badges(p),
            vec![Badge::Creator, Badge::VerifiedCreator]
        );
    }

    #[test]
    fn fully_badged_creator() {
        let p = CreatorProfile::new(true, true, true);
        assert_eq!(
            earned_badges(p),
            vec![
                Badge::Creator,
                Badge::ExclusiveCreator,
                Badge::VerifiedCreator
            ]
        );
    }

    #[test]
    fn verified_non_creator_gets_nothing() {
        // Verification alone is not creatorship: badges are for
        // digital creators.
        let p = CreatorProfile::new(false, false, true);
        assert!(earned_badges(p).is_empty());
    }

    #[test]
    fn grant_is_active_until_revoked() {
        let mut grant = BadgeGrant::new(Badge::ExclusiveCreator, "alice", 1_700_000_000);
        assert_eq!(grant.handle, "alice");
        assert!(grant.is_active());
        grant.revoke();
        assert!(!grant.is_active());
        assert!(grant.revoked);
    }

    #[test]
    fn grant_trims_handle() {
        let grant = BadgeGrant::new(Badge::Creator, "  bob  ", 0);
        assert_eq!(grant.handle, "bob");
    }
}
