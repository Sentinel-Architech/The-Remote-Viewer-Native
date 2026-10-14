//! On-device paywall gating for the TRV Network.
//!
//! Access, content, and icon customization are exclusive to the TRV
//! Network. If not paid and verified, a viewer is essentially an
//! anonymous "ghost" with no reach or signal: research without a paid
//! monthly subscription shows only low-lights, with the rest paywalled
//! until the viewer pays and verifies.
//!
//! Gating is pure local computation over [`Tier`] and
//! [`VerificationStatus`]; no network calls, no billing SDKs.
//!
//! ## Trust model
//!
//! Be explicit about what this gate does and does not promise:
//!
//! - `tier` and `verification` are **caller-supplied inputs**. This
//!   module evaluates policy ("what may a viewer with this tier and
//!   this verification state do?"), not provenance ("how do we know
//!   they really have it?").
//! - In this local-first architecture the viewer controls their own
//!   device and its software. A modified client can therefore bypass
//!   these checks entirely — nothing here is an enforcement boundary.
//! - Server-side (or device-secure-enclave) attestation of tier and
//!   verification state is a future step, not a current property. The
//!   existing honesty about the activation-code checksum
//!   ([`crate::activation`]) applies equally here: these are local
//!   policy evaluations, not unforgeable guarantees.

use crate::subscriptions::{unlimited_entitlement, Tier, VerificationStatus};

/// A feature of the TRV Network behind the paywall.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Feature {
    /// Full research results. Ghost tier sees only low-lights.
    ResearchFull,
    /// Unlimited Enhanced Intelligence (The Sentinel) use: unlimited
    /// only after at least one subscribed month, no meter or keys.
    UnlimitedEi,
    /// Myspace-style live profile customization (music etc., ENHANCED).
    Customization,
}

impl Feature {
    /// Short machine-readable label.
    pub fn label(self) -> &'static str {
        match self {
            Feature::ResearchFull => "research-full",
            Feature::UnlimitedEi => "unlimited-ei",
            Feature::Customization => "customization",
        }
    }
}

/// On-device paywall gate.
///
/// Returns `true` only for viewers with an unlimited entitlement:
/// Monthly/Yearly tiers that are Verified, or Founding members. The
/// Free (ghost) tier is denied every gated feature — only low-lights
/// until the viewer pays and verifies.
pub fn can_access(
    feature: Feature,
    tier: Tier,
    verification: VerificationStatus,
) -> bool {
    match feature {
        // All gated features currently share one bar: paid + verified.
        // Split the arms when per-feature rules diverge.
        Feature::ResearchFull | Feature::UnlimitedEi | Feature::Customization => {
            unlimited_entitlement(tier, verification)
        }
    }
}

/// Low-lights view: whether a ghost-tier viewer may see the restricted
/// (paywalled-off) preview of `feature`.
///
/// Per spec, research without a paid subscription shows only low-lights
/// of everything in the DApp. Ghost tier always gets the low-lights
/// preview; fully entitled viewers skip the preview and get the feature
/// itself.
pub fn low_lights(feature: Feature) -> bool {
    matches!(feature, Feature::ResearchFull)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ghost_tier_denied_full_research() {
        // Free tier is denied even when the (impossible) verified state
        // is passed: the bar is paid + verified.
        assert!(!can_access(
            Feature::ResearchFull,
            Tier::Free,
            VerificationStatus::Unverified
        ));
        assert!(!can_access(
            Feature::ResearchFull,
            Tier::Free,
            VerificationStatus::Verified
        ));
    }

    #[test]
    fn paid_and_verified_granted_all_features() {
        for feature in [
            Feature::ResearchFull,
            Feature::UnlimitedEi,
            Feature::Customization,
        ] {
            assert!(can_access(
                feature,
                Tier::Monthly,
                VerificationStatus::Verified
            ));
            assert!(can_access(
                feature,
                Tier::Yearly,
                VerificationStatus::Verified
            ));
        }
    }

    #[test]
    fn paid_but_unverified_denied() {
        assert!(!can_access(
            Feature::UnlimitedEi,
            Tier::Monthly,
            VerificationStatus::Unverified
        ));
        assert!(!can_access(
            Feature::Customization,
            Tier::Yearly,
            VerificationStatus::Pending
        ));
    }

    #[test]
    fn founding_granted_everything() {
        for feature in [
            Feature::ResearchFull,
            Feature::UnlimitedEi,
            Feature::Customization,
        ] {
            assert!(can_access(
                feature,
                Tier::Founding,
                VerificationStatus::Unverified
            ));
        }
    }

    #[test]
    fn ghost_gets_low_lights_research_preview() {
        assert!(low_lights(Feature::ResearchFull));
        assert!(!low_lights(Feature::UnlimitedEi));
        assert!(!low_lights(Feature::Customization));
    }
}
