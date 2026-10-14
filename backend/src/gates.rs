//! Provenance-based feature gates for the TRV Network.
//!
//! [`crate::paywall`] evaluates policy over *caller-supplied* tier values,
//! which a modified client can simply lie about — so it had zero real
//! enforcement. These gates close that hole: every check takes an
//! [`Entitlement`] that could only have come from
//! [`verify_and_check`](crate::entitlement::verify_and_check), i.e. an
//! issuer-signed, unexpired receipt. There is no path from a bare
//! [`Tier`](crate::subscriptions::Tier) to an allowed feature.
//!
//! ## Fail-closed contract
//!
//! - `None` (no entitlement presented) denies every feature.
//! - An expired entitlement (or an unreadable clock) denies every feature.
//! - Tampered/forged receipts never produce an [`Entitlement`] (see
//!   [`crate::entitlement`]), so they deny by construction.
//!
//! ## Issuance assumption
//!
//! Monthly/Yearly receipts are issued only to ID-verified viewers (see
//! [`crate::verification`]). The receipt is therefore the issuer's
//! attestation of *both* payment and verification — the gate does not
//! re-check verification state from caller input, because caller input is
//! exactly what this module refuses to trust.
//!
//! ## Honesty note
//!
//! A modified client can still skip calling these gates entirely: on-device
//! checks raise the bar substantially but are not remote attestation. Same
//! caveat class as [`crate::paywall`] and [`crate::entitlement`].

use crate::entitlement::Entitlement;
use crate::subscriptions::Tier;

/// A gated capability of the TRV Network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Feature {
    /// Full research results. Ghost tier sees low-lights only.
    ResearchFull,
    /// Unlimited Enhanced Intelligence (The Sentinel).
    UnlimitedEi,
    /// Myspace-style live profile customization.
    Customization,
    /// Unlimited call/text/video.
    Messaging,
    /// Geo-TRV hunting and clan laser-tag rewards.
    ArRewards,
    /// Real-time full news feed.
    NewsFull,
    /// Basic native VPN. The one feature open to every tier.
    VpnBasic,
    /// VPN with more locations and options (paid tiers).
    VpnPlus,
}

impl Feature {
    /// Short machine-readable label (also the CLI `--feature` name).
    pub fn label(self) -> &'static str {
        match self {
            Feature::ResearchFull => "research-full",
            Feature::UnlimitedEi => "unlimited-ei",
            Feature::Customization => "customization",
            Feature::Messaging => "messaging",
            Feature::ArRewards => "ar-rewards",
            Feature::NewsFull => "news-full",
            Feature::VpnBasic => "vpn-basic",
            Feature::VpnPlus => "vpn-plus",
        }
    }

    /// Parse a [`Feature::label`]. Unknown names fail closed (callers map
    /// them to denial, never to a default feature).
    pub fn from_label(label: &str) -> Option<Feature> {
        Some(match label {
            "research-full" => Feature::ResearchFull,
            "unlimited-ei" => Feature::UnlimitedEi,
            "customization" => Feature::Customization,
            "messaging" => Feature::Messaging,
            "ar-rewards" => Feature::ArRewards,
            "news-full" => Feature::NewsFull,
            "vpn-basic" => Feature::VpnBasic,
            "vpn-plus" => Feature::VpnPlus,
            _ => return None,
        })
    }

    /// Every feature, for exhaustive testing.
    pub fn all() -> [Feature; 8] {
        [
            Feature::ResearchFull,
            Feature::UnlimitedEi,
            Feature::Customization,
            Feature::Messaging,
            Feature::ArRewards,
            Feature::NewsFull,
            Feature::VpnBasic,
            Feature::VpnPlus,
        ]
    }
}

/// Minimum tier that unlocks `feature`. Founding outranks everything.
fn min_tier(feature: Feature) -> Tier {
    match feature {
        // Native VPN for all tiers — the one universal feature.
        Feature::VpnBasic => Tier::Free,
        // Everything else: paid (Monthly/Yearly, issued only when
        // verified) or Founding.
        Feature::ResearchFull
        | Feature::UnlimitedEi
        | Feature::Customization
        | Feature::Messaging
        | Feature::ArRewards
        | Feature::NewsFull
        | Feature::VpnPlus => Tier::Monthly,
    }
}

fn tier_rank(tier: Tier) -> u8 {
    match tier {
        Tier::Free => 0,
        Tier::Monthly => 1,
        Tier::Yearly => 2,
        Tier::Founding => 3,
    }
}

/// Provenance-based gate: `true` only with a *live* (unexpired)
/// issuer-signed entitlement whose tier meets the feature's bar.
///
/// `None` denies everything. Expiry (or an unreadable clock) denies
/// everything. There is no "default allow" path.
pub fn can_access(feature: Feature, ent: Option<Entitlement>) -> bool {
    let ent = match ent {
        Some(e) => e,
        None => return false,
    };
    let ent = match ent.check() {
        Ok(e) => e,
        Err(_) => return false,
    };
    tier_rank(ent.tier()) >= tier_rank(min_tier(feature))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entitlement::{issue, verify_and_check, EntitlementError};

    /// Fixed issuer seed for tests only — never a real key.
    const ISSUER_SEED: [u8; 32] = *b"test-gates-issuer-00000000000000";

    fn issuer_pubkey() -> [u8; 32] {
        let (_, public) = trv_core::crypto::ed25519::generate(&ISSUER_SEED);
        *public.as_bytes()
    }

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .expect("test clock")
    }

    fn live_entitlement(tier: Tier) -> Entitlement {
        let now = now_secs();
        let receipt = issue(&ISSUER_SEED, tier, now, now + 30 * 86_400).expect("issue");
        verify_and_check(&issuer_pubkey(), &receipt).expect("live entitlement")
    }

    fn expired_entitlement(tier: Tier) -> Vec<u8> {
        let now = now_secs();
        issue(&ISSUER_SEED, tier, now - 60 * 86_400, now - 3_600).expect("issue")
    }

    #[test]
    fn no_entitlement_denies_everything() {
        for feature in Feature::all() {
            assert!(
                !can_access(feature, None),
                "None must deny {}",
                feature.label()
            );
        }
    }

    #[test]
    fn free_tier_gets_only_vpn_basic() {
        let ent = live_entitlement(Tier::Free);
        assert!(can_access(Feature::VpnBasic, Some(ent)));
        for feature in Feature::all() {
            if feature == Feature::VpnBasic {
                continue;
            }
            assert!(
                !can_access(feature, Some(ent)),
                "Free must deny {}",
                feature.label()
            );
        }
    }

    #[test]
    fn monthly_unlocks_everything() {
        let ent = live_entitlement(Tier::Monthly);
        for feature in Feature::all() {
            assert!(
                can_access(feature, Some(ent)),
                "Monthly must allow {}",
                feature.label()
            );
        }
    }

    #[test]
    fn yearly_unlocks_everything() {
        let ent = live_entitlement(Tier::Yearly);
        for feature in Feature::all() {
            assert!(can_access(feature, Some(ent)), "Yearly must allow all");
        }
    }

    #[test]
    fn founding_unlocks_everything() {
        let ent = live_entitlement(Tier::Founding);
        for feature in Feature::all() {
            assert!(can_access(feature, Some(ent)), "Founding must allow all");
        }
    }

    #[test]
    fn expired_entitlement_denies_everything() {
        for tier in [Tier::Free, Tier::Monthly, Tier::Yearly, Tier::Founding] {
            let receipt = expired_entitlement(tier);
            // Genuine receipt, dead entitlement: verify_and_check refuses it,
            // so no Entitlement value can even be built from it here.
            assert_eq!(
                verify_and_check(&issuer_pubkey(), &receipt),
                Err(EntitlementError::Expired)
            );
        }
        // And even if an Entitlement value somehow survived past expiry,
        // can_access re-checks liveness. Build one via a live receipt whose
        // check() would fail: simulate by verifying (provenance only) then
        // letting the clock do the work — instead assert the direct path:
        // a live entitlement denied after we wrap it as None is covered;
        // here assert check() itself fails closed on the expired receipt.
        let now = now_secs();
        let receipt =
            issue(&ISSUER_SEED, Tier::Monthly, now - 7_200, now - 3_600).expect("issue");
        let ent = crate::entitlement::verify_receipt(&issuer_pubkey(), &receipt)
            .expect("genuine provenance");
        assert!(ent.check().is_err());
        assert!(!can_access(Feature::VpnBasic, Some(ent)));
        assert!(!can_access(Feature::UnlimitedEi, Some(ent)));
    }

    #[test]
    fn labels_round_trip() {
        for feature in Feature::all() {
            assert_eq!(Feature::from_label(feature.label()), Some(feature));
        }
        assert_eq!(Feature::from_label("nope"), None);
        assert_eq!(Feature::from_label(""), None);
    }
}
