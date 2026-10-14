//! Ads policy for The Remote Viewer Network.
//!
//! User decision (2026-10-13): Ghost (free) tier gets native ads —
//! 15 seconds of ads for every minute watched. No other tier gets ads.
//!
//! "Native ads" means ad creative rendered by the on-device native UI from
//! a local ad inventory. It is NOT a corporate ad network: no Google, Meta,
//! or Alphabet SDKs, no tracking beacons, no per-impression phoning home
//! (zero-corporate rule). Actual ad inventory, creative selection, and
//! playback wiring are out of scope — this module is the policy layer only.
//!
//! Local-only, std-only, no network I/O.

use crate::subscriptions::Tier;

/// The ad load a tier carries.
///
/// Ghost tier carries native ads; every paid tier carries none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdLoad {
    /// No ads for this tier.
    None,
    /// Native on-device ads: `secs_per_min` seconds of ads per minute watched.
    Native {
        /// Seconds of ads owed per 60 seconds of watched content.
        secs_per_min: u32,
    },
}

impl AdLoad {
    /// Short machine-readable label.
    pub fn label(self) -> &'static str {
        match self {
            AdLoad::None => "none",
            AdLoad::Native { .. } => "native",
        }
    }

    /// True when this load carries any ads.
    pub fn has_ads(self) -> bool {
        matches!(self, AdLoad::Native { .. })
    }
}

/// Seconds of native ads per minute watched for the ghost tier
/// (decided 2026-10-13). Single source of truth — the rate is policy,
/// not scattered in logic.
pub const GHOST_AD_SECS_PER_MIN: u32 = 15;

/// The ads policy: ghost gets native ads, everyone else gets none.
///
/// Implemented as a unit struct so the policy reads as
/// `AdPolicy::ads_for_tier(tier)`; the policy itself is total over tiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdPolicy;

impl AdPolicy {
    /// Ad load for a tier.
    ///
    /// `Tier::Free` (ghost) → [`AdLoad::Native`] at
    /// [`GHOST_AD_SECS_PER_MIN`] seconds per minute.
    /// Monthly / Yearly / Founding → [`AdLoad::None`].
    pub fn ads_for_tier(tier: Tier) -> AdLoad {
        match tier {
            Tier::Free => AdLoad::Native {
                secs_per_min: GHOST_AD_SECS_PER_MIN,
            },
            Tier::Monthly | Tier::Yearly | Tier::Founding => AdLoad::None,
        }
    }
}

/// Ad seconds owed for `watch_secs` seconds of watched content under
/// `load`.
///
/// Integer math only, rounds down:
/// `watch_secs * secs_per_min / 60`. A `None` load always owes zero.
pub fn ad_secs_for_watch_secs(watch_secs: u64, load: AdLoad) -> u64 {
    match load {
        AdLoad::None => 0,
        AdLoad::Native { secs_per_min } => watch_secs * u64::from(secs_per_min) / 60,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ghost_tier_gets_native_ads() {
        assert_eq!(
            AdPolicy::ads_for_tier(Tier::Free),
            AdLoad::Native { secs_per_min: 15 }
        );
    }

    #[test]
    fn ghost_ad_rate_is_fifteen_per_minute() {
        assert_eq!(GHOST_AD_SECS_PER_MIN, 15);
        let load = AdPolicy::ads_for_tier(Tier::Free);
        assert!(load.has_ads());
        assert_eq!(load.label(), "native");
    }

    #[test]
    fn paid_tiers_get_no_ads() {
        for tier in [Tier::Monthly, Tier::Yearly, Tier::Founding] {
            let load = AdPolicy::ads_for_tier(tier);
            assert_eq!(load, AdLoad::None, "tier {:?} must be ad-free", tier);
            assert!(!load.has_ads());
            assert_eq!(load.label(), "none");
        }
    }

    #[test]
    fn ad_secs_one_minute() {
        let load = AdPolicy::ads_for_tier(Tier::Free);
        assert_eq!(ad_secs_for_watch_secs(60, load), 15);
    }

    #[test]
    fn ad_secs_two_minutes() {
        let load = AdPolicy::ads_for_tier(Tier::Free);
        assert_eq!(ad_secs_for_watch_secs(120, load), 30);
    }

    #[test]
    fn ad_secs_rounds_down() {
        // 30s watched -> 30*15/60 = 7.5 -> 7 (rounds down).
        let load = AdPolicy::ads_for_tier(Tier::Free);
        assert_eq!(ad_secs_for_watch_secs(30, load), 7);
    }

    #[test]
    fn ad_secs_zero_watch() {
        let load = AdPolicy::ads_for_tier(Tier::Free);
        assert_eq!(ad_secs_for_watch_secs(0, load), 0);
    }

    #[test]
    fn ad_secs_none_load_always_zero() {
        for tier in [Tier::Monthly, Tier::Yearly, Tier::Founding] {
            let load = AdPolicy::ads_for_tier(tier);
            assert_eq!(ad_secs_for_watch_secs(3600, load), 0);
        }
    }
}
