//! Tier / entitlement / verification logic.
//!
//! Verified locally on-device. No billing network calls here —
//! Solana is the separate track, only for TRV token/governance.

/// Subscription tiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// Unregistered: 1-mile limit for all comms; emergency unlimited.
    Free,
    /// Recurring monthly.
    Monthly,
    /// Yearly ($100/$150/$200 per year depending on paid tier).
    Yearly,
    /// Built the native stack via GH manually: 100% everything unlimited.
    Founding,
}

impl Tier {
    /// Whether the tier itself grants unlimited use (before verification gating).
    ///
    /// Monthly/Yearly additionally require [`VerificationStatus::Verified`];
    /// use [`unlimited_entitlement`] for the full on-device check.
    pub fn unlimited_use(self) -> bool {
        matches!(self, Tier::Monthly | Tier::Yearly | Tier::Founding)
    }

    /// Proximity limit in miles, if any. `None` = unlimited.
    pub fn max_proximity_miles(self) -> Option<u32> {
        match self {
            Tier::Free => Some(1),
            Tier::Monthly | Tier::Yearly | Tier::Founding => None,
        }
    }
}

/// Paid tier levels with user-decided pricing (decided 2026-10-13).
///
/// Separate from [`Tier`] (which models entitlement/billing-period state):
/// `PaidTier` carries the price list. Tier 1/2/3 each offer a monthly or
/// yearly price. For an arbitrary percent-off calculation, use
/// [`PaidTier::discounted_yearly_cents`]; for the user-decided
/// discount-category rate, use
/// [`DiscountCategory::yearly_price_cents`]; for the American-citizen
/// yearly rate, use [`PaidTier::citizen_yearly_cents`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaidTier {
    /// $10/month or $100/year.
    Tier1,
    /// $25/month or $150/year.
    Tier2,
    /// $45/month or $200/year.
    Tier3,
}

impl PaidTier {
    /// Short human-readable label.
    pub fn label(self) -> &'static str {
        match self {
            PaidTier::Tier1 => "Tier 1",
            PaidTier::Tier2 => "Tier 2",
            PaidTier::Tier3 => "Tier 3",
        }
    }

    /// Monthly price in cents (avoids float money math).
    pub fn monthly_cents(self) -> u32 {
        match self {
            PaidTier::Tier1 => 1000,  // $10
            PaidTier::Tier2 => 2500,  // $25
            PaidTier::Tier3 => 4500,  // $45
        }
    }

    /// Yearly price in cents (avoids float money math).
    pub fn yearly_cents(self) -> u32 {
        match self {
            PaidTier::Tier1 => 10000, // $100
            PaidTier::Tier2 => 15000, // $150
            PaidTier::Tier3 => 20000, // $200
        }
    }

    /// Yearly price in cents with `percent_off` percent discount applied.
    ///
    /// `percent_off` is clamped to 0..=100; the result rounds down.
    /// The discount percentage itself is a user decision — pass it in
    /// explicitly; nothing here hardcodes a specific discount.
    pub fn discounted_yearly_cents(self, percent_off: u32) -> u32 {
        let pct = percent_off.min(100);
        let base = self.yearly_cents() as u64;
        ((base * u64::from(100 - pct)) / 100) as u32
    }

    /// Yearly price in cents with the American-citizen discount applied
    /// ([`CITIZEN_DISCOUNT_YEARLY_BASIS_POINTS`], 17.67%).
    ///
    /// Standalone rule: this does NOT stack with the
    /// [`DISCOUNT_YEARLY_PERCENT`] category discount. Use
    /// [`PaidTier::best_yearly_price_cents`] for the real single-discount
    /// rule; stacking semantics are undecided and intentionally not
    /// combined here. Computed with integer math; the result rounds down.
    pub fn citizen_yearly_cents(self) -> u32 {
        let base = self.yearly_cents() as u64;
        let multiplier = 10_000u64 - u64::from(CITIZEN_DISCOUNT_YEARLY_BASIS_POINTS);
        ((base * multiplier) / 10_000) as u32
    }

    /// The viewer's real yearly price, given discount eligibility.
    ///
    /// REAL discount rule (user decisions 2026-10-13): a viewer may
    /// qualify for the 20% discount-category rate ([`DiscountCategory`])
    /// and/or the 17.67% American-citizen rate ([`CITIZEN_DISCOUNT_YEARLY_BASIS_POINTS`]).
    ///
    /// NON-STACKING: at most one discount is applied — the largest one
    /// the viewer qualifies for. Today the 20% category rate always
    /// beats the 17.67% citizen rate, so a qualifying category wins
    /// outright. Whether discounts may ever combine is TBD per spec;
    /// this function deliberately never applies more than one.
    pub fn best_yearly_price_cents(
        self,
        category: Option<DiscountCategory>,
        citizen: bool,
    ) -> u32 {
        let mut best = self.yearly_cents();
        if let Some(cat) = category {
            best = best.min(cat.yearly_price_cents(self));
        }
        if citizen {
            best = best.min(self.citizen_yearly_cents());
        }
        best
    }
}

/// Yearly discount rate (percent) for discount categories, decided by the
/// user on 2026-10-13. Applies to Education, Authority, and ServeProtect.
pub const DISCOUNT_YEARLY_PERCENT: u32 = 20;

/// Yearly discount for American citizens, decided by the user on
/// 2026-10-13: 17.67% off yearly subscriptions.
///
/// Represented in basis points (17.67% = 1767 bps) because it is not a
/// whole number. Integer math only; results round down. This is a
/// standalone rule — whether it stacks with [`DISCOUNT_YEARLY_PERCENT`]
/// is undecided and intentionally not combined here.
pub const CITIZEN_DISCOUNT_YEARLY_BASIS_POINTS: u32 = 1767;

/// Discount categories per spec: monthly or yearly discounts for the
/// education system, authority, and all those who serve and protect
/// every American and are paid to do it willingly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscountCategory {
    /// Education system.
    Education,
    /// Authority.
    Authority,
    /// Those who serve and protect every American, paid to do it willingly.
    ServeProtect,
}

impl DiscountCategory {
    /// Human-readable label.
    pub fn label(self) -> &'static str {
        match self {
            DiscountCategory::Education => "Education system",
            DiscountCategory::Authority => "Authority",
            DiscountCategory::ServeProtect => "Serve and protect",
        }
    }

    /// Monthly discount flag per spec (all categories qualify).
    pub fn monthly_discount(self) -> bool {
        true
    }

    /// Yearly discount flag per spec (all categories qualify).
    pub fn yearly_discount(self) -> bool {
        true
    }

    /// Whether this category qualifies for a discount on the given tier.
    pub fn applies_to(self, tier: Tier) -> bool {
        match tier {
            Tier::Monthly => self.monthly_discount(),
            Tier::Yearly => self.yearly_discount(),
            Tier::Free | Tier::Founding => false,
        }
    }

    /// Yearly price in cents for `tier` with this category's discount
    /// applied ([`DISCOUNT_YEARLY_PERCENT`]).
    ///
    /// All three categories qualify per spec; the price does not vary by
    /// category, only by tier. Delegates to
    /// [`PaidTier::discounted_yearly_cents`] — no math is duplicated here.
    pub fn yearly_price_cents(self, tier: PaidTier) -> u32 {
        let _ = self; // All categories share the same yearly rate.
        tier.discounted_yearly_cents(DISCOUNT_YEARLY_PERCENT)
    }
}

/// Human-verification status. Background ID verification via state/fed ID.
///
/// Per spec: if a Remote Viewer does not own a State ID, verification
/// is ineligible — handled by [`check_verification`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationStatus {
    /// State ID present; verification not yet completed.
    Unverified,
    /// Verification submitted, awaiting completion.
    Pending,
    /// Verified human: unlocks unlimited call/text/video on Monthly/Yearly.
    Verified,
    /// No State ID: ineligible for verification.
    Ineligible,
}

/// On-device verification gate.
///
/// Returns [`VerificationStatus::Ineligible`] when the viewer has no
/// State ID; otherwise returns [`VerificationStatus::Unverified`]
/// (eligible to begin the background ID verification process).
pub fn check_verification(has_state_id: bool) -> VerificationStatus {
    if has_state_id {
        VerificationStatus::Unverified
    } else {
        VerificationStatus::Ineligible
    }
}

/// Full on-device entitlement check per spec.
///
/// - Free: no unlimited use (1-mile limit; emergency is the exception).
/// - Monthly/Yearly: unlimited call/text/video only when Verified.
/// - Founding: 100% everything unlimited (GH manual install).
pub fn unlimited_entitlement(tier: Tier, verification: VerificationStatus) -> bool {
    match tier {
        Tier::Free => false,
        Tier::Monthly | Tier::Yearly => verification == VerificationStatus::Verified,
        Tier::Founding => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier1_pricing() {
        assert_eq!(PaidTier::Tier1.monthly_cents(), 1000); // $10
        assert_eq!(PaidTier::Tier1.yearly_cents(), 10000); // $100
    }

    #[test]
    fn tier2_pricing() {
        assert_eq!(PaidTier::Tier2.monthly_cents(), 2500); // $25
        assert_eq!(PaidTier::Tier2.yearly_cents(), 15000); // $150
    }

    #[test]
    fn tier3_pricing() {
        assert_eq!(PaidTier::Tier3.monthly_cents(), 4500); // $45
        assert_eq!(PaidTier::Tier3.yearly_cents(), 20000); // $200
    }

    #[test]
    fn yearly_discount_applies() {
        // 20% off Tier 1 yearly: $100 -> $80.
        assert_eq!(PaidTier::Tier1.discounted_yearly_cents(20), 8000);
        // 0% off leaves the price unchanged.
        assert_eq!(PaidTier::Tier2.discounted_yearly_cents(0), 15000);
    }

    #[test]
    fn discount_clamped() {
        // 100% off is free; anything above clamps to 100%.
        assert_eq!(PaidTier::Tier3.discounted_yearly_cents(100), 0);
        assert_eq!(PaidTier::Tier3.discounted_yearly_cents(150), 0);
        // 15% off Tier 3 yearly: $200 -> $170.
        assert_eq!(PaidTier::Tier3.discounted_yearly_cents(15), 17000);
    }

    #[test]
    fn paid_tier_labels() {
        assert_eq!(PaidTier::Tier1.label(), "Tier 1");
        assert_eq!(PaidTier::Tier2.label(), "Tier 2");
        assert_eq!(PaidTier::Tier3.label(), "Tier 3");
    }

    #[test]
    fn discount_yearly_percent_is_twenty() {
        assert_eq!(DISCOUNT_YEARLY_PERCENT, 20);
    }

    #[test]
    fn discount_category_yearly_prices() {
        // 20% off each tier's yearly price.
        assert_eq!(PaidTier::Tier1.yearly_cents(), 10000); // $100 base
        assert_eq!(PaidTier::Tier2.yearly_cents(), 15000); // $150 base
        assert_eq!(PaidTier::Tier3.yearly_cents(), 20000); // $200 base

        // Every discount category gets the same 20% off yearly rate.
        for category in [
            DiscountCategory::Education,
            DiscountCategory::Authority,
            DiscountCategory::ServeProtect,
        ] {
            // Tier 1: $100 -> $80
            assert_eq!(category.yearly_price_cents(PaidTier::Tier1), 8000);
            // Tier 2: $150 -> $120
            assert_eq!(category.yearly_price_cents(PaidTier::Tier2), 12000);
            // Tier 3: $200 -> $160
            assert_eq!(category.yearly_price_cents(PaidTier::Tier3), 16000);
        }
    }

    #[test]
    fn discount_category_yearly_matches_helper() {
        // The category rate delegates to the generic helper: 20% off.
        for tier in [PaidTier::Tier1, PaidTier::Tier2, PaidTier::Tier3] {
            assert_eq!(
                DiscountCategory::Education.yearly_price_cents(tier),
                tier.discounted_yearly_cents(20)
            );
        }
    }

    #[test]
    fn citizen_discount_constant_is_1767_bps() {
        // 17.67% expressed in basis points.
        assert_eq!(CITIZEN_DISCOUNT_YEARLY_BASIS_POINTS, 1767);
    }

    #[test]
    fn citizen_yearly_prices() {
        // 17.67% off: price * 8233 / 10000, rounded down.
        // Tier 1: $100.00 -> $82.33 (8233 cents, exact).
        assert_eq!(PaidTier::Tier1.citizen_yearly_cents(), 8233);
        // Tier 2: $150.00 -> $123.495 -> 12349 cents (round down).
        assert_eq!(PaidTier::Tier2.citizen_yearly_cents(), 12349);
        // Tier 3: $200.00 -> $164.66 (16466 cents, exact).
        assert_eq!(PaidTier::Tier3.citizen_yearly_cents(), 16466);
    }

    #[test]
    fn citizen_discount_is_standalone() {
        // No stacking with the 20% category discount: the citizen price
        // must differ from applying both. Tier 1: 20% of $80.00... the
        // category price ($80) is not further reduced here.
        let category_price = DiscountCategory::Education.yearly_price_cents(PaidTier::Tier1);
        let citizen_price = PaidTier::Tier1.citizen_yearly_cents();
        assert_eq!(category_price, 8000);
        assert_eq!(citizen_price, 8233);
        // Stacking semantics are TBD, so the two must not be equal
        // (guard against an accidental future merge).
        assert_ne!(category_price, citizen_price);
    }

    #[test]
    fn best_yearly_price_applies_single_best_discount() {
        // No eligibility: full price.
        assert_eq!(PaidTier::Tier1.best_yearly_price_cents(None, false), 10000);
        // Citizen only: 17.67% off -> 8233.
        assert_eq!(PaidTier::Tier1.best_yearly_price_cents(None, true), 8233);
        // Category only: 20% off -> 8000.
        assert_eq!(
            PaidTier::Tier1.best_yearly_price_cents(Some(DiscountCategory::Education), false),
            8000
        );
        // Both: NO stacking — single best (category) wins, not both.
        assert_eq!(
            PaidTier::Tier1.best_yearly_price_cents(Some(DiscountCategory::ServeProtect), true),
            8000
        );
        // Same on Tier 3: category ($160) beats citizen ($164.66).
        assert_eq!(
            PaidTier::Tier3.best_yearly_price_cents(Some(DiscountCategory::Authority), true),
            16000
        );
        assert_eq!(PaidTier::Tier3.best_yearly_price_cents(None, true), 16466);
    }

    #[test]
    fn discount_category_applies_to() {
        for cat in [
            DiscountCategory::Education,
            DiscountCategory::Authority,
            DiscountCategory::ServeProtect,
        ] {
            assert!(cat.applies_to(Tier::Monthly));
            assert!(cat.applies_to(Tier::Yearly));
            assert!(!cat.applies_to(Tier::Free));
            assert!(!cat.applies_to(Tier::Founding));
        }
    }

    #[test]
    fn tier_unlimited_use_flags() {
        assert!(!Tier::Free.unlimited_use());
        assert!(Tier::Monthly.unlimited_use());
        assert!(Tier::Yearly.unlimited_use());
        assert!(Tier::Founding.unlimited_use());
    }

    #[test]
    fn tier_max_proximity_miles() {
        // Free: 1-mile limit for all comms. Everything else: unlimited.
        assert_eq!(Tier::Free.max_proximity_miles(), Some(1));
        assert_eq!(Tier::Monthly.max_proximity_miles(), None);
        assert_eq!(Tier::Yearly.max_proximity_miles(), None);
        assert_eq!(Tier::Founding.max_proximity_miles(), None);
    }

    #[test]
    fn check_verification_gates_on_state_id() {
        assert_eq!(
            check_verification(true),
            VerificationStatus::Unverified
        );
        assert_eq!(
            check_verification(false),
            VerificationStatus::Ineligible
        );
    }

    #[test]
    fn unlimited_entitlement_full_matrix() {
        let free = Tier::Free;
        let monthly = Tier::Monthly;
        let yearly = Tier::Yearly;
        let founding = Tier::Founding;
        // Free: never unlimited, in any verification state.
        for v in [
            VerificationStatus::Unverified,
            VerificationStatus::Pending,
            VerificationStatus::Verified,
            VerificationStatus::Ineligible,
        ] {
            assert!(!unlimited_entitlement(free, v));
            // Founding: always unlimited, even unverified.
            assert!(unlimited_entitlement(founding, v));
        }
        // Monthly/Yearly: unlimited only when Verified.
        for tier in [monthly, yearly] {
            assert!(!unlimited_entitlement(tier, VerificationStatus::Unverified));
            assert!(!unlimited_entitlement(tier, VerificationStatus::Pending));
            assert!(unlimited_entitlement(tier, VerificationStatus::Verified));
            assert!(!unlimited_entitlement(tier, VerificationStatus::Ineligible));
        }
    }
}
