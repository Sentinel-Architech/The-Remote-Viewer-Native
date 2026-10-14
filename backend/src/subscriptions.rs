//! Tier / entitlement / verification logic.
//!
//! Verified locally on-device. No billing network calls here —
//! Solana is the separate track, only for TRV token/governance.

use crate::entitlement;
use crate::entitlement::EntitlementError;

/// Seconds in a 30-day billing month.
pub const MONTH_SECS: u64 = 30 * 86_400;
/// Seconds in a 365-day billing year.
pub const YEAR_SECS: u64 = 365 * 86_400;
/// Ghost grace period: no fees for the first 30 days as ghost.
pub const GHOST_GRACE_DAYS: u64 = 30;
/// Ghost fee step: $5.00 (500 cents) per billing month after grace.
pub const GHOST_FEE_STEP_CENTS: u32 = 500;

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

// ---------------------------------------------------------------------------
// Subscription lifecycle (the money loop)
// ---------------------------------------------------------------------------

/// Errors from subscription lifecycle operations.
///
/// Fail closed: bad windows never produce a subscription.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscriptionError {
    /// `expires_at <= started_at`: the subscription window is inverted.
    BadWindow,
    /// A paid billing tier (Monthly/Yearly) was requested with no price tier.
    MissingPriceTier,
    /// A price tier was given for a non-billable tier (Free/Founding).
    UnexpectedPriceTier,
}

impl core::fmt::Display for SubscriptionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            SubscriptionError::BadWindow => "subscription: invalid validity window",
            SubscriptionError::MissingPriceTier => "subscription: paid tier needs a price tier",
            SubscriptionError::UnexpectedPriceTier => {
                "subscription: price tier not allowed for this tier"
            }
        };
        f.write_str(s)
    }
}

impl std::error::Error for SubscriptionError {}

/// Lifecycle status of a [`Subscription`] at a given moment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscriptionStatus {
    /// Within its validity window (or cancelled-but-still-paid-through).
    Active,
    /// Past `expires_at` with `auto_renew` on: awaiting the next payment.
    Expired,
    /// Past `expires_at` with `auto_renew` off: dead, needs re-purchase.
    Lapsed,
    /// Explicitly cancelled by the viewer; no further renewals.
    Cancelled,
}

/// A subscription: tier + price + validity window + renewal preference.
///
/// All time is injected as unix seconds — there is **no system-clock
/// dependency** in this logic, so expiry is deterministic and testable.
/// Fields are private; build with [`Subscription::new`] which validates
/// the window and the tier/price combination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Subscription {
    tier: Tier,
    paid_tier: Option<PaidTier>,
    started_at: u64,
    expires_at: u64,
    auto_renew: bool,
    cancelled: bool,
}

impl Subscription {
    /// Create a subscription. Fails closed when `expires_at <= started_at`
    /// or when the tier/price combination is incoherent (paid billing
    /// tiers must carry a price; Free/Founding must not).
    pub fn new(
        tier: Tier,
        paid_tier: Option<PaidTier>,
        started_at: u64,
        expires_at: u64,
        auto_renew: bool,
    ) -> Result<Self, SubscriptionError> {
        if expires_at <= started_at {
            return Err(SubscriptionError::BadWindow);
        }
        match (tier, paid_tier) {
            (Tier::Monthly | Tier::Yearly, None) => {
                return Err(SubscriptionError::MissingPriceTier)
            }
            (Tier::Free | Tier::Founding, Some(_)) => {
                return Err(SubscriptionError::UnexpectedPriceTier)
            }
            _ => {}
        }
        Ok(Subscription {
            tier,
            paid_tier,
            started_at,
            expires_at,
            auto_renew,
            cancelled: false,
        })
    }

    /// Billing tier (Monthly/Yearly/Free/Founding).
    pub fn tier(self) -> Tier {
        self.tier
    }

    /// Price tier (Tier1/2/3), if this subscription is paid.
    pub fn paid_tier(self) -> Option<PaidTier> {
        self.paid_tier
    }

    /// Unix seconds the subscription started.
    pub fn started_at(self) -> u64 {
        self.started_at
    }

    /// Unix seconds the subscription lapses without renewal.
    pub fn expires_at(self) -> u64 {
        self.expires_at
    }

    /// Whether renewal is automatic at expiry.
    pub fn auto_renew(self) -> bool {
        self.auto_renew
    }

    /// Lifecycle status at injected time `now`.
    ///
    /// Cancelled wins over everything (a cancelled subscription never
    /// renews, even if paid through). Past expiry with `auto_renew` on
    /// is [`SubscriptionStatus::Expired`] (renewable); with it off it is
    /// [`SubscriptionStatus::Lapsed`].
    pub fn status(self, now: u64) -> SubscriptionStatus {
        if self.cancelled {
            return SubscriptionStatus::Cancelled;
        }
        if now >= self.expires_at {
            return if self.auto_renew {
                SubscriptionStatus::Expired
            } else {
                SubscriptionStatus::Lapsed
            };
        }
        SubscriptionStatus::Active
    }

    /// Convenience: true only while [`SubscriptionStatus::Active`].
    pub fn is_active(self, now: u64) -> bool {
        self.status(now) == SubscriptionStatus::Active
    }

    /// Renew for `period_secs` more seconds.
    ///
    /// The extension starts at `max(now, expires_at)`: renewing early
    /// keeps the remaining paid time (no double-charging), renewing
    /// late restarts from now. Clears cancellation.
    pub fn renew(&mut self, now: u64, period_secs: u64) {
        let base = self.expires_at.max(now);
        self.expires_at = base.saturating_add(period_secs);
        self.cancelled = false;
    }

    /// Renew for the subscription's own billing period (Monthly = 30
    /// days, Yearly = 365 days). Free/Founding have no period and are
    /// left unchanged.
    pub fn renew_period(&mut self, now: u64) {
        let period = match self.tier {
            Tier::Monthly => MONTH_SECS,
            Tier::Yearly => YEAR_SECS,
            Tier::Free | Tier::Founding => return,
        };
        self.renew(now, period);
    }

    /// Cancel: no further renewals. A paid-through window stays
    /// [`SubscriptionStatus::Active`] until `expires_at`.
    pub fn cancel(&mut self) {
        self.cancelled = true;
    }

    /// Price of one billing period in cents, for the subscription's
    /// tier and price tier. `None` for non-billable tiers.
    pub fn period_price_cents(self) -> Option<u32> {
        let paid = self.paid_tier?;
        Some(match self.tier {
            Tier::Monthly => paid.monthly_cents(),
            Tier::Yearly => paid.yearly_cents(),
            Tier::Free | Tier::Founding => return None,
        })
    }
}

// ---------------------------------------------------------------------------
// Ghost tier escalation
// ---------------------------------------------------------------------------

/// An unpaid, unverified account ("ghost").
///
/// Per spec: after 30 days as ghost the viewer is billed $5 for the
/// first month, $10 for the next, and +$5 each month after, until they
/// verify and pay. The grace period is free.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GhostAccount {
    /// Unix seconds the viewer became a ghost.
    ghost_since: u64,
}

impl GhostAccount {
    /// Create a ghost account starting at `ghost_since` (unix seconds).
    pub fn new(ghost_since: u64) -> Self {
        GhostAccount { ghost_since }
    }

    /// When ghost status began (unix seconds).
    pub fn ghost_since(self) -> u64 {
        self.ghost_since
    }

    /// Whole days spent as a ghost at injected time `now`.
    pub fn days_as_ghost(self, now: u64) -> u64 {
        now.saturating_sub(self.ghost_since) / 86_400
    }

    /// Current monthly fee in cents at injected time `now`.
    ///
    /// - First 30 days: 0 (grace).
    /// - Month 1 after grace: 500 ($5), month 2: 1000 ($10),
    ///   month n: 500*n — i.e. +$5 each month after.
    ///
    /// Returns `None` on arithmetic overflow (fail closed; the caller
    /// must not bill an uncomputable amount).
    pub fn monthly_fee_cents(self, now: u64) -> Option<u32> {
        let days = self.days_as_ghost(now);
        if days < GHOST_GRACE_DAYS {
            return Some(0);
        }
        let billing_month = (days - GHOST_GRACE_DAYS) / 30 + 1;
        billing_month
            .checked_mul(u64::from(GHOST_FEE_STEP_CENTS))
            .and_then(|fee| u32::try_from(fee).ok())
    }

    /// Collect this ghost's current monthly fee into the community pool.
    ///
    /// The fee is computed by [`GhostAccount::monthly_fee_cents`] and
    /// deposited automatically — per spec, ghost-tier escalation fees
    /// fund the community pool (NFT fee/gas waivers). Returns the fee
    /// collected in cents. `None` on arithmetic overflow: fail closed,
    /// nothing is deposited.
    pub fn pay_monthly_fee(self, pool: &mut CommunityPool, now: u64) -> Option<u32> {
        let fee = self.monthly_fee_cents(now)?;
        pool.deposit(u64::from(fee));
        Some(fee)
    }
}

// ---------------------------------------------------------------------------
// Community pool: ghost fees fund NFT fee/gas waivers
// ---------------------------------------------------------------------------

/// Errors from community-pool operations.
///
/// Fail closed: the pool never overdrafts and never wraps around.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommunityPoolError {
    /// Withdrawal/waiver exceeds the pool balance: denied, untouched.
    InsufficientFunds,
}

impl core::fmt::Display for CommunityPoolError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            CommunityPoolError::InsufficientFunds => {
                "community pool: insufficient funds"
            }
        };
        f.write_str(s)
    }
}

impl std::error::Error for CommunityPoolError {}

/// The community pool: every ghost-tier escalation fee flows here, and
/// it funds NFT fee/gas waivers for viewers.
///
/// Balance is tracked in cents (the smallest currency unit). All math
/// saturates — deposits can never wrap around — and withdrawals fail
/// closed on insufficient funds, so the pool can never go negative.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CommunityPool {
    balance_cents: u64,
}

impl CommunityPool {
    /// An empty pool.
    pub fn new() -> Self {
        Self::default()
    }

    /// Current balance in cents.
    pub fn balance_cents(self) -> u64 {
        self.balance_cents
    }

    /// Deposit community revenue (ghost fees, per
    /// [`GhostAccount::pay_monthly_fee`]). Saturates at `u64::MAX`.
    pub fn deposit(&mut self, amount_cents: u64) {
        self.balance_cents = self.balance_cents.saturating_add(amount_cents);
    }

    /// Withdraw `amount_cents` to cover an NFT fee/gas waiver.
    ///
    /// Fails closed with [`CommunityPoolError::InsufficientFunds`] when
    /// the pool cannot cover it; the balance is left untouched.
    pub fn withdraw(&mut self, amount_cents: u64) -> Result<(), CommunityPoolError> {
        if amount_cents > self.balance_cents {
            return Err(CommunityPoolError::InsufficientFunds);
        }
        self.balance_cents -= amount_cents;
        Ok(())
    }

    /// Attempt an NFT fee/gas waiver of `fee_cents`.
    ///
    /// Returns `true` and deducts the fee when the pool covers it;
    /// returns `false` and leaves the pool untouched when it does not.
    /// This is the check-and-deduct entry point for waiver grants.
    pub fn try_waiver(&mut self, fee_cents: u64) -> bool {
        self.withdraw(fee_cents).is_ok()
    }
}

// ---------------------------------------------------------------------------
// Receipt bridge: subscriptions <-> signed entitlements
// ---------------------------------------------------------------------------

/// Issue a signed entitlement receipt for a subscription.
///
/// Issuer-side only: `issuer_seed` must never leave the signing
/// environment. The receipt's tier and validity window are the
/// subscription's own — the signature is what makes them trustworthy
/// on-device (see [`entitlement`]).
pub fn issue_subscription_receipt(
    issuer_seed: &[u8; 32],
    sub: &Subscription,
) -> Result<Vec<u8>, EntitlementError> {
    entitlement::issue(issuer_seed, sub.tier, sub.started_at, sub.expires_at)
}

/// Verify a receipt's provenance and check it against injected time
/// `now` (not the system clock).
///
/// Returns the granted [`Tier`] only when the signature is genuine AND
/// `now < expires_at`. This is the deterministic, testable sibling of
/// [`entitlement::verify_and_check`], which reads the system clock.
pub fn receipt_active_at(
    issuer_pubkey: &[u8; 32],
    receipt: &[u8],
    now: u64,
) -> Result<Tier, EntitlementError> {
    let ent = entitlement::verify_receipt(issuer_pubkey, receipt)?;
    if now >= ent.expires_at() {
        return Err(EntitlementError::Expired);
    }
    Ok(ent.tier())
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

    // ---- Subscription lifecycle ----

    fn monthly_sub(now: u64) -> Subscription {
        Subscription::new(Tier::Monthly, Some(PaidTier::Tier2), now, now + MONTH_SECS, true)
            .expect("valid subscription")
    }

    #[test]
    fn subscription_new_rejects_bad_window() {
        let now = 1_700_000_000;
        assert_eq!(
            Subscription::new(Tier::Monthly, Some(PaidTier::Tier1), now, now, true),
            Err(SubscriptionError::BadWindow)
        );
        assert_eq!(
            Subscription::new(Tier::Monthly, Some(PaidTier::Tier1), now + 1, now, true),
            Err(SubscriptionError::BadWindow)
        );
    }

    #[test]
    fn subscription_new_rejects_incoherent_tier_price() {
        let now = 1_700_000_000;
        // Paid billing tier without a price tier: rejected.
        assert_eq!(
            Subscription::new(Tier::Monthly, None, now, now + MONTH_SECS, true),
            Err(SubscriptionError::MissingPriceTier)
        );
        assert_eq!(
            Subscription::new(Tier::Yearly, None, now, now + YEAR_SECS, false),
            Err(SubscriptionError::MissingPriceTier)
        );
        // Price tier on a non-billable tier: rejected.
        assert_eq!(
            Subscription::new(Tier::Free, Some(PaidTier::Tier1), now, now + 86_400, false),
            Err(SubscriptionError::UnexpectedPriceTier)
        );
        assert_eq!(
            Subscription::new(Tier::Founding, Some(PaidTier::Tier3), now, now + 86_400, false),
            Err(SubscriptionError::UnexpectedPriceTier)
        );
        // Coherent combos accepted.
        assert!(Subscription::new(Tier::Free, None, now, now + 86_400, false).is_ok());
        assert!(Subscription::new(Tier::Founding, None, now, now + 86_400, false).is_ok());
    }

    #[test]
    fn subscription_expiry_enforced() {
        let now = 1_700_000_000;
        let sub = monthly_sub(now);
        assert!(sub.is_active(now));
        assert!(sub.is_active(now + MONTH_SECS - 1));
        // At exactly expires_at the subscription is dead.
        assert!(!sub.is_active(now + MONTH_SECS));
        assert_eq!(sub.status(now + MONTH_SECS), SubscriptionStatus::Expired);
    }

    #[test]
    fn subscription_lapse_when_no_auto_renew() {
        let now = 1_700_000_000;
        let sub = Subscription::new(
            Tier::Yearly,
            Some(PaidTier::Tier1),
            now,
            now + YEAR_SECS,
            false, // no auto-renew
        )
        .expect("valid subscription");
        assert_eq!(sub.status(now), SubscriptionStatus::Active);
        assert_eq!(
            sub.status(now + YEAR_SECS),
            SubscriptionStatus::Lapsed
        );
    }

    #[test]
    fn subscription_renew_extends_from_expiry_when_early() {
        let now = 1_700_000_000;
        let mut sub = monthly_sub(now);
        // Renew 10 days in: the remaining 20 days are kept.
        sub.renew(now + 10 * 86_400, MONTH_SECS);
        assert_eq!(sub.expires_at(), now + 2 * MONTH_SECS);
    }

    #[test]
    fn subscription_renew_restarts_from_now_when_late() {
        let now = 1_700_000_000;
        let mut sub = monthly_sub(now);
        // Renew 5 days after expiry: starts from now, not the old expiry.
        sub.renew(now + MONTH_SECS + 5 * 86_400, MONTH_SECS);
        assert_eq!(sub.expires_at(), now + MONTH_SECS + 5 * 86_400 + MONTH_SECS);
        assert!(sub.is_active(now + MONTH_SECS + 5 * 86_400));
    }

    #[test]
    fn subscription_renew_period_uses_billing_cycle() {
        let now = 1_700_000_000;
        let mut sub = monthly_sub(now);
        sub.renew_period(now);
        assert_eq!(sub.expires_at(), now + 2 * MONTH_SECS);

        let mut yearly = Subscription::new(
            Tier::Yearly,
            Some(PaidTier::Tier3),
            now,
            now + YEAR_SECS,
            true,
        )
        .expect("valid subscription");
        yearly.renew_period(now);
        assert_eq!(yearly.expires_at(), now + 2 * YEAR_SECS);
    }

    #[test]
    fn subscription_cancel_blocks_renewal() {
        let now = 1_700_000_000;
        let mut sub = monthly_sub(now);
        sub.cancel();
        // Cancelled wins even while paid through.
        assert_eq!(sub.status(now), SubscriptionStatus::Cancelled);
        assert!(!sub.is_active(now));
        // Renewing after cancel clears the cancellation.
        sub.renew(now, MONTH_SECS);
        assert_eq!(sub.status(now), SubscriptionStatus::Active);
    }

    #[test]
    fn subscription_period_price_cents() {
        let now = 1_700_000_000;
        let monthly = monthly_sub(now); // Tier2 monthly = $25
        assert_eq!(monthly.period_price_cents(), Some(2500));
        let yearly = Subscription::new(
            Tier::Yearly,
            Some(PaidTier::Tier1),
            now,
            now + YEAR_SECS,
            true,
        )
        .expect("valid subscription");
        assert_eq!(yearly.period_price_cents(), Some(10000)); // $100
        let free =
            Subscription::new(Tier::Free, None, now, now + 86_400, false).expect("valid");
        assert_eq!(free.period_price_cents(), None);
    }

    // ---- Ghost escalation ----

    #[test]
    fn ghost_grace_period_is_free() {
        let ghost = GhostAccount::new(1_700_000_000);
        let start = ghost.ghost_since();
        assert_eq!(ghost.days_as_ghost(start), 0);
        assert_eq!(ghost.monthly_fee_cents(start), Some(0));
        // Day 29: still free.
        assert_eq!(ghost.monthly_fee_cents(start + 29 * 86_400), Some(0));
    }

    #[test]
    fn ghost_escalation_math() {
        let ghost = GhostAccount::new(1_700_000_000);
        let start = ghost.ghost_since();
        // Day 30: first billing month begins -> $5.
        assert_eq!(ghost.monthly_fee_cents(start + 30 * 86_400), Some(500));
        // Day 59: still month 1.
        assert_eq!(ghost.monthly_fee_cents(start + 59 * 86_400), Some(500));
        // Day 60: month 2 -> $10.
        assert_eq!(ghost.monthly_fee_cents(start + 60 * 86_400), Some(1000));
        // Day 90: month 3 -> $15 (+$5 each month after).
        assert_eq!(ghost.monthly_fee_cents(start + 90 * 86_400), Some(1500));
        // Day 120: month 4 -> $20.
        assert_eq!(ghost.monthly_fee_cents(start + 120 * 86_400), Some(2000));
        // One year as ghost: 335 paid days -> billing month 12 -> $60.
        assert_eq!(
            ghost.monthly_fee_cents(start + 365 * 86_400),
            Some(6000)
        );
    }

    #[test]
    fn ghost_fee_before_start_is_zero() {
        // now before ghost_since: saturates, treated as day 0.
        let ghost = GhostAccount::new(1_700_000_000);
        assert_eq!(ghost.days_as_ghost(1_699_999_999), 0);
        assert_eq!(ghost.monthly_fee_cents(1_699_999_999), Some(0));
    }

    // ---- Community pool ----

    #[test]
    fn community_pool_deposits_accumulate() {
        let mut pool = CommunityPool::new();
        assert_eq!(pool.balance_cents(), 0);
        pool.deposit(500); // $5 ghost month 1
        pool.deposit(1000); // $10 ghost month 2
        assert_eq!(pool.balance_cents(), 1500);
    }

    #[test]
    fn community_pool_waiver_deducts_when_covered() {
        let mut pool = CommunityPool::new();
        pool.deposit(2000);
        assert!(pool.try_waiver(500)); // $5 NFT gas waiver
        assert_eq!(pool.balance_cents(), 1500);
        assert!(pool.try_waiver(1500)); // exact-balance waiver
        assert_eq!(pool.balance_cents(), 0);
    }

    #[test]
    fn community_pool_waiver_fails_closed_when_short() {
        let mut pool = CommunityPool::new();
        // Empty pool: denied, balance untouched.
        assert!(!pool.try_waiver(500));
        assert_eq!(pool.balance_cents(), 0);
        // Partial coverage: denied, balance untouched.
        pool.deposit(300);
        assert!(!pool.try_waiver(500));
        assert_eq!(pool.balance_cents(), 300);
        // withdraw() reports the failure explicitly.
        assert_eq!(
            pool.withdraw(500),
            Err(CommunityPoolError::InsufficientFunds)
        );
        assert_eq!(pool.balance_cents(), 300);
    }

    #[test]
    fn community_pool_withdraw_exact_balance_ok() {
        let mut pool = CommunityPool::new();
        pool.deposit(500);
        assert_eq!(pool.withdraw(500), Ok(()));
        assert_eq!(pool.balance_cents(), 0);
        // Zero-amount operations are no-ops, never errors.
        assert_eq!(pool.withdraw(0), Ok(()));
        assert!(pool.try_waiver(0));
    }

    #[test]
    fn community_pool_saturates_never_overflows() {
        let mut pool = CommunityPool::new();
        pool.deposit(u64::MAX);
        assert_eq!(pool.balance_cents(), u64::MAX);
        pool.deposit(1); // must saturate, not wrap to 0
        assert_eq!(pool.balance_cents(), u64::MAX);
        pool.deposit(u64::MAX);
        assert_eq!(pool.balance_cents(), u64::MAX);
    }

    #[test]
    fn ghost_fee_collection_feeds_pool() {
        let mut pool = CommunityPool::new();
        let ghost = GhostAccount::new(1_700_000_000);
        let start = ghost.ghost_since();
        // Day 90: month 3 -> $15 collected into the pool.
        assert_eq!(
            ghost.pay_monthly_fee(&mut pool, start + 90 * 86_400),
            Some(1500)
        );
        assert_eq!(pool.balance_cents(), 1500);
        // Day 120: month 4 -> $20 more; pool accumulates.
        assert_eq!(
            ghost.pay_monthly_fee(&mut pool, start + 120 * 86_400),
            Some(2000)
        );
        assert_eq!(pool.balance_cents(), 3500);
    }

    #[test]
    fn ghost_grace_collects_nothing() {
        let mut pool = CommunityPool::new();
        let ghost = GhostAccount::new(1_700_000_000);
        // Day 10: grace period, fee is $0 -> pool stays empty.
        assert_eq!(
            ghost.pay_monthly_fee(&mut pool, ghost.ghost_since() + 10 * 86_400),
            Some(0)
        );
        assert_eq!(pool.balance_cents(), 0);
    }

    #[test]
    fn community_pool_waiver_uses_ghost_fees() {
        // End-to-end: ghost pays in, viewer gets an NFT fee waiver out.
        let mut pool = CommunityPool::new();
        let ghost = GhostAccount::new(1_700_000_000);
        let start = ghost.ghost_since();
        ghost
            .pay_monthly_fee(&mut pool, start + 60 * 86_400)
            .expect("collect month 2: $10");
        ghost
            .pay_monthly_fee(&mut pool, start + 90 * 86_400)
            .expect("collect month 3: $15");
        assert_eq!(pool.balance_cents(), 2500); // $25 total
        // A $20 NFT gas waiver is covered.
        assert!(pool.try_waiver(2000));
        assert_eq!(pool.balance_cents(), 500);
        // A second $20 waiver is not.
        assert!(!pool.try_waiver(2000));
        assert_eq!(pool.balance_cents(), 500);
    }

    #[test]
    fn community_pool_error_display_is_stable() {
        assert!(!format!("{}", CommunityPoolError::InsufficientFunds).is_empty());
        assert_eq!(
            format!("{}", CommunityPoolError::InsufficientFunds),
            "community pool: insufficient funds"
        );
    }

    // ---- Receipt bridge ----

    /// Fixed issuer seed for tests only — never a real key.
    const BILLING_ISSUER_SEED: [u8; 32] = *b"billing-issuer-seed0000000000000";
    const BILLING_OTHER_SEED: [u8; 32] = *b"billing-attacker-seed00000000000";

    fn billing_pubkey() -> [u8; 32] {
        let (_, public) = trv_core::crypto::ed25519::generate(&BILLING_ISSUER_SEED);
        *public.as_bytes()
    }

    #[test]
    fn subscription_receipt_round_trip() {
        let now = 1_700_000_000;
        let sub = monthly_sub(now);
        let receipt = issue_subscription_receipt(&BILLING_ISSUER_SEED, &sub)
            .expect("issuance");
        let tier = receipt_active_at(&billing_pubkey(), &receipt, now).expect("active");
        assert_eq!(tier, Tier::Monthly);
    }

    #[test]
    fn subscription_receipt_expiry_enforced_at_injected_time() {
        let now = 1_700_000_000;
        let sub = monthly_sub(now);
        let receipt = issue_subscription_receipt(&BILLING_ISSUER_SEED, &sub)
            .expect("issuance");
        // One second before expiry: active.
        assert!(receipt_active_at(&billing_pubkey(), &receipt, now + MONTH_SECS - 1).is_ok());
        // At expiry with injected time: dead — even though the receipt is genuine.
        assert_eq!(
            receipt_active_at(&billing_pubkey(), &receipt, now + MONTH_SECS),
            Err(EntitlementError::Expired)
        );
    }

    #[test]
    fn subscription_receipt_tampered_rejected() {
        let now = 1_700_000_000;
        let sub = monthly_sub(now);
        let mut receipt = issue_subscription_receipt(&BILLING_ISSUER_SEED, &sub)
            .expect("issuance");
        // Flip the tier byte to a different *valid* tier: decode passes,
        // but the signature no longer matches.
        receipt[5] = 2; // Tier::Yearly discriminant (was Monthly = 1)
        assert_eq!(
            receipt_active_at(&billing_pubkey(), &receipt, now),
            Err(EntitlementError::BadSignature)
        );
    }

    #[test]
    fn subscription_receipt_forged_rejected() {
        // Signed by a different issuer key: provenance fails.
        let now = 1_700_000_000;
        let sub = monthly_sub(now);
        let forged = issue_subscription_receipt(&BILLING_OTHER_SEED, &sub)
            .expect("forged issuance");
        assert_eq!(
            receipt_active_at(&billing_pubkey(), &forged, now),
            Err(EntitlementError::BadSignature)
        );
    }

    #[test]
    fn subscription_error_display_is_stable() {
        assert!(!format!("{}", SubscriptionError::BadWindow).is_empty());
        assert!(!format!("{}", SubscriptionError::MissingPriceTier).is_empty());
        assert!(!format!("{}", SubscriptionError::UnexpectedPriceTier).is_empty());
    }
}
