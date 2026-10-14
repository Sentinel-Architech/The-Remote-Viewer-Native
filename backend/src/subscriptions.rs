//! Tier / entitlement / verification logic.
//!
//! Verified locally on-device. No billing network calls here —
//! Solana is the separate track, only for TRV token/governance.

use crate::entitlement;
use crate::entitlement::Entitlement;
use crate::entitlement::EntitlementError;
use std::path::Path;

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

/// Upper bound on billable ghost months in one settlement. A caller
/// passing an absurd `now` (e.g. `u64::MAX`) must not hang the billing
/// tick in a near-infinite loop: beyond 100 years the settlement fails
/// closed and the operator must intervene.
const GHOST_MAX_BILLABLE_MONTHS: u64 = 1_200;

/// Enforceable ghost-fee ledger: the single choke point through which
/// ghost escalation is actually collected.
///
/// [`GhostAccount`] computes the fee schedule, but nothing in the app
/// called [`GhostAccount::pay_monthly_fee`] outside tests — escalation
/// was computed but never collected. This ledger closes that gap:
/// it tracks how many billing months have been collected and
/// [`GhostLedger::settle`] collects every uncollected month through
/// `now`, depositing each fee into the community pool.
///
/// Caller contract (the app's billing tick, e.g. on start and daily):
/// persist the ledger, call `settle` with the current time, persist
/// again. `settle` is idempotent — calling it twice for the same `now`
/// collects nothing the second time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GhostLedger {
    ghost: GhostAccount,
    /// Billing months already collected (1-based count).
    months_collected: u64,
}

impl GhostLedger {
    /// Start tracking a ghost account; nothing collected yet.
    pub fn new(ghost_since: u64) -> Self {
        GhostLedger {
            ghost: GhostAccount::new(ghost_since),
            months_collected: 0,
        }
    }

    /// The underlying ghost account.
    pub fn ghost(self) -> GhostAccount {
        self.ghost
    }

    /// Billing months already collected.
    pub fn months_collected(self) -> u64 {
        self.months_collected
    }

    /// Billing months elapsed through `now` (0 during the grace period).
    fn months_elapsed(self, now: u64) -> Option<u64> {
        let days = self.ghost.days_as_ghost(now);
        if days < GHOST_GRACE_DAYS {
            return Some(0);
        }
        let months = (days - GHOST_GRACE_DAYS) / 30 + 1;
        if months > GHOST_MAX_BILLABLE_MONTHS {
            return None;
        }
        Some(months)
    }

    /// Collect every uncollected billing month through `now` into the
    /// community pool. Returns the total cents collected (0 when
    /// nothing was due). Idempotent: re-settling the same period
    /// collects nothing.
    ///
    /// Fail-closed: on any arithmetic overflow nothing is deposited and
    /// `months_collected` is left unchanged — the caller must retry
    /// later, never bill a partial amount.
    pub fn settle(&mut self, pool: &mut CommunityPool, now: u64) -> Option<u64> {
        let elapsed = self.months_elapsed(now)?;
        if elapsed <= self.months_collected {
            return Some(0);
        }
        // Compute the whole batch first; deposit only when every fee is
        // known-good, so a late overflow never leaves a partial charge.
        let mut total: u64 = 0;
        let mut month = self.months_collected + 1;
        while month <= elapsed {
            let fee = u64::from(GHOST_FEE_STEP_CENTS)
                .checked_mul(month)
                .and_then(|f| u32::try_from(f).ok())
                .map(u64::from)?;
            total = total.checked_add(fee)?;
            month += 1;
        }
        pool.deposit(total);
        self.months_collected = elapsed;
        Some(total)
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

// ---------------------------------------------------------------------------
// Billing tick: the scheduled job that actually collects ghost fees
// ---------------------------------------------------------------------------

/// Grace period after a paid subscription expires before ghost
/// escalation begins: 3 days. During grace the viewer keeps full
/// access and sees a renewal warning; no ghost fees accrue.
pub const SUBSCRIPTION_GRACE_DAYS: u64 = 3;
/// Seconds in the subscription grace period.
pub const SUBSCRIPTION_GRACE_SECS: u64 = SUBSCRIPTION_GRACE_DAYS * 86_400;
/// Minimum interval between daily billing ticks: 20 hours. A tick
/// requested sooner is a no-op, so a crash-loop or double scheduler
/// can never double-bill.
pub const DAILY_TICK_MIN_SECS: u64 = 20 * 3_600;

/// What a billing tick did.
///
/// `ran` is false when the daily tick was skipped as too soon —
///
/// everything else is zero in that case. `total_cents` is `None`
/// only when settlement itself failed (fail closed); the pool is
/// untouched then.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TickOutcome {
    /// Whether the tick executed settlement (false = skipped as too soon).
    pub ran: bool,
    /// Billing months collected by this tick.
    pub months_collected: u64,
    /// Total cents collected by this tick.
    pub total_cents: u64,
    /// Pool balance in cents after the tick.
    pub pool_balance_cents: u64,
}

/// The billing tick: the app's scheduled job that turns ghost
/// escalation from math into money.
///
/// Caller contract (this is THE enforcement point the paywall audit
/// asked for):
///
/// 1. On app startup, load the persisted [`GhostLedger`] (see
///    [`GhostLedger::load`]), call
///    [`BillingTick::tick_at_startup`], then
///    [`GhostLedger::save`] the ledger — even when nothing was due,
///    so a fresh install's ledger is durable from day one.
/// 2. Once per day (alarm, job scheduler, or a foreground check),
///    call [`BillingTick::tick_daily`] with the last-run timestamp;
///    it no-ops when under 20 hours have passed.
/// 3. The ledger file lives at `<app_data_dir>/ghost_ledger.trvl`.
///    It holds no secrets (timestamps and month counts only), so it
///    is not encrypted — but a corrupt file fails closed and the app
///    must surface the error, never silently reset billing.
///
/// No real payment processing happens here: ghost fees are internal
/// ledger movements into the [`CommunityPool`]. Actual money movement
/// is out of scope for this module.
pub struct BillingTick;

impl BillingTick {
    /// Run the billing tick at app startup: settle every uncollected
    /// ghost month through `now` into the pool.
    ///
    /// Idempotent: running twice for the same `now` collects nothing
    /// the second time. Returns `None` when settlement fails closed
    /// (overflow) — the pool and ledger are untouched; the app must
    /// retry later.
    pub fn tick_at_startup(
        ledger: &mut GhostLedger,
        pool: &mut CommunityPool,
        now: u64,
    ) -> Option<TickOutcome> {
        let before = ledger.months_collected();
        let total = ledger.settle(pool, now)?;
        Some(TickOutcome {
            ran: true,
            months_collected: ledger.months_collected() - before,
            total_cents: total,
            pool_balance_cents: pool.balance_cents(),
        })
    }

    /// Run the daily billing tick. When fewer than
    /// [`DAILY_TICK_MIN_SECS`] have passed since `last_run`, this is a
    /// no-op returning `ran: false` — the pool and ledger are untouched.
    /// Otherwise it behaves exactly like
    /// [`BillingTick::tick_at_startup`].
    ///
    /// `last_run = 0` (never ran) always executes. Clock skew where
    /// `now < last_run` saturates to 0 elapsed and no-ops, fail closed.
    pub fn tick_daily(
        ledger: &mut GhostLedger,
        pool: &mut CommunityPool,
        now: u64,
        last_run: u64,
    ) -> Option<TickOutcome> {
        if now.saturating_sub(last_run) < DAILY_TICK_MIN_SECS {
            return Some(TickOutcome {
                ran: false,
                months_collected: 0,
                total_cents: 0,
                pool_balance_cents: pool.balance_cents(),
            });
        }
        Self::tick_at_startup(ledger, pool, now)
    }
}

// ---------------------------------------------------------------------------
// Ghost ledger persistence
// ---------------------------------------------------------------------------

/// Magic bytes for the ledger file.
const LEDGER_MAGIC: &[u8; 4] = b"TRVG";
/// Ledger file format version.
const LEDGER_VERSION: u8 = 1;
/// Exact file length: magic(4) + version(1) + ghost_since(8) + months_collected(8).
const LEDGER_FILE_LEN: usize = 21;

/// Errors from ghost-ledger persistence.
///
/// Fail closed: a corrupt ledger never silently resets someone's
/// billing — the app must surface the error and the operator must
/// intervene.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LedgerError {
    /// Filesystem failure (read, stage, or rename).
    Io(String),
    /// Bad magic or wrong length: not a ledger file, or torn.
    Corrupt(String),
    /// Version byte is not one this build understands.
    UnsupportedVersion(u8),
}

impl core::fmt::Display for LedgerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            LedgerError::Io(e) => write!(f, "ghost ledger io: {e}"),
            LedgerError::Corrupt(e) => write!(f, "ghost ledger corrupt: {e}"),
            LedgerError::UnsupportedVersion(v) => {
                write!(f, "ghost ledger: unsupported version {v}")
            }
        }
    }
}

impl std::error::Error for LedgerError {}

/// Atomic temp-file write for the ledger: stage next to the target,
/// fsync, rename over it. Same pattern as the profile vault's
/// `atomic_write`, kept local so this module stays self-contained.
/// On any failure the temp is removed and the old ledger is untouched.
fn atomic_write_ledger(path: &Path, bytes: &[u8]) -> Result<(), LedgerError> {
    let mut tmp_name = path
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_default();
    tmp_name.push(".tmp");
    let tmp = path.with_file_name(tmp_name);
    let staged = (|| -> std::io::Result<()> {
        std::fs::write(&tmp, bytes)?;
        std::fs::File::open(&tmp)?.sync_all()?;
        Ok(())
    })();
    if let Err(e) = staged {
        let _ = std::fs::remove_file(&tmp);
        return Err(LedgerError::Io(format!("ledger stage failed: {e}")));
    }
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        LedgerError::Io(format!("ledger commit failed: {e}"))
    })
}

impl GhostLedger {
    /// Persist the ledger to `path` atomically.
    ///
    /// The file holds NO secrets — only the ghost-start timestamp and
    /// collected-month count — so it is deliberately not encrypted.
    /// What it holds is billing truth, so writes are atomic: readers
    /// see the complete old ledger or the complete new one, never a
    /// torn write.
    pub fn save(&self, path: &Path) -> Result<(), LedgerError> {
        let mut buf = Vec::with_capacity(LEDGER_FILE_LEN);
        buf.extend_from_slice(LEDGER_MAGIC);
        buf.push(LEDGER_VERSION);
        buf.extend_from_slice(&self.ghost.ghost_since().to_be_bytes());
        buf.extend_from_slice(&self.months_collected.to_be_bytes());
        atomic_write_ledger(path, &buf)
    }

    /// Load a persisted ledger. Fails closed on missing file
    /// ([`LedgerError::Io`]), bad magic or length
    /// ([`LedgerError::Corrupt`]), and unknown versions
    /// ([`LedgerError::UnsupportedVersion`]) — never a silent reset.
    pub fn load(path: &Path) -> Result<Self, LedgerError> {
        let bytes = std::fs::read(path)
            .map_err(|e| LedgerError::Io(format!("ledger read failed: {e}")))?;
        if bytes.len() != LEDGER_FILE_LEN {
            return Err(LedgerError::Corrupt(format!(
                "expected {LEDGER_FILE_LEN} bytes, got {}",
                bytes.len()
            )));
        }
        if &bytes[0..4] != LEDGER_MAGIC {
            return Err(LedgerError::Corrupt("bad magic".to_string()));
        }
        if bytes[4] != LEDGER_VERSION {
            return Err(LedgerError::UnsupportedVersion(bytes[4]));
        }
        let mut gs = [0u8; 8];
        gs.copy_from_slice(&bytes[5..13]);
        let mut mc = [0u8; 8];
        mc.copy_from_slice(&bytes[13..21]);
        Ok(GhostLedger {
            ghost: GhostAccount::new(u64::from_be_bytes(gs)),
            months_collected: u64::from_be_bytes(mc),
        })
    }
}

// ---------------------------------------------------------------------------
// Viewer-facing subscription status
// ---------------------------------------------------------------------------

/// What the UI shows for "your subscription".
///
/// This is the viewer-facing view; [`SubscriptionStatus`] remains the
/// internal lifecycle enum. Name differs on purpose: the old name was
/// taken and this one carries billing detail (tier, grace days, ghost
/// fees) the UI needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewerStatus {
    /// Paid and valid: full access until `expires_at`.
    Active {
        /// Granted tier.
        tier: Tier,
        /// Unix seconds the entitlement lapses.
        expires_at: u64,
    },
    /// Subscription expired within the last [`SUBSCRIPTION_GRACE_DAYS`]
    /// days: features still work, the UI must show a renewal warning.
    GracePeriod {
        /// Whole days of grace remaining.
        days_left: u64,
    },
    /// Past grace with no valid entitlement: ghost escalation applies.
    Ghost {
        /// Billing months elapsed but not yet collected.
        months_unpaid: u64,
        /// Fee in cents for the next uncollected month (0 when none due).
        next_fee_cents: u32,
    },
    /// No valid entitlement and no ghost billing relationship: dormant.
    /// The viewer must purchase or verify to get going; nothing is billed.
    Lapsed,
}

/// Compute the viewer-facing status from an entitlement (or `None`
/// for a viewer who never paid) and the ghost ledger.
///
/// Ghost-clock contract: for a never-paid viewer the ledger's
/// `ghost_since` is account creation. For an expired paid viewer the
/// app must track ghost billing with a ledger whose `ghost_since` is
/// `expires_at + SUBSCRIPTION_GRACE_SECS` — i.e. the ghost clock
/// starts when the 3-day grace ends, not at expiry.
///
/// Pass `ledger: None` when no ghost billing relationship exists for
/// this viewer; an expired entitlement with no ledger reports
/// [`ViewerStatus::Lapsed`] instead of [`ViewerStatus::Ghost`].
pub fn viewer_status(
    ent: Option<Entitlement>,
    ledger: Option<&GhostLedger>,
    now: u64,
) -> ViewerStatus {
    match ent {
        Some(e) if now < e.expires_at() => ViewerStatus::Active {
            tier: e.tier(),
            expires_at: e.expires_at(),
        },
        Some(e) => {
            let days_over = now.saturating_sub(e.expires_at()) / 86_400;
            if days_over < SUBSCRIPTION_GRACE_DAYS {
                return ViewerStatus::GracePeriod {
                    days_left: SUBSCRIPTION_GRACE_DAYS - days_over,
                };
            }
            match ledger {
                Some(l) => ghost_status(l, now),
                None => ViewerStatus::Lapsed,
            }
        }
        None => match ledger {
            Some(l) => ghost_status(l, now),
            None => ViewerStatus::Lapsed,
        },
    }
}

/// Ghost status from a ledger: months elapsed but uncollected, and
/// the fee due for the next uncollected month.
fn ghost_status(ledger: &GhostLedger, now: u64) -> ViewerStatus {
    // months_elapsed is private to this module — same file, so callable.
    let elapsed = ledger.months_elapsed(now).unwrap_or(0);
    let collected = ledger.months_collected();
    let months_unpaid = elapsed.saturating_sub(collected);
    let next_fee_cents = if months_unpaid == 0 {
        0
    } else {
        // months_collected is capped at GHOST_MAX_BILLABLE_MONTHS by
        // settle(), so this cannot overflow in practice; the fallback
        // is fail-closed toward "no fee shown" rather than a wrong fee.
        u64::from(GHOST_FEE_STEP_CENTS)
            .checked_mul(collected.saturating_add(1))
            .and_then(|f| u32::try_from(f).ok())
            .unwrap_or(0)
    };
    ViewerStatus::Ghost {
        months_unpaid,
        next_fee_cents,
    }
}

// ---------------------------------------------------------------------------
// First-month 50% discount for new Remote Viewers
// ---------------------------------------------------------------------------

/// First-month discount percent for new Remote Viewers (user rule
/// 2026-10-14): **50% off the first month on every paid tier**
/// (Tier 1/2/3), for the viewer's first purchase only. Renewals are
/// full price.
pub const FIRST_MONTH_DISCOUNT_PERCENT: u32 = 50;

/// Apply `percent_off` (0..=100) to a cent price with buyer-friendly
/// rounding: the DISCOUNT amount rounds half-up, so a fractional cent
/// of discount always lands in the buyer's favor (the price rounds
/// down). Integer math only — no float money math.
fn apply_percent_off_buyer_friendly(price_cents: u32, percent_off: u32) -> u32 {
    let pct = percent_off.min(100);
    let price = u64::from(price_cents);
    // Discount rounds half-up: (price * pct + 50) / 100.
    let discount = (price * u64::from(pct) + 50) / 100;
    price_cents.saturating_sub(discount as u32)
}

impl PaidTier {
    /// First-month price for a MONTHLY purchase by a new viewer: 50%
    /// off the standard monthly price
    /// ([`FIRST_MONTH_DISCOUNT_PERCENT`]), buyer-friendly rounding.
    ///
    /// Tier 1: $10.00 -> $5.00; Tier 2: $25.00 -> $12.50; Tier 3:
    /// $45.00 -> $22.50. Renewals after the first month are full
    /// price.
    pub fn first_month_monthly_cents(self) -> u32 {
        apply_percent_off_buyer_friendly(self.monthly_cents(), FIRST_MONTH_DISCOUNT_PERCENT)
    }
}

/// Price in cents the viewer pays NOW for a subscription purchase.
///
/// - `billing` must be [`Tier::Monthly`] or [`Tier::Yearly`];
///   [`Tier::Free`] and [`Tier::Founding`] are not purchases and
///   return `None`.
/// - First purchase (`is_first_purchase == true`): 50% off the first
///   month ([`FIRST_MONTH_DISCOUNT_PERCENT`]). Monthly billing charges
///   the discounted month; yearly billing charges the yearly price
///   minus 50% of one prorated month (`yearly / 12`).
/// - Renewal (`is_first_purchase == false`): the full period price.
///   Yearly renewals still honor the single-best yearly discount
///   ([`PaidTier::best_yearly_price_cents`]).
/// - Ghost escalation fees are a separate track and are NEVER
///   discounted by this function.
///
/// The caller decides `is_first_purchase` from
/// [`FirstMonthLedger::claim_first_month`]: it returns `true` (and
/// records the claim) only for an identity that has never claimed.
///
/// STACKING — undecided, documented (2026-10-14): the 50%
/// first-month discount and the yearly discounts (20% category /
/// 17.67% citizen) overlap on a first YEARLY purchase. This
/// implementation applies the existing non-stacking yearly rule
/// FIRST ([`PaidTier::best_yearly_price_cents`], largest single
/// discount wins), then takes 50% off the prorated first month of
/// that discounted total. The user has not decided whether these
/// should combine differently; until they do, no other combination
/// is applied.
///
/// Monthly category discounts are also unpriced: [`DiscountCategory`]
/// flags monthly eligibility, but no monthly category price exists,
/// so the 50% first-month applies to the standard monthly price.
/// Whether a future monthly category price would stack is likewise
/// undecided.
pub fn purchase_price_cents(
    paid_tier: PaidTier,
    billing: Tier,
    is_first_purchase: bool,
    category: Option<DiscountCategory>,
    citizen: bool,
) -> Option<u32> {
    match billing {
        Tier::Monthly => {
            let monthly = paid_tier.monthly_cents();
            Some(if is_first_purchase {
                apply_percent_off_buyer_friendly(monthly, FIRST_MONTH_DISCOUNT_PERCENT)
            } else {
                monthly
            })
        }
        Tier::Yearly => {
            let yearly = paid_tier.best_yearly_price_cents(category, citizen);
            if !is_first_purchase {
                return Some(yearly);
            }
            // Prorated one-month share of the (possibly discounted)
            // yearly total, rounded half-up; then 50% off that share,
            // discount rounded half-up (buyer-friendly). The rest of
            // the year is full price.
            let month_share = ((u64::from(yearly) + 6) / 12) as u32;
            let discount =
                ((u64::from(month_share) * u64::from(FIRST_MONTH_DISCOUNT_PERCENT) + 50) / 100)
                    as u32;
            Some(yearly.saturating_sub(discount))
        }
        Tier::Free | Tier::Founding => None,
    }
}

// ---------------------------------------------------------------------------
// First-month discount ledger: one claim per verified identity
// ---------------------------------------------------------------------------

/// Magic bytes for the first-month ledger file.
const FIRST_MONTH_MAGIC: &[u8; 4] = b"TRVD";
/// First-month ledger file format version.
const FIRST_MONTH_VERSION: u8 = 1;
/// Fixed header length: magic(4) + version(1) + claim count(8).
const FIRST_MONTH_HEADER_LEN: usize = 13;
/// One claimed identity public key: 32 bytes.
const FIRST_MONTH_KEY_LEN: usize = 32;

/// Tracks which verified identities already claimed the first-month
/// 50% discount — the anti-abuse choke point.
///
/// Rule (2026-10-14): the discount is claimed ONCE PER VERIFIED
/// IDENTITY, keyed by the identity's Ed25519 public key (32 bytes,
/// e.g. `trv_core::crypto::ed25519::PublicKey::as_bytes()`). The
/// caller MUST pass the key of the verified identity making the
/// purchase — never a device-generated throwaway.
///
/// Burn-and-restart: per the ghost policy a viewer may burn an
/// account and start over. A fresh account carries a fresh keypair,
/// so this ledger alone cannot link the new account to the old one.
/// Full cross-account enforcement needs the verification layer to
/// bind the State ID (or its attestation) to the discount claim and
/// refuse re-claims for an already-used State ID — that binding is
/// future work. What this ledger guarantees: the same verified
/// identity key can never claim twice, and a corrupt ledger fails
/// closed (no discount) instead of silently resetting.
///
/// Persist with [`FirstMonthLedger::save`]; the file holds no secrets
/// (public keys only) so it is not encrypted, but writes are atomic
/// and a corrupt file is an error, never a silent reset.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FirstMonthLedger {
    claimed: std::collections::HashSet<[u8; 32]>,
}

impl FirstMonthLedger {
    /// An empty ledger: no identity has claimed yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether this identity public key already claimed the discount.
    pub fn has_claimed(&self, identity_pubkey: &[u8; 32]) -> bool {
        self.claimed.contains(identity_pubkey)
    }

    /// Attempt to claim the first-month discount for this identity
    /// public key.
    ///
    /// Returns `true` — and records the claim — only when this
    /// identity has never claimed before: the purchase gets the 50%
    /// first-month price. Returns `false` when the identity already
    /// claimed: full price, no discount. The caller feeds the result
    /// into [`purchase_price_cents`] as `is_first_purchase`.
    pub fn claim_first_month(&mut self, identity_pubkey: &[u8; 32]) -> bool {
        self.claimed.insert(*identity_pubkey)
    }

    /// Number of identities that have claimed.
    pub fn claims_count(&self) -> usize {
        self.claimed.len()
    }

    /// Persist the ledger atomically (temp + fsync + rename, same
    /// pattern as [`GhostLedger::save`]).
    pub fn save(&self, path: &Path) -> Result<(), LedgerError> {
        let mut keys: Vec<[u8; 32]> = self.claimed.iter().copied().collect();
        keys.sort_unstable();
        let mut buf = Vec::with_capacity(FIRST_MONTH_HEADER_LEN + keys.len() * FIRST_MONTH_KEY_LEN);
        buf.extend_from_slice(FIRST_MONTH_MAGIC);
        buf.push(FIRST_MONTH_VERSION);
        buf.extend_from_slice(&(keys.len() as u64).to_be_bytes());
        for k in &keys {
            buf.extend_from_slice(k);
        }
        atomic_write_ledger(path, &buf)
    }

    /// Load a persisted ledger. Fails closed on missing file, bad
    /// magic, wrong length, or unknown version — never a silent
    /// reset (a reset would re-grant discounts).
    pub fn load(path: &Path) -> Result<Self, LedgerError> {
        let bytes = std::fs::read(path)
            .map_err(|e| LedgerError::Io(format!("first-month ledger read failed: {e}")))?;
        if bytes.len() < FIRST_MONTH_HEADER_LEN
            || (bytes.len() - FIRST_MONTH_HEADER_LEN) % FIRST_MONTH_KEY_LEN != 0
        {
            return Err(LedgerError::Corrupt(format!(
                "bad length {}: not a whole number of keys",
                bytes.len()
            )));
        }
        if &bytes[0..4] != FIRST_MONTH_MAGIC {
            return Err(LedgerError::Corrupt("bad magic".to_string()));
        }
        if bytes[4] != FIRST_MONTH_VERSION {
            return Err(LedgerError::UnsupportedVersion(bytes[4]));
        }
        let mut count_bytes = [0u8; 8];
        count_bytes.copy_from_slice(&bytes[5..13]);
        let count = u64::from_be_bytes(count_bytes) as usize;
        let keys_in_file = (bytes.len() - FIRST_MONTH_HEADER_LEN) / FIRST_MONTH_KEY_LEN;
        if count != keys_in_file {
            return Err(LedgerError::Corrupt(format!(
                "header claims {count} keys, file holds {keys_in_file}"
            )));
        }
        let mut claimed = std::collections::HashSet::with_capacity(count);
        for i in 0..count {
            let start = FIRST_MONTH_HEADER_LEN + i * FIRST_MONTH_KEY_LEN;
            let mut k = [0u8; 32];
            k.copy_from_slice(&bytes[start..start + FIRST_MONTH_KEY_LEN]);
            claimed.insert(k);
        }
        Ok(FirstMonthLedger { claimed })
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
    fn ghost_ledger_settle_collects_escalation() {
        let start = 1_700_000_000u64;
        let mut pool = CommunityPool::new();
        let mut ledger = GhostLedger::new(start);
        // Day 45: month 1 only -> $5.
        assert_eq!(ledger.settle(&mut pool, start + 45 * 86_400), Some(500));
        assert_eq!(ledger.months_collected(), 1);
        assert_eq!(pool.balance_cents(), 500);
        // Day 75: month 2 now due -> $10 more; month 1 not re-collected.
        assert_eq!(ledger.settle(&mut pool, start + 75 * 86_400), Some(1000));
        assert_eq!(ledger.months_collected(), 2);
        assert_eq!(pool.balance_cents(), 1500);
    }

    #[test]
    fn ghost_ledger_settle_is_idempotent() {
        let start = 1_700_000_000u64;
        let mut pool = CommunityPool::new();
        let mut ledger = GhostLedger::new(start);
        assert_eq!(ledger.settle(&mut pool, start + 45 * 86_400), Some(500));
        // Same period again: nothing new to collect.
        assert_eq!(ledger.settle(&mut pool, start + 50 * 86_400), Some(0));
        assert_eq!(pool.balance_cents(), 500);
        assert_eq!(ledger.months_collected(), 1);
    }

    #[test]
    fn ghost_ledger_grace_period_collects_nothing() {
        let start = 1_700_000_000u64;
        let mut pool = CommunityPool::new();
        let mut ledger = GhostLedger::new(start);
        assert_eq!(ledger.settle(&mut pool, start + 29 * 86_400), Some(0));
        assert_eq!(pool.balance_cents(), 0);
        assert_eq!(ledger.months_collected(), 0);
    }

    #[test]
    fn ghost_ledger_absurd_now_fails_closed() {
        let start = 1_700_000_000u64;
        let mut pool = CommunityPool::new();
        let mut ledger = GhostLedger::new(start);
        // u64::MAX would mean ~1.7M billing months: refuse, don't hang.
        assert_eq!(ledger.settle(&mut pool, u64::MAX), None);
        assert_eq!(pool.balance_cents(), 0);
        assert_eq!(ledger.months_collected(), 0);
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

    // -- Billing tick ----------------------------------------------------

    fn tick_ledger(ghost_since: u64) -> GhostLedger {
        GhostLedger::new(ghost_since)
    }

    #[test]
    fn billing_tick_startup_collects_and_is_idempotent() {
        let now = 1_700_000_000u64;
        // 100 days as ghost: (100-30)/30+1 = 3 billing months.
        let mut ledger = tick_ledger(now - 100 * 86_400);
        let mut pool = CommunityPool::new();
        let first = BillingTick::tick_at_startup(&mut ledger, &mut pool, now)
            .expect("tick");
        assert!(first.ran);
        assert_eq!(first.months_collected, 3);
        assert_eq!(first.total_cents, 500 + 1000 + 1500); // $5, $10, $15
        assert_eq!(first.pool_balance_cents, 3000);
        assert_eq!(ledger.months_collected(), 3);
        // Second tick at the same `now` collects nothing.
        let second = BillingTick::tick_at_startup(&mut ledger, &mut pool, now)
            .expect("tick");
        assert!(second.ran);
        assert_eq!(second.months_collected, 0);
        assert_eq!(second.total_cents, 0);
        assert_eq!(pool.balance_cents(), 3000);
    }

    #[test]
    fn billing_tick_startup_nothing_due_in_grace() {
        let now = 1_700_000_000u64;
        let mut ledger = tick_ledger(now - 10 * 86_400); // 10 days: grace
        let mut pool = CommunityPool::new();
        let outcome = BillingTick::tick_at_startup(&mut ledger, &mut pool, now)
            .expect("tick");
        assert!(outcome.ran);
        assert_eq!(outcome.months_collected, 0);
        assert_eq!(outcome.total_cents, 0);
    }

    #[test]
    fn billing_tick_daily_noop_within_20h() {
        let now = 1_700_000_000u64;
        let mut ledger = tick_ledger(now - 100 * 86_400);
        let mut pool = CommunityPool::new();
        // First daily tick runs (never ran before).
        let first = BillingTick::tick_daily(&mut ledger, &mut pool, now, 0)
            .expect("tick");
        assert!(first.ran);
        assert_eq!(pool.balance_cents(), 3000);
        // 10 hours later: no-op.
        let second =
            BillingTick::tick_daily(&mut ledger, &mut pool, now + 10 * 3600, now)
                .expect("tick");
        assert!(!second.ran);
        assert_eq!(second.months_collected, 0);
        assert_eq!(pool.balance_cents(), 3000);
    }

    #[test]
    fn billing_tick_daily_runs_after_20h() {
        let now = 1_700_000_000u64;
        let mut ledger = tick_ledger(now - 200 * 86_400);
        let mut pool = CommunityPool::new();
        let outcome =
            BillingTick::tick_daily(&mut ledger, &mut pool, now, now - 21 * 3600)
                .expect("tick");
        assert!(outcome.ran);
        assert!(outcome.months_collected > 0);
    }

    #[test]
    fn billing_tick_daily_clock_skew_noop() {
        // now < last_run (clock went backwards): saturates, no-op.
        let now = 1_700_000_000u64;
        let mut ledger = tick_ledger(now - 100 * 86_400);
        let mut pool = CommunityPool::new();
        let outcome =
            BillingTick::tick_daily(&mut ledger, &mut pool, now, now + 3600)
                .expect("tick");
        assert!(!outcome.ran);
        assert_eq!(pool.balance_cents(), 0);
    }

    // -- Ledger persistence ----------------------------------------------

    fn tmp_ledger_path(tag: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "trv-ledger-test-{}-{}.trvl",
            tag,
            std::process::id()
        ));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn ledger_save_load_roundtrip() {
        let path = tmp_ledger_path("roundtrip");
        let mut ledger = GhostLedger::new(1_699_000_000);
        ledger.months_collected = 2; // same module: field access OK
        ledger.save(&path).expect("save");
        let loaded = GhostLedger::load(&path).expect("load");
        assert_eq!(loaded, ledger);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn ledger_load_missing_file_fails() {
        let path = tmp_ledger_path("missing");
        assert!(matches!(
            GhostLedger::load(&path),
            Err(LedgerError::Io(_))
        ));
    }

    #[test]
    fn ledger_load_corrupt_fails_closed() {
        let path = tmp_ledger_path("corrupt");
        std::fs::write(&path, b"this is not a ledger file at all!!!!").unwrap();
        let err = GhostLedger::load(&path).unwrap_err();
        assert!(matches!(err, LedgerError::Corrupt(_)), "got {err:?}");
        // Truncated to a plausible-but-short length also fails.
        std::fs::write(&path, b"TRVG\x01\x00").unwrap();
        assert!(matches!(
            GhostLedger::load(&path),
            Err(LedgerError::Corrupt(_))
        ));
        // Bad magic.
        let mut bad = vec![0u8; 21];
        bad[0..4].copy_from_slice(b"XXXX");
        std::fs::write(&path, &bad).unwrap();
        assert!(matches!(
            GhostLedger::load(&path),
            Err(LedgerError::Corrupt(_))
        ));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn ledger_load_bad_version_fails() {
        let path = tmp_ledger_path("version");
        let mut bytes = vec![0u8; 21];
        bytes[0..4].copy_from_slice(b"TRVG");
        bytes[4] = 99;
        std::fs::write(&path, &bytes).unwrap();
        assert_eq!(
            GhostLedger::load(&path),
            Err(LedgerError::UnsupportedVersion(99))
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn ledger_error_display_is_stable() {
        assert!(!format!("{}", LedgerError::Io("x".into())).is_empty());
        assert!(!format!("{}", LedgerError::Corrupt("x".into())).is_empty());
        assert!(!format!("{}", LedgerError::UnsupportedVersion(9)).is_empty());
    }

    // -- Viewer status ----------------------------------------------------

    fn test_entitlement(expires_at: u64) -> Entitlement {
        let now = 1_700_000_000u64;
        let sub = Subscription::new(
            Tier::Monthly,
            Some(PaidTier::Tier1),
            now - 2 * MONTH_SECS,
            expires_at,
            true,
        )
        .expect("sub");
        let receipt = issue_subscription_receipt(&BILLING_ISSUER_SEED, &sub)
            .expect("issue");
        entitlement::verify_receipt(&billing_pubkey(), &receipt).expect("verify")
    }

    #[test]
    fn viewer_status_active() {
        let now = 1_700_000_000u64;
        let ent = test_entitlement(now + MONTH_SECS);
        let ledger = GhostLedger::new(now);
        match viewer_status(Some(ent), Some(&ledger), now) {
            ViewerStatus::Active { tier, expires_at } => {
                assert_eq!(tier, Tier::Monthly);
                assert_eq!(expires_at, now + MONTH_SECS);
            }
            s => panic!("expected Active, got {s:?}"),
        }
    }

    #[test]
    fn viewer_status_grace_period() {
        let now = 1_700_000_000u64;
        // Expired 1 day ago: 2 days of grace left.
        let ent = test_entitlement(now - 86_400);
        let ledger = GhostLedger::new(now);
        assert_eq!(
            viewer_status(Some(ent), Some(&ledger), now),
            ViewerStatus::GracePeriod { days_left: 2 }
        );
        // Expired exactly at the boundary (3 days): grace over -> ghost.
        let ent2 = test_entitlement(now - 3 * 86_400);
        assert!(matches!(
            viewer_status(Some(ent2), Some(&ledger), now),
            ViewerStatus::Ghost { .. }
        ));
    }

    #[test]
    fn viewer_status_lapsed_without_ledger() {
        let now = 1_700_000_000u64;
        // No entitlement, no ledger: dormant.
        assert_eq!(
            viewer_status(None, None, now),
            ViewerStatus::Lapsed
        );
        // Expired past grace, no ledger: lapsed, not ghost.
        let ent = test_entitlement(now - 30 * 86_400);
        assert_eq!(
            viewer_status(Some(ent), None, now),
            ViewerStatus::Lapsed
        );
    }

    #[test]
    fn viewer_status_ghost_amounts() {
        let now = 1_700_000_000u64;
        // 100 days as ghost, nothing collected: 3 months unpaid,
        // next fee is month-1's $5.
        let ledger = GhostLedger::new(now - 100 * 86_400);
        assert_eq!(
            viewer_status(None, Some(&ledger), now),
            ViewerStatus::Ghost {
                months_unpaid: 3,
                next_fee_cents: 500,
            }
        );
    }

    #[test]
    fn viewer_status_ghost_after_partial_collection() {
        let now = 1_700_000_000u64;
        let mut ledger = GhostLedger::new(now - 100 * 86_400);
        let mut pool = CommunityPool::new();
        // Collect month 1 only via a manual settle at day 45.
        ledger
            .settle(&mut pool, now - 55 * 86_400)
            .expect("settle");
        assert_eq!(ledger.months_collected(), 1);
        // Now: 3 elapsed, 1 collected -> 2 unpaid, next fee $10.
        assert_eq!(
            viewer_status(None, Some(&ledger), now),
            ViewerStatus::Ghost {
                months_unpaid: 2,
                next_fee_cents: 1000,
            }
        );
    }

    #[test]
    fn viewer_status_ghost_in_grace_no_fee() {
        let now = 1_700_000_000u64;
        // 10 days as ghost: within the 30-day ghost grace.
        let ledger = GhostLedger::new(now - 10 * 86_400);
        assert_eq!(
            viewer_status(None, Some(&ledger), now),
            ViewerStatus::Ghost {
                months_unpaid: 0,
                next_fee_cents: 0,
            }
        );
    }

    #[test]
    fn viewer_status_back_to_active_on_payment() {
        // The full lifecycle: active -> grace -> ghost -> active again.
        let now = 1_700_000_000u64;
        let ledger = GhostLedger::new(now - 100 * 86_400);
        // Fresh entitlement = active, regardless of ghost history.
        let ent = test_entitlement(now + MONTH_SECS);
        assert!(matches!(
            viewer_status(Some(ent), Some(&ledger), now),
            ViewerStatus::Active { .. }
        ));
    }

    /// Integration: a ghost user's full journey through the paywall.
    ///
    /// Walks a never-paid user through: denied gated features, ghost fee
    /// accumulation across billing ticks, and the ledger/pool state after.
    /// This is the end-to-end proof that the second paywall audit's
    /// requirements hold: gates deny, ticks collect, nothing is skipped.
    #[test]
    fn ghost_user_journey_denied_then_billed() {
        use crate::gates::{can_access, Feature};

        let start = 1_700_000_000u64;
        let ghost_since = start;

        // 1. Ghost user (no entitlement): all paid features deny.
        // Note: can_access denies EVERYTHING with None — even VpnBasic
        // needs at least a Free-tier entitlement object, not absence.
        let no_ent: Option<crate::entitlement::Entitlement> = None;
        assert!(!can_access(Feature::UnlimitedEi, no_ent));
        assert!(!can_access(Feature::Messaging, no_ent));
        assert!(!can_access(Feature::IdentityVerification, no_ent));
        assert!(!can_access(Feature::VpnBasic, no_ent));

        // 2. ViewerStatus reflects ghost with no fees yet (within 30-day grace).
        let ledger = GhostLedger::new(ghost_since);
        let status = viewer_status(no_ent, Some(&ledger), start + 10 * 86_400);
        assert!(matches!(status, ViewerStatus::Ghost { months_unpaid: 0, .. }),
            "ghost in grace period should show 0 months unpaid, got {:?}", status);

        // 3. First billing tick after grace: 1 month collected ($5).
        let mut ledger = GhostLedger::new(ghost_since);
        let mut pool = CommunityPool::new();
        let t1 = start + 31 * 86_400; // just past 30-day grace
        let outcome = BillingTick::tick_at_startup(&mut ledger, &mut pool, t1)
            .expect("tick must not fail closed here");
        assert!(outcome.ran);
        assert_eq!(outcome.months_collected, 1);
        assert_eq!(outcome.total_cents, 500); // $5 first month
        assert_eq!(pool.balance_cents(), 500);

        // 4. Second tick a month later: escalation to $10.
        let t2 = t1 + MONTH_SECS;
        let outcome2 = BillingTick::tick_at_startup(&mut ledger, &mut pool, t2)
            .expect("tick must not fail closed here");
        assert_eq!(outcome2.months_collected, 1);
        assert_eq!(outcome2.total_cents, 1000); // $10 second month
        assert_eq!(pool.balance_cents(), 1500);

        // 5. Idempotency: re-running the same tick collects nothing.
        let outcome3 = BillingTick::tick_at_startup(&mut ledger, &mut pool, t2)
            .expect("tick must not fail closed here");
        assert!(outcome3.ran);
        assert_eq!(outcome3.months_collected, 0);
        assert_eq!(pool.balance_cents(), 1500);

        // 6. Status before collection would show 2 months unpaid.
        // (After our ticks collected both, unpaid is 0 — verify with a
        // fresh ledger at the same timestamp.)
        let fresh_ledger = GhostLedger::new(ghost_since);
        let status = viewer_status(no_ent, Some(&fresh_ledger), t2);
        match status {
            ViewerStatus::Ghost { months_unpaid, next_fee_cents } => {
                assert_eq!(months_unpaid, 2);
                assert_eq!(next_fee_cents, 500); // $5 first uncollected month
            }
            other => panic!("expected Ghost status, got {:?}", other),
        }
        // And the collected ledger shows 0 unpaid (both months settled).
        let status = viewer_status(no_ent, Some(&ledger), t2);
        assert!(matches!(
            status,
            ViewerStatus::Ghost { months_unpaid: 0, .. }
        ));

        // 7. Ghost pays for verification: fresh entitlement → Active,
        //    gates now allow. (Entitlement expiry must be in the future
        //    relative to the REAL system clock, which check() uses.)
        let far_future = 9_999_999_999u64; // year 2286
        let ent = test_entitlement(far_future);
        assert!(can_access(Feature::Messaging, Some(ent)));
        assert!(can_access(Feature::IdentityVerification, Some(ent)));
        let status = viewer_status(Some(ent), Some(&ledger), t2);
        assert!(matches!(status, ViewerStatus::Active { .. }));
    }

    // ---- First-month 50% discount ----

    #[test]
    fn first_month_discount_constant_is_fifty() {
        assert_eq!(FIRST_MONTH_DISCOUNT_PERCENT, 50);
    }

    #[test]
    fn new_viewer_gets_half_off_monthly_all_tiers() {
        // Tier 1: $10.00 -> $5.00; Tier 2: $25.00 -> $12.50;
        // Tier 3: $45.00 -> $22.50.
        assert_eq!(PaidTier::Tier1.first_month_monthly_cents(), 500);
        assert_eq!(PaidTier::Tier2.first_month_monthly_cents(), 1250);
        assert_eq!(PaidTier::Tier3.first_month_monthly_cents(), 2250);
    }

    #[test]
    fn buyer_friendly_rounding_rounds_discount_up() {
        // Odd-cent price: 50% of 101 = 50.5 -> discount rounds UP to
        // 51 (buyer-friendly), price 50.
        assert_eq!(apply_percent_off_buyer_friendly(101, 50), 50);
        // 33% of 100 = 33.33 -> discount 33, price 67.
        assert_eq!(apply_percent_off_buyer_friendly(100, 33), 67);
        // 0% off and 100% off behave.
        assert_eq!(apply_percent_off_buyer_friendly(999, 0), 999);
        assert_eq!(apply_percent_off_buyer_friendly(999, 100), 0);
        // Percent clamps at 100.
        assert_eq!(apply_percent_off_buyer_friendly(999, 150), 0);
    }

    #[test]
    fn purchase_price_monthly_first_vs_renewal() {
        for tier in [PaidTier::Tier1, PaidTier::Tier2, PaidTier::Tier3] {
            // First purchase: half off the month.
            assert_eq!(
                purchase_price_cents(tier, Tier::Monthly, true, None, false),
                Some(tier.monthly_cents() / 2)
            );
            // Renewal: full monthly price.
            assert_eq!(
                purchase_price_cents(tier, Tier::Monthly, false, None, false),
                Some(tier.monthly_cents())
            );
        }
    }

    #[test]
    fn purchase_price_yearly_first_purchase_prorates_first_month() {
        // Tier 1 yearly $100: prorated month = 833c, half = 417c off.
        // 10000 - 417 = 9583.
        assert_eq!(
            purchase_price_cents(PaidTier::Tier1, Tier::Yearly, true, None, false),
            Some(9583)
        );
        // Tier 2 yearly $150: month = 1250c, half = 625c off -> 14375.
        assert_eq!(
            purchase_price_cents(PaidTier::Tier2, Tier::Yearly, true, None, false),
            Some(14375)
        );
        // Tier 3 yearly $200: month = 1667c, half = 834c off -> 19166.
        assert_eq!(
            purchase_price_cents(PaidTier::Tier3, Tier::Yearly, true, None, false),
            Some(19166)
        );
        // Yearly renewals are full price.
        assert_eq!(
            purchase_price_cents(PaidTier::Tier1, Tier::Yearly, false, None, false),
            Some(10000)
        );
    }

    #[test]
    fn purchase_price_yearly_first_purchase_with_citizen_discount() {
        // Citizen Tier 1: best yearly = 8233. Month share = 686c,
        // half = 343c off -> 7890. Documents the stacking rule:
        // yearly discount first, then 50% off the prorated month.
        assert_eq!(
            purchase_price_cents(PaidTier::Tier1, Tier::Yearly, true, None, true),
            Some(7890)
        );
        // Citizen renewal: the plain citizen yearly price.
        assert_eq!(
            purchase_price_cents(PaidTier::Tier1, Tier::Yearly, false, None, true),
            Some(8233)
        );
    }

    #[test]
    fn purchase_price_rejects_non_purchases() {
        // Free/Founding are not purchases.
        assert_eq!(
            purchase_price_cents(PaidTier::Tier1, Tier::Free, true, None, false),
            None
        );
        assert_eq!(
            purchase_price_cents(PaidTier::Tier1, Tier::Founding, false, None, false),
            None
        );
    }

    #[test]
    fn first_month_ledger_claims_once_per_identity() {
        let mut ledger = FirstMonthLedger::new();
        let alice = [0xA1u8; 32];
        let bob = [0xB2u8; 32];
        // First claim succeeds: discount applies.
        assert!(ledger.claim_first_month(&alice));
        assert!(ledger.has_claimed(&alice));
        // Same identity again: no discount.
        assert!(!ledger.claim_first_month(&alice));
        assert!(!ledger.claim_first_month(&alice));
        // A different identity still gets its own first claim.
        assert!(ledger.claim_first_month(&bob));
        assert_eq!(ledger.claims_count(), 2);
    }

    #[test]
    fn burned_account_same_identity_gets_no_second_discount() {
        // The abuse case: a viewer burns their account and comes back
        // with the SAME verified identity key. The ledger refuses the
        // second claim.
        let mut ledger = FirstMonthLedger::new();
        let identity_key = [0x1Du8; 32];
        assert!(ledger.claim_first_month(&identity_key));
        // "New" account, same verified identity -> no discount.
        assert!(!ledger.claim_first_month(&identity_key));
        let price = purchase_price_cents(
            PaidTier::Tier2,
            Tier::Monthly,
            ledger.claim_first_month(&identity_key),
            None,
            false,
        );
        assert_eq!(price, Some(2500)); // full price, no 50% off
    }

    #[test]
    fn ghost_fees_never_discounted() {
        // The first-month discount is a purchase-track rule only.
        // Ghost escalation fees are untouched: same schedule as ever.
        let ghost_since = 1_700_000_000u64;
        let ghost = GhostAccount::new(ghost_since);
        // Month 1 after grace: $5; month 2: $10.
        assert_eq!(
            ghost.monthly_fee_cents(ghost_since + 45 * 86_400),
            Some(500)
        );
        assert_eq!(
            ghost.monthly_fee_cents(ghost_since + 75 * 86_400),
            Some(1000)
        );
        // And purchase_price_cents has no ghost path at all: Free
        // (the ghost-adjacent tier) is not a purchase.
        assert_eq!(
            purchase_price_cents(PaidTier::Tier1, Tier::Free, true, None, false),
            None
        );
    }

    #[test]
    fn first_month_ledger_persists_across_restarts() {
        let dir = std::env::temp_dir().join("trv-first-month-test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("claims.trvl");
        let _ = std::fs::remove_file(&path);
        let mut ledger = FirstMonthLedger::new();
        let alice = [0xA1u8; 32];
        let bob = [0xB2u8; 32];
        assert!(ledger.claim_first_month(&alice));
        assert!(ledger.claim_first_month(&bob));
        ledger.save(&path).expect("save works");
        let loaded = FirstMonthLedger::load(&path).expect("load works");
        assert!(loaded.has_claimed(&alice));
        assert!(loaded.has_claimed(&bob));
        assert!(!loaded.has_claimed(&[0xC3u8; 32]));
        // Claims survive: no re-grant after restart.
        let mut loaded = loaded;
        assert!(!loaded.claim_first_month(&alice));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn first_month_ledger_load_fails_closed() {
        let dir = std::env::temp_dir().join("trv-first-month-test");
        let _ = std::fs::create_dir_all(&dir);
        // Missing file.
        assert!(FirstMonthLedger::load(&dir.join("nope.trvl")).is_err());
        // Bad magic.
        let bad = dir.join("bad.trvl");
        std::fs::write(&bad, b"XXXX\x01garbage").unwrap();
        assert!(FirstMonthLedger::load(&bad).is_err());
        // Header count lies about the key count.
        let mut buf = Vec::new();
        buf.extend_from_slice(b"TRVD");
        buf.push(1);
        buf.extend_from_slice(&5u64.to_be_bytes()); // claims 5...
        buf.extend_from_slice(&[0xABu8; 32]); // ...holds 1
        let lying = dir.join("lying.trvl");
        std::fs::write(&lying, &buf).unwrap();
        assert!(FirstMonthLedger::load(&lying).is_err());
        let _ = std::fs::remove_file(&bad);
        let _ = std::fs::remove_file(&lying);
    }
}
