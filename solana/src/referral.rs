//! TRV referral rewards: $5 in TRV per verified friend.
//!
//! Policy (user decision 2026-10-13, economics 2026-10-14):
//!
//! * A referrer earns **$5 worth of TRV** for each friend who
//!   registers via the referrer's QR code.
//! * The reward becomes claimable **only after the friend pays for
//!   verification**. The [`ReferralLedger::mark_verified`] caller
//!   attests that payment happened; on-chain the adapter verifies
//!   the payment receipt before forwarding.
//! * The reward must be claimed **within 14 days** of becoming
//!   eligible (the "1–2 week" payout window). After that it
//!   **expires** — an anti-hoarding rule, fail closed.
//! * No double-claims: each referral pays exactly once.
//!
//! # Placeholders
//!
//! * **TRV/USD price**: "$5 worth of TRV" needs a price. The
//!   scaffold assumes **1 TRV = $1 USD**
//!   ([`TRV_USD_CENTS_PLACEHOLDER`]), so the reward is a flat
//!   [`REFERRAL_REWARD_BASE_UNITS`]. The real conversion comes from
//!   a price oracle or governance-set rate before mainnet.

use crate::math::MathError;
use core::fmt;

/// Placeholder TRV price: 100 cents = $1 USD per TRV.
///
/// **PLACEHOLDER — NOT FINAL.** Replaced by a price oracle or
/// governance-set rate before mainnet. Do not treat "$5 = 5 TRV"
/// as economic policy.
pub const TRV_USD_CENTS_PLACEHOLDER: u64 = 100;

/// Referral reward in USD cents: $5.
pub const REFERRAL_REWARD_USD_CENTS: u64 = 500;

/// Referral reward in TRV base units: $5 at the placeholder
/// $1/TRV = 5 TRV = 5 × 10^9 base units.
pub const REFERRAL_REWARD_BASE_UNITS: u64 = 5_000_000_000;

/// Claim window: 14 days from eligibility ("1–2 weeks").
pub const REFERRAL_CLAIM_WINDOW_SECS: u64 = 14 * 86_400;

/// One referral: a friend's QR signup attributed to a referrer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReferralRecord {
    /// 32-byte referrer pubkey (who earned the reward).
    pub referrer: [u8; 32],
    /// Unique QR identifier for this signup (prevents double-count
    /// of the same scan; distinct scans get distinct ids).
    pub qr_id: [u8; 32],
    /// Unix timestamp when the referral was recorded.
    pub recorded_at: u64,
    /// Unix timestamp when the friend's verification payment was
    /// attested. 0 = not yet verified (pending).
    pub verified_at: u64,
    /// True once the $5 reward has been paid out.
    pub claimed: bool,
    /// True once the 14-day window passed unclaimed (forfeit).
    pub expired: bool,
}

/// Referral errors. Every failure is explicit — nothing panics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferralError {
    /// `qr_id` was already recorded.
    DuplicateReferral,
    /// `mark_verified` called with an unknown `qr_id`.
    UnknownReferral,
    /// `mark_verified` called twice for the same `qr_id`.
    AlreadyVerified,
    /// Nothing eligible to claim (pending, unknown referrer, or
    /// everything already claimed/expired-handled).
    NothingClaimable,
    /// At least one verified reward expired unclaimed past the
    /// 14-day window (and nothing else was claimable).
    RewardExpired,
    /// All of the referrer's rewards were already claimed.
    DoubleClaim,
    /// Reward accounting overflowed (defensive).
    Math(MathError),
}

impl fmt::Display for ReferralError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReferralError::DuplicateReferral => write!(f, "referral already recorded for this QR id"),
            ReferralError::UnknownReferral => write!(f, "unknown referral QR id"),
            ReferralError::AlreadyVerified => write!(f, "referral already marked verified"),
            ReferralError::NothingClaimable => write!(f, "no claimable referral rewards"),
            ReferralError::RewardExpired => {
                write!(f, "referral reward expired: 14-day claim window passed")
            }
            ReferralError::DoubleClaim => write!(f, "referral rewards already claimed"),
            ReferralError::Math(e) => write!(f, "referral math error: {e}"),
        }
    }
}

impl From<MathError> for ReferralError {
    fn from(e: MathError) -> Self {
        ReferralError::Math(e)
    }
}

/// On-chain referral ledger (mirrors the Anchor account layout).
///
/// A flat record list is deliberate: referrals are write-rare and
/// the scaffold favors auditability over index structures.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReferralLedger {
    pub records: Vec<ReferralRecord>,
}

impl ReferralLedger {
    /// A fresh, empty ledger.
    pub fn new() -> Self {
        ReferralLedger { records: Vec::new() }
    }

    /// Record a friend's QR signup. Starts as *pending* — not
    /// claimable until [`ReferralLedger::mark_verified`].
    pub fn record_referral(
        &mut self,
        referrer: [u8; 32],
        qr_id: [u8; 32],
        now: u64,
    ) -> Result<(), ReferralError> {
        if self.records.iter().any(|r| r.qr_id == qr_id) {
            return Err(ReferralError::DuplicateReferral);
        }
        self.records.push(ReferralRecord {
            referrer,
            qr_id,
            recorded_at: now,
            verified_at: 0,
            claimed: false,
            expired: false,
        });
        Ok(())
    }

    /// Attest that the friend paid for verification, making the $5
    /// reward eligible. The caller MUST have verified the payment;
    /// this function trusts the attestation (on-chain, the adapter
    /// checks the payment receipt first).
    pub fn mark_verified(&mut self, qr_id: &[u8; 32], now: u64) -> Result<(), ReferralError> {
        let rec = self
            .records
            .iter_mut()
            .find(|r| &r.qr_id == qr_id)
            .ok_or(ReferralError::UnknownReferral)?;
        if rec.verified_at != 0 {
            return Err(ReferralError::AlreadyVerified);
        }
        rec.verified_at = now;
        Ok(())
    }

    /// Rewards currently claimable for `referrer`: verified,
    /// unclaimed, and inside the 14-day window. Returns
    /// `(count, total_base_units)`.
    pub fn claimable(&self, referrer: &[u8; 32], now: u64) -> (u64, u64) {
        let mut count = 0u64;
        let mut total = 0u64;
        for r in self.records.iter().filter(|r| &r.referrer == referrer) {
            if r.claimed || r.expired || r.verified_at == 0 {
                continue;
            }
            if now.saturating_sub(r.verified_at) > REFERRAL_CLAIM_WINDOW_SECS {
                continue;
            }
            count += 1;
            total = total.saturating_add(REFERRAL_REWARD_BASE_UNITS);
        }
        (count, total)
    }

    /// Pay out all currently claimable rewards for `referrer` and
    /// mark them claimed. Expired-unclaimed rewards are marked
    /// expired (forfeit) as a side effect.
    ///
    /// Fails closed: double-claims, pre-verification claims, and
    /// post-window claims all return errors, never partial payouts.
    pub fn claim(
        &mut self,
        referrer: &[u8; 32],
        now: u64,
    ) -> Result<u64, ReferralError> {
        let mut paid = 0u64;
        let mut saw_expired = false;
        let mut saw_claimed = false;
        let mut any = false;

        for r in self.records.iter_mut().filter(|r| &r.referrer == referrer) {
            any = true;
            if r.claimed {
                saw_claimed = true;
                continue;
            }
            if r.expired {
                saw_expired = true;
                continue;
            }
            if r.verified_at == 0 {
                continue; // pending: not eligible yet
            }
            if now.saturating_sub(r.verified_at) > REFERRAL_CLAIM_WINDOW_SECS {
                r.expired = true; // forfeit: anti-hoarding
                saw_expired = true;
                continue;
            }
            r.claimed = true;
            paid = paid.checked_add(REFERRAL_REWARD_BASE_UNITS).ok_or(MathError::Overflow)?;
        }

        if paid > 0 {
            return Ok(paid);
        }
        if !any {
            return Err(ReferralError::NothingClaimable);
        }
        if saw_expired {
            return Err(ReferralError::RewardExpired);
        }
        if saw_claimed {
            return Err(ReferralError::DoubleClaim);
        }
        Err(ReferralError::NothingClaimable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn referrer() -> [u8; 32] {
        [11u8; 32]
    }

    fn qr(n: u8) -> [u8; 32] {
        [n; 32]
    }

    #[test]
    fn reward_is_five_trv_at_placeholder_price() {
        // $5 at the placeholder $1/TRV, 9 decimals.
        assert_eq!(TRV_USD_CENTS_PLACEHOLDER, 100);
        assert_eq!(REFERRAL_REWARD_USD_CENTS, 500);
        assert_eq!(REFERRAL_REWARD_BASE_UNITS, 5_000_000_000);
    }

    #[test]
    fn full_lifecycle_pending_to_claimed() {
        let mut ledger = ReferralLedger::new();
        ledger.record_referral(referrer(), qr(1), 1_000).unwrap();

        // Pending: nothing claimable, claim fails.
        assert_eq!(ledger.claimable(&referrer(), 2_000), (0, 0));
        assert_eq!(
            ledger.claim(&referrer(), 2_000),
            Err(ReferralError::NothingClaimable)
        );

        // Friend pays for verification: now eligible.
        ledger.mark_verified(&qr(1), 3_000).unwrap();
        assert_eq!(
            ledger.claimable(&referrer(), 4_000),
            (1, REFERRAL_REWARD_BASE_UNITS)
        );

        // Claim pays $5 in TRV.
        assert_eq!(
            ledger.claim(&referrer(), 4_000),
            Ok(REFERRAL_REWARD_BASE_UNITS)
        );

        // Double-claim fails.
        assert_eq!(
            ledger.claim(&referrer(), 5_000),
            Err(ReferralError::DoubleClaim)
        );
    }

    #[test]
    fn duplicate_qr_rejected() {
        let mut ledger = ReferralLedger::new();
        ledger.record_referral(referrer(), qr(1), 0).unwrap();
        assert_eq!(
            ledger.record_referral(referrer(), qr(1), 1),
            Err(ReferralError::DuplicateReferral)
        );
        // ...even from a different referrer: the QR id is global.
        assert_eq!(
            ledger.record_referral([22u8; 32], qr(1), 1),
            Err(ReferralError::DuplicateReferral)
        );
    }

    #[test]
    fn verify_unknown_or_twice_fails() {
        let mut ledger = ReferralLedger::new();
        assert_eq!(
            ledger.mark_verified(&qr(9), 0),
            Err(ReferralError::UnknownReferral)
        );
        ledger.record_referral(referrer(), qr(1), 0).unwrap();
        ledger.mark_verified(&qr(1), 1).unwrap();
        assert_eq!(
            ledger.mark_verified(&qr(1), 2),
            Err(ReferralError::AlreadyVerified)
        );
    }

    #[test]
    fn claim_at_exactly_14_days_works() {
        let mut ledger = ReferralLedger::new();
        ledger.record_referral(referrer(), qr(1), 0).unwrap();
        ledger.mark_verified(&qr(1), 1_000).unwrap();
        let boundary = 1_000 + REFERRAL_CLAIM_WINDOW_SECS;
        assert_eq!(
            ledger.claim(&referrer(), boundary),
            Ok(REFERRAL_REWARD_BASE_UNITS)
        );
    }

    #[test]
    fn claim_after_14_days_expires() {
        let mut ledger = ReferralLedger::new();
        ledger.record_referral(referrer(), qr(1), 0).unwrap();
        ledger.mark_verified(&qr(1), 1_000).unwrap();
        let too_late = 1_000 + REFERRAL_CLAIM_WINDOW_SECS + 1;
        assert_eq!(ledger.claimable(&referrer(), too_late), (0, 0));
        assert_eq!(
            ledger.claim(&referrer(), too_late),
            Err(ReferralError::RewardExpired)
        );
        // Expired stays expired: a later claim still fails the same way.
        assert_eq!(
            ledger.claim(&referrer(), too_late + 1),
            Err(ReferralError::RewardExpired)
        );
    }

    #[test]
    fn multiple_referrals_pay_each_once() {
        let mut ledger = ReferralLedger::new();
        for n in 1u8..=3 {
            ledger.record_referral(referrer(), qr(n), 0).unwrap();
            ledger.mark_verified(&qr(n), 100).unwrap();
        }
        assert_eq!(
            ledger.claim(&referrer(), 200),
            Ok(3 * REFERRAL_REWARD_BASE_UNITS)
        );
        assert_eq!(
            ledger.claim(&referrer(), 300),
            Err(ReferralError::DoubleClaim)
        );
    }

    #[test]
    fn referrers_are_isolated() {
        let mut ledger = ReferralLedger::new();
        ledger.record_referral(referrer(), qr(1), 0).unwrap();
        ledger.mark_verified(&qr(1), 1).unwrap();
        // A different referrer has nothing.
        assert_eq!(
            ledger.claim(&[99u8; 32], 2),
            Err(ReferralError::NothingClaimable)
        );
        // The real referrer still can.
        assert_eq!(
            ledger.claim(&referrer(), 2),
            Ok(REFERRAL_REWARD_BASE_UNITS)
        );
    }

    #[test]
    fn mixed_one_fresh_one_expired() {
        let mut ledger = ReferralLedger::new();
        ledger.record_referral(referrer(), qr(1), 0).unwrap();
        ledger.record_referral(referrer(), qr(2), 0).unwrap();
        // qr(1) verified recently, qr(2) verified long ago.
        ledger.mark_verified(&qr(2), 1_000).unwrap();
        let now = 1_000 + REFERRAL_CLAIM_WINDOW_SECS + 1;
        ledger.mark_verified(&qr(1), now - 100).unwrap();
        // Fresh one pays; expired one is forfeited in the same call.
        assert_eq!(
            ledger.claim(&referrer(), now),
            Ok(REFERRAL_REWARD_BASE_UNITS)
        );
        // Nothing left that can pay; the expired record is still
        // there, so the error names the expiry.
        assert_eq!(
            ledger.claim(&referrer(), now + 1),
            Err(ReferralError::RewardExpired)
        );
    }
}
