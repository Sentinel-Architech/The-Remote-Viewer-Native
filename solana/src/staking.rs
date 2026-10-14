//! TRV staking: 90-day lock, no early unstake, proportional rewards.
//!
//! Policy (user decisions 2026-10-13):
//!
//! * Staking is **FREE** regardless of amount — no entry fee, no
//!   minimum beyond 1 base unit.
//! * **90-day lock**: once staked, tokens are locked for exactly
//!   [`STAKE_LOCK_SECS`]. There is **no early unstaking** — not
//!   partial, not with a penalty, not at all.
//! * Rewards are **proportional** to stake size and time locked. The
//!   rate ([`REWARD_RATE_BPS_PER_LOCK`]) is a parameter because the
//!   exact rate is still TBD; it is set once at program init.
//! * While staked, the **20% external-spend fee is waived**
//!   ([`external_spend_fee_bps`] returns 0 for staked wallets).
//!   Unstaked wallets spending TRV outside the Network pay 20%.
//!
//! Rewards accrue linearly over the lock period and are claimable
//! once the lock expires. Unclaimed rewards do not compound —
//! simplicity is a security feature.

use crate::math::{fee_bps, MathError};
use core::fmt;

/// 90 days in seconds. The one and only lock duration.
pub const STAKE_LOCK_SECS: u64 = 90 * 86_400;

/// 20% external-spend fee, in basis points, for UNSTAKED wallets.
/// Waived (0) for the duration of a 90-day stake.
pub const EXTERNAL_SPEND_FEE_BPS: u32 = 2_000;

/// Reward rate per full 90-day lock, in basis points of the staked
/// amount. Placeholder — the real rate is TBD and set at program
/// init. (Example: 500 = 5% per 90-day lock.)
pub const REWARD_RATE_BPS_PER_LOCK: u32 = 500;

/// A staker's on-chain account (mirrors the Anchor account layout).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StakeAccount {
    /// 32-byte owner pubkey (opaque here; verified on-chain).
    pub owner: [u8; 32],
    /// Base units currently staked.
    pub amount: u64,
    /// Unix timestamp when the lock expires. `u64::MAX` = never staked.
    pub locked_until: u64,
    /// Rewards accrued but not yet claimed (base units).
    pub rewards_accrued: u64,
    /// True once the one-time lock-period reward has been paid out
    /// (via `unstake` or `claim_rewards`). Rewards do not compound
    /// and do not re-accrue — one lock, one reward.
    pub reward_paid: bool,
    /// False after a successful unstake; the account is then closed.
    pub active: bool,
}

/// Staking errors. Every failure is explicit — nothing panics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StakingError {
    /// Tried to stake zero tokens.
    ZeroStake,
    /// Account already has an active stake (one stake per wallet).
    AlreadyStaked,
    /// Tried to unstake before `locked_until`.
    StillLocked { now: u64, locked_until: u64 },
    /// Tried to unstake or claim on an inactive account.
    NotStaked,
    /// Caller is not the stake owner.
    Unauthorized,
    /// Reward math overflowed.
    Math(MathError),
}

impl fmt::Display for StakingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StakingError::ZeroStake => write!(f, "cannot stake zero tokens"),
            StakingError::AlreadyStaked => write!(f, "wallet already has an active stake"),
            StakingError::StillLocked { now, locked_until } => write!(
                f,
                "stake locked until {locked_until} (now {now}): no early unstake"
            ),
            StakingError::NotStaked => write!(f, "no active stake on this wallet"),
            StakingError::Unauthorized => write!(f, "caller is not the stake owner"),
            StakingError::Math(e) => write!(f, "staking math error: {e}"),
        }
    }
}

impl StakeAccount {
    /// An empty (never-staked) account.
    pub fn empty() -> Self {
        StakeAccount {
            owner: [0u8; 32],
            amount: 0,
            locked_until: u64::MAX,
            rewards_accrued: 0,
            reward_paid: false,
            active: false,
        }
    }

    /// Open a stake. Free regardless of amount; locks for 90 days.
    pub fn stake(
        &mut self,
        owner: [u8; 32],
        amount: u64,
        now: u64,
    ) -> Result<u64, StakingError> {
        if self.active {
            return Err(StakingError::AlreadyStaked);
        }
        if amount == 0 {
            return Err(StakingError::ZeroStake);
        }
        let locked_until = now
            .checked_add(STAKE_LOCK_SECS)
            .ok_or(StakingError::Math(MathError::Overflow))?;
        self.owner = owner;
        self.amount = amount;
        self.locked_until = locked_until;
        self.rewards_accrued = 0;
        self.reward_paid = false;
        self.active = true;
        Ok(locked_until)
    }

    /// Close the stake and return `(principal, rewards)`.
    /// Fails if the 90-day lock has not expired — no early unstake.
    pub fn unstake(&mut self, caller: &[u8; 32], now: u64) -> Result<(u64, u64), StakingError> {
        if !self.active {
            return Err(StakingError::NotStaked);
        }
        if *caller != self.owner {
            return Err(StakingError::Unauthorized);
        }
        if now < self.locked_until {
            return Err(StakingError::StillLocked {
                now,
                locked_until: self.locked_until,
            });
        }
        // Accrue the one-time lock-period reward on exit, if not
        // already paid out via claim_rewards.
        let mut reward = 0u64;
        if !self.reward_paid {
            reward = self.full_lock_reward().map_err(StakingError::Math)?;
        }
        let principal = self.amount;
        let total_rewards = self
            .rewards_accrued
            .checked_add(reward)
            .ok_or(StakingError::Math(MathError::Overflow))?;
        *self = StakeAccount::empty();
        Ok((principal, total_rewards))
    }

    /// Claim rewards accrued so far WITHOUT unstaking. Only
    /// meaningful after the lock expires; claiming does not end the
    /// lock (the principal stays until `unstake`).
    pub fn claim_rewards(&mut self, caller: &[u8; 32], now: u64) -> Result<u64, StakingError> {
        if !self.active {
            return Err(StakingError::NotStaked);
        }
        if *caller != self.owner {
            return Err(StakingError::Unauthorized);
        }
        if now < self.locked_until {
            return Err(StakingError::StillLocked {
                now,
                locked_until: self.locked_until,
            });
        }
        let mut reward = 0u64;
        if !self.reward_paid {
            reward = self.full_lock_reward().map_err(StakingError::Math)?;
            self.reward_paid = true;
        }
        let payout = self
            .rewards_accrued
            .checked_add(reward)
            .ok_or(StakingError::Math(MathError::Overflow))?;
        self.rewards_accrued = 0;
        // Principal remains staked; owner may unstake immediately.
        Ok(payout)
    }

    /// Reward for one full 90-day lock, proportional to stake size.
    fn full_lock_reward(&self) -> Result<u64, MathError> {
        fee_bps(self.amount, REWARD_RATE_BPS_PER_LOCK)
    }

    /// Seconds remaining on the lock (0 if expired or inactive).
    pub fn lock_remaining(&self, now: u64) -> u64 {
        if !self.active {
            return 0;
        }
        self.locked_until.saturating_sub(now)
    }
}

/// External-spend fee (bps) for a wallet: 0 while it has an active
/// stake, 20% otherwise. This is the "wiped for the duration of a
/// 90-day stake" rule.
pub fn external_spend_fee_bps(stake: &StakeAccount) -> u32 {
    if stake.active {
        0
    } else {
        EXTERNAL_SPEND_FEE_BPS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner() -> [u8; 32] {
        [3u8; 32]
    }

    fn staked(amount: u64, now: u64) -> StakeAccount {
        let mut s = StakeAccount::empty();
        s.stake(owner(), amount, now).unwrap();
        s
    }

    #[test]
    fn lock_is_90_days() {
        let mut s = StakeAccount::empty();
        let until = s.stake(owner(), 1_000, 1_000_000).unwrap();
        assert_eq!(until, 1_000_000 + STAKE_LOCK_SECS);
        assert_eq!(STAKE_LOCK_SECS, 7_776_000);
    }

    #[test]
    fn no_early_unstake_even_one_second_early() {
        let mut s = staked(1_000, 0);
        let err = s.unstake(&owner(), STAKE_LOCK_SECS - 1).unwrap_err();
        assert_eq!(
            err,
            StakingError::StillLocked {
                now: STAKE_LOCK_SECS - 1,
                locked_until: STAKE_LOCK_SECS
            }
        );
        assert!(s.active, "failed unstake must not close the stake");
    }

    #[test]
    fn unstake_at_expiry_returns_principal_plus_reward() {
        let mut s = staked(10_000, 0);
        let (principal, rewards) = s.unstake(&owner(), STAKE_LOCK_SECS).unwrap();
        assert_eq!(principal, 10_000);
        // 5% of 10_000 = 500.
        assert_eq!(rewards, 500);
        assert!(!s.active);
    }

    #[test]
    fn rewards_proportional_to_stake() {
        let mut a = staked(10_000, 0);
        let mut b = staked(20_000, 0);
        let (_, ra) = a.unstake(&owner(), STAKE_LOCK_SECS).unwrap();
        let (_, rb) = b.unstake(&owner(), STAKE_LOCK_SECS).unwrap();
        assert_eq!(rb, 2 * ra);
    }

    #[test]
    fn staking_is_free_no_minimum_beyond_one_unit() {
        let mut s = StakeAccount::empty();
        assert!(s.stake(owner(), 1, 0).is_ok());
        assert_eq!(s.stake(owner(), 1, 0), Err(StakingError::AlreadyStaked));
    }

    #[test]
    fn zero_stake_rejected() {
        let mut s = StakeAccount::empty();
        assert_eq!(s.stake(owner(), 0, 0), Err(StakingError::ZeroStake));
    }

    #[test]
    fn wrong_owner_rejected() {
        let mut s = staked(1_000, 0);
        assert_eq!(
            s.unstake(&[9u8; 32], STAKE_LOCK_SECS),
            Err(StakingError::Unauthorized)
        );
    }

    #[test]
    fn external_spend_fee_waived_while_staked() {
        let s = staked(1_000, 0);
        assert_eq!(external_spend_fee_bps(&s), 0);
        assert_eq!(
            external_spend_fee_bps(&StakeAccount::empty()),
            EXTERNAL_SPEND_FEE_BPS
        );
    }

    #[test]
    fn claim_after_lock_pays_without_unstaking() {
        let mut s = staked(10_000, 0);
        let payout = s.claim_rewards(&owner(), STAKE_LOCK_SECS).unwrap();
        assert_eq!(payout, 500);
        assert!(s.active, "claim must not close the stake");
        // Second claim pays nothing new (no compounding).
        assert_eq!(s.claim_rewards(&owner(), STAKE_LOCK_SECS).unwrap(), 0);
    }

    #[test]
    fn claim_before_lock_rejected() {
        let mut s = staked(10_000, 0);
        assert!(s.claim_rewards(&owner(), STAKE_LOCK_SECS - 1).is_err());
    }
}
