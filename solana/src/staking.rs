//! TRV staking: 90-day lock, no early unstake, proportional rewards.
//!
//! Policy (user decisions 2026-10-13, reward model 2026-10-14):
//!
//! * Staking is **FREE** regardless of amount — no entry fee, no
//!   minimum beyond 1 base unit.
//! * **90-day lock**: once staked, tokens are locked for exactly
//!   [`STAKE_LOCK_SECS`]. There is **no early unstaking** — not
//!   partial, not with a penalty, not at all.
//! * Rewards are **proportional**: a [`StakingPool`] tracks total
//!   staked across all stakers, and each staker's share is
//!   `their_stake / total_staked`, time-weighted. Rewards accrue at
//!   [`REWARD_APY_BPS_PLACEHOLDER`] — a **PLACEHOLDER** 5% APY,
//!   not final; the real rate is set by governance before mainnet.
//! * While the 90-day lock is active, **both** the 25% transfer fee
//!   and the 20% external-spend fee are **waived**
//!   ([`StakeAccount::waiver_active`]). The waiver covers only the
//!   locked period — not before staking, not after the lock expires.
//! * **Claiming**: rewards may be claimed while the stake is active
//!   (locked or past-lock-but-not-unstaked). After unstaking, any
//!   unclaimed rewards remain claimable for
//!   [`CLAIM_WINDOW_AFTER_UNSTAKE_SECS`] (30 days); then they are
//!   **forfeit**. Unclaimed rewards never compound.
//!
//! Rewards accrue only while staked. The pool uses a fixed-point
//! "reward per token staked" accumulator (scaled by
//! [`REWARD_SCALE`]), so late joiners earn only from the moment
//! they stake — no retroactive rewards.

use crate::math::MathError;
use core::fmt;

/// 90 days in seconds. The one and only lock duration.
pub const STAKE_LOCK_SECS: u64 = 90 * 86_400;

/// Seconds in a (non-leap) year, for APY math.
pub const SECS_PER_YEAR: u64 = 365 * 86_400;

/// Reward rate, in basis points per year.
///
/// **PLACEHOLDER — NOT FINAL.** 500 = 5% APY. The real rate is set
/// by governance before mainnet. Marked unmistakably so no one
/// mistakes the scaffold number for policy.
pub const REWARD_APY_BPS_PLACEHOLDER: u32 = 500;

/// Post-unstake claim window: 30 days. Unclaimed rewards left
/// longer than this after unstaking are forfeit.
pub const CLAIM_WINDOW_AFTER_UNSTAKE_SECS: u64 = 30 * 86_400;

/// 20% external-spend fee, in basis points, for UNSTAKED wallets.
/// Waived (0) for the duration of a 90-day stake.
pub const EXTERNAL_SPEND_FEE_BPS: u32 = 2_000;

/// Fixed-point scale for the reward-per-token accumulator.
const REWARD_SCALE: u128 = 1_000_000_000_000_000_000;

/// A staker's on-chain account (mirrors the Anchor account layout).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StakeAccount {
    /// 32-byte owner pubkey (opaque here; verified on-chain).
    pub owner: [u8; 32],
    /// Base units currently staked. Zero after unstaking.
    pub amount: u64,
    /// Unix timestamp when the stake opened.
    pub staked_at: u64,
    /// Unix timestamp when the lock expires.
    pub locked_until: u64,
    /// False after a successful unstake; the stake is then closed.
    pub active: bool,
    /// Pool accumulator value at the staker's last sync. Used to
    /// compute newly earned rewards without retroactive credit.
    pub reward_per_token_paid: u128,
    /// Rewards earned but not yet claimed (base units). Survives
    /// unstaking for the 30-day post-unstake claim window.
    pub rewards_accrued: u64,
    /// Unix timestamp of unstaking. 0 while the stake is active.
    pub unstaked_at: u64,
}

/// The global staking pool: tracks total staked and accrues rewards
/// pro-rata at [`REWARD_APY_BPS_PLACEHOLDER`].
///
/// On-chain this is a singleton account; here it is an explicit
/// struct the instruction handlers take alongside the stake
/// account, so all pool accounting is atomic with state changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StakingPool {
    /// Base units staked across ALL stakers.
    pub total_staked: u64,
    /// Cumulative rewards per base unit staked, scaled by
    /// [`REWARD_SCALE`]. Only ever increases.
    pub reward_per_token_stored: u128,
    /// Unix timestamp of the last accrual.
    pub last_update: u64,
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
    /// Tried to unstake or claim on an account with no stake history.
    NotStaked,
    /// Caller is not the stake owner.
    Unauthorized,
    /// Claim attempted more than 30 days after unstaking; the
    /// leftover rewards are forfeit.
    RewardsForfeited,
    /// The provided timestamp is older than the pool's last update.
    /// On-chain time is monotonic; a regression is a caller bug.
    ClockWentBackwards { now: u64, last_update: u64 },
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
            StakingError::NotStaked => write!(f, "no stake on this account"),
            StakingError::Unauthorized => write!(f, "caller is not the stake owner"),
            StakingError::RewardsForfeited => write!(
                f,
                "unclaimed rewards forfeited: claim window after unstaking expired"
            ),
            StakingError::ClockWentBackwards { now, last_update } => write!(
                f,
                "timestamp {now} is older than pool's last update {last_update}"
            ),
            StakingError::Math(e) => write!(f, "staking math error: {e}"),
        }
    }
}

impl From<MathError> for StakingError {
    fn from(e: MathError) -> Self {
        StakingError::Math(e)
    }
}

impl StakeAccount {
    /// An empty (never-staked) account.
    pub fn empty() -> Self {
        StakeAccount {
            owner: [0u8; 32],
            amount: 0,
            staked_at: 0,
            locked_until: u64::MAX,
            active: false,
            reward_per_token_paid: 0,
            rewards_accrued: 0,
            unstaked_at: 0,
        }
    }

    /// True only while the 90-day lock is in force: the account holds
    /// an active stake AND `now` is before `locked_until`.
    ///
    /// This is the waiver predicate for both the 25% transfer fee
    /// and the 20% spending fee. It is deliberately stricter than
    /// `active`: once the lock expires, the waiver ends even if the
    /// owner has not unstaked yet.
    pub fn waiver_active(&self, now: u64) -> bool {
        self.active && now < self.locked_until
    }

    /// Seconds remaining on the lock (0 if expired or inactive).
    pub fn lock_remaining(&self, now: u64) -> u64 {
        if !self.active {
            return 0;
        }
        self.locked_until.saturating_sub(now)
    }
}

impl StakingPool {
    /// A fresh pool: nothing staked, no rewards accrued.
    pub fn new() -> Self {
        StakingPool {
            total_staked: 0,
            reward_per_token_stored: 0,
            last_update: 0,
        }
    }

    /// Accrue pool rewards up to `now` at the placeholder APY.
    ///
    /// `new_rewards = total_staked * APY_BPS * elapsed / (10_000 * SECS_PER_YEAR)`,
    /// folded into the per-token accumulator. Called automatically
    /// by every mutating pool method; idempotent for repeated `now`.
    pub fn accrue(&mut self, now: u64) -> Result<(), StakingError> {
        if now < self.last_update {
            return Err(StakingError::ClockWentBackwards {
                now,
                last_update: self.last_update,
            });
        }
        let elapsed = now - self.last_update;
        self.last_update = now;
        if elapsed == 0 || self.total_staked == 0 {
            return Ok(());
        }
        let new_rewards: u128 = (self.total_staked as u128)
            .checked_mul(REWARD_APY_BPS_PLACEHOLDER as u128)
            .ok_or(MathError::Overflow)?
            .checked_mul(elapsed as u128)
            .ok_or(MathError::Overflow)?
            / (10_000u128 * SECS_PER_YEAR as u128);
        let per_token: u128 = new_rewards
            .checked_mul(REWARD_SCALE)
            .ok_or(MathError::Overflow)?
            / self.total_staked as u128;
        self.reward_per_token_stored = self
            .reward_per_token_stored
            .checked_add(per_token)
            .ok_or(MathError::Overflow)?;
        Ok(())
    }

    /// Move an account's newly earned rewards into `rewards_accrued`.
    /// Late joiners earn only from their join moment: `paid` starts
    /// at the current accumulator, so past accruals are excluded.
    fn sync(&mut self, acct: &mut StakeAccount, now: u64) -> Result<(), StakingError> {
        self.accrue(now)?;
        let delta = self
            .reward_per_token_stored
            .checked_sub(acct.reward_per_token_paid)
            .ok_or(MathError::Overflow)?;
        let earned: u128 = (acct.amount as u128)
            .checked_mul(delta)
            .ok_or(MathError::Overflow)?
            / REWARD_SCALE;
        let earned_u64 = u64::try_from(earned).map_err(|_| MathError::Overflow)?;
        acct.rewards_accrued = acct
            .rewards_accrued
            .checked_add(earned_u64)
            .ok_or(MathError::Overflow)?;
        acct.reward_per_token_paid = self.reward_per_token_stored;
        Ok(())
    }

    /// Open a stake. Free regardless of amount; locks for 90 days.
    /// Returns the lock-expiry timestamp.
    pub fn open_stake(
        &mut self,
        acct: &mut StakeAccount,
        owner: [u8; 32],
        amount: u64,
        now: u64,
    ) -> Result<u64, StakingError> {
        self.accrue(now)?;
        if acct.active {
            return Err(StakingError::AlreadyStaked);
        }
        if amount == 0 {
            return Err(StakingError::ZeroStake);
        }
        let locked_until = now
            .checked_add(STAKE_LOCK_SECS)
            .ok_or(MathError::Overflow)?;
        self.total_staked = self
            .total_staked
            .checked_add(amount)
            .ok_or(MathError::Overflow)?;
        acct.owner = owner;
        acct.amount = amount;
        acct.staked_at = now;
        acct.locked_until = locked_until;
        acct.active = true;
        // Start earning from NOW: no retroactive rewards.
        acct.reward_per_token_paid = self.reward_per_token_stored;
        acct.rewards_accrued = 0;
        acct.unstaked_at = 0;
        Ok(locked_until)
    }

    /// Close a stake after the lock expires. Returns the principal.
    ///
    /// Fails if the 90-day lock has not expired — no early unstake,
    /// no exceptions. Accrued rewards are NOT auto-paid: they remain
    /// in `rewards_accrued`, claimable for 30 days via [`claim`],
    /// then forfeit.
    pub fn close_stake(
        &mut self,
        acct: &mut StakeAccount,
        caller: &[u8; 32],
        now: u64,
    ) -> Result<u64, StakingError> {
        if !acct.active {
            return Err(StakingError::NotStaked);
        }
        if *caller != acct.owner {
            return Err(StakingError::Unauthorized);
        }
        if now < acct.locked_until {
            return Err(StakingError::StillLocked {
                now,
                locked_until: acct.locked_until,
            });
        }
        self.sync(acct, now)?;
        let principal = acct.amount;
        self.total_staked = self
            .total_staked
            .checked_sub(principal)
            .ok_or(MathError::Overflow)?;
        acct.amount = 0;
        acct.active = false;
        acct.unstaked_at = now;
        Ok(principal)
    }

    /// Claim accrued rewards. Allowed while the stake is active
    /// (locked or past-lock-but-not-unstaked), and within 30 days
    /// after unstaking. Later than that, the rewards are forfeit.
    pub fn claim(
        &mut self,
        acct: &mut StakeAccount,
        caller: &[u8; 32],
        now: u64,
    ) -> Result<u64, StakingError> {
        if *caller != acct.owner {
            return Err(StakingError::Unauthorized);
        }
        if acct.active {
            self.sync(acct, now)?;
        } else {
            // Post-unstake window.
            if acct.unstaked_at == 0 {
                return Err(StakingError::NotStaked);
            }
            if now.saturating_sub(acct.unstaked_at) > CLAIM_WINDOW_AFTER_UNSTAKE_SECS {
                acct.rewards_accrued = 0;
                return Err(StakingError::RewardsForfeited);
            }
        }
        let payout = acct.rewards_accrued;
        acct.rewards_accrued = 0;
        Ok(payout)
    }

    /// Rewards the account could claim right now, without claiming.
    /// Pure view: syncs accounting but moves nothing out.
    pub fn pending_rewards(
        &mut self,
        acct: &mut StakeAccount,
        now: u64,
    ) -> Result<u64, StakingError> {
        if acct.active {
            self.sync(acct, now)?;
            Ok(acct.rewards_accrued)
        } else if acct.unstaked_at != 0
            && now.saturating_sub(acct.unstaked_at) <= CLAIM_WINDOW_AFTER_UNSTAKE_SECS
        {
            Ok(acct.rewards_accrued)
        } else {
            Ok(0)
        }
    }
}

/// External-spend fee (bps) for a wallet: 0 while it has an active
/// stake, 20% otherwise. This is the "wiped for the duration of a
/// 90-day stake" rule.
///
/// Note: this is the coarse active/not-active view. The precise
/// fee-waiver predicate used by the transfer hook is
/// [`StakeAccount::waiver_active`], which additionally requires the
/// lock to still be in force.
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

    fn pool_and_stake(amount: u64, now: u64) -> (StakingPool, StakeAccount) {
        let mut pool = StakingPool::new();
        let mut s = StakeAccount::empty();
        pool.open_stake(&mut s, owner(), amount, now).unwrap();
        (pool, s)
    }

    /// Expected reward at the placeholder 5% APY for `amount` base
    /// units over `elapsed_secs`, computed independently of the pool.
    fn expected_apy_reward(amount: u64, elapsed_secs: u64) -> u64 {
        ((amount as u128) * (REWARD_APY_BPS_PLACEHOLDER as u128) * (elapsed_secs as u128)
            / (10_000u128 * SECS_PER_YEAR as u128)) as u64
    }

    #[test]
    fn lock_is_90_days() {
        let mut pool = StakingPool::new();
        let mut s = StakeAccount::empty();
        let until = pool.open_stake(&mut s, owner(), 1_000, 1_000_000).unwrap();
        assert_eq!(until, 1_000_000 + STAKE_LOCK_SECS);
        assert_eq!(STAKE_LOCK_SECS, 7_776_000);
    }

    #[test]
    fn no_early_unstake_even_one_second_early() {
        let (mut pool, mut s) = pool_and_stake(1_000, 0);
        let err = pool
            .close_stake(&mut s, &owner(), STAKE_LOCK_SECS - 1)
            .unwrap_err();
        assert_eq!(
            err,
            StakingError::StillLocked {
                now: STAKE_LOCK_SECS - 1,
                locked_until: STAKE_LOCK_SECS
            }
        );
        assert!(s.active, "failed unstake must not close the stake");
        assert_eq!(pool.total_staked, 1_000, "failed unstake must not touch the pool");
    }

    #[test]
    fn unstake_at_exactly_90_days_succeeds() {
        let (mut pool, mut s) = pool_and_stake(10_000, 0);
        let principal = pool.close_stake(&mut s, &owner(), STAKE_LOCK_SECS).unwrap();
        assert_eq!(principal, 10_000);
        assert!(!s.active);
        assert_eq!(pool.total_staked, 0);
        // Rewards were NOT auto-paid: they wait for an explicit claim.
        assert!(s.rewards_accrued > 0);
    }

    #[test]
    fn waiver_active_only_during_lock() {
        let (mut pool, mut s) = pool_and_stake(1_000, 0);
        assert!(s.waiver_active(0));
        assert!(s.waiver_active(STAKE_LOCK_SECS - 1));
        // At the exact expiry second the lock is over: no waiver.
        assert!(!s.waiver_active(STAKE_LOCK_SECS));
        assert!(!s.waiver_active(STAKE_LOCK_SECS + 1_000));
        // After unstaking: no waiver.
        pool.close_stake(&mut s, &owner(), STAKE_LOCK_SECS).unwrap();
        assert!(!s.waiver_active(STAKE_LOCK_SECS));
        // Never staked: no waiver.
        assert!(!StakeAccount::empty().waiver_active(0));
    }

    #[test]
    fn rewards_match_placeholder_apy() {
        let (mut pool, mut s) = pool_and_stake(10_000_000_000, 0); // 10 TRV
        let pending = pool.pending_rewards(&mut s, STAKE_LOCK_SECS).unwrap();
        let expected = expected_apy_reward(10_000_000_000, STAKE_LOCK_SECS);
        // Fixed-point rounding may shave at most a few base units.
        assert!(
            pending <= expected && expected - pending <= 10,
            "pending={pending} expected~{expected}"
        );
    }

    #[test]
    fn rewards_proportional_two_stakers_split() {
        let mut pool = StakingPool::new();
        let mut a = StakeAccount::empty();
        let mut b = StakeAccount::empty();
        pool.open_stake(&mut a, [1u8; 32], 10_000_000_000, 0).unwrap();
        pool.open_stake(&mut b, [2u8; 32], 20_000_000_000, 0).unwrap();
        assert_eq!(pool.total_staked, 30_000_000_000);

        let ra = pool.pending_rewards(&mut a, STAKE_LOCK_SECS).unwrap();
        let rb = pool.pending_rewards(&mut b, STAKE_LOCK_SECS).unwrap();
        // 2x stake -> 2x rewards (within fixed-point rounding).
        assert!(rb >= 2 * ra - 10 && rb <= 2 * ra + 10, "ra={ra} rb={rb}");
        assert!(ra > 0);
    }

    #[test]
    fn late_joiner_earns_no_retroactive_rewards() {
        let mut pool = StakingPool::new();
        let mut a = StakeAccount::empty();
        let mut b = StakeAccount::empty();
        pool.open_stake(&mut a, [1u8; 32], 10_000_000_000, 0).unwrap();
        // B joins halfway through A's lock.
        pool.open_stake(&mut b, [2u8; 32], 10_000_000_000, STAKE_LOCK_SECS / 2).unwrap();

        let ra = pool.pending_rewards(&mut a, STAKE_LOCK_SECS).unwrap();
        let rb = pool.pending_rewards(&mut b, STAKE_LOCK_SECS).unwrap();
        // Same stake, but A was in twice as long -> ~2x rewards.
        assert!(ra >= 2 * rb - 20 && ra <= 2 * rb + 20, "ra={ra} rb={rb}");
    }

    #[test]
    fn claim_while_locked_pays_accrued_so_far() {
        let (mut pool, mut s) = pool_and_stake(10_000_000_000, 0);
        let halfway = STAKE_LOCK_SECS / 2;
        let payout = pool.claim(&mut s, &owner(), halfway).unwrap();
        let expected = expected_apy_reward(10_000_000_000, halfway);
        assert!(payout <= expected && expected - payout <= 10, "payout={payout}");
        assert!(s.active, "claim must not close the stake");
        // Second immediate claim pays ~nothing (no time passed).
        assert_eq!(pool.claim(&mut s, &owner(), halfway).unwrap(), 0);
    }

    #[test]
    fn claim_after_unstake_within_30_days() {
        let (mut pool, mut s) = pool_and_stake(10_000_000_000, 0);
        pool.close_stake(&mut s, &owner(), STAKE_LOCK_SECS).unwrap();
        let day_after = STAKE_LOCK_SECS + 86_400;
        let payout = pool.claim(&mut s, &owner(), day_after).unwrap();
        assert!(payout > 0, "rewards should survive unstaking for 30 days");
        // Claimed: nothing left.
        assert_eq!(pool.claim(&mut s, &owner(), day_after).unwrap(), 0);
    }

    #[test]
    fn claim_after_30_days_forfeits() {
        let (mut pool, mut s) = pool_and_stake(10_000_000_000, 0);
        pool.close_stake(&mut s, &owner(), STAKE_LOCK_SECS).unwrap();
        let too_late = STAKE_LOCK_SECS + CLAIM_WINDOW_AFTER_UNSTAKE_SECS + 1;
        let err = pool.claim(&mut s, &owner(), too_late).unwrap_err();
        assert_eq!(err, StakingError::RewardsForfeited);
        assert_eq!(s.rewards_accrued, 0, "forfeited rewards are zeroed");
    }

    #[test]
    fn claim_at_exactly_30_days_still_works() {
        let (mut pool, mut s) = pool_and_stake(10_000_000_000, 0);
        pool.close_stake(&mut s, &owner(), STAKE_LOCK_SECS).unwrap();
        let boundary = STAKE_LOCK_SECS + CLAIM_WINDOW_AFTER_UNSTAKE_SECS;
        assert!(pool.claim(&mut s, &owner(), boundary).unwrap() > 0);
    }

    #[test]
    fn pending_rewards_zero_when_nothing_staked() {
        let mut pool = StakingPool::new();
        let mut s = StakeAccount::empty();
        assert_eq!(pool.pending_rewards(&mut s, 1_000_000).unwrap(), 0);
    }

    #[test]
    fn double_unstake_fails() {
        let (mut pool, mut s) = pool_and_stake(1_000, 0);
        pool.close_stake(&mut s, &owner(), STAKE_LOCK_SECS).unwrap();
        assert_eq!(
            pool.close_stake(&mut s, &owner(), STAKE_LOCK_SECS),
            Err(StakingError::NotStaked)
        );
    }

    #[test]
    fn clock_regression_fails_closed() {
        let mut pool = StakingPool::new();
        pool.accrue(1_000_000).unwrap();
        assert_eq!(
            pool.accrue(999_999),
            Err(StakingError::ClockWentBackwards {
                now: 999_999,
                last_update: 1_000_000
            })
        );
    }

    #[test]
    fn accrue_no_overflow_at_full_supply_over_century() {
        // 1B TRV staked for 100 years at the placeholder APY must not
        // overflow the u128 intermediates.
        let mut pool = StakingPool::new();
        let mut s = StakeAccount::empty();
        pool.open_stake(&mut s, owner(), 1_000_000_000_000_000_000, 0).unwrap();
        pool.accrue(100 * SECS_PER_YEAR).unwrap();
        assert!(pool.reward_per_token_stored > 0);
    }

    #[test]
    fn staking_is_free_no_minimum_beyond_one_unit() {
        let mut pool = StakingPool::new();
        let mut s = StakeAccount::empty();
        assert!(pool.open_stake(&mut s, owner(), 1, 0).is_ok());
        assert_eq!(
            pool.open_stake(&mut s, owner(), 1, 0),
            Err(StakingError::AlreadyStaked)
        );
    }

    #[test]
    fn zero_stake_rejected() {
        let mut pool = StakingPool::new();
        let mut s = StakeAccount::empty();
        assert_eq!(
            pool.open_stake(&mut s, owner(), 0, 0),
            Err(StakingError::ZeroStake)
        );
    }

    #[test]
    fn wrong_owner_rejected() {
        let (mut pool, mut s) = pool_and_stake(1_000, 0);
        assert_eq!(
            pool.close_stake(&mut s, &[9u8; 32], STAKE_LOCK_SECS),
            Err(StakingError::Unauthorized)
        );
        assert_eq!(
            pool.claim(&mut s, &[9u8; 32], STAKE_LOCK_SECS),
            Err(StakingError::Unauthorized)
        );
    }

    #[test]
    fn external_spend_fee_waived_while_staked() {
        let (_, s) = pool_and_stake(1_000, 0);
        assert_eq!(external_spend_fee_bps(&s), 0);
        assert_eq!(
            external_spend_fee_bps(&StakeAccount::empty()),
            EXTERNAL_SPEND_FEE_BPS
        );
    }

    #[test]
    fn total_staked_tracks_open_and_close() {
        let mut pool = StakingPool::new();
        let mut a = StakeAccount::empty();
        let mut b = StakeAccount::empty();
        pool.open_stake(&mut a, [1u8; 32], 100, 0).unwrap();
        pool.open_stake(&mut b, [2u8; 32], 200, 0).unwrap();
        assert_eq!(pool.total_staked, 300);
        pool.close_stake(&mut a, &[1u8; 32], STAKE_LOCK_SECS).unwrap();
        assert_eq!(pool.total_staked, 200);
    }
}
