//! TRV anti-manipulation guards: pump-and-dump prohibition.
//!
//! Policy (user decision 2026-10-14): **"PUMP N DUMP is PROHIBITED."**
//!
//! These guards are deterrents and speed-bumps, **not a guarantee**.
//! A sufficiently distributed coordinated dump — many small wallets
//! each staying under every limit — cannot be fully prevented by
//! code. What the guards do is make manipulation slow, expensive,
//! and visible:
//!
//! 1. **Transfer velocity limits** — an address may move at most
//!    10% of its balance to outside wallets per 24h
//!    ([`VELOCITY_MAX_BPS_OF_BALANCE`]). Addresses with an active
//!    90-day stake get a higher 25% limit
//!    ([`VELOCITY_MAX_BPS_OF_BALANCE_STAKED`]): stakers have
//!    committed, so they are trusted with faster exits.
//! 2. **Cooldown on large transfers** — any single outside transfer
//!    of >= 5% of total supply ([`LARGE_TRANSFER_BPS_OF_SUPPLY`])
//!    locks that address out of further outside transfers for 72h
//!    ([`COOLDOWN_SECS`]).
//! 3. **Buy/sell asymmetry** — TRV bought and then sold within 7
//!    days ([`FLIP_WINDOW_SECS`]) pays an extra 15%
//!    ([`FLIP_PENALTY_BPS`]) flip penalty on the flipped amount,
//!    on top of the standard 25% outside-transfer fee. This targets
//!    the pump-and-dump pattern directly: fast in, fast out.
//! 4. **Whale watch** — an address holding >= 1% of total supply
//!    ([`WHALE_HOLDING_BPS_OF_SUPPLY`]) that moves > 50% of its
//!    holdings to outside wallets in 24h
//!    ([`WHALE_DUMP_BPS_OF_HOLDINGS`]) is **flagged** in a
//!    transparent event ([`WhaleFlag`]). Flagged, never frozen —
//!    consistent with the project's transparency values.
//!
//!    Honest interaction note: the 10%/25% velocity caps make a
//!    single-window >50% outside move unreachable through
//!    [`guard_transfer`] — that is the cap doing its job. The
//!    flag's real power is (a) the off-chain indexer aggregating
//!    24h movement across consecutive windows to catch sustained
//!    dumping that the caps only slow down, and (b) defense in
//!    depth if governance ever raises the caps. [`check_whale`]
//!    is a pure predicate so the program and the indexer share one
//!    definition of "whale dump".
//! 5. **Early-unstake review flag** — unstaking before the 90-day
//!    lock stays prohibited ([`crate::staking::StakingError::StillLocked`]);
//!    a failed attempt additionally produces an
//!    [`EarlyUnstakeFlag`] for review.
//! 6. **Community pool beneficiary** — every manipulation penalty
//!    levied here routes to the **community pool**
//!    ([`COMMUNITY_POOL_PLACEHOLDER`]), per the user rule
//!    (2026-10-14): "Any service fees go to community pool native
//!    in TRV market." The standard 25%/20% fees keep going to the
//!    treasury ([`crate::transfer_hook::TREASURY_PLACEHOLDER`]);
//!    manipulation penalties are separate and go to the pool.
//!
//! # Deploy mapping (for the Anchor adapter, later)
//!
//! * `GuardState` is a PDA per wallet (seeds: wallet pubkey,
//!   `"guard"`). The adapter loads it, calls [`guard_transfer`],
//!   and persists the returned state.
//! * `FlipTracker::record_acquisition` is called by the adapter
//!   whenever the wallet receives TRV from an outside source (a
//!   buy-in). In-Network receipts are not acquisitions.
//! * `flag_early_unstake` is called by the adapter when an
//!   `Unstake` instruction fails with `StakingError::StillLocked`.
//! * `WhaleFlag`s are emitted as program log events; an off-chain
//!   indexer builds the public whale-watch feed from them.
//! * Timestamps (`now`) are injected unix seconds, never read here —
//!   same pattern as the rest of this crate.
//!
//! All thresholds are `pub const` so governance can tune them via a
//! program upgrade, never silently.

use crate::math::{fee_bps, MathError};
use crate::token::TRV_TOTAL_SUPPLY;
use core::fmt;

/// Rolling window for velocity accounting: 24 hours.
pub const VELOCITY_WINDOW_SECS: u64 = 86_400;

/// Max outside-wallet movement per 24h, as basis points of the
/// address's balance: 1_000 = 10%. Tunable.
pub const VELOCITY_MAX_BPS_OF_BALANCE: u32 = 1_000;

/// Same, for addresses holding an active 90-day stake: 2_500 = 25%.
/// Stakers have committed their tokens, so they get faster exits.
/// Tunable.
pub const VELOCITY_MAX_BPS_OF_BALANCE_STAKED: u32 = 2_500;

/// A single outside transfer at or above this share of total supply
/// triggers the 72h cooldown: 500 bps = 5%. Tunable.
pub const LARGE_TRANSFER_BPS_OF_SUPPLY: u32 = 500;

/// Cooldown after a large transfer: 72 hours. No outside transfers
/// from that address until it expires. Tunable.
pub const COOLDOWN_SECS: u64 = 72 * 86_400;

/// Buy-then-sell window: selling within 7 days of buying pays the
/// flip penalty. Tunable.
pub const FLIP_WINDOW_SECS: u64 = 7 * 86_400;

/// Flip penalty on the flipped amount, in basis points: 1_500 = 15%.
/// Routes to the community pool. Tunable.
pub const FLIP_PENALTY_BPS: u32 = 1_500;

/// Whale threshold: holding at least this share of total supply
/// (100 bps = 1%) puts an address on the whale watch. Tunable.
pub const WHALE_HOLDING_BPS_OF_SUPPLY: u32 = 100;

/// Whale dump threshold: moving more than this share of holdings
/// (5_000 bps = 50%) to outside wallets in 24h triggers a flag.
/// Tunable.
pub const WHALE_DUMP_BPS_OF_HOLDINGS: u32 = 5_000;

/// Community pool pubkey: every manipulation penalty levied here is
/// routed to the community pool, NOT the treasury. Placeholder
/// bytes — replaced by the real pool address at deploy. All-`0xFF`,
/// deliberately distinct from the all-zero
/// [`crate::transfer_hook::TREASURY_PLACEHOLDER`], so the two fee
/// destinations can never be confused with each other.
pub const COMMUNITY_POOL_PLACEHOLDER: [u8; 32] = [0xFFu8; 32];

/// Per-wallet rolling 24h record of outside-wallet movement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VelocityTracker {
    /// Unix time the current window started. 0 = never used.
    pub window_start: u64,
    /// Base units moved to outside wallets in the current window.
    pub moved_outside: u64,
}

/// Per-wallet cooldown state after a large transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CooldownState {
    /// Unix time the cooldown expires. 0 = no cooldown.
    pub cooldown_until: u64,
}

/// Tracks the wallet's most recent outside acquisition (buy-in) so
/// rapid buy-then-sell can be penalized.
///
/// "No buy recorded" is defined by `last_buy_amount == 0`, NOT by
/// the timestamp: unix time 0 is a valid (if ancient) timestamp, so
/// the timestamp alone cannot serve as the empty sentinel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FlipTracker {
    /// Unix time of the most recent acquisition.
    pub last_buy_at: u64,
    /// Base units acquired in that buy. 0 = none recorded.
    pub last_buy_amount: u64,
}

/// The full per-wallet guard state (one PDA per wallet on-chain).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GuardState {
    pub velocity: VelocityTracker,
    pub cooldown: CooldownState,
    pub flip: FlipTracker,
}

/// A transparent whale-movement event. Emitted, never enforced:
///
/// flagging is public accountability, not a freeze.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WhaleFlag {
    /// The whale's wallet pubkey.
    pub address: [u8; 32],
    /// Its balance at flag time (base units).
    pub balance: u64,
    /// Base units it moved to outside wallets in the last 24h.
    pub moved_24h: u64,
    /// Unix time the flag was raised.
    pub flagged_at: u64,
}

/// A failed early-unstake attempt, for review. The unstake itself
/// remains prohibited; this record exists so repeated attempts are
/// visible to governance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EarlyUnstakeFlag {
    /// The would-be unstaker's pubkey.
    pub owner: [u8; 32],
    /// Unix time of the attempt.
    pub attempted_at: u64,
    /// Unix time the 90-day lock actually expires.
    pub locked_until: u64,
}

/// Anti-manipulation errors. Every failure is explicit — nothing panics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AntiDumpError {
    /// Fee/limit math overflowed.
    Math(MathError),
    /// The transfer would push 24h outside movement past the limit.
    VelocityExceeded {
        /// Base units attempted in this transfer.
        attempted: u64,
        /// Base units already moved in the current 24h window.
        moved_24h: u64,
        /// The 24h limit for this address.
        limit: u64,
    },
    /// The address is in a large-transfer cooldown.
    CooldownActive {
        now: u64,
        cooldown_until: u64,
    },
    /// `now` moved backwards relative to recorded state. On-chain
    /// time is monotonic; a regression is a caller bug. Fail closed.
    ClockWentBackwards { now: u64, reference: u64 },
}

impl fmt::Display for AntiDumpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AntiDumpError::Math(e) => write!(f, "anti-dump math error: {e}"),
            AntiDumpError::VelocityExceeded { attempted, moved_24h, limit } => write!(
                f,
                "velocity limit exceeded: attempted {attempted}, already moved {moved_24h} in 24h, limit {limit}"
            ),
            AntiDumpError::CooldownActive { now, cooldown_until } => write!(
                f,
                "large-transfer cooldown active until {cooldown_until} (now {now})"
            ),
            AntiDumpError::ClockWentBackwards { now, reference } => write!(
                f,
                "clock went backwards: now {now} < recorded {reference}"
            ),
        }
    }
}

/// The 24h outside-transfer limit for an address: 10% of balance,
/// or 25% while it holds an active 90-day stake.
pub fn velocity_limit(balance: u64, staked: bool) -> Result<u64, AntiDumpError> {
    let bps = if staked {
        VELOCITY_MAX_BPS_OF_BALANCE_STAKED
    } else {
        VELOCITY_MAX_BPS_OF_BALANCE
    };
    fee_bps(balance, bps).map_err(AntiDumpError::Math)
}

/// Enforce the velocity limit: record `amount` of outside movement
/// and fail if the 24h window is exceeded. Resets the window when it
/// has elapsed. Mutates `tracker` only on success.
pub fn check_velocity(
    tracker: &mut VelocityTracker,
    amount: u64,
    balance: u64,
    staked: bool,
    now: u64,
) -> Result<(), AntiDumpError> {
    if now < tracker.window_start {
        return Err(AntiDumpError::ClockWentBackwards {
            now,
            reference: tracker.window_start,
        });
    }
    let mut window_start = tracker.window_start;
    let mut moved = tracker.moved_outside;
    // "Never used" is window_start == 0 AND nothing moved: a window
    // that genuinely started at unix time 0 is distinguished by its
    // recorded movement. (Unix time 0 alone cannot be the sentinel —
    // it is a valid timestamp.)
    let never_used = window_start == 0 && moved == 0;
    if never_used || now - window_start >= VELOCITY_WINDOW_SECS {
        // Fresh window (or first use): start counting from now.
        window_start = now;
        moved = 0;
    }
    let limit = velocity_limit(balance, staked)?;
    let new_moved = moved
        .checked_add(amount)
        .ok_or(AntiDumpError::Math(MathError::Overflow))?;
    if new_moved > limit {
        return Err(AntiDumpError::VelocityExceeded {
            attempted: amount,
            moved_24h: moved,
            limit,
        });
    }
    tracker.window_start = window_start;
    tracker.moved_outside = new_moved;
    Ok(())
}

/// Reject the transfer if the address is inside a large-transfer
/// cooldown.
pub fn check_cooldown(state: &CooldownState, now: u64) -> Result<(), AntiDumpError> {
    if now < state.cooldown_until {
        return Err(AntiDumpError::CooldownActive {
            now,
            cooldown_until: state.cooldown_until,
        });
    }
    Ok(())
}

/// If `amount` is a large transfer (>= 5% of total supply), start a
/// 72h cooldown on the address. Returns true when triggered.
pub fn maybe_trigger_cooldown(
    state: &mut CooldownState,
    amount: u64,
    now: u64,
) -> Result<bool, AntiDumpError> {
    let threshold = fee_bps(TRV_TOTAL_SUPPLY, LARGE_TRANSFER_BPS_OF_SUPPLY)
        .map_err(AntiDumpError::Math)?;
    if amount < threshold {
        return Ok(false);
    }
    state.cooldown_until = now
        .checked_add(COOLDOWN_SECS)
        .ok_or(AntiDumpError::Math(MathError::Overflow))?;
    Ok(true)
}

/// Record an outside acquisition (buy-in). Called by the adapter
/// whenever the wallet receives TRV from an outside source.
/// Tracks the most recent buy — the canonical pump-and-dump pattern
/// is a single buy followed by a fast sell.
pub fn record_acquisition(flip: &mut FlipTracker, amount: u64, now: u64) {
    flip.last_buy_at = now;
    flip.last_buy_amount = amount;
}

/// Compute the flip penalty for selling `sell_amount` base units.
/// If the most recent buy is within the 7-day window, the overlapped
/// portion pays 15% to the community pool. The overlapped buy amount
/// is consumed so repeat sells are not double-penalized.
pub fn flip_penalty(
    flip: &mut FlipTracker,
    sell_amount: u64,
    now: u64,
) -> Result<u64, AntiDumpError> {
    // Empty is defined by amount, not timestamp (see struct docs).
    if flip.last_buy_amount == 0 {
        return Ok(0);
    }
    if now < flip.last_buy_at {
        return Err(AntiDumpError::ClockWentBackwards {
            now,
            reference: flip.last_buy_at,
        });
    }
    if now - flip.last_buy_at > FLIP_WINDOW_SECS {
        // Buy is stale: the window expired, no penalty. Clear it.
        flip.last_buy_at = 0;
        flip.last_buy_amount = 0;
        return Ok(0);
    }
    let flipped = sell_amount.min(flip.last_buy_amount);
    let penalty = fee_bps(flipped, FLIP_PENALTY_BPS).map_err(AntiDumpError::Math)?;
    flip.last_buy_amount -= flipped;
    if flip.last_buy_amount == 0 {
        flip.last_buy_at = 0;
    }
    Ok(penalty)
}

/// Whale watch: flag an address holding >= 1% of supply that moved
/// > 50% of its holdings to outside wallets in 24h. Returns `None`
/// when there is nothing to flag. This is transparency, not a
/// freeze — the transfer itself is unaffected.
pub fn check_whale(
    address: [u8; 32],
    balance: u64,
    moved_24h: u64,
    now: u64,
) -> Result<Option<WhaleFlag>, AntiDumpError> {
    let whale_threshold = fee_bps(TRV_TOTAL_SUPPLY, WHALE_HOLDING_BPS_OF_SUPPLY)
        .map_err(AntiDumpError::Math)?;
    if balance < whale_threshold {
        return Ok(None);
    }
    let dump_threshold = fee_bps(balance, WHALE_DUMP_BPS_OF_HOLDINGS)
        .map_err(AntiDumpError::Math)?;
    if moved_24h > dump_threshold {
        Ok(Some(WhaleFlag {
            address,
            balance,
            moved_24h,
            flagged_at: now,
        }))
    } else {
        Ok(None)
    }
}

/// Build the review flag for a failed early-unstake attempt. The
/// adapter calls this when `Unstake` fails with
/// [`crate::staking::StakingError::StillLocked`]; the unstake stays
/// prohibited.
pub fn flag_early_unstake(
    owner: [u8; 32],
    attempted_at: u64,
    locked_until: u64,
) -> EarlyUnstakeFlag {
    EarlyUnstakeFlag {
        owner,
        attempted_at,
        locked_until,
    }
}

/// What [`guard_transfer`] decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuardedTransferReceipt {
    /// Gross base units the transfer attempted to move.
    pub amount: u64,
    /// Flip penalty levied (base units) — routes to the COMMUNITY
    /// POOL ([`COMMUNITY_POOL_PLACEHOLDER`]), never the treasury.
    pub community_pool_fee: u64,
    /// Updated guard state for the wallet (persist on-chain).
    pub state: GuardState,
    /// Whale flag, if the movement tripped the whale watch.
    pub whale_flag: Option<WhaleFlag>,
    /// True when this transfer triggered a fresh 72h cooldown.
    pub cooldown_triggered: bool,
}

/// Run every anti-manipulation guard on an outside-wallet transfer,
/// in order: cooldown → velocity → flip penalty → whale watch.
///
/// In-Network transfers (`is_outside == false`) skip the guards
/// entirely: moving TRV inside the Network is everyday activity, not
/// a dump vector. The flip tracker is still consulted for outside
/// transfers only.
///
/// On success the returned receipt carries the updated guard state
/// (which the adapter must persist) and any community-pool fee.
/// The caller still applies the standard transfer hook
/// ([`crate::transfer_hook::execute_transfer`]) separately — these
/// guards compose with it, they do not replace it.
pub fn guard_transfer(
    address: [u8; 32],
    amount: u64,
    balance: u64,
    staked: bool,
    is_outside: bool,
    mut state: GuardState,
    now: u64,
) -> Result<GuardedTransferReceipt, AntiDumpError> {
    if !is_outside {
        return Ok(GuardedTransferReceipt {
            amount,
            community_pool_fee: 0,
            state,
            whale_flag: None,
            cooldown_triggered: false,
        });
    }

    // 1. Cooldown first: a cooling-down address moves nothing.
    check_cooldown(&state.cooldown, now)?;

    // 2. Velocity: cap 24h outside movement.
    check_velocity(&mut state.velocity, amount, balance, staked, now)?;

    // 3. Flip penalty: fast buy-then-sell pays extra to the pool.
    let community_pool_fee = flip_penalty(&mut state.flip, amount, now)?;

    // 4. Large transfers start a fresh 72h cooldown.
    let cooldown_triggered = maybe_trigger_cooldown(&mut state.cooldown, amount, now)?;

    // 5. Whale watch: transparent flag on the updated 24h movement.
    let whale_flag = check_whale(address, balance, state.velocity.moved_outside, now)?;

    Ok(GuardedTransferReceipt {
        amount,
        community_pool_fee,
        state,
        whale_flag,
        cooldown_triggered,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr() -> [u8; 32] {
        [11u8; 32]
    }

    fn fresh_state() -> GuardState {
        GuardState::default()
    }

    // --- 1. Velocity limits ---

    #[test]
    fn velocity_caps_outside_movement_at_10_percent() {
        // Balance 1_000 -> 24h limit is 100.
        let mut t = VelocityTracker::default();
        check_velocity(&mut t, 60, 1_000, false, 1_000).unwrap();
        check_velocity(&mut t, 40, 1_000, false, 1_001).unwrap();
        assert_eq!(t.moved_outside, 100);
        // One more unit exceeds the limit.
        let err = check_velocity(&mut t, 1, 1_000, false, 1_002).unwrap_err();
        assert!(matches!(
            err,
            AntiDumpError::VelocityExceeded { attempted: 1, moved_24h: 100, limit: 100 }
        ));
        // Failed attempt leaves the tracker untouched.
        assert_eq!(t.moved_outside, 100);
    }

    #[test]
    fn velocity_window_resets_after_24h() {
        let mut t = VelocityTracker::default();
        check_velocity(&mut t, 100, 1_000, false, 0).unwrap();
        // 24h later the window resets and the full limit is back.
        check_velocity(&mut t, 100, 1_000, false, VELOCITY_WINDOW_SECS).unwrap();
        assert_eq!(t.moved_outside, 100);
        assert_eq!(t.window_start, VELOCITY_WINDOW_SECS);
    }

    #[test]
    fn staked_addresses_get_higher_velocity_limit() {
        // Same balance: unstaked limit 100, staked limit 250.
        assert_eq!(velocity_limit(1_000, false).unwrap(), 100);
        assert_eq!(velocity_limit(1_000, true).unwrap(), 250);
        let mut t = VelocityTracker::default();
        check_velocity(&mut t, 200, 1_000, true, 0).unwrap();
        assert_eq!(t.moved_outside, 200);
    }

    #[test]
    fn velocity_clock_backwards_fails_closed() {
        let mut t = VelocityTracker { window_start: 5_000, moved_outside: 10 };
        let err = check_velocity(&mut t, 1, 1_000, false, 4_999).unwrap_err();
        assert_eq!(
            err,
            AntiDumpError::ClockWentBackwards { now: 4_999, reference: 5_000 }
        );
    }

    // --- 2. Cooldown ---

    #[test]
    fn large_transfer_triggers_72h_cooldown() {
        let threshold = fee_bps(TRV_TOTAL_SUPPLY, LARGE_TRANSFER_BPS_OF_SUPPLY).unwrap();
        let mut s = CooldownState::default();
        // Just under: no cooldown.
        assert!(!maybe_trigger_cooldown(&mut s, threshold - 1, 0).unwrap());
        assert_eq!(s.cooldown_until, 0);
        // At threshold: cooldown starts.
        assert!(maybe_trigger_cooldown(&mut s, threshold, 1_000).unwrap());
        assert_eq!(s.cooldown_until, 1_000 + COOLDOWN_SECS);
        // Blocked during cooldown.
        let err = check_cooldown(&s, 1_001).unwrap_err();
        assert_eq!(
            err,
            AntiDumpError::CooldownActive { now: 1_001, cooldown_until: 1_000 + COOLDOWN_SECS }
        );
        // Expired: allowed again.
        check_cooldown(&s, 1_000 + COOLDOWN_SECS).unwrap();
    }

    #[test]
    fn guard_transfer_blocks_during_cooldown() {
        let state = GuardState {
            cooldown: CooldownState { cooldown_until: 10_000 },
            ..Default::default()
        };
        let err = guard_transfer(addr(), 10, 1_000_000, false, true, state, 9_999).unwrap_err();
        assert!(matches!(err, AntiDumpError::CooldownActive { .. }));
    }

    // --- 3. Flip penalty ---

    #[test]
    fn rapid_flip_pays_15_percent_to_community_pool() {
        let mut f = FlipTracker::default();
        record_acquisition(&mut f, 1_000, 0);
        // Sell 400 within 7 days: 15% of 400 = 60.
        let penalty = flip_penalty(&mut f, 400, FLIP_WINDOW_SECS - 1).unwrap();
        assert_eq!(penalty, 60);
        // The flipped 400 is consumed; selling the rest penalizes 600.
        let penalty = flip_penalty(&mut f, 600, FLIP_WINDOW_SECS - 1).unwrap();
        assert_eq!(penalty, 90);
        // Buy fully consumed: no more penalty.
        assert_eq!(f.last_buy_amount, 0);
        assert_eq!(flip_penalty(&mut f, 600, FLIP_WINDOW_SECS - 1).unwrap(), 0);
    }

    #[test]
    fn stale_buy_pays_no_flip_penalty() {
        let mut f = FlipTracker::default();
        record_acquisition(&mut f, 1_000, 0);
        // One second past the window: no penalty, tracker cleared.
        assert_eq!(flip_penalty(&mut f, 1_000, FLIP_WINDOW_SECS + 1).unwrap(), 0);
        assert_eq!(f, FlipTracker::default());
    }

    #[test]
    fn flip_penalty_capped_at_bought_amount() {
        let mut f = FlipTracker::default();
        record_acquisition(&mut f, 100, 0);
        // Selling more than was bought: penalty only on the 100.
        assert_eq!(flip_penalty(&mut f, 10_000, 1).unwrap(), 15);
    }

    // --- 4. Whale watch ---

    #[test]
    fn whale_moving_half_holdings_gets_flagged() {
        // 1% of supply balance; move 51% in 24h.
        let balance = fee_bps(TRV_TOTAL_SUPPLY, WHALE_HOLDING_BPS_OF_SUPPLY).unwrap();
        let moved = balance * 51 / 100;
        let flag = check_whale(addr(), balance, moved, 7_777).unwrap().unwrap();
        assert_eq!(flag.address, addr());
        assert_eq!(flag.balance, balance);
        assert_eq!(flag.moved_24h, moved);
        assert_eq!(flag.flagged_at, 7_777);
    }

    #[test]
    fn whale_under_threshold_not_flagged() {
        let balance = fee_bps(TRV_TOTAL_SUPPLY, WHALE_HOLDING_BPS_OF_SUPPLY).unwrap();
        // Exactly 50% is not *more than* 50%.
        let moved = balance / 2;
        assert_eq!(check_whale(addr(), balance, moved, 0).unwrap(), None);
        // Below the 1% whale line entirely.
        assert_eq!(check_whale(addr(), balance - 1, u64::MAX, 0).unwrap(), None);
    }

    // --- 5. Early-unstake flag ---

    #[test]
    fn early_unstake_attempt_produces_review_flag() {
        let flag = flag_early_unstake(addr(), 1_000, 2_000);
        assert_eq!(
            flag,
            EarlyUnstakeFlag { owner: addr(), attempted_at: 1_000, locked_until: 2_000 }
        );
    }

    // --- 6. Community pool routing ---

    #[test]
    fn penalty_recipient_is_community_pool_not_treasury() {
        // The two destinations must never be confused.
        assert_ne!(
            COMMUNITY_POOL_PLACEHOLDER,
            crate::transfer_hook::TREASURY_PLACEHOLDER,
            "community pool and treasury placeholders must differ"
        );
        // A guarded flip produces a community-pool fee on the receipt.
        let mut flip = FlipTracker::default();
        record_acquisition(&mut flip, 1_000, 0);
        let state = GuardState { flip, ..Default::default() };
        let r = guard_transfer(addr(), 1_000, 100_000, false, true, state, 1).unwrap();
        assert_eq!(r.community_pool_fee, 150);
    }

    // --- 7. Composition ---

    #[test]
    fn normal_small_transfers_unaffected() {
        // A small everyday transfer: no velocity issue, no flip, no
        // whale flag, no cooldown. Guards are invisible.
        let r = guard_transfer(addr(), 50, 100_000, false, true, fresh_state(), 1_000).unwrap();
        assert_eq!(r.community_pool_fee, 0);
        assert_eq!(r.whale_flag, None);
        assert!(!r.cooldown_triggered);
        assert_eq!(r.state.velocity.moved_outside, 50);
    }

    #[test]
    fn in_network_transfers_skip_guards() {
        // Even a huge in-Network move touches no guard state.
        let r = guard_transfer(
            addr(),
            TRV_TOTAL_SUPPLY / 2,
            TRV_TOTAL_SUPPLY,
            false,
            false,
            fresh_state(),
            1_000,
        )
        .unwrap();
        assert_eq!(r.state, GuardState::default());
        assert_eq!(r.whale_flag, None);
        assert!(!r.cooldown_triggered);
    }

    #[test]
    fn staked_whale_exits_faster_but_velocity_still_caps_window() {
        // Staked 1%-holder moves the full 25% staked limit in one
        // window: allowed, and correctly NOT whale-flagged (25% is
        // under the 50% flag line). A second chunk in the same
        // window breaches the velocity cap — the cap is what stops
        // the dump, the flag is the backstop.
        let balance = fee_bps(TRV_TOTAL_SUPPLY, WHALE_HOLDING_BPS_OF_SUPPLY).unwrap();
        let chunk = balance * 25 / 100;
        let r = guard_transfer(addr(), chunk, balance, true, true, fresh_state(), 0).unwrap();
        assert_eq!(r.whale_flag, None);
        assert_eq!(r.state.velocity.moved_outside, chunk);
        let err = guard_transfer(addr(), chunk, balance, true, true, r.state, 1).unwrap_err();
        assert!(matches!(err, AntiDumpError::VelocityExceeded { .. }));
    }

    #[test]
    fn sustained_dump_across_windows_still_flags() {
        // The off-chain indexer aggregates 24h movement across
        // consecutive windows; check_whale flags sustained dumping
        // that the per-window velocity caps can only slow down.
        let balance = fee_bps(TRV_TOTAL_SUPPLY, WHALE_HOLDING_BPS_OF_SUPPLY).unwrap();
        let aggregated_24h = balance * 51 / 100;
        let flag = check_whale(addr(), balance, aggregated_24h, 0).unwrap();
        assert!(flag.is_some());
        assert_eq!(flag.unwrap().moved_24h, aggregated_24h);
    }

    #[test]
    fn constants_match_documented_policy() {
        assert_eq!(VELOCITY_WINDOW_SECS, 86_400);
        assert_eq!(VELOCITY_MAX_BPS_OF_BALANCE, 1_000);
        assert_eq!(VELOCITY_MAX_BPS_OF_BALANCE_STAKED, 2_500);
        assert_eq!(LARGE_TRANSFER_BPS_OF_SUPPLY, 500);
        assert_eq!(COOLDOWN_SECS, 72 * 86_400);
        assert_eq!(FLIP_WINDOW_SECS, 7 * 86_400);
        assert_eq!(FLIP_PENALTY_BPS, 1_500);
        assert_eq!(WHALE_HOLDING_BPS_OF_SUPPLY, 100);
        assert_eq!(WHALE_DUMP_BPS_OF_HOLDINGS, 5_000);
    }

    #[test]
    fn error_display_is_human_readable() {
        let e = AntiDumpError::VelocityExceeded { attempted: 5, moved_24h: 100, limit: 100 };
        let s = format!("{e}");
        assert!(s.contains("velocity limit exceeded"));
        let e = AntiDumpError::CooldownActive { now: 1, cooldown_until: 2 };
        assert!(format!("{e}").contains("cooldown"));
        let e = AntiDumpError::ClockWentBackwards { now: 1, reference: 2 };
        assert!(format!("{e}").contains("backwards"));
    }
}
