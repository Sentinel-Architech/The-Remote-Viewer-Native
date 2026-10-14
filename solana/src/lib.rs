//! TRV token programs for Solana — chain-agnostic pure-Rust logic.
//!
//! This crate holds the complete business logic for the three TRV
//! on-chain programs as ordinary Rust: no Solana SDK, no Anchor
//! dependency, standard library only. Every instruction handler is a
//! pure function over explicit state structs, so the entire suite is
//! testable offline with `cargo test`.
//!
//! To deploy, the logic in [`program`] is wrapped by a thin
//! Anchor (or `solana-program`) adapter that deserializes accounts
//! and forwards to these functions. See `README.md` for the full
//! deploy checklist.
//!
//! # Programs
//!
//! * [`token`] — fixed-supply TRV mint. The mint authority can mint
//!   up to [`token::TRV_TOTAL_SUPPLY`] and then the supply is
//!   permanently locked; no inflation is possible afterwards.
//! * [`transfer_hook`] — transfer hook enforcing the 25% TRV fee on
//!   moves to outside wallets, the separate 20% outside-Network
//!   spending fee, the staker fee waiver, and the AR soulbound
//!   "dust" rule.
//! * [`staking`] — 90-day locked staking. Free to enter regardless
//!   of amount, no early unstake, proportional rewards at a
//!   placeholder 5% APY, and both the 25% transfer fee and the 20%
//!   external-spend fee waived while the lock is active.
//! * [`referral`] — $5 in TRV per friend who registers via QR and
//!   pays for verification; claimable within 14 days, then expired.
//! * [`anti_dump`] — pump-and-dump prohibition: transfer velocity
//!   limits, 72h cooldowns on large transfers, a 15% flip penalty
//!   on rapid buy-then-sell (to the community pool), transparent
//!   whale-watch flagging, and early-unstake review flags.
//!
//! # Policy sources
//!
//! All fee and lock parameters below are user decisions recorded in
//! the workspace spec (2026-10-13, economics 2026-10-14). They are
//! constants here so a future governance vote can only change them
//! via a program upgrade, never silently.
//!
//! # Placeholders (not final — set before mainnet)
//!
//! * [`staking::REWARD_APY_BPS_PLACEHOLDER`] — 5% APY reward rate.
//! * [`referral::TRV_USD_CENTS_PLACEHOLDER`] — $1/TRV price for the
//!   $5 referral reward.
//! * [`transfer_hook::TREASURY_PLACEHOLDER`] — treasury pubkey.
//! * [`program::PROGRAM_ID`] — program address.

pub mod anti_dump;
pub mod math;
pub mod program;
pub mod referral;
pub mod staking;
pub mod token;
pub mod transfer_hook;
pub mod identity;

pub use anti_dump::{
    AntiDumpError, CooldownState, EarlyUnstakeFlag, FlipTracker, GuardState, GuardedTransferReceipt,
    VelocityTracker, WhaleFlag, COMMUNITY_POOL_PLACEHOLDER, COOLDOWN_SECS, FLIP_PENALTY_BPS,
    FLIP_WINDOW_SECS, LARGE_TRANSFER_BPS_OF_SUPPLY, VELOCITY_MAX_BPS_OF_BALANCE,
    VELOCITY_MAX_BPS_OF_BALANCE_STAKED, VELOCITY_WINDOW_SECS, WHALE_DUMP_BPS_OF_HOLDINGS,
    WHALE_HOLDING_BPS_OF_SUPPLY,
};
pub use math::MathError;
pub use program::{Instruction, ProgramError};
pub use referral::{
    ReferralError, ReferralLedger, ReferralRecord, REFERRAL_CLAIM_WINDOW_SECS,
    REFERRAL_REWARD_BASE_UNITS,
};
pub use staking::{
    StakeAccount, StakingError, StakingPool, CLAIM_WINDOW_AFTER_UNSTAKE_SECS,
    REWARD_APY_BPS_PLACEHOLDER, STAKE_LOCK_SECS,
};
pub use token::{MintState, MintError, TRV_DECIMALS, TRV_TOTAL_SUPPLY};
pub use transfer_hook::{
    TransferHookError, TransferReceipt, TRANSFER_FEE_BPS, SPEND_FEE_BPS,
};
