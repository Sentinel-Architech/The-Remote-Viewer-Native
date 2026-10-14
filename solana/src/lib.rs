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
//!   moves to outside wallets, and the AR soulbound "dust" rule.
//! * [`staking`] — 90-day locked staking. Free to enter regardless
//!   of amount, no early unstake, proportional rewards, and the 20%
//!   external-spend fee is waived while staked.
//!
//! # Policy sources
//!
//! All fee and lock parameters below are user decisions recorded in
//! the workspace spec (2026-10-13). They are constants here so a
//! future governance vote can only change them via a program
//! upgrade, never silently.

pub mod math;
pub mod program;
pub mod staking;
pub mod token;
pub mod transfer_hook;

pub use math::MathError;
pub use program::{Instruction, ProgramError};
pub use staking::{StakeAccount, StakingError, STAKE_LOCK_SECS};
pub use token::{MintState, MintError, TRV_DECIMALS, TRV_TOTAL_SUPPLY};
pub use transfer_hook::{TransferHookError, TransferReceipt, TRANSFER_FEE_BPS};
