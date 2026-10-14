//! TRV transfer hook: outside-wallet fee + AR soulbound rule.
//!
//! Policy (user decisions 2026-10-13, fee-waiver update 2026-10-14):
//!
//! * Moving TRV to an **outside wallet** (any destination that is not
//!   a TRV Network wallet) pays a **25% transfer fee** to the TRV
//!   treasury. In-Network transfers are fee-free.
//! * **Spending** TRV outside the Network (a separate action from
//!   moving it between wallets) pays a **20% spending fee**.
//!   See [`apply_spending_fee`].
//! * **Stakers are exempt**: while a wallet holds an active 90-day
//!   stake, BOTH the 25% transfer fee and the 20% spending fee are
//!   waived. The waiver is caller-attested here
//!   (`sender_stake_waiver`); on-chain the adapter verifies it
//!   against the sender's stake account via
//!   [`crate::staking::StakeAccount::waiver_active`].
//! * AR-earned TRV is **soulbound** to the Network: it can be spent
//!   inside the Network but can never move to an outside wallet.
//!   A cash-out attempt burns it to **dust** (the transfer nets
//!   zero and the tokens are destroyed).
//!
//! On-chain this is implemented as a Token-2022 transfer hook: the
//! hook program below runs on every transfer of the TRV mint and
//! either approves it, levies the fee, or burns soulbound tokens.

use crate::math::{split_fee, MathError};
use core::fmt;

/// 25% transfer fee on outside-wallet moves, in basis points.
/// Matches `trv_core::wallet::TRANSFER_FEE_BPS`.
pub const TRANSFER_FEE_BPS: u32 = 2_500;

/// 20% spending fee on outside-Network spends, in basis points.
/// Waived (0) for the duration of an active 90-day stake.
pub const SPEND_FEE_BPS: u32 = 2_000;

/// Where the 25% fee goes: the TRV treasury (pubkey set at deploy).
/// Placeholder bytes — replaced by the real treasury address on deploy.
pub const TREASURY_PLACEHOLDER: [u8; 32] = [0u8; 32];

/// What kind of wallet a transfer endpoint is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletKind {
    /// A TRV Network wallet (in-Network).
    Network,
    /// Any wallet outside the TRV Network.
    Outside,
}

/// A transfer request presented to the hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferRequest {
    /// Base units to move (gross).
    pub amount: u64,
    /// Kind of the source wallet.
    pub from: WalletKind,
    /// Kind of the destination wallet.
    pub to: WalletKind,
    /// True if the tokens were earned via AR (soulbound).
    pub ar_earned: bool,
    /// True if the sender holds an active 90-day stake, waiving the
    /// 25% outside-wallet fee. Caller-attested; on-chain the adapter
    /// verifies it against the sender's stake account via
    /// [`crate::staking::StakeAccount::waiver_active`].
    pub sender_stake_waiver: bool,
}

/// What the hook decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferReceipt {
    /// Base units the recipient receives.
    pub net: u64,
    /// Base units routed to the TRV treasury.
    pub fee: u64,
    /// Base units burned to dust (AR cash-out attempts).
    pub burned: u64,
}

/// Quote from [`apply_transfer_fee`]: what the recipient gets and
/// what the treasury takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferFeeQuote {
    /// Base units the recipient receives.
    pub net: u64,
    /// Base units routed to the TRV treasury.
    pub fee: u64,
}

/// Quote from [`apply_spending_fee`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpendFeeQuote {
    /// Base units the spender keeps / the merchant receives.
    pub net: u64,
    /// Base units routed to the TRV treasury.
    pub fee: u64,
}

/// Transfer hook errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferHookError {
    /// Fee math overflowed.
    Math(MathError),
}

impl fmt::Display for TransferHookError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransferHookError::Math(e) => write!(f, "transfer hook math error: {e}"),
        }
    }
}

/// Run the transfer hook. Never panics; all policy branches are explicit.
pub fn execute_transfer(req: TransferRequest) -> Result<TransferReceipt, TransferHookError> {
    // AR soulbound rule first: it overrides everything. Soulbound
    // tokens can never leave the Network; the attempt burns them.
    if req.ar_earned && req.to == WalletKind::Outside {
        return Ok(TransferReceipt {
            net: 0,
            fee: 0,
            burned: req.amount,
        });
    }

    let quote = apply_transfer_fee(
        req.amount,
        req.to == WalletKind::Outside,
        req.sender_stake_waiver,
    )?;
    Ok(TransferReceipt {
        net: quote.net,
        fee: quote.fee,
        burned: 0,
    })
}

/// Apply the 25% outside-wallet transfer fee.
///
/// * In-Network moves (`is_outside_wallet == false`): fee-free.
/// * Active 90-day stakers (`staker_waiver_active == true`): fee-free.
/// * Otherwise: 25% ([`TRANSFER_FEE_BPS`]) to the treasury.
///
/// Dust amounts whose fee rounds to zero pass through with no fee
/// rather than failing. All math is checked; overflow is an error.
pub fn apply_transfer_fee(
    amount: u64,
    is_outside_wallet: bool,
    staker_waiver_active: bool,
) -> Result<TransferFeeQuote, TransferHookError> {
    if !is_outside_wallet || staker_waiver_active {
        return Ok(TransferFeeQuote { net: amount, fee: 0 });
    }
    let (fee, net) = split_fee(amount, TRANSFER_FEE_BPS).map_err(TransferHookError::Math)?;
    Ok(TransferFeeQuote { net, fee })
}

/// Apply the 20% outside-Network spending fee.
///
/// This is a SEPARATE fee from the transfer fee: it applies when TRV
/// is *spent* outside the Network (e.g. at an outside merchant),
/// not when it merely moves between wallets.
///
/// * In-Network spends (`is_outside_network == false`): fee-free.
/// * Active 90-day stakers (`staker_waiver_active == true`): fee-free.
/// * Otherwise: 20% ([`SPEND_FEE_BPS`]) to the treasury.
///
/// Dust amounts whose fee rounds to zero pass through with no fee
/// rather than failing. All math is checked; overflow is an error.
pub fn apply_spending_fee(
    amount: u64,
    is_outside_network: bool,
    staker_waiver_active: bool,
) -> Result<SpendFeeQuote, TransferHookError> {
    if !is_outside_network || staker_waiver_active {
        return Ok(SpendFeeQuote { net: amount, fee: 0 });
    }
    let (fee, net) = split_fee(amount, SPEND_FEE_BPS).map_err(TransferHookError::Math)?;
    Ok(SpendFeeQuote { net, fee })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(amount: u64, to: WalletKind, ar_earned: bool) -> TransferRequest {
        TransferRequest {
            amount,
            from: WalletKind::Network,
            to,
            ar_earned,
            sender_stake_waiver: false,
        }
    }

    fn req_waived(amount: u64, to: WalletKind) -> TransferRequest {
        TransferRequest {
            amount,
            from: WalletKind::Network,
            to,
            ar_earned: false,
            sender_stake_waiver: true,
        }
    }

    #[test]
    fn in_network_is_fee_free() {
        let r = execute_transfer(req(1_000, WalletKind::Network, false)).unwrap();
        assert_eq!(r, TransferReceipt { net: 1_000, fee: 0, burned: 0 });
    }

    #[test]
    fn outside_move_pays_25_percent() {
        let r = execute_transfer(req(1_000, WalletKind::Outside, false)).unwrap();
        assert_eq!(r.fee, 250);
        assert_eq!(r.net, 750);
        assert_eq!(r.fee + r.net, 1_000);
    }

    #[test]
    fn ar_cashout_burns_to_dust() {
        let r = execute_transfer(req(1_000, WalletKind::Outside, true)).unwrap();
        assert_eq!(r, TransferReceipt { net: 0, fee: 0, burned: 1_000 });
    }

    #[test]
    fn ar_spend_inside_network_allowed() {
        let r = execute_transfer(req(1_000, WalletKind::Network, true)).unwrap();
        assert_eq!(r.net, 1_000);
        assert_eq!(r.burned, 0);
    }

    #[test]
    fn dust_amounts_round_down() {
        // 25% of 3 = 0.75 -> 0 fee; the dust stays with the recipient.
        let r = execute_transfer(req(3, WalletKind::Outside, false)).unwrap();
        assert_eq!(r.fee, 0);
        assert_eq!(r.net, 3);
    }

    #[test]
    fn max_amount_splits_cleanly() {
        let r = execute_transfer(req(u64::MAX, WalletKind::Outside, false)).unwrap();
        assert_eq!(r.fee + r.net, u64::MAX);
    }

    #[test]
    fn staker_waiver_zeroes_outside_transfer_fee() {
        let r = execute_transfer(req_waived(1_000, WalletKind::Outside)).unwrap();
        assert_eq!(r, TransferReceipt { net: 1_000, fee: 0, burned: 0 });
    }

    #[test]
    fn staker_waiver_does_not_save_ar_cashout() {
        // Soulbound rule overrides the waiver: AR tokens still burn.
        let r = TransferRequest {
            amount: 1_000,
            from: WalletKind::Network,
            to: WalletKind::Outside,
            ar_earned: true,
            sender_stake_waiver: true,
        };
        let r = execute_transfer(r).unwrap();
        assert_eq!(r, TransferReceipt { net: 0, fee: 0, burned: 1_000 });
    }

    #[test]
    fn apply_transfer_fee_matrix() {
        // In-network: free regardless of waiver.
        assert_eq!(
            apply_transfer_fee(1_000, false, false).unwrap(),
            TransferFeeQuote { net: 1_000, fee: 0 }
        );
        assert_eq!(
            apply_transfer_fee(1_000, false, true).unwrap(),
            TransferFeeQuote { net: 1_000, fee: 0 }
        );
        // Outside without waiver: 25%.
        assert_eq!(
            apply_transfer_fee(1_000, true, false).unwrap(),
            TransferFeeQuote { net: 750, fee: 250 }
        );
        // Outside with waiver: free.
        assert_eq!(
            apply_transfer_fee(1_000, true, true).unwrap(),
            TransferFeeQuote { net: 1_000, fee: 0 }
        );
        // Dust passes through.
        assert_eq!(
            apply_transfer_fee(3, true, false).unwrap(),
            TransferFeeQuote { net: 3, fee: 0 }
        );
        // Max amount: no overflow, sums exactly.
        let q = apply_transfer_fee(u64::MAX, true, false).unwrap();
        assert_eq!(q.fee + q.net, u64::MAX);
    }

    #[test]
    fn apply_spending_fee_matrix() {
        // 20% == 2_000 bps.
        assert_eq!(SPEND_FEE_BPS, 2_000);
        // In-network spend: free.
        assert_eq!(
            apply_spending_fee(1_000, false, false).unwrap(),
            SpendFeeQuote { net: 1_000, fee: 0 }
        );
        // Outside spend without waiver: 20%.
        assert_eq!(
            apply_spending_fee(1_000, true, false).unwrap(),
            SpendFeeQuote { net: 800, fee: 200 }
        );
        // Outside spend with active stake waiver: free.
        assert_eq!(
            apply_spending_fee(1_000, true, true).unwrap(),
            SpendFeeQuote { net: 1_000, fee: 0 }
        );
        // Dust passes through.
        assert_eq!(
            apply_spending_fee(4, true, false).unwrap(),
            SpendFeeQuote { net: 4, fee: 0 }
        );
        // Max amount: no overflow, sums exactly.
        let q = apply_spending_fee(u64::MAX, true, false).unwrap();
        assert_eq!(q.fee + q.net, u64::MAX);
    }

    #[test]
    fn transfer_and_spend_fees_are_separate() {
        // Same amount, outside, no waiver: 25% to move, 20% to spend.
        let t = apply_transfer_fee(10_000, true, false).unwrap();
        let s = apply_spending_fee(10_000, true, false).unwrap();
        assert_eq!((t.fee, t.net), (2_500, 7_500));
        assert_eq!((s.fee, s.net), (2_000, 8_000));
    }
}
