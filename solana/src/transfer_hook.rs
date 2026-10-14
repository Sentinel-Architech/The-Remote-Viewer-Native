//! TRV transfer hook: outside-wallet fee + AR soulbound rule.
//!
//! Policy (user decisions 2026-10-13):
//!
//! * Moving TRV to an **outside wallet** (any destination that is not
//!   a TRV Network wallet) pays a **25% transfer fee** to the TRV
//!   treasury. In-Network transfers are fee-free.
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

    // In-Network moves are fee-free.
    if req.to == WalletKind::Network {
        return Ok(TransferReceipt {
            net: req.amount,
            fee: 0,
            burned: 0,
        });
    }

    // Outside-wallet move: levy the 25% fee to the treasury.
    let (fee, net) = split_fee(req.amount, TRANSFER_FEE_BPS).map_err(TransferHookError::Math)?;
    Ok(TransferReceipt { net, fee, burned: 0 })
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
}
