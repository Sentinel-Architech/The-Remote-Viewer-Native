//! TRV-exclusive digital wallet for each Remote Viewer.
//!
//! Every Remote Viewer gets their own wallet to add money or buy
//! through the TRV ecosystem. This is a local state machine only:
//! balances, add-funds, and buy flows are tracked on-device with no
//! network I/O and no Solana code (token/governance is a separate
//! track per spec).
//!
//! Custody policy (user decision 2026-10-13): each Remote Viewer is
//! 100% in charge of their own crypto wallet. Wallets are
//! exclusively TRV and self-custodied — the viewer holds their own
//! keys, TRV never takes custody of anyone's wallet or keys, and
//! keys never leave the device. See [`Custody`].
//!
//! Policy: TRV tokens cannot move to other platforms without a
//! transfer fee paid to TRV. The fee is expressed as a constant
//! here; enforcement lives with the (future) token track.

/// Basis points (1/100 of a percent) charged to TRV when TRV tokens
/// are relocated to an outside wallet / another platform. User-decided
/// policy (2026-10-13): a 25% transfer fee to TRV. Moving tokens
/// off-platform without paying this fee is not permitted by policy.
pub const TRANSFER_FEE_BPS: u32 = 2500;

/// Human-readable policy statement for the transfer-fee rule.
pub const TRANSFER_FEE_POLICY: &str =
    "No TRV tokens are transferred to other platforms without a transfer fee to TRV.";

/// Token/economy unit held in the wallet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Asset {
    /// Local funds added by the owner (e.g. money loaded for use
    /// inside the TRV ecosystem).
    Funds,
    /// TRV token, earned or bought inside the TRV ecosystem.
    TrvToken,
}

impl Asset {
    /// Canonical name for display in a future native UI.
    pub fn name(self) -> &'static str {
        match self {
            Asset::Funds => "funds",
            Asset::TrvToken => "TRV",
        }
    }
}

/// Errors for wallet state transitions. All local; no I/O.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletError {
    /// Amount was zero or negative (amounts are u64, so zero).
    InvalidAmount,
    /// Not enough of the asset to complete the operation.
    InsufficientFunds,
}

impl WalletError {
    /// Short machine-readable label.
    pub fn label(self) -> &'static str {
        match self {
            WalletError::InvalidAmount => "invalid-amount",
            WalletError::InsufficientFunds => "insufficient-funds",
        }
    }
}

/// Custody model for a Remote Viewer's wallet.
///
/// User decision (2026-10-13): each Remote Viewer is 100% in charge
/// of their own crypto wallet. There is exactly one custody model —
/// self-custody — so no custodial variant exists and one can never
/// be added without a deliberate policy change.
///
/// Concretely:
/// * the viewer holds their own keys;
/// * TRV never takes custody of a viewer's wallet or keys;
/// * keys never leave the device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Custody {
    /// The viewer — and only the viewer — controls the wallet.
    SelfCustodied,
}

impl Custody {
    /// Short machine-readable label.
    pub fn label(self) -> &'static str {
        match self {
            Custody::SelfCustodied => "self-custodied",
        }
    }
}

/// A Remote Viewer's own TRV-exclusive wallet.
///
/// State is kept entirely on-device. The `owner` is a local
/// identifier string only (for a future identity module to verify);
/// nothing leaves the device.
#[derive(Debug, Clone)]
pub struct Wallet {
    owner: String,
    funds: u64,
    trv_tokens: u64,
}

impl Wallet {
    /// Create an empty wallet for a local owner label.
    pub fn new(owner: &str) -> Self {
        Wallet {
            owner: owner.to_string(),
            funds: 0,
            trv_tokens: 0,
        }
    }

    /// Custody model for this wallet.
    ///
    /// Always [`Custody::SelfCustodied`]: each Remote Viewer is 100%
    /// in charge of their own crypto wallet, which is exclusively
    /// TRV. TRV never takes custody of a viewer's wallet or keys,
    /// and keys never leave the device.
    pub fn custody(&self) -> Custody {
        Custody::SelfCustodied
    }

    /// Local owner label.
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Current added-funds balance (smallest unit).
    pub fn funds(&self) -> u64 {
        self.funds
    }

    /// Current TRV token balance (smallest unit).
    pub fn trv_tokens(&self) -> u64 {
        self.trv_tokens
    }

    /// Add money to the wallet. Local-only state transition.
    pub fn add_funds(&mut self, amount: u64) -> Result<(), WalletError> {
        if amount == 0 {
            return Err(WalletError::InvalidAmount);
        }
        self.funds = self.funds.saturating_add(amount);
        Ok(())
    }

    /// Buy TRV tokens with added funds at a fixed local rate.
    ///
    /// `rate_per_token` is the funds cost of one token. This is a
    /// stub conversion for local testing; pricing policy is decided
    /// elsewhere.
    pub fn buy_trv(
        &mut self,
        tokens: u64,
        rate_per_token: u64,
    ) -> Result<(), WalletError> {
        if tokens == 0 || rate_per_token == 0 {
            return Err(WalletError::InvalidAmount);
        }
        let cost = tokens.saturating_mul(rate_per_token);
        if self.funds < cost {
            return Err(WalletError::InsufficientFunds);
        }
        self.funds -= cost;
        self.trv_tokens = self.trv_tokens.saturating_add(tokens);
        Ok(())
    }

    /// Transfer TRV tokens to another Remote Viewer inside the TRV
    /// network (peer-to-peer, no platform fee per current policy).
    pub fn send_within_network(&mut self, tokens: u64) -> Result<u64, WalletError> {
        if tokens == 0 {
            return Err(WalletError::InvalidAmount);
        }
        if self.trv_tokens < tokens {
            return Err(WalletError::InsufficientFunds);
        }
        self.trv_tokens -= tokens;
        // Returns the amount the recipient receives (no fee in-network).
        Ok(tokens)
    }

    /// Quote the fee TRV collects when tokens relocate to an outside
    /// wallet. Returns `(fee, net_to_wallet)`.
    ///
    /// User-decided policy (2026-10-13): the fee is 25% of the moved
    /// amount, computed with integer math rounding down.
    ///
    /// This is a local policy computation only; no transfer happens
    /// here and no network is involved.
    pub fn outbound_platform_quote(tokens: u64) -> (u64, u64) {
        let fee = tokens * u64::from(TRANSFER_FEE_BPS) / 10_000;
        (fee, tokens.saturating_sub(fee))
    }

    /// Transfer TRV tokens to an outside wallet, paying the user-decided
    /// 25% transfer fee to TRV. Deducts the full amount from the wallet
    /// and returns the fee owed to TRV; the caller/settlement layer
    /// delivers `net_to_wallet`.
    pub fn transfer_to_platform(&mut self, tokens: u64) -> Result<u64, WalletError> {
        if tokens == 0 {
            return Err(WalletError::InvalidAmount);
        }
        if self.trv_tokens < tokens {
            return Err(WalletError::InsufficientFunds);
        }
        self.trv_tokens -= tokens;
        let (fee, _net) = Self::outbound_platform_quote(tokens);
        Ok(fee)
    }

    /// Balance of one asset.
    pub fn balance(&self, asset: Asset) -> u64 {
        match asset {
            Asset::Funds => self.funds,
            Asset::TrvToken => self.trv_tokens,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wallet_is_self_custodied() {
        let w = Wallet::new("viewer-self");
        // The only custody model is self-custody: the viewer is 100%
        // in charge of their own TRV-exclusive wallet.
        assert_eq!(w.custody(), Custody::SelfCustodied);
        assert_eq!(w.custody().label(), "self-custodied");
        // Exhaustive match proves no custodial variant can exist
        // without a deliberate policy change.
        match w.custody() {
            Custody::SelfCustodied => {}
        }
    }

    #[test]
    fn add_funds_increases_balance() {
        let mut w = Wallet::new("viewer-a");
        assert_eq!(w.balance(Asset::Funds), 0);
        assert!(w.add_funds(150).is_ok());
        assert_eq!(w.balance(Asset::Funds), 150);
        assert!(w.add_funds(50).is_ok());
        assert_eq!(w.balance(Asset::Funds), 200);
    }

    #[test]
    fn invalid_and_zero_amounts_rejected() {
        let mut w = Wallet::new("viewer-b");
        assert_eq!(w.add_funds(0), Err(WalletError::InvalidAmount));
        assert_eq!(
            w.buy_trv(0, 10),
            Err(WalletError::InvalidAmount)
        );
        assert_eq!(
            w.buy_trv(10, 0),
            Err(WalletError::InvalidAmount)
        );
        assert_eq!(
            w.send_within_network(0),
            Err(WalletError::InvalidAmount)
        );
        assert_eq!(
            w.transfer_to_platform(0),
            Err(WalletError::InvalidAmount)
        );
        assert_eq!(w.balance(Asset::Funds), 0);
        assert_eq!(w.balance(Asset::TrvToken), 0);
    }

    #[test]
    fn insufficient_funds_rejected() {
        let mut w = Wallet::new("viewer-c");
        assert!(w.add_funds(100).is_ok());
        assert_eq!(
            w.buy_trv(50, 10),
            Err(WalletError::InsufficientFunds)
        );
        assert!(w.buy_trv(5, 10).is_ok()); // costs 50
        assert_eq!(w.balance(Asset::Funds), 50);
        assert_eq!(w.balance(Asset::TrvToken), 5);
        assert_eq!(
            w.send_within_network(6),
            Err(WalletError::InsufficientFunds)
        );
        assert_eq!(
            w.transfer_to_platform(6),
            Err(WalletError::InsufficientFunds)
        );
    }

    #[test]
    fn send_within_network_has_no_fee() {
        let mut w = Wallet::new("viewer-d");
        assert!(w.add_funds(1_000).is_ok());
        assert!(w.buy_trv(40, 10).is_ok());
        let before = w.balance(Asset::TrvToken);
        let received = w.send_within_network(40).expect("send works");
        assert_eq!(received, 40, "in-network send must have no fee");
        assert_eq!(w.balance(Asset::TrvToken), before - 40);
    }

    #[test]
    fn transfer_fee_rounds_down_with_integer_math() {
        // 25% of 5 = 1.25 -> rounds down to 1.
        let (fee, net) = Wallet::outbound_platform_quote(5);
        assert_eq!(fee, 1);
        assert_eq!(net, 4);
        // 25% of 3 = 0.75 -> rounds down to 0.
        let (fee, net) = Wallet::outbound_platform_quote(3);
        assert_eq!(fee, 0);
        assert_eq!(net, 3);
    }

    #[test]
    fn transfer_to_platform_deducts_fee_per_bps_quote() {
        let mut w = Wallet::new("viewer-e");
        assert!(w.add_funds(100_000).is_ok());
        assert!(w.buy_trv(10_000, 10).is_ok());
        let tokens = 10_000u64;
        let (fee, net) = Wallet::outbound_platform_quote(tokens);
        let expected_fee = tokens * u64::from(TRANSFER_FEE_BPS) / 10_000;
        assert_eq!(TRANSFER_FEE_BPS, 2500, "fee is 25% per user policy");
        assert_eq!(fee, expected_fee);
        assert_eq!(fee, 2_500, "25% of 10,000 tokens");
        assert_eq!(net, 7_500, "10,000 tokens minus 25% fee");
        assert_eq!(fee + net, tokens);
        let fee_charged = w
            .transfer_to_platform(tokens)
            .expect("platform transfer works");
        assert_eq!(fee_charged, fee);
        assert_eq!(w.balance(Asset::TrvToken), 0);
        assert!(TRANSFER_FEE_POLICY.contains("transfer fee"));
        assert!(TRANSFER_FEE_POLICY.contains("TRV"));
        assert_eq!(Asset::Funds.name(), "funds");
        assert_eq!(Asset::TrvToken.name(), "TRV");
        assert_eq!(WalletError::InvalidAmount.label(), "invalid-amount");
        assert_eq!(
            WalletError::InsufficientFunds.label(),
            "insufficient-funds"
        );
    }
}
