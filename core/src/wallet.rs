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
//!
//! Token inflow (user decision 2026-10-13): TRV tokens gathered
//! through AR are added to the Remote Viewer's TRV wallet, to be
//! spent on profile customization and other purchases through the
//! Network.
//!
//! Anti-cashout rule (user decision 2026-10-13): AR-earned TRV is
//! soulbound to the Network — it can be spent inside the Network
//! but can never move to an outside wallet. Attempting to cash it
//! out reduces it to dust. See [`AR_DUST_POLICY`].
//!
//! # Arithmetic policy
//!
//! Token math follows one rule: overflow that would be a bug is an
//! *error*, and only documented capping is *saturating*.
//!
//! * Checked ops with [`WalletError`] on overflow: fee/quote math
//!   ([`Wallet::outbound_platform_quote`]). A wrapped fee would
//!   silently undercharge TRV, so overflow is a hard error.
//! * Saturating ops where capping is the documented policy: balance
//!   accumulation (`add_funds`, `buy_trv`, `earn_ar_tokens`,
//!   [`Wallet::trv_tokens`]). A balance can never exceed `u64::MAX`;
//!   the cap — not an error — is the documented behavior there.

/// Basis points (1/100 of a percent) charged to TRV when TRV tokens
/// are relocated to an outside wallet / another platform. User-decided
/// policy (2026-10-13): a 25% transfer fee to TRV. Moving tokens
/// off-platform without paying this fee is not permitted by policy.
pub const TRANSFER_FEE_BPS: u32 = 2500;

/// Human-readable policy statement for the transfer-fee rule.
pub const TRANSFER_FEE_POLICY: &str =
    "No TRV tokens are transferred to other platforms without a transfer fee to TRV.";

/// Human-readable policy statement for the AR anti-cashout rule.
///
/// AR-earned TRV is for in-Network spending only: profile
/// customization and other purchases through the Network. It can
/// never leave for an outside wallet — a cash-out attempt burns it
/// to dust.
pub const AR_DUST_POLICY: &str = "AR-earned TRV is soulbound to the Network: \
    it can be spent inside the Network but can never move to an outside \
    wallet — attempting to cash it out reduces it to dust.";

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
    /// Arithmetic overflow in fee/quote math. Overflow there is a
    /// bug (a wrapped fee would silently undercharge TRV), so it is
    /// a hard error — not a silent wrap and not a cap.
    ArithmeticOverflow,
}

impl WalletError {
    /// Short machine-readable label.
    pub fn label(self) -> &'static str {
        match self {
            WalletError::InvalidAmount => "invalid-amount",
            WalletError::InsufficientFunds => "insufficient-funds",
            WalletError::ArithmeticOverflow => "arithmetic-overflow",
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

/// Outcome of a transfer to an outside wallet.
///
/// Honest accounting for the two token classes: purchased tokens can
/// leave (minus the 25% fee), while any AR-earned tokens swept up by
/// the request are burned to dust and never leave the Network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutsideTransfer {
    /// AR-earned tokens burned as dust (never leaves the Network).
    pub dusted: u64,
    /// Fee owed to TRV on the purchased portion (25%, rounded down).
    pub fee: u64,
    /// Net purchased tokens that actually reach the outside wallet.
    pub net_to_outside: u64,
}

/// A Remote Viewer's own TRV-exclusive wallet.
///
/// State is kept entirely on-device. The `owner` is a local
/// identifier string only (for a future identity module to verify);
/// nothing leaves the device.
///
/// TRV tokens are tracked in two ledgers: `trv_purchased` (bought or
/// otherwise acquired inside the Network and therefore eligible to
/// leave) and `trv_ar_earned` (earned through AR play — soulbound to
/// the Network per [`AR_DUST_POLICY`]).
#[derive(Debug, Clone)]
pub struct Wallet {
    owner: String,
    funds: u64,
    trv_purchased: u64,
    trv_ar_earned: u64,
}

impl Wallet {
    /// Create an empty wallet for a local owner label.
    pub fn new(owner: &str) -> Self {
        Wallet {
            owner: owner.to_string(),
            funds: 0,
            trv_purchased: 0,
            trv_ar_earned: 0,
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

    /// Current TRV token balance (smallest unit), combining the
    /// purchased and AR-earned ledgers.
    pub fn trv_tokens(&self) -> u64 {
        self.trv_purchased.saturating_add(self.trv_ar_earned)
    }

    /// Purchased TRV tokens — the only tokens eligible to leave for
    /// an outside wallet.
    pub fn trv_purchased(&self) -> u64 {
        self.trv_purchased
    }

    /// AR-earned TRV tokens — soulbound to the Network, spendable
    /// in-Network only (see [`AR_DUST_POLICY`]).
    pub fn trv_ar_earned(&self) -> u64 {
        self.trv_ar_earned
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
    /// Bought tokens credit the purchased ledger, so they are
    /// eligible to leave for an outside wallet (with the 25% fee).
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
        self.trv_purchased = self.trv_purchased.saturating_add(tokens);
        Ok(())
    }

    /// Credit TRV tokens gathered through AR geolocation play.
    ///
    /// User decision (2026-10-13): AR-gathered TRV is added to the
    /// Remote Viewer's TRV wallet, to be spent on profile
    /// customization and other purchases through the Network. Like
    /// everything in this module this is a local state transition;
    /// proof of geolocation lives with the (future) AR track.
    ///
    /// AR-earned tokens credit a separate ledger: they are soulbound
    /// to the Network and can never move to an outside wallet (see
    /// [`AR_DUST_POLICY`]).
    pub fn earn_ar_tokens(&mut self, amount: u64) -> Result<(), WalletError> {
        if amount == 0 {
            return Err(WalletError::InvalidAmount);
        }
        self.trv_ar_earned = self.trv_ar_earned.saturating_add(amount);
        Ok(())
    }

    /// Spend TRV tokens inside the Network — e.g. profile
    /// customization and other purchases.
    ///
    /// Either ledger may fund in-Network spending, since AR earnings
    /// are meant to be spent inside the Network. The AR-earned ledger
    /// is consumed first: AR tokens can never leave the Network, so
    /// spending them preserves the viewer's purchased balance (the
    /// only tokens that can ever exit).
    ///
    /// No transfer fee applies: the 25% fee is only for relocating
    /// tokens to an outside wallet (see [`TRANSFER_FEE_BPS`]).
    pub fn spend(&mut self, amount: u64) -> Result<(), WalletError> {
        if amount == 0 {
            return Err(WalletError::InvalidAmount);
        }
        if self.trv_tokens() < amount {
            return Err(WalletError::InsufficientFunds);
        }
        // AR-earned first (soulbound: use it or it's stuck in-network).
        let from_ar = amount.min(self.trv_ar_earned);
        self.trv_ar_earned -= from_ar;
        self.trv_purchased -= amount - from_ar;
        Ok(())
    }

    /// Transfer TRV tokens to another Remote Viewer inside the TRV
    /// network (peer-to-peer, no platform fee per current policy).
    ///
    /// This is in-Network movement, so either ledger may fund it;
    /// AR-earned tokens stay soulbound to the Network when passed
    /// peer-to-peer. Consumes the AR-earned ledger first, for the
    /// same reason as [`Wallet::spend`].
    pub fn send_within_network(&mut self, tokens: u64) -> Result<u64, WalletError> {
        if tokens == 0 {
            return Err(WalletError::InvalidAmount);
        }
        if self.trv_tokens() < tokens {
            return Err(WalletError::InsufficientFunds);
        }
        let from_ar = tokens.min(self.trv_ar_earned);
        self.trv_ar_earned -= from_ar;
        self.trv_purchased -= tokens - from_ar;
        // Returns the amount the recipient receives (no fee in-network).
        Ok(tokens)
    }

    /// Quote the fee TRV collects when purchased tokens relocate to
    /// an outside wallet. Returns `Ok((fee, net_to_wallet))`.
    ///
    /// User-decided policy (2026-10-13): the fee is 25% of the moved
    /// amount, computed with integer math rounding down.
    ///
    /// Arithmetic policy: the `tokens * TRANSFER_FEE_BPS` product is
    /// computed with [`u64::checked_mul`]. Overflow is a bug here — a
    /// wrapped fee would silently undercharge TRV — so it returns
    /// [`WalletError::ArithmeticOverflow`] instead of wrapping or
    /// saturating. The final subtraction cannot underflow (the fee is
    /// at most 25% of `tokens`), so plain `-` is provably safe there.
    ///
    /// This is a local policy computation only; no transfer happens
    /// here and no network is involved. Only purchased tokens can
    /// relocate, so quote the purchased portion.
    pub fn outbound_platform_quote(tokens: u64) -> Result<(u64, u64), WalletError> {
        let scaled = tokens
            .checked_mul(u64::from(TRANSFER_FEE_BPS))
            .ok_or(WalletError::ArithmeticOverflow)?;
        let fee = scaled / 10_000;
        // fee = floor(tokens * 2500 / 10000) <= tokens: no underflow.
        Ok((fee, tokens - fee))
    }

    /// Transfer TRV tokens to an outside wallet.
    ///
    /// Only purchased tokens can leave, paying the user-decided 25%
    /// transfer fee to TRV (see [`TRANSFER_FEE_BPS`]). Any AR-earned
    /// tokens swept up by the requested amount are **burned to dust**
    /// — they never leave the Network (see [`AR_DUST_POLICY`]).
    ///
    /// The request consumes the purchased ledger first. If the
    /// requested amount exceeds the purchased balance, the remainder
    /// comes from the AR-earned ledger and is forfeited as dust, not
    /// transferred. The 25% fee applies only to the purchased
    /// portion; dusted tokens are simply destroyed.
    ///
    /// Deducts the full consumed amount from the wallet and returns
    /// an [`OutsideTransfer`] with honest accounting of what was
    /// dusted, what fee is owed to TRV, and what actually reaches the
    /// outside wallet.
    pub fn transfer_to_platform(
        &mut self,
        tokens: u64,
    ) -> Result<OutsideTransfer, WalletError> {
        if tokens == 0 {
            return Err(WalletError::InvalidAmount);
        }
        if self.trv_tokens() < tokens {
            return Err(WalletError::InsufficientFunds);
        }
        let from_purchased = tokens.min(self.trv_purchased);
        let from_ar = tokens - from_purchased;
        self.trv_purchased -= from_purchased;
        // Burned, not moved: AR-earned TRV can never leave the Network.
        self.trv_ar_earned -= from_ar;
        let (fee, net) = Self::outbound_platform_quote(from_purchased)?;
        Ok(OutsideTransfer {
            dusted: from_ar,
            fee,
            net_to_outside: net,
        })
    }

    /// Balance of one asset.
    pub fn balance(&self, asset: Asset) -> u64 {
        match asset {
            Asset::Funds => self.funds,
            Asset::TrvToken => self.trv_tokens(),
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
        let (fee, net) = Wallet::outbound_platform_quote(5).expect("small quote");
        assert_eq!(fee, 1);
        assert_eq!(net, 4);
        // 25% of 3 = 0.75 -> rounds down to 0.
        let (fee, net) = Wallet::outbound_platform_quote(3).expect("small quote");
        assert_eq!(fee, 0);
        assert_eq!(net, 3);
    }

    #[test]
    fn outbound_platform_quote_errors_on_overflow_instead_of_wrapping() {
        // Regression: the old `tokens * TRANSFER_FEE_BPS` product
        // wrapped (debug) / panicked on huge inputs. Overflow is a
        // bug here, so it must be a hard error.
        assert_eq!(
            Wallet::outbound_platform_quote(u64::MAX),
            Err(WalletError::ArithmeticOverflow)
        );
        assert_eq!(
            Wallet::outbound_platform_quote(u64::MAX - 1),
            Err(WalletError::ArithmeticOverflow)
        );
        assert_eq!(
            WalletError::ArithmeticOverflow.label(),
            "arithmetic-overflow"
        );
        // Boundary: the largest input whose product still fits.
        let max_ok = u64::MAX / u64::from(TRANSFER_FEE_BPS);
        let (fee, net) = Wallet::outbound_platform_quote(max_ok).expect("boundary fits");
        assert_eq!(fee, max_ok * u64::from(TRANSFER_FEE_BPS) / 10_000);
        assert_eq!(fee + net, max_ok);
        // One more token tips the product over u64::MAX.
        assert_eq!(
            Wallet::outbound_platform_quote(max_ok + 1),
            Err(WalletError::ArithmeticOverflow)
        );
    }

    #[test]
    fn ar_earnings_credit_trv_balance() {
        let mut w = Wallet::new("viewer-ar");
        assert_eq!(w.balance(Asset::TrvToken), 0);
        assert!(w.earn_ar_tokens(250).is_ok());
        assert_eq!(w.balance(Asset::TrvToken), 250);
        assert!(w.earn_ar_tokens(750).is_ok());
        assert_eq!(w.balance(Asset::TrvToken), 1_000);
        // Zero earn is rejected.
        assert_eq!(
            w.earn_ar_tokens(0),
            Err(WalletError::InvalidAmount)
        );
        assert_eq!(w.balance(Asset::TrvToken), 1_000);
        // AR earnings credit the AR ledger specifically.
        assert_eq!(w.trv_ar_earned(), 1_000);
        assert_eq!(w.trv_purchased(), 0);
    }

    #[test]
    fn spend_deducts_for_customization_and_purchases() {
        let mut w = Wallet::new("viewer-spend");
        assert!(w.earn_ar_tokens(500).is_ok());
        assert!(w.spend(200).is_ok());
        assert_eq!(w.balance(Asset::TrvToken), 300);
        // Zero spend is rejected.
        assert_eq!(w.spend(0), Err(WalletError::InvalidAmount));
        // Overspend fails and leaves the balance untouched.
        assert_eq!(
            w.spend(301),
            Err(WalletError::InsufficientFunds)
        );
        assert_eq!(w.balance(Asset::TrvToken), 300);
        // Spending everything is allowed.
        assert!(w.spend(300).is_ok());
        assert_eq!(w.balance(Asset::TrvToken), 0);
    }

    #[test]
    fn spend_uses_ar_balance_first() {
        let mut w = Wallet::new("viewer-ar-first");
        assert!(w.add_funds(7_000).is_ok());
        assert!(w.buy_trv(700, 10).is_ok());
        assert!(w.earn_ar_tokens(300).is_ok());
        // Spending 500 consumes the 300 AR tokens first, then 200 purchased.
        assert!(w.spend(500).is_ok());
        assert_eq!(w.trv_ar_earned(), 0);
        assert_eq!(w.trv_purchased(), 500);
        assert_eq!(w.balance(Asset::TrvToken), 500);
    }

    #[test]
    fn ar_only_cashout_turns_everything_to_dust() {
        let mut w = Wallet::new("viewer-dust");
        assert!(w.earn_ar_tokens(500).is_ok());
        let out = w
            .transfer_to_platform(500)
            .expect("transfer runs but dusts");
        // No purchased tokens to move: nothing leaves, no fee owed,
        // and the AR balance is burned to dust.
        assert_eq!(out.dusted, 500);
        assert_eq!(out.fee, 0);
        assert_eq!(out.net_to_outside, 0);
        assert_eq!(w.balance(Asset::TrvToken), 0);
        assert_eq!(w.trv_ar_earned(), 0);
        assert_eq!(w.trv_purchased(), 0);
    }

    #[test]
    fn purchased_only_transfer_keeps_ar_ledger_intact() {
        let mut w = Wallet::new("viewer-mixed");
        assert!(w.add_funds(10_000).is_ok());
        assert!(w.buy_trv(1_000, 10).is_ok());
        assert!(w.earn_ar_tokens(500).is_ok());
        let out = w
            .transfer_to_platform(1_000)
            .expect("transfer works");
        // The request is covered by purchased tokens: nothing dusted,
        // AR ledger untouched, 25% fee on the purchased portion.
        assert_eq!(out.dusted, 0);
        assert_eq!(out.fee, 250);
        assert_eq!(out.net_to_outside, 750);
        assert_eq!(w.trv_purchased(), 0);
        assert_eq!(w.trv_ar_earned(), 500);
        assert_eq!(w.balance(Asset::TrvToken), 500);
    }

    #[test]
    fn transfer_beyond_purchased_dusts_the_ar_shortfall() {
        let mut w = Wallet::new("viewer-shortfall");
        assert!(w.add_funds(4_000).is_ok());
        assert!(w.buy_trv(400, 10).is_ok());
        assert!(w.earn_ar_tokens(500).is_ok());
        // Request 600: 400 purchased moves out (fee 100), 200 AR dusted.
        let out = w
            .transfer_to_platform(600)
            .expect("transfer works");
        assert_eq!(out.dusted, 200);
        assert_eq!(out.fee, 100);
        assert_eq!(out.net_to_outside, 300);
        assert_eq!(w.trv_purchased(), 0);
        assert_eq!(w.trv_ar_earned(), 300);
        assert_eq!(w.balance(Asset::TrvToken), 300);
    }

    #[test]
    fn cashout_rejected_when_total_balance_is_insufficient() {
        let mut w = Wallet::new("viewer-nofunds");
        assert!(w.add_funds(1_000).is_ok());
        assert!(w.buy_trv(100, 10).is_ok());
        assert!(w.earn_ar_tokens(100).is_ok());
        // 300 requested against 200 total: rejected, nothing dusted.
        assert_eq!(
            w.transfer_to_platform(300),
            Err(WalletError::InsufficientFunds)
        );
        assert_eq!(w.trv_purchased(), 100);
        assert_eq!(w.trv_ar_earned(), 100);
    }

    #[test]
    fn transfer_to_platform_deducts_fee_per_bps_quote() {
        let mut w = Wallet::new("viewer-e");
        assert!(w.add_funds(100_000).is_ok());
        assert!(w.buy_trv(10_000, 10).is_ok());
        let tokens = 10_000u64;
        let (fee, net) = Wallet::outbound_platform_quote(tokens).expect("small quote");
        let expected_fee = tokens * u64::from(TRANSFER_FEE_BPS) / 10_000;
        assert_eq!(TRANSFER_FEE_BPS, 2500, "fee is 25% per user policy");
        assert_eq!(fee, expected_fee);
        assert_eq!(fee, 2_500, "25% of 10,000 tokens");
        assert_eq!(net, 7_500, "10,000 tokens minus 25% fee");
        assert_eq!(fee + net, tokens);
        let out = w
            .transfer_to_platform(tokens)
            .expect("platform transfer works");
        assert_eq!(out.fee, fee);
        assert_eq!(out.net_to_outside, net);
        assert_eq!(out.dusted, 0, "no AR involved: nothing dusted");
        assert_eq!(w.balance(Asset::TrvToken), 0);
        assert!(TRANSFER_FEE_POLICY.contains("transfer fee"));
        assert!(TRANSFER_FEE_POLICY.contains("TRV"));
        assert!(AR_DUST_POLICY.contains("soulbound"));
        assert!(AR_DUST_POLICY.contains("dust"));
        assert_eq!(Asset::Funds.name(), "funds");
        assert_eq!(Asset::TrvToken.name(), "TRV");
        assert_eq!(WalletError::InvalidAmount.label(), "invalid-amount");
        assert_eq!(
            WalletError::InsufficientFunds.label(),
            "insufficient-funds"
        );
    }
}
