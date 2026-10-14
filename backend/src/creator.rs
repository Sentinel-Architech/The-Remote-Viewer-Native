//! Creator payout economics for the TRV Network.
//!
//! Standing principle: creators and artists come FIRST. The network
//! takes its cut second. Every number here is integer cents — no float
//! money math — and all computation is local: no network calls.
//!
//! ## Splits (user decisions, 2026-10-13)
//!
//! - Standard content: 80% to the creator, 20% to the network
//!   (for creators earning a living exclusively on TRV).
//! - Adult XXX (consenting adults, behind a paywall): 85/15 —
//!   the only exception to 80/20.
//! - NFTs sold OUTSIDE the network: 20% fee to TRV.
//! - NFTs sold INSIDE the network: no fee, creator keeps 100%.
//! - NFT mint/gas fees can be waived from the community pool
//!   ([`crate::subscriptions::CommunityPool`]), which is funded by
//!   ghost-tier escalation fees.
//!
//! ## Fail-closed money rules
//!
//! - Any arithmetic overflow produces `None` (or
//!   [`PayoutError::Overflow`]), never a payout.
//! - The creator's share is computed first and rounds down; the
//!   network takes the remainder (`sale - creator`), so the two
//!   shares always sum exactly to the sale and any rounding dust
//!   favors the creator.
//!
//! ## Badges
//!
//! Creator badges live in [`crate::badges`]; this module does not
//! duplicate them. [`qualifies_for_creator_economics`] bridges the
//! badge system to the money: the ExclusiveCreator badge is the
//! economic badge that unlocks the full creator share.

use crate::badges::{self, Badge, CreatorProfile};
use crate::subscriptions::CommunityPool;

/// What is being sold. The creator/network split depends on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentKind {
    /// Normal creator content: 80% creator, 20% network.
    Standard,
    /// Adult XXX, consenting adults, behind a paywall of the
    /// creator's choice: 85% creator, 15% network. The one exception
    /// to the 80/20 rule.
    AdultXxx,
}

impl ContentKind {
    /// The creator's share, in whole percent.
    pub fn creator_percent(self) -> u64 {
        match self {
            ContentKind::Standard => 80,
            ContentKind::AdultXxx => 85,
        }
    }
}

/// Errors from creator payout operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayoutError {
    /// Integer overflow while computing a split: no payout produced.
    Overflow,
}

impl core::fmt::Display for PayoutError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            PayoutError::Overflow => "creator payout: arithmetic overflow",
        };
        f.write_str(s)
    }
}

impl std::error::Error for PayoutError {}

/// The result of splitting one sale between creator and network.
///
/// `creator_cents + network_cents` always equals the sale amount.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayoutSplit {
    /// What the creator keeps, in cents.
    pub creator_cents: u64,
    /// What the network keeps, in cents.
    pub network_cents: u64,
}

impl PayoutSplit {
    /// The original sale amount, in cents.
    pub fn total_cents(self) -> u64 {
        // Cannot overflow: creator + network == the sale by construction.
        self.creator_cents + self.network_cents
    }
}

/// Split `sale_cents` between creator and network per [`ContentKind`].
///
/// Fail closed: returns `None` on any arithmetic overflow. The
/// creator's share is computed first and rounded down; the network
/// takes the remainder, so rounding dust always favors the creator.
pub fn split_payout(sale_cents: u64, kind: ContentKind) -> Option<PayoutSplit> {
    let creator_cents = sale_cents
        .checked_mul(kind.creator_percent())?
        .checked_div(100)?;
    // creator_percent <= 100, so creator_cents <= sale_cents; this
    // subtraction cannot underflow.
    let network_cents = sale_cents.checked_sub(creator_cents)?;
    Some(PayoutSplit {
        creator_cents,
        network_cents,
    })
}

/// [`split_payout`] as a `Result`, for callers that want an error value.
///
/// Returns [`PayoutError::Overflow`] where [`split_payout`] returns
/// `None`.
pub fn split_payout_result(
    sale_cents: u64,
    kind: ContentKind,
) -> Result<PayoutSplit, PayoutError> {
    split_payout(sale_cents, kind).ok_or(PayoutError::Overflow)
}

// ---------------------------------------------------------------------------
// NFTs
// ---------------------------------------------------------------------------

/// TRV's cut of an NFT sold OUTSIDE the network: 20% (whole percent).
pub const OUTSIDE_NETWORK_FEE_PERCENT: u64 = 20;

/// Where an NFT sale happens. The venue decides the fee.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaleVenue {
    /// Inside the TRV Network: no fee; the creator keeps 100%.
    InsideNetwork,
    /// Outside the network: 20% fee to TRV, 80% to the creator.
    OutsideNetwork,
}

/// A one-of-a-kind NFT minted from a TRV-camera photo.
///
/// Artists mint from photos taken with the native TRV camera and sell
/// them with TRV art skills. The content hash binds the token to the
/// photo; the record itself is the on-device mint ledger entry (the
/// on-chain TRV-token settlement is the separate Solana track).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NftMint {
    /// Unique token id assigned at mint.
    pub token_id: u64,
    /// The creator's handle.
    pub creator_handle: String,
    /// Hash of the TRV-camera photo content (e.g. SHA-256).
    pub content_hash: [u8; 32],
    /// When the token was minted, unix seconds.
    pub minted_unix_secs: u64,
}

impl NftMint {
    /// Record a new mint. Handles are trimmed.
    pub fn new(
        token_id: u64,
        creator_handle: &str,
        content_hash: [u8; 32],
        minted_unix_secs: u64,
    ) -> Self {
        NftMint {
            token_id,
            creator_handle: creator_handle.trim().to_string(),
            content_hash,
            minted_unix_secs,
        }
    }

    /// Compute the payout for a sale of this NFT at `venue`.
    ///
    /// - [`SaleVenue::InsideNetwork`]: no fee, creator keeps 100%.
    /// - [`SaleVenue::OutsideNetwork`]: 20% to the network, the rest
    ///   to the creator (rounding dust favors the creator, same as
    ///   [`split_payout`]).
    ///
    /// Fail closed: `None` on overflow.
    pub fn sale_payout(&self, sale_cents: u64, venue: SaleVenue) -> Option<PayoutSplit> {
        match venue {
            SaleVenue::InsideNetwork => Some(PayoutSplit {
                creator_cents: sale_cents,
                network_cents: 0,
            }),
            SaleVenue::OutsideNetwork => {
                let network_cents = sale_cents
                    .checked_mul(OUTSIDE_NETWORK_FEE_PERCENT)?
                    .checked_div(100)?;
                let creator_cents = sale_cents.checked_sub(network_cents)?;
                Some(PayoutSplit {
                    creator_cents,
                    network_cents,
                })
            }
        }
    }
}

/// Try to cover an NFT mint/gas fee from the community pool.
///
/// The community pool is funded by ghost-tier escalation fees (see
/// [`crate::subscriptions::CommunityPool`]); it pays the fee when it
/// can. Returns `true` and deducts the fee when covered; returns
/// `false` and leaves the pool untouched when funds are short.
pub fn waive_nft_fee(pool: &mut CommunityPool, fee_cents: u64) -> bool {
    pool.try_waiver(fee_cents)
}

// ---------------------------------------------------------------------------
// Badge bridge
// ---------------------------------------------------------------------------

/// Whether a creator qualifies for the full creator economics
/// (the 80% share and NFT minting).
///
/// The [`Badge::ExclusiveCreator`] badge is the economic badge:
/// creators earning a living exclusively on TRV unlock the full
/// share. Extensible: add further badge-gated economics here as the
/// spec grows.
pub fn qualifies_for_creator_economics(profile: CreatorProfile) -> bool {
    badges::qualifies_for(Badge::ExclusiveCreator, profile)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Splits ----

    #[test]
    fn standard_split_is_80_20_exact() {
        // $10.00 sale: creator $8.00, network $2.00.
        let split = split_payout(1000, ContentKind::Standard).expect("no overflow");
        assert_eq!(split.creator_cents, 800);
        assert_eq!(split.network_cents, 200);
        assert_eq!(split.total_cents(), 1000);
    }

    #[test]
    fn adult_split_is_85_15_exact() {
        // $10.00 sale: creator $8.50, network $1.50.
        let split = split_payout(1000, ContentKind::AdultXxx).expect("no overflow");
        assert_eq!(split.creator_cents, 850);
        assert_eq!(split.network_cents, 150);
        assert_eq!(split.total_cents(), 1000);
    }

    #[test]
    fn split_rounding_dust_favors_creator() {
        // $9.99: creator 799.2 -> 799, network takes the remainder 200.
        let split = split_payout(999, ContentKind::Standard).expect("no overflow");
        assert_eq!(split.creator_cents, 799);
        assert_eq!(split.network_cents, 200);
        assert_eq!(split.total_cents(), 999);
        // $9.99 adult: creator 849.15 -> 849, network 150.
        let split = split_payout(999, ContentKind::AdultXxx).expect("no overflow");
        assert_eq!(split.creator_cents, 849);
        assert_eq!(split.network_cents, 150);
        assert_eq!(split.total_cents(), 999);
    }

    #[test]
    fn split_sums_to_sale_at_many_amounts() {
        for sale in [0u64, 1, 3, 7, 33, 100, 101, 9999, 123_456_789] {
            for kind in [ContentKind::Standard, ContentKind::AdultXxx] {
                let split = split_payout(sale, kind).expect("no overflow");
                assert_eq!(
                    split.total_cents(),
                    sale,
                    "split must always sum to the sale"
                );
            }
        }
    }

    #[test]
    fn split_zero_sale_is_zero_zero() {
        let split = split_payout(0, ContentKind::Standard).expect("no overflow");
        assert_eq!(split.creator_cents, 0);
        assert_eq!(split.network_cents, 0);
    }

    #[test]
    fn split_overflow_fails_closed() {
        // u64::MAX * 80 overflows: no payout is produced.
        assert_eq!(split_payout(u64::MAX, ContentKind::Standard), None);
        assert_eq!(split_payout(u64::MAX, ContentKind::AdultXxx), None);
        // Same through the Result wrapper.
        assert_eq!(
            split_payout_result(u64::MAX, ContentKind::Standard),
            Err(PayoutError::Overflow)
        );
    }

    #[test]
    fn split_result_ok_path() {
        let split = split_payout_result(1000, ContentKind::Standard).expect("ok");
        assert_eq!(split.creator_cents, 800);
    }

    #[test]
    fn content_kind_creator_percents() {
        assert_eq!(ContentKind::Standard.creator_percent(), 80);
        assert_eq!(ContentKind::AdultXxx.creator_percent(), 85);
    }

    // ---- NFTs ----

    fn test_mint() -> NftMint {
        NftMint::new(42, "  alice  ", [0xABu8; 32], 1_700_000_000)
    }

    #[test]
    fn mint_record_trims_handle() {
        let mint = test_mint();
        assert_eq!(mint.token_id, 42);
        assert_eq!(mint.creator_handle, "alice");
        assert_eq!(mint.content_hash, [0xABu8; 32]);
    }

    #[test]
    fn inside_network_sale_has_no_fee() {
        let mint = test_mint();
        // $25.00 sale inside the network: creator keeps everything.
        let split = mint
            .sale_payout(2500, SaleVenue::InsideNetwork)
            .expect("no overflow");
        assert_eq!(split.creator_cents, 2500);
        assert_eq!(split.network_cents, 0);
    }

    #[test]
    fn outside_network_sale_takes_20_percent() {
        let mint = test_mint();
        // $25.00 sale outside the network: 20% to TRV.
        let split = mint
            .sale_payout(2500, SaleVenue::OutsideNetwork)
            .expect("no overflow");
        assert_eq!(split.network_cents, 500);
        assert_eq!(split.creator_cents, 2000);
        assert_eq!(split.total_cents(), 2500);
    }

    #[test]
    fn outside_network_sale_rounding_favors_creator() {
        let mint = test_mint();
        // $9.99: network 199.8 -> 199, creator 800.
        let split = mint
            .sale_payout(999, SaleVenue::OutsideNetwork)
            .expect("no overflow");
        assert_eq!(split.network_cents, 199);
        assert_eq!(split.creator_cents, 800);
        assert_eq!(split.total_cents(), 999);
    }

    #[test]
    fn outside_network_sale_overflow_fails_closed() {
        let mint = test_mint();
        assert_eq!(
            mint.sale_payout(u64::MAX, SaleVenue::OutsideNetwork),
            None
        );
        // Inside-network never does fee math: no overflow possible.
        assert!(mint
            .sale_payout(u64::MAX, SaleVenue::InsideNetwork)
            .is_some());
    }

    #[test]
    fn outside_network_fee_constant_is_20() {
        assert_eq!(OUTSIDE_NETWORK_FEE_PERCENT, 20);
    }

    // ---- Community pool waiver path ----

    #[test]
    fn nft_fee_waiver_covered_by_pool() {
        let mut pool = CommunityPool::new();
        pool.deposit(2000); // ghost fees in
        assert!(waive_nft_fee(&mut pool, 500)); // $5 gas waiver
        assert_eq!(pool.balance_cents(), 1500);
    }

    #[test]
    fn nft_fee_waiver_fails_closed_when_pool_short() {
        let mut pool = CommunityPool::new();
        pool.deposit(300);
        assert!(!waive_nft_fee(&mut pool, 500));
        // Pool untouched on denial.
        assert_eq!(pool.balance_cents(), 300);
    }

    #[test]
    fn nft_fee_waiver_end_to_end_ghost_fees_fund_mint() {
        use crate::subscriptions::GhostAccount;
        let mut pool = CommunityPool::new();
        let ghost = GhostAccount::new(1_700_000_000);
        let start = ghost.ghost_since();
        // Two ghost months feed the pool: $10 + $15 = $25.
        ghost
            .pay_monthly_fee(&mut pool, start + 60 * 86_400)
            .expect("collect");
        ghost
            .pay_monthly_fee(&mut pool, start + 90 * 86_400)
            .expect("collect");
        assert_eq!(pool.balance_cents(), 2500);
        // A $20 mint gas fee is waived from the pool.
        assert!(waive_nft_fee(&mut pool, 2000));
        assert_eq!(pool.balance_cents(), 500);
    }

    // ---- Badge bridge ----

    #[test]
    fn exclusive_creator_gets_full_economics() {
        let profile = CreatorProfile::new(true, true, false);
        assert!(qualifies_for_creator_economics(profile));
    }

    #[test]
    fn non_exclusive_creator_does_not() {
        let profile = CreatorProfile::new(true, false, true);
        assert!(!qualifies_for_creator_economics(profile));
    }

    #[test]
    fn non_creator_gets_nothing() {
        let profile = CreatorProfile::new(false, false, false);
        assert!(!qualifies_for_creator_economics(profile));
    }

    // ---- Errors ----

    #[test]
    fn payout_error_display_is_stable() {
        assert_eq!(
            format!("{}", PayoutError::Overflow),
            "creator payout: arithmetic overflow"
        );
    }
}
