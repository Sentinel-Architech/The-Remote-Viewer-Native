//! TRV fixed-supply mint.
//!
//! Policy (user decision 2026-10-13): the TRV token has a fixed total
//! supply. The mint authority may mint up to [`TRV_TOTAL_SUPPLY`]
//! base units; once the cap is reached — or the authority explicitly
//! locks the mint — no further tokens can ever be created. There is no
//! inflation mechanism and no backdoor mint path.

use crate::math::MathError;
use core::fmt;

/// Token decimals: 9, the Solana convention (1 TRV = 10^9 base units).
pub const TRV_DECIMALS: u8 = 9;

/// Fixed total supply: 1,000,000,000 TRV expressed in base units.
///
/// 10^18 fits comfortably in `u64` (`u64::MAX` ≈ 1.8 × 10^19).
pub const TRV_TOTAL_SUPPLY: u64 = 1_000_000_000_000_000_000;

/// On-chain mint state (mirrors the Anchor account layout).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MintState {
    /// Base units minted so far.
    pub minted_so_far: u64,
    /// 32-byte mint authority pubkey (opaque here; verified on-chain).
    pub mint_authority: [u8; 32],
    /// When true, no further minting is possible, ever.
    pub supply_locked: bool,
}

/// Mint errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MintError {
    /// Minting `amount` would exceed [`TRV_TOTAL_SUPPLY`].
    SupplyCapExceeded,
    /// The mint is locked; no further tokens can be created.
    MintLocked,
    /// Caller is not the mint authority.
    Unauthorized,
    /// Fee/quote math overflowed (defensive; unreachable in practice).
    Math(MathError),
}

impl fmt::Display for MintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MintError::SupplyCapExceeded => write!(f, "mint would exceed fixed total supply"),
            MintError::MintLocked => write!(f, "mint supply is permanently locked"),
            MintError::Unauthorized => write!(f, "caller is not the mint authority"),
            MintError::Math(e) => write!(f, "mint math error: {e}"),
        }
    }
}

impl MintState {
    /// Create a fresh mint with zero supply.
    pub fn initialize(mint_authority: [u8; 32]) -> Self {
        MintState {
            minted_so_far: 0,
            mint_authority,
            supply_locked: false,
        }
    }

    /// Mint `amount` base units. Fails closed on cap, lock, or wrong authority.
    pub fn mint_to(
        &mut self,
        caller: &[u8; 32],
        amount: u64,
    ) -> Result<u64, MintError> {
        if *caller != self.mint_authority {
            return Err(MintError::Unauthorized);
        }
        if self.supply_locked {
            return Err(MintError::MintLocked);
        }
        let new_total = self
            .minted_so_far
            .checked_add(amount)
            .ok_or(MintError::Math(MathError::Overflow))?;
        if new_total > TRV_TOTAL_SUPPLY {
            return Err(MintError::SupplyCapExceeded);
        }
        self.minted_so_far = new_total;
        if new_total == TRV_TOTAL_SUPPLY {
            // Cap reached: lock automatically so the invariant
            // "minted == cap implies locked" always holds.
            self.supply_locked = true;
        }
        Ok(new_total)
    }

    /// Permanently lock the mint. Irreversible by design.
    pub fn lock_supply(&mut self, caller: &[u8; 32]) -> Result<(), MintError> {
        if *caller != self.mint_authority {
            return Err(MintError::Unauthorized);
        }
        self.supply_locked = true;
        Ok(())
    }

    /// Base units still mintable.
    pub fn remaining(&self) -> u64 {
        TRV_TOTAL_SUPPLY.saturating_sub(self.minted_so_far)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authority() -> [u8; 32] {
        [7u8; 32]
    }

    #[test]
    fn mint_up_to_cap_then_auto_locks() {
        let mut m = MintState::initialize(authority());
        m.mint_to(&authority(), TRV_TOTAL_SUPPLY).unwrap();
        assert!(m.supply_locked);
        assert_eq!(m.mint_to(&authority(), 1), Err(MintError::MintLocked));
    }

    #[test]
    fn cap_exceeded_rejected() {
        let mut m = MintState::initialize(authority());
        m.mint_to(&authority(), TRV_TOTAL_SUPPLY - 1).unwrap();
        assert_eq!(
            m.mint_to(&authority(), 2),
            Err(MintError::SupplyCapExceeded)
        );
        // Failed mint leaves state untouched.
        assert_eq!(m.minted_so_far, TRV_TOTAL_SUPPLY - 1);
    }

    #[test]
    fn wrong_authority_rejected() {
        let mut m = MintState::initialize(authority());
        assert_eq!(
            m.mint_to(&[9u8; 32], 100),
            Err(MintError::Unauthorized)
        );
        assert_eq!(m.lock_supply(&[9u8; 32]), Err(MintError::Unauthorized));
    }

    #[test]
    fn explicit_lock_is_irreversible() {
        let mut m = MintState::initialize(authority());
        m.lock_supply(&authority()).unwrap();
        assert_eq!(m.mint_to(&authority(), 1), Err(MintError::MintLocked));
        assert_eq!(m.remaining(), TRV_TOTAL_SUPPLY);
    }

    #[test]
    fn supply_constant_fits_u64() {
        assert!(TRV_TOTAL_SUPPLY <= u64::MAX / 2);
        assert_eq!(TRV_TOTAL_SUPPLY, 10u64.pow(9 + TRV_DECIMALS as u32));
    }
}
