//! Checked fee arithmetic shared by the TRV programs.
//!
//! Token math follows one rule, matching `trv_core::wallet`: overflow
//! that would be a bug is an *error*; only documented capping is
//! saturating. Fee math always runs through `u128` intermediates so a
//! large amount can never wrap a fee into an undercharge.

use core::fmt;

/// Errors from fee/quote math.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MathError {
    /// A fee or net amount did not fit back into `u64`.
    Overflow,
    /// Basis points were above 10_000 (more than 100%).
    InvalidBps,
}

impl fmt::Display for MathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MathError::Overflow => write!(f, "fee math overflowed u64"),
            MathError::InvalidBps => write!(f, "basis points exceed 100%"),
        }
    }
}

/// Compute `amount * bps / 10_000` with a `u128` intermediate.
///
/// A wrapped fee would silently undercharge TRV, so any overflow is
/// a hard error rather than a wrap.
pub fn fee_bps(amount: u64, bps: u32) -> Result<u64, MathError> {
    if bps > 10_000 {
        return Err(MathError::InvalidBps);
    }
    let fee = (amount as u128)
        .checked_mul(bps as u128)
        .ok_or(MathError::Overflow)?
        / 10_000;
    u64::try_from(fee).map_err(|_| MathError::Overflow)
}

/// Split `amount` into `(fee, net)` for the given basis points.
pub fn split_fee(amount: u64, bps: u32) -> Result<(u64, u64), MathError> {
    let fee = fee_bps(amount, bps)?;
    let net = amount.checked_sub(fee).ok_or(MathError::Overflow)?;
    Ok((fee, net))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quarter_fee_exact() {
        assert_eq!(fee_bps(1_000, 2_500).unwrap(), 250);
    }

    #[test]
    fn fee_rounds_down() {
        // 25% of 3 base units = 0.75 -> 0. Dust stays with the sender.
        assert_eq!(fee_bps(3, 2_500).unwrap(), 0);
    }

    #[test]
    fn max_amount_no_overflow() {
        let (fee, net) = split_fee(u64::MAX, 2_500).unwrap();
        assert_eq!(fee + net, u64::MAX);
    }

    #[test]
    fn invalid_bps_rejected() {
        assert_eq!(fee_bps(100, 10_001), Err(MathError::InvalidBps));
    }

    #[test]
    fn split_sums_to_amount() {
        for amount in [0u64, 1, 99, 100, 10_000, 1_000_000_000] {
            let (fee, net) = split_fee(amount, 2_500).unwrap();
            assert_eq!(fee + net, amount, "amount={amount}");
        }
    }
}
