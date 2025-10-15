//! Currency domain primitives: safe arithmetic around the Crit denomination.

use borsh::{BorshDeserialize, BorshSerialize};
use thiserror::Error;

/// Error variants emitted when [`Crit`] arithmetic guards fire.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CurrencyError {
    #[error("Overflow on currency arithmetics")]
    Overflow,
    #[error("Underflow on currency arithmetics")]
    Underflow,
}

/// Fixed-precision currency amount used throughout the crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, BorshSerialize, BorshDeserialize)]
pub struct Crit(u128);

impl Crit {
    /// Human-readable abbreviation of the denomination.
    pub const NAME: &'static str = "CRIT";
    /// Zero-value constant for convenience.
    pub const ZERO: Self = Self(0);
    /// Number of decimal places used when formatting amounts.
    pub const DECIMAL: u8 = 8;
    /// Scaling factor (1 CRIT = 10^DECIMAL internal units).
    pub const UNIT: u128 = 10u128.pow(Self::DECIMAL as u32);

    const FEE_NUMERATOR: u128 = 1; // 0.1% = 1 / 1_000
    const FEE_DENOMINATOR: u128 = 1_000;
    const MIN_FEE_UNITS: u128 = 1;

    /// Represents exactly 1 CRIT.
    pub const ONE: Self = Self(Self::UNIT);

    /// Builds an amount directly from internal units.
    pub const fn from_units(units: u128) -> Self {
        Self(units)
    }

    /// Exposes the raw centcrit value.
    pub const fn units(self) -> u128 {
        self.0
    }

    /// Adds `amount`, returning the new value or an overflow error.
    pub(crate) fn checked_add(&self, amount: Self) -> Result<Self, CurrencyError> {
        self.0
            .checked_add(amount.0)
            .map(Self)
            .ok_or(CurrencyError::Overflow)
    }

    /// Subtracts `amount`, returning the new value or an underflow error.
    pub(crate) fn checked_sub(&self, amount: Self) -> Result<Self, CurrencyError> {
        self.0
            .checked_sub(amount.0)
            .map(Self)
            .ok_or(CurrencyError::Underflow)
    }

    /// Adds `amount` in-place; leaves the original untouched if overflow occurs.
    pub(crate) fn add_assign(&mut self, amount: Self) -> Result<(), CurrencyError> {
        self.0 = self
            .0
            .checked_add(amount.0)
            .ok_or(CurrencyError::Overflow)?;
        Ok(())
    }

    /// Subtracts `amount` in-place; leaves the original untouched if underflow occurs.
    pub(crate) fn sub_assign(&mut self, amount: Self) -> Result<(), CurrencyError> {
        self.0 = self
            .0
            .checked_sub(amount.0)
            .ok_or(CurrencyError::Underflow)?;
        Ok(())
    }

    /// Computes the protocol fee (0.1%) for a transaction amount.
    ///
    /// The fee is calculated entirely in internal units, rounded up to the next
    /// centcrit and clamped to a minimum of one centcrit for non-zero amounts.
    pub fn compute_fee(amount: Self) -> Result<Self, CurrencyError> {
        if amount == Self::ZERO {
            return Ok(Self::ZERO);
        }

        let numerator = amount
            .0
            .checked_mul(Self::FEE_NUMERATOR)
            .ok_or(CurrencyError::Overflow)?;

        let mut fee_units = numerator / Self::FEE_DENOMINATOR;
        if numerator % Self::FEE_DENOMINATOR != 0 {
            fee_units = fee_units.checked_add(1).ok_or(CurrencyError::Overflow)?;
        }

        if fee_units < Self::MIN_FEE_UNITS {
            fee_units = Self::MIN_FEE_UNITS;
        }

        Ok(Self(fee_units))
    }
}

impl From<u128> for Crit {
    fn from(value: u128) -> Self {
        Self(value)
    }
}

impl From<Crit> for u128 {
    fn from(value: Crit) -> Self {
        value.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_are_correct() {
        assert_eq!(u128::from(Crit::ZERO), 0);
        assert_eq!(Crit::NAME, "CRIT");
        assert_eq!(Crit::DECIMAL, 8);
        assert_eq!(Crit::UNIT, 100_000_000);
    }

    #[test]
    fn checked_add_succeeds_without_mutating_inputs() {
        let lhs = Crit::from(5);
        let rhs = Crit::from(7);

        let sum = lhs.checked_add(rhs).expect("addition should succeed");
        assert_eq!(u128::from(sum), 12);
        assert_eq!(u128::from(lhs), 5);
        assert_eq!(u128::from(rhs), 7);
    }

    #[test]
    fn checked_add_detects_overflow() {
        let lhs = Crit::from(u128::MAX);
        let rhs = Crit::from(1);

        let result = lhs.checked_add(rhs);
        assert!(matches!(result, Err(CurrencyError::Overflow)));
    }

    #[test]
    fn checked_sub_succeeds() {
        let lhs = Crit::from(10);
        let rhs = Crit::from(4);

        let difference = lhs.checked_sub(rhs).expect("subtraction should succeed");
        assert_eq!(u128::from(difference), 6);
    }

    #[test]
    fn checked_sub_detects_underflow() {
        let lhs = Crit::from(3);
        let rhs = Crit::from(4);

        let result = lhs.checked_sub(rhs);
        assert!(matches!(result, Err(CurrencyError::Underflow)));
    }

    #[test]
    fn add_assign_mutates_on_success() {
        let mut value = Crit::from(2);
        value.add_assign(Crit::from(5)).expect("should succeed");
        assert_eq!(u128::from(value), 7);
    }

    #[test]
    fn add_assign_rolls_back_on_overflow() {
        let mut value = Crit::from(u128::MAX);
        let result = value.add_assign(Crit::from(1));
        assert!(matches!(result, Err(CurrencyError::Overflow)));
        assert_eq!(u128::from(value), u128::MAX, "value must remain unchanged");
    }

    #[test]
    fn sub_assign_mutates_on_success() {
        let mut value = Crit::from(10);
        value.sub_assign(Crit::from(3)).expect("should succeed");
        assert_eq!(u128::from(value), 7);
    }

    #[test]
    fn sub_assign_rolls_back_on_underflow() {
        let mut value = Crit::from(0);
        let result = value.sub_assign(Crit::from(1));
        assert!(matches!(result, Err(CurrencyError::Underflow)));
        assert_eq!(u128::from(value), 0, "value must remain unchanged");
    }

    #[test]
    fn conversions_from_and_into_u128() {
        let original: u128 = 42;
        let crit_value: Crit = original.into();
        assert_eq!(u128::from(crit_value), original);

        let back: u128 = crit_value.into();
        assert_eq!(back, original);
    }

    #[test]
    fn compute_fee_handles_zero_amount() {
        assert_eq!(Crit::compute_fee(Crit::ZERO).unwrap(), Crit::ZERO);
    }

    #[test]
    fn compute_fee_applies_fraction_and_rounding() {
        let amount = Crit::from(Crit::UNIT); // 1 CRIT
        let fee = Crit::compute_fee(amount).expect("fee should compute");
        assert_eq!(u128::from(fee), 100_000); // 0.001 CRIT

        let amount = Crit::from(250_000_000); // 2.5 CRIT
        let fee = Crit::compute_fee(amount).expect("fee should compute");
        assert_eq!(u128::from(fee), 250_000);
    }

    #[test]
    fn compute_fee_applies_minimum_floor() {
        let tiny = Crit::from(1);
        let fee = Crit::compute_fee(tiny).expect("fee should compute");
        assert_eq!(u128::from(fee), 1);
    }
}
