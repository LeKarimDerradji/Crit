//! Currency domain primitives: safe arithmetic around the Crit denomination.

use thiserror::Error;

/// Error variants emitted when [`Crit`] arithmetic guards fire.
#[derive(Debug, Error)]
pub enum CurrencyError {
    #[error("Overflow on currency arithmetics")]
    Overflow,
    #[error("Underflow on currency arithmetics")]
    Underflow,
}

/// Fixed-precision currency amount used throughout the crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Crit(u128);

impl Crit {
    /// Human-readable abbreviation of the denomination.
    pub const NAME: &'static str = "CRIT";
    /// Zero-value constant for convenience.
    pub const ZERO: Self = Self(0);

    /// Number of decimal places used when formatting amounts.
    pub const DECIMAL: u8 = 8;

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
        assert_eq!(
            u128::from(value),
            u128::MAX,
            "value must remain unchanged"
        );
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
}
