#[derive(Debug, Clone, Copy)]
pub struct Crit(u128);

pub enum CurrencyError {
    Overflow,
    Underflow
}

impl Crit {
    pub const NAME: &'static str= "CRIT";
    pub const ZERO: Self = Self(0);
    
    // TODO: do we need this?
    pub const DECIMAL: u8 = 8;

    pub fn checked_add(&self, amount: Self) -> Result<Self, CurrencyError> {
        self.0.checked_add(amount.0).map(Self).ok_or(CurrencyError::Overflow)
    }

    pub fn checked_sub(&self, amount: Self) -> Result<Self, CurrencyError> {
        self.0.checked_sub(amount.0).map(Self).ok_or(CurrencyError::Underflow)
    }

    pub fn add_assign(&mut self, amount: Self) -> Result<(), CurrencyError> {
        self.0 = self.0.checked_add(amount.0).ok_or(CurrencyError::Overflow)?;
        Ok(())
    }

    pub fn sub_assign(&mut self, amount: Self) -> Result<(), CurrencyError> {
        self.0 = self.0.checked_sub(amount.0).ok_or(CurrencyError::Underflow)?;
        Ok(())
    }
}

// TODO: unit test;