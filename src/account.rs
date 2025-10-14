/*
use crate::currency::Crit;
use crate::wallet::Wallet;

pub type AccountId = u64;

pub enum AccountError {
    NonceOverflow,
    BalanceOverflow,
    BalanceUnderflow,
    StakeOverflow,
    StakeUnderflow,
}

#[derive(Debug, Clone, Copy)]
pub struct Account {
    pub nonce: u64,
    wallet: Wallet,
}

impl Account {
    pub fn increment_nonce(&mut self) -> Result<(), AccountError> {
        self.nonce = self
            .nonce
            .checked_add(1)
            .ok_or(AccountError::NonceOverflow)?;
        Ok(())
    }

    pub fn credit_balance(&mut self, amount: Crit) -> Result<(), AccountError> {
        self.wallet.credit_balance(amount)?;
        Ok(())
    }

    pub fn debit_balance(&mut self, amount: Crit) -> Result<(), AccountError> {
        self.wallet.debit_balance(amount)?;
        Ok(())
    }

    pub fn stake(&mut self, amount: Crit) -> Result<(), AccountError> {
        self.wallet.stake(amount)?;
        Ok(())
    }

    pub fn unstake(&mut self, amount: Crit) -> Result<(), AccountError> {
        self.wallet.unstake(amount)?;
        Ok(())
    }
}
*/