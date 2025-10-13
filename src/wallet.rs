use crate::currency::*;

pub enum WalletError {

}

#[derive(Debug, Copy, Clone)]
pub struct Wallet {
    balance: Crit,
    stake: Crit,
}

impl Wallet {
    pub fn credit_balance(&mut self, amount: Crit) -> Result<(), WalletError> {
        Ok(())
    }

    pub fn debit_balance(&mut self, amount: Crit) -> Result<(), WalletError> {
        Ok(())
    }

    pub fn stake(&mut self, amount: Crit) -> Result<(), WalletError> {
        Ok(())
    }

    pub fn unstake(&mut self, amount: Crit) -> Result<(), WalletError> {
        Ok(())
    }
}