/*
use std::collections::HashMap;
//use crate::currency::*;
use crate::account::*;

pub type Storage = HashMap<AccountId, Account>;

pub enum StorageError {
    InsufficientCrit,
    InsufficientStake,
    NonceOverflow,
    CritOverflow,
    StakeOverflow,
}

impl Account {
    fn increment_nonce(&mut self) -> Result<(), StorageError> {
        self.nonce = self
            .nonce
            .checked_add(1)
            .ok_or(StorageError::NonceOverflow)?;
        Ok(())
    }

    fn increment_crit(&mut self, amount: CritAmount) -> Result<(), StorageError> {
        self.crit_balance = self
            .crit_balance
            .checked_add(amount)
            .ok_or(StorageError::CritOverflow)?;
        Ok(())
    }
    fn decrement_crit(&mut self, amount: CritAmount) -> Result<(), StorageError> {
        self.crit_balance = self
            .crit_balance
            .checked_sub(amount)
            .ok_or(StorageError::InsufficientCrit)?;
        Ok(())
    }

    fn unstake(&mut self, amount: StakeAmount) -> Result<(), StorageError> {
        let mut account_copy = self;
        account_copy.stake_balance = account_copy
            .stake_balance
            .checked_sub(amount)
            .ok_or(StorageError::InsufficientStake)?;
        account_copy.increment_crit(amount)?;
        // la il faut faire une copie ou un remplacement
        Ok(())
    }

    fn stake(&mut self, amount: StakeAmount) -> Result<(), StorageError> {
        self.stake // should check crit_balance
    }
}
*/
