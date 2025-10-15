//! Wallet domain primitives: handles available, staked, and reward balances with safe arithmetic.

use crate::currency::*;
use thiserror::Error;

/// Errors that can occur while manipulating a [`Wallet`].
#[derive(Debug, Error)]
pub enum WalletError {
    /// Adding funds to the available balance would overflow.
    #[error("Available balance overflow")]
    AvailableOverflow,
    /// Adding funds to the staked balance would overflow.
    #[error("Staked balance overflow")]
    StakedOverflow,
    /// Adding funds to the reward balance would overflow.
    #[error("Reward balance overflow")]
    RewardOverflow,
    /// Attempting to use more than the available balance allows.
    #[error("Insufficient available balance")]
    InsufficientAvailable,
    /// Attempting to unstake more than currently staked.
    #[error("Insufficient staked balance")]
    InsufficientStaked,
    /// Attempting to withdraw more than the reward balance holds.
    #[error("Insufficient reward balance")]
    InsufficientReward,
    /// Propagated arithmetic errors from the currency layer.
    #[error(transparent)]
    Currency(#[from] CurrencyError),
}

/// Tracks the available, staked, and reward balances for a single account.
#[derive(Debug, Copy, Clone, Default)]
pub struct Wallet {
    /// Spendable balance.
    available: Crit,
    /// Amount currently staked.
    staked: Crit,
    /// Rewards accrued but not yet transferred to the spendable balance.
    reward: Crit,
}

impl Wallet {
    /// Creates a wallet initialized with zero balances.
    pub fn new() -> Self {
        Self {
            available: Crit::ZERO,
            staked: Crit::ZERO,
            reward: Crit::ZERO,
        }
    }

    /// Returns the spendable balance.
    pub fn available_balance(&self) -> Crit {
        self.available
    }

    /// Returns the staked balance.
    pub fn staked_balance(&self) -> Crit {
        self.staked
    }

    /// Returns the reward balance.
    pub fn reward_balance(&self) -> Crit {
        self.reward
    }

    /// Adds funds to the available balance, guarding against overflow.
    pub fn credit_available(&mut self, amount: Crit) -> Result<(), WalletError> {
        self.available.add_assign(amount).map_err(|e| match e {
            CurrencyError::Overflow => WalletError::AvailableOverflow,
            other => WalletError::Currency(other),
        })?;
        Ok(())
    }

    /// Removes funds from the available balance if enough are present.
    pub fn debit_available(&mut self, amount: Crit) -> Result<(), WalletError> {
        self.available.sub_assign(amount).map_err(|e| match e {
            CurrencyError::Underflow => WalletError::InsufficientAvailable,
            other => WalletError::Currency(other),
        })?;
        Ok(())
    }

    /// Moves funds from available into the staked balance.
    pub fn credit_staked(&mut self, amount: Crit) -> Result<(), WalletError> {
        let new_available = self
            .available
            .checked_sub(amount)
            .map_err(|err| match err {
                CurrencyError::Underflow => WalletError::InsufficientAvailable,
                other => WalletError::Currency(other),
            })?;
        let new_staked = self.staked.checked_add(amount).map_err(|err| match err {
            CurrencyError::Overflow => WalletError::StakedOverflow,
            other => WalletError::Currency(other),
        })?;
        self.available = new_available;
        self.staked = new_staked;
        Ok(())
    }

    /// Moves funds from staked back into the available balance.
    pub fn debit_staked(&mut self, amount: Crit) -> Result<(), WalletError> {
        let new_staked = self.staked.checked_sub(amount).map_err(|err| match err {
            CurrencyError::Underflow => WalletError::InsufficientStaked,
            other => WalletError::Currency(other),
        })?;
        let new_available = self
            .available
            .checked_add(amount)
            .map_err(|err| match err {
                CurrencyError::Overflow => WalletError::AvailableOverflow,
                other => WalletError::Currency(other),
            })?;
        self.staked = new_staked;
        self.available = new_available;
        Ok(())
    }

    /// Credits the reward balance.
    pub fn credit_reward(&mut self, amount: Crit) -> Result<(), WalletError> {
        self.reward.add_assign(amount).map_err(|err| match err {
            CurrencyError::Overflow => WalletError::RewardOverflow,
            other => WalletError::Currency(other),
        })?;
        Ok(())
    }

    /// Converts a portion of the reward balance into available funds.
    pub fn debit_reward(&mut self, amount: Crit) -> Result<(), WalletError> {
        let new_reward = self.reward.checked_sub(amount).map_err(|err| match err {
            CurrencyError::Underflow => WalletError::InsufficientReward,
            other => WalletError::Currency(other),
        })?;
        let new_available = self
            .available
            .checked_add(amount)
            .map_err(|err| match err {
                CurrencyError::Overflow => WalletError::AvailableOverflow,
                other => WalletError::Currency(other),
            })?;
        self.reward = new_reward;
        self.available = new_available;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wallet(available: u128, staked: u128, reward: u128) -> Wallet {
        Wallet {
            available: available.into(),
            staked: staked.into(),
            reward: reward.into(),
        }
    }

    fn snapshot(wallet: &Wallet) -> (u128, u128, u128) {
        (
            u128::from(wallet.available),
            u128::from(wallet.staked),
            u128::from(wallet.reward),
        )
    }

    #[test]
    fn credit_available_increases_balance() {
        let mut wallet = wallet(10, 0, 0);
        wallet
            .credit_available(5u128.into())
            .expect("credit should succeed");
        assert_eq!(snapshot(&wallet), (15, 0, 0));
    }

    #[test]
    fn credit_available_overflow_is_reported_without_mutation() {
        let mut wallet = wallet(u128::MAX, 0, 0);
        let result = wallet.credit_available(1u128.into());
        assert!(matches!(result, Err(WalletError::AvailableOverflow)));
        assert_eq!(snapshot(&wallet), (u128::MAX, 0, 0));
    }

    #[test]
    fn debit_available_reduces_balance() {
        let mut wallet = wallet(10, 0, 0);
        wallet
            .debit_available(4u128.into())
            .expect("debit should succeed");
        assert_eq!(snapshot(&wallet), (6, 0, 0));
    }

    #[test]
    fn debit_available_underflow_is_prevented() {
        let mut wallet = wallet(2, 0, 0);
        let result = wallet.debit_available(3u128.into());
        assert!(matches!(result, Err(WalletError::InsufficientAvailable)));
        assert_eq!(snapshot(&wallet), (2, 0, 0));
    }

    #[test]
    fn credit_staked_moves_between_balances() {
        let mut wallet = wallet(10, 5, 0);
        wallet
            .credit_staked(4u128.into())
            .expect("staking should succeed");
        assert_eq!(snapshot(&wallet), (6, 9, 0));
    }

    #[test]
    fn credit_staked_fails_on_insufficient_available() {
        let mut wallet = wallet(1, 0, 0);
        let result = wallet.credit_staked(2u128.into());
        assert!(matches!(result, Err(WalletError::InsufficientAvailable)));
        assert_eq!(snapshot(&wallet), (1, 0, 0));
    }

    #[test]
    fn credit_staked_fails_on_stake_overflow() {
        let mut wallet = wallet(1, u128::MAX, 0);
        let result = wallet.credit_staked(1u128.into());
        assert!(matches!(result, Err(WalletError::StakedOverflow)));
        assert_eq!(snapshot(&wallet), (1, u128::MAX, 0));
    }

    #[test]
    fn debit_staked_returns_to_available() {
        let mut wallet = wallet(3, 7, 0);
        wallet
            .debit_staked(5u128.into())
            .expect("unstaking should succeed");
        assert_eq!(snapshot(&wallet), (8, 2, 0));
    }

    #[test]
    fn debit_staked_requires_sufficient_staked_balance() {
        let mut wallet = wallet(5, 1, 0);
        let result = wallet.debit_staked(2u128.into());
        assert!(matches!(result, Err(WalletError::InsufficientStaked)));
        assert_eq!(snapshot(&wallet), (5, 1, 0));
    }

    #[test]
    fn debit_staked_prevents_available_overflow() {
        let mut wallet = wallet(u128::MAX, 10, 0);
        let result = wallet.debit_staked(1u128.into());
        assert!(matches!(result, Err(WalletError::AvailableOverflow)));
        assert_eq!(snapshot(&wallet), (u128::MAX, 10, 0));
    }

    #[test]
    fn credit_reward_adds_to_reward_balance() {
        let mut wallet = wallet(0, 0, 2);
        wallet
            .credit_reward(3u128.into())
            .expect("crediting reward should succeed");
        assert_eq!(snapshot(&wallet), (0, 0, 5));
    }

    #[test]
    fn credit_reward_reports_overflow() {
        let mut wallet = wallet(0, 0, u128::MAX);
        let result = wallet.credit_reward(1u128.into());
        assert!(matches!(result, Err(WalletError::RewardOverflow)));
        assert_eq!(snapshot(&wallet), (0, 0, u128::MAX));
    }

    #[test]
    fn debit_reward_transfers_to_available() {
        let mut wallet = wallet(4, 0, 6);
        wallet
            .debit_reward(5u128.into())
            .expect("debiting reward should succeed");
        assert_eq!(snapshot(&wallet), (9, 0, 1));
    }

    #[test]
    fn debit_reward_requires_sufficient_reward() {
        let mut wallet = wallet(0, 0, 1);
        let result = wallet.debit_reward(3u128.into());
        assert!(matches!(result, Err(WalletError::InsufficientReward)));
        assert_eq!(snapshot(&wallet), (0, 0, 1));
    }

    #[test]
    fn debit_reward_prevents_available_overflow() {
        let mut wallet = wallet(u128::MAX, 0, 5);
        let result = wallet.debit_reward(1u128.into());
        assert!(matches!(result, Err(WalletError::AvailableOverflow)));
        assert_eq!(snapshot(&wallet), (u128::MAX, 0, 5));
    }
}
