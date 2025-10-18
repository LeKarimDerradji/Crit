//! Account domain objects: combine a deterministic nonce with wallet balances.
//!
//! Account identifiers are expected to live outside of this structure (e.g. as
//! keys in a state map backed by addresses or public keys).

use thiserror::Error;

use crate::crypto;
use crate::currency::Crit;
use crate::network::NetId;
use crate::wallet::{Wallet, WalletError};
use ed25519_dalek::{SigningKey, VerifyingKey};

/// Alias representing an external account identifier.
pub type AccountId = VerifyingKey;

/// Errors that can arise while mutating an account.
#[derive(Debug, Error)]
pub enum AccountError {
    #[error("Nonce overflow")]
    NonceOverflow,
    #[error(transparent)]
    Wallet(#[from] WalletError),
}

/// Stateful representation of a ledger account.
///
/// Every state mutation exposed here increments the nonce only after the wallet
/// update succeeds, guaranteeing atomicity between the two.
#[derive(Debug, Clone, Copy)]
pub struct Account {
    pub network_id: NetId,
    /// Monotonically increasing nonce used for replay protection.
    pub nonce: u64,
    wallet: Wallet,
}

impl Account {
    /// Generates a fresh account identity returning the public identifier and signing key.
    pub fn generate_account_keys() -> (AccountId, SigningKey) {
        let (public, private) = crypto::generate_keypair();
        (public, private)
    }

    /// Creates a new account bound to the provided network identifier.
    pub fn new(network_id: NetId) -> Self {
        Self {
            network_id,
            nonce: 0,
            wallet: Wallet::new(),
        }
    }

    /// Bumps the nonce by one, ensuring it never wraps.
    pub fn increment_nonce(&mut self) -> Result<(), AccountError> {
        self.nonce = self.next_nonce()?;
        Ok(())
    }

    fn next_nonce(&self) -> Result<u64, AccountError> {
        self.nonce.checked_add(1).ok_or(AccountError::NonceOverflow)
    }

    fn apply_with_nonce<F>(&mut self, op: F) -> Result<(), AccountError>
    where
        F: FnOnce(&mut Wallet) -> Result<(), WalletError>,
    {
        let new_nonce = self.next_nonce()?;
        op(&mut self.wallet)?;
        self.nonce = new_nonce;
        Ok(())
    }

    /// Credits the underlying wallet's available balance, consuming the nonce on success.
    pub fn deposit(&mut self, amount: Crit) -> Result<(), AccountError> {
        self.apply_with_nonce(|wallet| wallet.credit_available(amount))
    }

    /// Debits the underlying wallet's available balance, consuming the nonce on success.
    pub fn withdraw(&mut self, amount: Crit) -> Result<(), AccountError> {
        self.apply_with_nonce(|wallet| wallet.debit_available(amount))
    }

    /// Moves funds from the available balance into the staked balance, consuming the nonce on success.
    pub fn stake(&mut self, amount: Crit) -> Result<(), AccountError> {
        self.apply_with_nonce(|wallet| wallet.credit_staked(amount))
    }

    /// Releases funds from the staked balance back into the available balance, consuming the nonce on success.
    pub fn unstake(&mut self, amount: Crit) -> Result<(), AccountError> {
        self.apply_with_nonce(|wallet| wallet.debit_staked(amount))
    }

    /// Credits the reward balance for future claims, consuming the nonce on success.
    pub fn receive_reward(&mut self, amount: Crit) -> Result<(), AccountError> {
        self.apply_with_nonce(|wallet| wallet.credit_reward(amount))
    }

    /// Converts reward balance back into the available balance, consuming the nonce on success.
    pub fn claim_reward(&mut self, amount: Crit) -> Result<(), AccountError> {
        self.apply_with_nonce(|wallet| wallet.debit_reward(amount))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::MAIN_NET;
    use ed25519_dalek::{Signer, Verifier};

    fn new_account() -> Account {
        Account::new(MAIN_NET)
    }

    fn balances(account: &Account) -> (u128, u128, u128) {
        (
            u128::from(account.wallet.available_balance()),
            u128::from(account.wallet.staked_balance()),
            u128::from(account.wallet.reward_balance()),
        )
    }

    #[test]
    fn new_initializes_zeroed_wallet_and_nonce() {
        let account = Account::new(MAIN_NET);
        assert_eq!(account.network_id, MAIN_NET);
        assert_eq!(account.nonce, 0);
        assert_eq!(balances(&account), (0, 0, 0));
    }

    #[test]
    fn increment_nonce_advances_by_one() {
        let mut account = new_account();
        account
            .increment_nonce()
            .expect("nonce increment should succeed");
        assert_eq!(account.nonce, 1);
    }

    #[test]
    fn increment_nonce_detects_overflow() {
        let mut account = new_account();
        account.nonce = u64::MAX;
        let result = account.increment_nonce();
        assert!(matches!(result, Err(AccountError::NonceOverflow)));
    }

    #[test]
    fn deposit_updates_balance_and_nonce() {
        let mut account = new_account();
        account
            .deposit(10u128.into())
            .expect("deposit should succeed");
        assert_eq!(account.nonce, 1);
        assert_eq!(balances(&account), (10, 0, 0));
    }

    #[test]
    fn deposit_propagates_wallet_errors_without_consuming_nonce() {
        let mut account = new_account();
        account
            .wallet
            .credit_available(u128::MAX.into())
            .expect("setup should succeed");
        let result = account.deposit(1u128.into());
        assert!(matches!(
            result,
            Err(AccountError::Wallet(WalletError::AvailableOverflow))
        ));
        assert_eq!(account.nonce, 0);
    }

    #[test]
    fn withdraw_success_increments_nonce() {
        let mut account = new_account();
        account
            .deposit(8u128.into())
            .expect("deposit should succeed");
        account
            .withdraw(5u128.into())
            .expect("withdraw should succeed");
        assert_eq!(account.nonce, 2);
        assert_eq!(balances(&account), (3, 0, 0));
    }

    #[test]
    fn withdraw_requires_sufficient_funds_without_nonce_increment() {
        let mut account = new_account();
        account
            .deposit(3u128.into())
            .expect("deposit should succeed");
        let result = account.withdraw(4u128.into());
        assert!(matches!(
            result,
            Err(AccountError::Wallet(WalletError::InsufficientAvailable))
        ));
        assert_eq!(account.nonce, 1);
    }

    #[test]
    fn stake_moves_balance_and_increments_nonce() {
        let mut account = new_account();
        account
            .deposit(10u128.into())
            .expect("deposit should succeed");
        account.stake(4u128.into()).expect("stake should succeed");
        assert_eq!(account.nonce, 2);
        assert_eq!(balances(&account), (6, 4, 0));
    }

    #[test]
    fn stake_failure_preserves_nonce() {
        let mut account = new_account();
        let result = account.stake(1u128.into());
        assert!(matches!(
            result,
            Err(AccountError::Wallet(WalletError::InsufficientAvailable))
        ));
        assert_eq!(account.nonce, 0);
    }

    #[test]
    fn stake_respects_wallet_overflow_without_nonce_increment() {
        let mut account = new_account();
        account
            .wallet
            .credit_available((u128::MAX - 1).into())
            .expect("setup should succeed");
        account
            .wallet
            .credit_staked((u128::MAX - 1).into())
            .expect("setup stake should succeed");
        account
            .wallet
            .credit_available(2u128.into())
            .expect("top up available balance");

        let result = account.stake(2u128.into());
        assert!(matches!(
            result,
            Err(AccountError::Wallet(WalletError::StakedOverflow))
        ));
        assert_eq!(account.nonce, 0);
    }

    #[test]
    fn unstake_returns_funds_and_increments_nonce() {
        let mut account = new_account();
        account
            .deposit(10u128.into())
            .expect("deposit should succeed");
        account.stake(6u128.into()).expect("stake should succeed");
        account
            .unstake(4u128.into())
            .expect("unstake should succeed");
        assert_eq!(account.nonce, 3);
        assert_eq!(balances(&account), (8, 2, 0));
    }

    #[test]
    fn unstake_failure_preserves_nonce() {
        let mut account = new_account();
        account
            .deposit(2u128.into())
            .expect("deposit should succeed");
        account.stake(2u128.into()).expect("stake should succeed");
        let result = account.unstake(3u128.into());
        assert!(matches!(
            result,
            Err(AccountError::Wallet(WalletError::InsufficientStaked))
        ));
        assert_eq!(account.nonce, 2);
    }

    #[test]
    fn receive_reward_increments_nonce_and_balance() {
        let mut account = new_account();
        account
            .receive_reward(5u128.into())
            .expect("receiving reward should succeed");
        assert_eq!(balances(&account), (0, 0, 5));
        assert_eq!(account.nonce, 1);
    }

    #[test]
    fn claim_reward_transfers_to_available() {
        let mut account = new_account();
        account
            .receive_reward(7u128.into())
            .expect("reward reception should succeed");
        account
            .claim_reward(4u128.into())
            .expect("claim should succeed");
        assert_eq!(balances(&account), (4, 0, 3));
        assert_eq!(account.nonce, 2);
    }

    #[test]
    fn claim_reward_failure_preserves_nonce() {
        let mut account = new_account();
        account
            .receive_reward(2u128.into())
            .expect("reward reception should succeed");
        let result = account.claim_reward(3u128.into());
        assert!(matches!(
            result,
            Err(AccountError::Wallet(WalletError::InsufficientReward))
        ));
        assert_eq!(account.nonce, 1);
    }

    #[test]
    fn generate_account_keys_produces_unique_identity() {
        let (id1, sk1) = Account::generate_account_keys();
        let (id2, sk2) = Account::generate_account_keys();
        assert_ne!(
            id1.to_bytes(),
            id2.to_bytes(),
            "public identifiers should differ"
        );
        assert_ne!(sk1.to_bytes(), sk2.to_bytes(), "signing keys should differ");

        let message = b"crit account identity test";
        let signature = sk1.sign(message);
        id1.verify(message, &signature)
            .expect("signature must verify with matching key");
        assert!(
            id2.verify(message, &signature).is_err(),
            "signature should not verify with a different identifier"
        );
    }
}
