//! Minimal transaction pool storing state-checked transactions keyed by `TxId`.
//!
//! The pool assumes transactions were already screened statelessly by the
//! [`TransactionCollector`]. Before queuing a transaction it validates nonce and
//! balance constraints against the latest account snapshot.

use crate::currency::CurrencyError;
use crate::state::AccountStateView;
use crate::tx::{Tx, TxError};
use ed25519_dalek::VerifyingKey;
use std::collections::HashMap;

/// Errors reported when attempting to add a transaction to the pool.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MempoolError {
    #[error("transaction already exists in the pool")]
    Duplicate,
    #[error(transparent)]
    Tx(#[from] TxError),
    #[error(transparent)]
    Currency(#[from] CurrencyError),
    #[error("account not present in state view")]
    UnknownAccount,
    #[error("unexpected nonce (expected {expected}, found {found})")]
    UnexpectedNonce { expected: u64, found: u64 },
    #[error("insufficient available balance")]
    InsufficientAvailable,
    #[error("insufficient staked balance")]
    InsufficientStaked,
    #[error("insufficient reward balance")]
    InsufficientReward,
}

/// Stateless transaction pool keyed by [`crate::tx::TxId`].
pub struct Mempool<S: AccountStateView> {
    state: S,
    entries: HashMap<[u8; 32], Tx>,
}

impl<S: AccountStateView> Mempool<S> {
    /// Creates an empty pool tied to the provided state view.
    pub fn new(state: S) -> Self {
        Self {
            state,
            entries: HashMap::new(),
        }
    }

    /// Returns the number of transactions currently buffered.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` when no transactions are buffered.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Attempts to insert `tx` in the pool.
    ///
    /// Validation rules executed:
    /// * transaction targets the same network as the pool;
    /// * account exists in the state view;
    /// * nonce matches the expected value;
    /// * balances (available/staked/reward) can satisfy the transaction and its fee;
    /// * the pool does not already contain a transaction with the same identifier.
    pub fn insert(&mut self, tx: Tx) -> Result<(), MempoolError> {
        let sender_key =
            VerifyingKey::from_bytes(&tx.from).expect("collector already checked sender key");
        let snapshot = self
            .state
            .account_snapshot(&sender_key)
            .ok_or(MempoolError::UnknownAccount)?;

        if tx.nonce != snapshot.nonce {
            return Err(MempoolError::UnexpectedNonce {
                expected: snapshot.nonce,
                found: tx.nonce,
            });
        }

        let fee = tx.fee()?;
        let amount = tx.kind.amount();

        match tx.kind {
            crate::tx::TxKind::Transfer { .. } | crate::tx::TxKind::Stake { .. } => {
                let required = fee.checked_add(amount)?;
                snapshot
                    .available
                    .checked_sub(required)
                    .map_err(|_| MempoolError::InsufficientAvailable)?;
            }
            crate::tx::TxKind::Unstake { .. } => {
                snapshot
                    .staked
                    .checked_sub(amount)
                    .map_err(|_| MempoolError::InsufficientStaked)?;
                snapshot
                    .available
                    .checked_sub(fee)
                    .map_err(|_| MempoolError::InsufficientAvailable)?;
            }
            crate::tx::TxKind::ClaimReward { .. } => {
                snapshot
                    .reward
                    .checked_sub(amount)
                    .map_err(|_| MempoolError::InsufficientReward)?;
                snapshot
                    .available
                    .checked_sub(fee)
                    .map_err(|_| MempoolError::InsufficientAvailable)?;
            }
        }

        let tx_id = tx.tx_id()?;
        let key = *tx_id.as_bytes();
        if self.entries.contains_key(&key) {
            return Err(MempoolError::Duplicate);
        }
        self.entries.insert(key, tx);
        Ok(())
    }

    /// Returns an iterator over the buffered transactions.
    pub fn iter(&self) -> impl Iterator<Item = &Tx> {
        self.entries.values()
    }

    /// Removes all transactions from the mempool.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Exposes the state view used by the pool.
    pub fn state(&self) -> &S {
        &self.state
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::Account;
    use crate::currency::Crit;
    use crate::network::MAIN_NET;
    use crate::state::{AccountSnapshot, State};
    use crate::tx::TxKind;

    fn state_with_account() -> (State, crate::account::AccountId, ed25519_dalek::SigningKey) {
        let (account_id, signing_key) = Account::generate_account_keys();
        let mut account = Account::new(MAIN_NET);
        account.deposit(Crit::from_units(10_000)).unwrap();

        let mut state = State::new(MAIN_NET);
        state.insert_snapshot(&account_id, AccountSnapshot::from_account(&account));

        (state, account_id, signing_key)
    }

    #[test]
    fn insert_rejects_duplicates() {
        let (state, account_id, signing_key) = state_with_account();
        let nonce = state.nonce(&account_id).expect("nonce available");
        let tx = Tx::new(
            MAIN_NET,
            account_id,
            nonce,
            TxKind::stake(Crit::from_units(1_000)),
        )
        .sign(&signing_key)
        .expect("sign");

        let mut pool = Mempool::new(state);
        pool.insert(tx.clone()).expect("first insert");
        let result = pool.insert(tx);
        assert!(matches!(result, Err(MempoolError::Duplicate)));
    }

    #[test]
    fn insert_rejects_insufficient_available() {
        let (mut state, account_id, signing_key) = state_with_account();
        let nonce = state.nonce(&account_id).expect("nonce");
        let limited = AccountSnapshot {
            nonce,
            available: Crit::from_units(10),
            staked: Crit::ZERO,
            reward: Crit::ZERO,
        };
        state.insert_snapshot(&account_id, limited);

        let tx = Tx::new(
            MAIN_NET,
            account_id,
            nonce,
            TxKind::stake(Crit::from_units(1_000)),
        )
        .sign(&signing_key)
        .expect("sign");

        let mut pool = Mempool::new(state);
        let result = pool.insert(tx);
        assert!(matches!(result, Err(MempoolError::InsufficientAvailable)));
    }

    #[test]
    fn insert_rejects_insufficient_staked() {
        let (mut state, account_id, signing_key) = state_with_account();
        let nonce = state.nonce(&account_id).expect("nonce");
        let snapshot = AccountSnapshot {
            nonce,
            available: Crit::from_units(2_000),
            staked: Crit::from_units(500),
            reward: Crit::ZERO,
        };
        state.insert_snapshot(&account_id, snapshot);

        let tx = Tx::new(
            MAIN_NET,
            account_id,
            nonce,
            TxKind::unstake(Crit::from_units(1_000)),
        )
        .sign(&signing_key)
        .expect("sign");

        let mut pool = Mempool::new(state);
        let result = pool.insert(tx);
        assert!(matches!(result, Err(MempoolError::InsufficientStaked)));
    }

    #[test]
    fn insert_rejects_insufficient_reward() {
        let (mut state, account_id, signing_key) = state_with_account();
        let nonce = state.nonce(&account_id).expect("nonce");
        let snapshot = AccountSnapshot {
            nonce,
            available: Crit::from_units(2_000),
            staked: Crit::ZERO,
            reward: Crit::from_units(100),
        };
        state.insert_snapshot(&account_id, snapshot);

        let tx = Tx::new(
            MAIN_NET,
            account_id,
            nonce,
            TxKind::claim_reward(Crit::from_units(500)),
        )
        .sign(&signing_key)
        .expect("sign");

        let mut pool = Mempool::new(state);
        let result = pool.insert(tx);
        assert!(matches!(result, Err(MempoolError::InsufficientReward)));
    }

    #[test]
    fn insert_rejects_unexpected_nonce() {
        let (state, account_id, signing_key) = state_with_account();
        let nonce = state.nonce(&account_id).expect("nonce");
        let tx = Tx::new(
            MAIN_NET,
            account_id,
            nonce + 1,
            TxKind::stake(Crit::from_units(1_000)),
        )
        .sign(&signing_key)
        .expect("sign");

        let mut pool = Mempool::new(state);
        let result = pool.insert(tx);
        assert!(matches!(
            result,
            Err(MempoolError::UnexpectedNonce { expected, found }) if expected == nonce && found == nonce + 1
        ));
    }

    #[test]
    fn insert_rejects_unknown_account() {
        let state = State::new(MAIN_NET);
        let (account_id, signing_key) = Account::generate_account_keys();
        let tx = Tx::new(
            MAIN_NET,
            account_id,
            0,
            TxKind::stake(Crit::from_units(1_000)),
        )
        .sign(&signing_key)
        .expect("sign");

        let mut pool = Mempool::new(state);
        let result = pool.insert(tx);
        assert!(matches!(result, Err(MempoolError::UnknownAccount)));
    }
}
