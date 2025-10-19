//! Lightweight account state snapshots exposed to stateless components.
//!
//! A `State` aggregates the minimal information required by the transaction
//! pipeline (e.g. mempool, validation) to reason about account nonces and
//! balances without holding a full storage backend. Callers are expected to
//! hydrate the state from persistent storage first, then keep it in sync with
//! the executed transactions.

use crate::account::{Account, AccountId};
use crate::currency::Crit;
use crate::network::NetId;
use std::collections::HashMap;

/// Copyable snapshot of an account used by stateless validators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountSnapshot {
    pub nonce: u64,
    pub available: Crit,
    pub staked: Crit,
    pub reward: Crit,
}

impl AccountSnapshot {
    /// Builds a snapshot from the full [`Account`] representation.
    pub fn from_account(account: &Account) -> Self {
        Self {
            nonce: account.nonce,
            available: account.available_balance(),
            staked: account.staked_balance(),
            reward: account.reward_balance(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct AccountKey([u8; 32]);

impl From<&AccountId> for AccountKey {
    fn from(id: &AccountId) -> Self {
        AccountKey(id.to_bytes())
    }
}

/// Read-only view over account metadata exposed to components such as the mempool.
pub trait AccountStateView {
    /// Network identifier associated with this snapshot.
    fn network_id(&self) -> NetId;

    /// Returns the snapshot for `account_id`, if present.
    fn account_snapshot(&self, account_id: &AccountId) -> Option<AccountSnapshot>;

    /// Convenience accessor for the expected nonce of `account_id`.
    fn nonce(&self, account_id: &AccountId) -> Option<u64> {
        self.account_snapshot(account_id)
            .map(|snapshot| snapshot.nonce)
    }

    /// Convenience accessor for the available balance of `account_id`.
    fn available_balance(&self, account_id: &AccountId) -> Option<Crit> {
        self.account_snapshot(account_id)
            .map(|snapshot| snapshot.available)
    }
}

impl<T: AccountStateView + ?Sized> AccountStateView for &T {
    fn network_id(&self) -> NetId {
        (**self).network_id()
    }

    fn account_snapshot(&self, account_id: &AccountId) -> Option<AccountSnapshot> {
        (**self).account_snapshot(account_id)
    }
}

/// In-memory map of account snapshots used by stateless verifiers.
#[derive(Debug)]
pub struct State {
    network_id: NetId,
    accounts: HashMap<AccountKey, AccountSnapshot>,
}

impl State {
    /// Creates an empty state for the provided network identifier.
    pub fn new(network_id: NetId) -> Self {
        Self {
            network_id,
            accounts: HashMap::new(),
        }
    }

    /// Populates the state from an iterator of `(AccountId, AccountSnapshot)` pairs.
    ///
    /// This is intended to be fed from persistent storage at startup.
    pub fn load_from_iter<I>(network_id: NetId, entries: I) -> Self
    where
        I: IntoIterator<Item = (AccountId, AccountSnapshot)>,
    {
        let mut state = Self::new(network_id);
        for (account_id, snapshot) in entries {
            state.insert_snapshot(&account_id, snapshot);
        }
        state
    }

    /// Inserts or replaces the snapshot for `account_id`.
    ///
    /// This can be used to hydrate from storage or to apply updates produced by the
    /// execution layer after a transaction is accepted.
    pub fn insert_snapshot(&mut self, account_id: &AccountId, snapshot: AccountSnapshot) {
        self.accounts.insert(AccountKey::from(account_id), snapshot);
    }

    /// Synchronises the snapshot with the provided [`Account`] instance.
    pub fn sync_account(&mut self, account_id: &AccountId, account: &Account) {
        self.insert_snapshot(account_id, AccountSnapshot::from_account(account));
    }

    /// Removes the snapshot associated with `account_id`.
    pub fn remove_account(&mut self, account_id: &AccountId) {
        self.accounts.remove(&AccountKey::from(account_id));
    }
}

impl AccountStateView for State {
    fn network_id(&self) -> NetId {
        self.network_id
    }

    fn account_snapshot(&self, account_id: &AccountId) -> Option<AccountSnapshot> {
        self.accounts.get(&AccountKey::from(account_id)).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::Account;
    use crate::network::MAIN_NET;

    #[test]
    fn loads_from_iterator() {
        let (account_id, _) = Account::generate_account_keys();
        let mut account = Account::new(MAIN_NET);
        account.deposit(Crit::from_units(500)).unwrap();
        let snapshot = AccountSnapshot::from_account(&account);

        let state = State::load_from_iter(MAIN_NET, vec![(account_id, snapshot)]);
        assert_eq!(state.network_id(), MAIN_NET);
        assert_eq!(
            state.account_snapshot(&account_id),
            Some(snapshot),
            "snapshot must be available after load"
        );
    }

    #[test]
    fn sync_account_updates_snapshot() {
        let (account_id, _) = Account::generate_account_keys();
        let mut account = Account::new(MAIN_NET);

        let mut state = State::new(MAIN_NET);
        state.sync_account(&account_id, &account);
        assert_eq!(
            state.nonce(&account_id),
            Some(0),
            "initial nonce should be synchronised"
        );

        account.deposit(Crit::from_units(1_000)).unwrap();
        state.sync_account(&account_id, &account);
        assert_eq!(
            state.available_balance(&account_id),
            Some(account.available_balance())
        );
    }

    #[test]
    fn remove_account_clears_snapshot() {
        let (account_id, _) = Account::generate_account_keys();
        let account = Account::new(MAIN_NET);

        let mut state = State::new(MAIN_NET);
        state.sync_account(&account_id, &account);
        state.remove_account(&account_id);

        assert!(
            state.account_snapshot(&account_id).is_none(),
            "account removal should clear snapshot"
        );
    }
}
