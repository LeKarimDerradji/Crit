//! Transaction primitives for Crit: encoding, signing, verification, fee handling, and identifiers.
//!
//! A transaction transports a payload [`TxKind`], a monotonically increasing
//! nonce, the sender public key and, once prepared, an Ed25519 signature. The
//! types exposed here derive [`BorshSerialize`]/[`BorshDeserialize`] so they can
//! be persisted and included in checkpoints with Merkle proofs. Signing targets
//! the Borsh encoding of `(network_id, from, nonce, kind)`, hashed with BLAKE3 (via
//! [`crate::crypto`]) to produce a
//! fixed-size digest before the Ed25519 signature is computed, avoiding
//! circular dependencies on the signature field. Transaction identifiers are derived by hashing the
//! Borsh serialization (including the optional signature) with BLAKE3 via
//! [`Tx::tx_id`], yielding the canonical [`TxId`].

use crate::account::AccountId;
use crate::crypto::{Blake3Hash as TxId, blake3_hash};
use crate::currency::{Crit, CurrencyError};
use crate::network::NetId;
use borsh::{BorshDeserialize, BorshSerialize, to_vec};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use thiserror::Error;

const PUBKEY_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;

/// Transaction payload accepted by the Crit ledger.
///
/// Variants encode the minimal data required for each action:
/// * `Transfer` – serialized recipient public key and amount to move.
/// * `Stake` / `Unstake` – amount moved between available balance and stake.
/// * `ClaimReward` – reward amount credited back to the available balance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum TxKind {
    Transfer {
        to: [u8; PUBKEY_BYTES],
        amount: Crit,
    },
    Stake {
        amount: Crit,
    },
    Unstake {
        amount: Crit,
    },
    ClaimReward {
        amount: Crit,
    },
}

impl TxKind {
    pub fn amount(self) -> Crit {
        match self {
            TxKind::Transfer { amount, .. }
            | TxKind::Stake { amount }
            | TxKind::Unstake { amount }
            | TxKind::ClaimReward { amount } => amount,
        }
    }

    pub fn transfer(to: &AccountId, amount: Crit) -> Self {
        Self::Transfer {
            to: to.to_bytes(),
            amount,
        }
    }

    pub fn stake(amount: Crit) -> Self {
        Self::Stake { amount }
    }

    pub fn unstake(amount: Crit) -> Self {
        Self::Unstake { amount }
    }

    pub fn claim_reward(amount: Crit) -> Self {
        Self::ClaimReward { amount }
    }
}

/// Errors that can be produced while building, signing or decoding transactions.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TxError {
    /// The transaction does not carry a signature.
    #[error("transaction signature is missing")]
    MissingSignature,
    /// The transaction signature cannot be verified.
    #[error("transaction signature is invalid: {reason}")]
    InvalidSignature { reason: String },
    /// Attempted to sign the transaction with a key that does not match `from`.
    #[error("attempted to sign transaction with mismatched key")]
    MismatchedSigner,
    /// The `from` field is not a valid Ed25519 public key.
    #[error("sender public key is invalid")]
    InvalidSenderKey,
    /// The transfer recipient key is not a valid Ed25519 public key.
    #[error("recipient public key is invalid")]
    InvalidRecipientKey,
    /// Transactions must move a strictly positive amount of CRIT.
    #[error("transaction amount must be greater than zero")]
    AmountZero,
    /// Transfers may not send funds to the sender itself.
    #[error("transfer destination matches sender")]
    SelfTransfer,
    /// Fee computation overflowed in the currency layer.
    #[error("fee computation overflowed")]
    Fee(CurrencyError),
    /// Borsh serialization failed.
    #[error("failed to encode transaction: {0}")]
    Encode(String),
    /// Borsh deserialization failed.
    #[error("failed to decode transaction: {0}")]
    Decode(String),
}

/// Canonical representation of a Crit transaction.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
pub struct Tx {
    /// Identifies the Crit network the transaction targets.
    pub network_id: NetId,
    /// Sender public key in raw Ed25519 format (32 bytes).
    pub from: [u8; PUBKEY_BYTES],
    /// Monotonically increasing counter used to prevent replay and order actions per account.
    pub nonce: u64,
    /// Payload describing the action executed by this transaction.
    pub kind: TxKind,
    /// Optional Ed25519 signature; `None` means the transaction has not been signed yet.
    pub signature: Option<[u8; SIGNATURE_BYTES]>,
}

impl Tx {
    /// Creates a new unsigned transaction.
    pub fn new(network_id: NetId, from: AccountId, nonce: u64, kind: TxKind) -> Self {
        Self {
            network_id,
            from: from.to_bytes(),
            nonce,
            kind,
            signature: None,
        }
    }

    /// Runs all stateless validation checks on the transaction (`from` key, signature,
    /// positive amount, transfer-specific invariants).
    ///
    /// The caller is responsible for checking the network id before invoking this method;
    /// the [`TransactionCollector`] performs this guard internally.
    ///
    /// This does **not** check the network id; callers (e.g. the collector) are expected
    /// to compare `self.network_id` with their expected network before calling this.
    pub fn check_stateless(&self) -> Result<(), TxError> {
        self.verify_signature()?; // verify sender key and signature.
        self.check_amount()?;
        self.check_transfer_rules()?;
        Ok(())
    }

    /// Parses a raw Ed25519 public key in compressed form.
    fn verify_key(
        bytes: &[u8; PUBKEY_BYTES],
    ) -> Result<VerifyingKey, ed25519_dalek::SignatureError> {
        VerifyingKey::from_bytes(bytes)
    }

    /// Validates the sender public key stored in `from`.
    fn verify_sender_key(&self) -> Result<VerifyingKey, TxError> {
        Self::verify_key(&self.from).map_err(|_| TxError::InvalidSenderKey)
    }

    /// Validates the transfer recipient key if the transaction is a transfer.
    fn verify_recipient_key(&self) -> Result<Option<VerifyingKey>, TxError> {
        if let TxKind::Transfer { to, .. } = self.kind {
            let key = Self::verify_key(&to).map_err(|_| TxError::InvalidRecipientKey)?;
            return Ok(Some(key));
        }
        Ok(None)
    }

    /// Ensures the amount moved by the transaction is strictly positive.
    fn check_amount(&self) -> Result<(), TxError> {
        if self.kind.amount() == Crit::ZERO {
            return Err(TxError::AmountZero);
        }
        Ok(())
    }

    /// Applies the invariants specific to transfers (recipient key validity and anti self-transfer).
    fn check_transfer_rules(&self) -> Result<(), TxError> {
        if let Some(recipient_key) = self.verify_recipient_key()?
            && recipient_key.to_bytes() == self.from
        {
            return Err(TxError::SelfTransfer);
        }
        Ok(())
    }

    /// Returns the fee associated with this transaction according to the currency rules.
    pub fn fee(&self) -> Result<Crit, TxError> {
        Crit::compute_fee(self.kind.amount()).map_err(TxError::Fee)
    }

    /// Signs the transaction with the provided signing key.
    pub fn sign(mut self, signing_key: &SigningKey) -> Result<Self, TxError> {
        if signing_key.verifying_key().to_bytes() != self.from {
            return Err(TxError::MismatchedSigner);
        }
        let digest = self.signing_digest()?;
        let signature = signing_key.sign(&digest);
        self.signature = Some(signature.to_bytes());
        Ok(self)
    }

    /// Verifies the transaction signature against the embedded public key.
    ///
    /// This also re-validates the `from` public key (via [`verify_sender_key`]).
    pub fn verify_signature(&self) -> Result<(), TxError> {
        let signature_bytes = self.signature.ok_or(TxError::MissingSignature)?;
        let signature = Signature::from_bytes(&signature_bytes);
        let from_key = self.verify_sender_key()?;
        let digest = self.signing_digest()?;
        from_key
            .verify(&digest, &signature)
            .map_err(|err| TxError::InvalidSignature {
                reason: err.to_string(),
            })
    }

    /// Serializes the transaction (including signature) using Borsh.
    pub fn to_bytes(&self) -> Result<Vec<u8>, TxError> {
        to_vec(self).map_err(|err| TxError::Encode(err.to_string()))
    }

    /// Deserializes a transaction from Borsh bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TxError> {
        Tx::try_from_slice(bytes).map_err(|err| TxError::Decode(err.to_string()))
    }

    /// Computes the canonical transaction identifier using BLAKE3.
    ///
    /// The hash is calculated over the Borsh serialization including the optional
    /// signature. Any modification to the transaction (payload, nonce, signer,
    /// signature) therefore yields a different identifier. Returns the raw
    /// [`TxId`] so callers can convert to bytes or hex when needed.
    pub fn tx_id(&self) -> Result<TxId, TxError> {
        let bytes = self.to_bytes()?;
        Ok(blake3_hash(&bytes))
    }

    /// Serializes the signable portion of the transaction and hashes it with BLAKE3.
    fn signing_digest(&self) -> Result<[u8; 32], TxError> {
        // Hash the Borsh encoding of the transaction without the signature field.
        let signable = TxSignable {
            network_id: self.network_id,
            from: self.from,
            nonce: self.nonce,
            kind: self.kind,
        };
        let payload = to_vec(&signable).map_err(|err| TxError::Encode(err.to_string()))?;
        Ok(blake3_hash(&payload).into())
    }
}

/// Helper struct containing the fields that are part of the signed message.
#[derive(BorshSerialize, BorshDeserialize)]
struct TxSignable {
    network_id: NetId,
    from: [u8; PUBKEY_BYTES],
    nonce: u64,
    kind: TxKind,
}

/// Errors returned by [`TransactionCollector`] when filtering incoming transactions.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CollectError {
    /// The transaction targets a different network than this collector instance.
    #[error("transaction targets unexpected network (expected {expected}, found {found})")]
    WrongNetwork { expected: NetId, found: NetId },
    /// Stateless validation reported an error (forwarded from [`TxError`]).
    #[error(transparent)]
    Tx(#[from] TxError),
}

/// Utility that gathers valid transactions before handing them to the state layer.
///
/// A transaction is accepted if and only if it:
/// * targets the configured [`NetId`];
/// * carries a valid Ed25519 signature;
/// * moves a non-zero amount; and
/// * for transfers, sends funds to an address different from the sender.
pub struct TransactionCollector {
    network_id: NetId,
    buffer: Vec<Tx>,
}

impl TransactionCollector {
    /// Creates a collector configured for a specific Crit network.
    ///
    /// Any transaction whose `network_id` differs from `network_id` will be rejected.
    pub fn new(network_id: NetId) -> Self {
        Self {
            network_id,
            buffer: Vec::new(),
        }
    }

    /// Attempts to enqueue `tx`, rejecting it if validation fails.
    pub fn push(&mut self, tx: Tx) -> Result<(), CollectError> {
        self.check(&tx)?;
        self.buffer.push(tx);
        Ok(())
    }

    /// Returns the collected transactions without draining them.
    ///
    /// The collector does not mutate or clone the transactions; the slice is a direct
    /// reference to the internal buffer.
    pub fn batch(&self) -> &[Tx] {
        &self.buffer
    }

    /// Drains the current batch, returning ownership of the collected transactions.
    pub fn drain(&mut self) -> Vec<Tx> {
        std::mem::take(&mut self.buffer)
    }

    /// Number of transactions currently buffered.
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Returns `true` when no transactions are buffered.
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Applies the stateless validation rules to `tx`:
    /// - the transaction network matches the collector network;
    /// - the signature verifies against the embedded public key;
    /// - the moved amount is strictly greater than zero; and
    /// - transfers do not target the sender themselves.
    fn check(&self, tx: &Tx) -> Result<(), CollectError> {
        self.check_network(tx)?;
        tx.check_stateless()?;
        Ok(())
    }

    /// Validates that the transaction targets the same network as the collector.
    fn check_network(&self, tx: &Tx) -> Result<(), CollectError> {
        if tx.network_id != self.network_id {
            return Err(CollectError::WrongNetwork {
                expected: self.network_id,
                found: tx.network_id,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::Account;
    use crate::network::{MAIN_NET, TEST_NET};

    fn stake_tx(account_id: AccountId) -> Tx {
        Tx::new(MAIN_NET, account_id, 0, TxKind::Stake { amount: Crit::ONE })
    }

    #[test]
    fn signing_and_verification_round_trip() {
        let (account_id, signing_key) = Account::generate_account_keys();
        let tx = Tx::new(
            MAIN_NET,
            account_id,
            42,
            TxKind::transfer(&account_id, Crit::from_units(1_000)),
        );
        let signed = tx.sign(&signing_key).expect("signing to succeed");
        assert!(signed.verify_signature().is_ok());
    }

    #[test]
    fn serialization_round_trip_unstake() {
        let (account_id, signing_key) = Account::generate_account_keys();
        let tx = Tx::new(
            MAIN_NET,
            account_id,
            99,
            TxKind::unstake(Crit::from_units(123_456)),
        )
        .sign(&signing_key)
        .expect("sign");

        let bytes = tx.to_bytes().expect("serialize");
        let decoded = Tx::from_bytes(&bytes).expect("deserialize");

        assert_eq!(decoded.network_id, MAIN_NET);
        assert_eq!(decoded.from, tx.from);
        assert_eq!(decoded.nonce, tx.nonce);
        assert!(matches!(decoded.kind, TxKind::Unstake { amount } if amount.units() == 123_456));
        assert_eq!(decoded.signature, tx.signature);
        assert!(decoded.verify_signature().is_ok());
    }

    #[test]
    fn serialization_round_trip_transfer_variant() {
        let (from, signing_key) = Account::generate_account_keys();
        let (to, _) = Account::generate_account_keys();
        let tx = Tx::new(
            MAIN_NET,
            from,
            7,
            TxKind::transfer(&to, Crit::from_units(2_000)),
        )
        .sign(&signing_key)
        .expect("sign");

        let bytes = tx.to_bytes().expect("serialize");
        let decoded = Tx::from_bytes(&bytes).expect("deserialize");

        assert_eq!(decoded.network_id, MAIN_NET);
        assert_eq!(decoded.from, tx.from);
        assert_eq!(decoded.nonce, tx.nonce);
        assert_eq!(decoded.kind, TxKind::transfer(&to, Crit::from_units(2_000)));
        assert_eq!(decoded.signature, tx.signature);
        assert!(decoded.verify_signature().is_ok());
    }

    #[test]
    fn serialization_round_trip_stake_variant() {
        let (from, _) = Account::generate_account_keys();
        let tx = Tx::new(MAIN_NET, from, 11, TxKind::stake(Crit::from_units(42_000)));

        let bytes = tx.to_bytes().expect("serialize");
        let decoded = Tx::from_bytes(&bytes).expect("deserialize");

        assert_eq!(decoded.network_id, MAIN_NET);
        assert_eq!(decoded.from, tx.from);
        assert_eq!(decoded.nonce, tx.nonce);
        assert_eq!(decoded.kind, TxKind::stake(Crit::from_units(42_000)));
        assert_eq!(decoded.signature, tx.signature);
    }

    #[test]
    fn serialization_round_trip_claim_variant() {
        let (from, _) = Account::generate_account_keys();
        let tx = Tx::new(
            MAIN_NET,
            from,
            5,
            TxKind::claim_reward(Crit::from_units(77_777)),
        );

        let bytes = tx.to_bytes().expect("serialize");
        let decoded = Tx::from_bytes(&bytes).expect("deserialize");

        assert_eq!(decoded.network_id, MAIN_NET);
        assert_eq!(decoded.kind, TxKind::claim_reward(Crit::from_units(77_777)));
    }

    #[test]
    fn deserializing_invalid_bytes_fails() {
        let bytes = vec![0u8; 3]; // too short
        assert!(matches!(Tx::from_bytes(&bytes), Err(TxError::Decode(_))));
    }

    #[test]
    fn signing_with_mismatched_key_fails() {
        let (account_id, _) = Account::generate_account_keys();
        let (_, other_sk) = Account::generate_account_keys();
        let tx = stake_tx(account_id);

        assert!(matches!(
            tx.clone().sign(&other_sk),
            Err(TxError::MismatchedSigner)
        ));
    }

    #[test]
    fn signing_with_matching_key_succeeds() {
        let (account_id, signing_key) = Account::generate_account_keys();
        let tx = stake_tx(account_id);
        let signed = tx.sign(&signing_key).expect("should sign");
        assert!(signed.verify_signature().is_ok());
    }

    #[test]
    fn verify_signature_detects_signer_tampering() {
        let (account_id, signing_key) = Account::generate_account_keys();
        let (other_id, _) = Account::generate_account_keys();
        let signed = stake_tx(account_id)
            .sign(&signing_key)
            .expect("should sign");
        let mut tampered = signed.clone();
        tampered.from = other_id.to_bytes();
        assert!(matches!(
            tampered.verify_signature(),
            Err(TxError::InvalidSignature { .. })
        ));
    }

    #[test]
    fn verify_signature_requires_signature() {
        let (account_id, _) = Account::generate_account_keys();
        let unsigned = Tx::new(
            MAIN_NET,
            account_id,
            1,
            TxKind::Unstake { amount: Crit::ONE },
        );
        assert!(matches!(
            unsigned.verify_signature(),
            Err(TxError::MissingSignature)
        ));
    }

    #[test]
    fn verify_signature_fails_with_invalid_public_key_bytes() {
        let (account_id, signing_key) = Account::generate_account_keys();
        let mut tx = Tx::new(MAIN_NET, account_id, 0, TxKind::stake(Crit::ONE))
            .sign(&signing_key)
            .expect("sign");
        tx.from = [0u8; PUBKEY_BYTES];
        assert!(matches!(
            tx.verify_signature(),
            Err(TxError::InvalidSenderKey) | Err(TxError::InvalidSignature { .. })
        ));
    }

    #[test]
    fn fee_computation_uses_currency_rules() {
        let (account_id, signing_key) = Account::generate_account_keys();
        let amount = Crit::from_units(250_000_000); // 2.5 CRIT
        let tx = Tx::new(
            MAIN_NET,
            account_id,
            1,
            TxKind::transfer(&account_id, amount),
        );
        let fee = tx.fee().expect("fee");
        // 0.1% of 2.5 CRIT = 0.0025 CRIT = 250_000 units.
        assert_eq!(fee.units(), 250_000);
        let signed = tx.sign(&signing_key).expect("sign");
        assert!(signed.verify_signature().is_ok());
    }

    #[test]
    fn tx_id_is_deterministic_for_identical_transactions() {
        let (account_id, signing_key) = Account::generate_account_keys();
        let signed = Tx::new(
            MAIN_NET,
            account_id,
            3,
            TxKind::stake(Crit::from_units(1_500)),
        )
        .sign(&signing_key)
        .expect("sign");
        let duplicate = signed.clone();

        let first_id = signed.tx_id().expect("tx id");
        let second_id = duplicate.tx_id().expect("tx id duplicate");

        assert_eq!(
            first_id, second_id,
            "identical transactions must yield the same identifier"
        );
    }

    #[test]
    fn tx_id_changes_when_transaction_is_tampered() {
        let (account_id, signing_key) = Account::generate_account_keys();
        let signed = Tx::new(
            MAIN_NET,
            account_id,
            7,
            TxKind::stake(Crit::from_units(2_000)),
        )
        .sign(&signing_key)
        .expect("sign");

        let mut tampered = signed.clone();
        // Simulate signature tampering; verification would fail, but tx_id must differ.
        tampered.signature = Some([0; SIGNATURE_BYTES]);

        let original_id = signed.tx_id().expect("tx id");
        let tampered_id = tampered.tx_id().expect("tampered tx id");

        assert_ne!(
            original_id, tampered_id,
            "changing any field must change the transaction identifier"
        );
    }

    #[test]
    fn identical_payloads_on_different_networks_produce_distinct_signatures() {
        let (account_id, signing_key) = Account::generate_account_keys();
        let kind = TxKind::stake(Crit::from_units(10_000));

        let main_tx = Tx::new(MAIN_NET, account_id, 1, kind);
        let test_tx = Tx::new(TEST_NET, account_id, 1, kind);

        let signed_main = main_tx.clone().sign(&signing_key).expect("main sign");
        let signed_test = test_tx.clone().sign(&signing_key).expect("test sign");

        assert_ne!(
            signed_main.signature, signed_test.signature,
            "different networks must yield different signatures"
        );

        assert_ne!(
            signed_main.tx_id().expect("main id"),
            signed_test.tx_id().expect("test id"),
            "network id participates in tx identifier hashing"
        );
    }

    #[test]
    fn collector_accepts_valid_transaction() {
        let (account_id, signing_key) = Account::generate_account_keys();
        let tx = Tx::new(
            MAIN_NET,
            account_id,
            1,
            TxKind::stake(Crit::from_units(5_000)),
        )
        .sign(&signing_key)
        .expect("sign");

        let mut collector = TransactionCollector::new(MAIN_NET);
        collector.push(tx.clone()).expect("collector push");
        assert_eq!(collector.len(), 1);
        assert_eq!(collector.batch()[0].tx_id().unwrap(), tx.tx_id().unwrap());
    }

    #[test]
    fn tx_check_stateless_passes_for_valid_transfer() {
        let (sender, signing_key) = Account::generate_account_keys();
        let (recipient, _) = Account::generate_account_keys();
        let tx = Tx::new(
            MAIN_NET,
            sender,
            7,
            TxKind::transfer(&recipient, Crit::from_units(1_000)),
        )
        .sign(&signing_key)
        .expect("sign");

        assert!(tx.check_stateless().is_ok());
    }

    #[test]
    fn tx_check_stateless_fails_on_missing_signature() {
        let (account_id, _) = Account::generate_account_keys();
        let tx = Tx::new(
            MAIN_NET,
            account_id,
            7,
            TxKind::stake(Crit::from_units(1_000)),
        );

        assert!(matches!(
            tx.check_stateless(),
            Err(TxError::MissingSignature)
        ));
    }

    #[test]
    fn tx_check_stateless_fails_on_zero_amount() {
        let (account_id, signing_key) = Account::generate_account_keys();
        let tx = Tx::new(MAIN_NET, account_id, 1, TxKind::stake(Crit::ZERO))
            .sign(&signing_key)
            .expect("sign");

        assert!(matches!(tx.check_stateless(), Err(TxError::AmountZero)));
    }

    fn invalid_ed25519_bytes() -> [u8; PUBKEY_BYTES] {
        for seed in 0u64.. {
            let mut candidate = [0u8; PUBKEY_BYTES];
            candidate[..8].copy_from_slice(&seed.to_le_bytes());
            if VerifyingKey::from_bytes(&candidate).is_err() {
                return candidate;
            }
        }
        unreachable!()
    }

    #[test]
    fn tx_check_stateless_fails_on_invalid_recipient_key() {
        let (account_id, signing_key) = Account::generate_account_keys();
        let to = invalid_ed25519_bytes();
        let tx = Tx::new(
            MAIN_NET,
            account_id,
            3,
            TxKind::Transfer {
                to,
                amount: Crit::from_units(500),
            },
        )
        .sign(&signing_key)
        .expect("sign");

        assert!(matches!(
            tx.check_stateless(),
            Err(TxError::InvalidRecipientKey)
        ));
    }

    #[test]
    fn tx_check_stateless_fails_on_self_transfer() {
        let (account_id, signing_key) = Account::generate_account_keys();
        let tx = Tx::new(
            MAIN_NET,
            account_id,
            2,
            TxKind::transfer(&account_id, Crit::from_units(500)),
        )
        .sign(&signing_key)
        .expect("sign");

        assert!(matches!(tx.check_stateless(), Err(TxError::SelfTransfer)));
    }

    #[test]
    fn tx_check_stateless_fails_on_invalid_signature() {
        let (account_id, signing_key) = Account::generate_account_keys();
        let mut tx = Tx::new(
            MAIN_NET,
            account_id,
            9,
            TxKind::stake(Crit::from_units(500)),
        )
        .sign(&signing_key)
        .expect("sign");
        tx.signature = Some([0u8; SIGNATURE_BYTES]);

        assert!(matches!(
            tx.check_stateless(),
            Err(TxError::InvalidSignature { .. })
        ));
    }

    #[test]
    fn collector_rejects_wrong_network() {
        let (account_id, signing_key) = Account::generate_account_keys();
        let tx = Tx::new(
            TEST_NET,
            account_id,
            1,
            TxKind::stake(Crit::from_units(5_000)),
        )
        .sign(&signing_key)
        .expect("sign");

        let mut collector = TransactionCollector::new(MAIN_NET);
        assert!(matches!(
            collector.push(tx),
            Err(CollectError::WrongNetwork {
                expected: MAIN_NET,
                found: TEST_NET
            })
        ));
        assert!(collector.is_empty());
    }

    #[test]
    fn collector_rejects_missing_signature() {
        let (account_id, _) = Account::generate_account_keys();
        let tx = Tx::new(
            MAIN_NET,
            account_id,
            1,
            TxKind::stake(Crit::from_units(5_000)),
        );

        let mut collector = TransactionCollector::new(MAIN_NET);
        assert!(matches!(
            collector.push(tx),
            Err(CollectError::Tx(TxError::MissingSignature))
        ));
    }

    #[test]
    fn collector_rejects_zero_amount_transactions() {
        let (account_id, signing_key) = Account::generate_account_keys();
        let tx = Tx::new(MAIN_NET, account_id, 1, TxKind::stake(Crit::ZERO))
            .sign(&signing_key)
            .expect("sign");

        let mut collector = TransactionCollector::new(MAIN_NET);
        assert!(matches!(
            collector.push(tx),
            Err(CollectError::Tx(TxError::AmountZero))
        ));
    }

    #[test]
    fn collector_rejects_self_transfer() {
        let (account_id, signing_key) = Account::generate_account_keys();
        let tx = Tx::new(
            MAIN_NET,
            account_id,
            1,
            TxKind::transfer(&account_id, Crit::from_units(1_000)),
        )
        .sign(&signing_key)
        .expect("sign");

        let mut collector = TransactionCollector::new(MAIN_NET);
        assert!(matches!(
            collector.push(tx),
            Err(CollectError::Tx(TxError::SelfTransfer))
        ));
    }

    #[test]
    fn collector_rejects_invalid_transfer_recipient() {
        let (account_id, signing_key) = Account::generate_account_keys();
        let invalid_recipient = (0u32..)
            .find_map(|seed| {
                let mut candidate = [0u8; PUBKEY_BYTES];
                candidate[0] = (seed & 0xFF) as u8;
                candidate[1] = ((seed >> 8) & 0xFF) as u8;
                if VerifyingKey::from_bytes(&candidate).is_err() {
                    Some(candidate)
                } else {
                    None
                }
            })
            .expect("should find an invalid recipient key");
        let tx = Tx::new(
            MAIN_NET,
            account_id,
            1,
            TxKind::Transfer {
                to: invalid_recipient,
                amount: Crit::from_units(1_000),
            },
        )
        .sign(&signing_key)
        .expect("sign");

        let mut collector = TransactionCollector::new(MAIN_NET);
        assert!(matches!(
            collector.push(tx),
            Err(CollectError::Tx(TxError::InvalidRecipientKey))
        ));
    }

    #[test]
    fn collector_drain_emits_transactions() {
        let (account_id, signing_key) = Account::generate_account_keys();
        let mut collector = TransactionCollector::new(MAIN_NET);
        for nonce in 1..=3 {
            let tx = Tx::new(
                MAIN_NET,
                account_id,
                nonce,
                TxKind::stake(Crit::from_units(1_000)),
            )
            .sign(&signing_key)
            .expect("sign");
            collector.push(tx).expect("collect");
        }

        let drained = collector.drain();
        assert_eq!(drained.len(), 3);
        assert!(collector.is_empty());
    }
}
