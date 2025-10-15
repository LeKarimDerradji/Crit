use crate::account::AccountId;
use crate::currency::{Crit, CurrencyError};
use borsh::{BorshDeserialize, BorshSerialize, to_vec};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use thiserror::Error;

const PUBKEY_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;

/// Supported transaction payloads.
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

/// Errors produced while working with transactions.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TxError {
    #[error("transaction signature is missing")]
    MissingSignature,
    #[error("transaction signature is invalid")]
    InvalidSignature,
    #[error("attempted to sign transaction with mismatched key")]
    MismatchedSigner,
    #[error("fee computation overflowed")]
    Fee(CurrencyError),
    #[error("failed to decode transaction")]
    Decode,
}

/// Canonical representation of a Crit transaction.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
pub struct Tx {
    pub from: [u8; PUBKEY_BYTES],
    pub nonce: u64,
    pub kind: TxKind,
    pub signature: Option<[u8; SIGNATURE_BYTES]>,
}

impl Tx {
    /// Creates a new unsigned transaction.
    pub fn new(from: AccountId, nonce: u64, kind: TxKind) -> Self {
        Self {
            from: from.to_bytes(),
            nonce,
            kind,
            signature: None,
        }
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
        let message = self.message();
        let signature = signing_key.sign(&message);
        self.signature = Some(signature.to_bytes());
        Ok(self)
    }

    /// Verifies the transaction signature against the embedded public key.
    pub fn verify_signature(&self) -> Result<(), TxError> {
        let signature_bytes = self.signature.ok_or(TxError::MissingSignature)?;
        let signature = Signature::from_bytes(&signature_bytes);
        let from_key = VerifyingKey::from_bytes(&self.from).map_err(|_| TxError::Decode)?;
        from_key
            .verify(&self.message(), &signature)
            .map_err(|_| TxError::InvalidSignature)
    }

    /// Serializes the transaction (including signature) using Borsh.
    pub fn to_bytes(&self) -> Result<Vec<u8>, TxError> {
        to_vec(self).map_err(|_| TxError::Decode)
    }

    /// Deserializes a transaction from Borsh bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TxError> {
        Tx::try_from_slice(bytes).map_err(|_| TxError::Decode)
    }

    fn message(&self) -> Vec<u8> {
        // sign only the Borsh encoding of the transaction without the signature field
        let signable = TxSignable {
            from: self.from,
            nonce: self.nonce,
            kind: self.kind,
        };
        to_vec(&signable).expect("borsh serialization should not fail")
    }
}

#[derive(BorshSerialize, BorshDeserialize)]
struct TxSignable {
    from: [u8; PUBKEY_BYTES],
    nonce: u64,
    kind: TxKind,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::Account;

    #[test]
    fn signing_and_verification_round_trip() {
        let (account_id, signing_key) = Account::generate_account_keys();
        let tx = Tx::new(
            account_id,
            42,
            TxKind::transfer(&account_id, Crit::from_units(1_000)),
        );
        let signed = tx.sign(&signing_key).expect("signing to succeed");
        assert!(signed.verify_signature().is_ok());
    }

    #[test]
    fn serialization_round_trip_preserves_fields() {
        let (account_id, signing_key) = Account::generate_account_keys();
        let tx = Tx::new(
            account_id,
            99,
            TxKind::Unstake {
                amount: Crit::from_units(123_456),
            },
        )
        .sign(&signing_key)
        .expect("sign");

        let bytes = tx.to_bytes().expect("serialize");
        let decoded = Tx::from_bytes(&bytes).expect("deserialize");

        assert_eq!(decoded.from, tx.from);
        assert_eq!(decoded.nonce, tx.nonce);
        assert!(matches!(decoded.kind, TxKind::Unstake { amount } if amount.units() == 123_456));
        assert_eq!(decoded.signature, tx.signature);
        assert!(decoded.verify_signature().is_ok());
    }

    #[test]
    fn deserializing_invalid_bytes_fails() {
        let bytes = vec![0u8; 3]; // too short
        assert!(matches!(Tx::from_bytes(&bytes), Err(TxError::Decode)));
    }

    #[test]
    fn mismatched_key_fails_to_sign() {
        let (account_id, signing_key) = Account::generate_account_keys();
        let (other_id, other_sk) = Account::generate_account_keys();
        let tx = Tx::new(account_id, 0, TxKind::Stake { amount: Crit::ONE });

        assert!(matches!(
            tx.clone().sign(&other_sk),
            Err(TxError::MismatchedSigner)
        ));

        // Ensure original key still works.
        let signed = tx.sign(&signing_key).expect("should sign");
        assert!(signed.verify_signature().is_ok());

        // Tamper the signer (replay attack with different key) using the same signature.
        let mut tampered = signed.clone();
        tampered.from = other_id.to_bytes();
        assert!(matches!(
            tampered.verify_signature(),
            Err(TxError::InvalidSignature)
        ));

        // Missing signature
        assert!(matches!(
            Tx::new(other_id, 1, TxKind::Unstake { amount: Crit::ONE }).verify_signature(),
            Err(TxError::MissingSignature)
        ));
    }

    #[test]
    fn fee_computation_uses_currency_rules() {
        let (account_id, signing_key) = Account::generate_account_keys();
        let amount = Crit::from_units(250_000_000); // 2.5 CRIT
        let tx = Tx::new(account_id, 1, TxKind::transfer(&account_id, amount));
        let fee = tx.fee().expect("fee");
        // 0.1% of 2.5 CRIT = 0.0025 CRIT = 250_000 units.
        assert_eq!(fee.units(), 250_000);
        let signed = tx.sign(&signing_key).expect("sign");
        assert!(signed.verify_signature().is_ok());
    }
}
