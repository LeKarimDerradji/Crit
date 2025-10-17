//! Minimal cryptographic helpers for prototype purposes.
//!
//! This module currently exposes a simple Ed25519 keypair generator and thin
//! wrappers around BLAKE3 so that higher layers can be wired without committing
//! to a final cryptographic design. The implementation should be revisited once
//! the networking and consensus layers impose stronger requirements (hardware
//! wallets, VRF, multisignatures, etc.).

use crate::random;
pub use blake3::Hash as Blake3Hash;
use ed25519_dalek::{SigningKey, VerifyingKey};

/// Generates an Ed25519 keypair using the thread-local cryptographic RNG.
pub fn generate_keypair() -> (VerifyingKey, SigningKey) {
    let mut rng = random::crypto_rng();
    let signing = SigningKey::generate(&mut rng);
    let verifying = signing.verifying_key();
    (verifying, signing)
}

/// Computes the BLAKE3 hash of `input`.
pub fn blake3_hash(input: &[u8]) -> Blake3Hash {
    blake3::hash(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, Verifier};

    #[test]
    fn generate_keypair_produces_unique_keys() {
        let (pub1, sec1) = generate_keypair();
        let (pub2, sec2) = generate_keypair();
        assert_ne!(
            pub1.to_bytes(),
            pub2.to_bytes(),
            "public keys should differ"
        );
        assert_ne!(
            sec1.to_bytes(),
            sec2.to_bytes(),
            "secret keys should differ"
        );
    }

    #[test]
    fn signing_and_verifying_round_trip() {
        let (public, private) = generate_keypair();
        let message = b"crit signing test";

        let signature = private.sign(message);
        public
            .verify(message, &signature)
            .expect("signature should verify");
    }

    #[test]
    fn signature_verification_fails_on_modified_message() {
        let (public, private) = generate_keypair();
        let signature = private.sign(b"original message");

        assert!(
            public.verify(b"tampered message", &signature).is_err(),
            "verification should fail on modified message"
        );
    }

    #[test]
    fn signature_verification_fails_on_modified_signature() {
        let (public, private) = generate_keypair();
        let mut signature = private.sign(b"crit mod sig").to_bytes();

        // Flip a bit in the signature to simulate tampering.
        signature[0] ^= 0x01;
        let tampered = ed25519_dalek::Signature::from_bytes(&signature);
        assert!(
            public.verify(b"crit mod sig", &tampered).is_err(),
            "verification should fail when the signature is tampered"
        );
    }

    #[test]
    fn signature_verification_fails_on_wrong_public_key() {
        let (_public1, private1) = generate_keypair();
        let (public2, _) = generate_keypair();
        let signature = private1.sign(b"crit wrong key");

        assert!(
            public2.verify(b"crit wrong key", &signature).is_err(),
            "verification should fail with a different public key"
        );
    }

    #[test]
    fn blake3_helpers_return_consistent_results() {
        let input = b"crit hashing";
        let hash = blake3_hash(input);
        let digest: [u8; 32] = *hash.as_bytes();
        assert_eq!(hash.as_bytes(), &digest);
    }
}
