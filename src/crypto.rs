//! Minimal cryptographic helpers for prototype purposes.
//!
//! This module currently exposes a simple Ed25519 keypair generator and thin
//! wrappers around BLAKE3 so that higher layers can be wired without committing
//! to a final cryptographic design. The implementation should be revisited once
//! the networking and consensus layers impose stronger requirements (hardware
//! wallets, VRF, multisignatures, etc.).
//!
use crate::random;
use argon2::Argon2;
pub use blake3::Hash as Blake3Hash;
use chacha20poly1305::{
    ChaCha20Poly1305,
    aead::{Aead, KeyInit},
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::RngCore;
use std::path::Path;
use std::{fs::File, io::Write};

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const SIGNING_KEY_LEN: usize = 32;
const AUTH_TAG_LEN: usize = 16;
const EXPECTED_FILE_SIZE: usize = SALT_LEN + NONCE_LEN + SIGNING_KEY_LEN + AUTH_TAG_LEN; // salt + nonce + key + auth tag

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

/// Derives a 32-byte encryption key from a passphrase using Argon2 KDF.
pub fn derive_key_from_passphrase(passphrase: Vec<u8>, salt: &[u8]) -> std::io::Result<[u8; 32]> {
    let mut output_key_material = [0u8; 32];

    Argon2::default()
        .hash_password_into(&passphrase, salt, &mut output_key_material)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    Ok(output_key_material)
}

/// Encrypts and writes a signing key to a file using Argon2 + ChaCha20Poly1305.
///
/// File format (76 bytes): `[salt: 16][nonce: 12][ciphertext+tag: 48]`
pub fn write_signing_key_to_file(
    signing_key: &SigningKey,
    path: &Path,
    passphrase: Vec<u8>,
) -> std::io::Result<()> {
    let mut file = File::create(path)?;
    let mut rng = random::crypto_rng();

    // Generate a random salt for Argon2
    let mut salt = [0u8; SALT_LEN];
    rng.fill_bytes(&mut salt);

    // Generate a random nonce for ChaCha20Poly1305 encryption
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);

    // Derive encryption key from passphrase and salt
    let output_key_material = derive_key_from_passphrase(passphrase, &salt)?;

    // Create ChaCha20Poly1305 cipher instance
    let cipher = ChaCha20Poly1305::new(&output_key_material.into());

    // Encrypt the signing key bytes with the derived key and nonce
    let ciphertext = cipher
        .encrypt(nonce.as_ref().into(), signing_key.to_bytes().as_ref())
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("encryption failed: {}", e),
            )
        })?;

    // Write salt + nonce + ciphertext to file
    file.write_all(&[&salt, &nonce[..], &ciphertext[..]].concat())?;

    Ok(())
}

/// Reads and decrypts a signing key from a file. Returns an error if the passphrase
/// is incorrect, the file is corrupted, or the size is invalid (must be exactly 76 bytes).
pub fn read_signing_key_from_file(path: &Path, passphrase: Vec<u8>) -> std::io::Result<SigningKey> {
    let file_content = std::fs::read(path)?;
    if file_content.len() != EXPECTED_FILE_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid file size: expected {} bytes, got {}", EXPECTED_FILE_SIZE, file_content.len())
        ));
    }
    // Extract salt and nonce from file content
    let salt = &file_content[0..SALT_LEN];
    let nonce = &file_content[SALT_LEN..SALT_LEN + NONCE_LEN];

    // Derive encryption key from passphrase and salt
    let output_key_material = derive_key_from_passphrase(passphrase, &salt)?;

    // Create ChaCha20Poly1305 cipher instance
    let cipher = ChaCha20Poly1305::new(&output_key_material.into());

    // Extract ciphertext from file content
    let ciphertext = &file_content[SALT_LEN + NONCE_LEN..];

    // Decrypt the signing key bytes with nonce and derived key 
    let plaintext = cipher
        .decrypt(nonce.into(), ciphertext.as_ref())
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "failed to decrypt signing key (incorrect passphrase or corrupted file)",
            )
        })?;

    // Expect a 32-byte Ed25519 signing key; convert from slice to array.
    let sk_bytes: [u8; 32] = plaintext.as_slice().try_into().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "decrypted key uses invalid length",
        )
    })?;

    Ok(SigningKey::from_bytes(&sk_bytes))
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

    #[test]
    fn encrypted_file_size_is_correct() {
        use std::fs;
        use std::path::PathBuf;

        let (_verifying, signing_key) = generate_keypair();
        let passphrase = b"test_password".to_vec();

        let temp_path = PathBuf::from("/tmp/test_encrypted_key_size.bin");

        write_signing_key_to_file(&signing_key, &temp_path, passphrase)
            .expect("should write encrypted key");

        let metadata = fs::metadata(&temp_path).expect("should get file metadata");
        assert_eq!(
            metadata.len() as usize,
            EXPECTED_FILE_SIZE,
            "encrypted file size should match expected size"
        );

        fs::remove_file(&temp_path).ok();
    }

    #[test]
    fn encrypt_decrypt_signing_key_round_trip() {
        use std::fs;
        use std::path::PathBuf;

        let (_verifying, signing_key) = generate_keypair();
        let passphrase = b"strong_password".to_vec();

        let temp_path = PathBuf::from("/tmp/test_encrypted_key.bin");

        write_signing_key_to_file(&signing_key, &temp_path, passphrase.clone())
            .expect("should write encrypted key");

        let decrypted_key =
            read_signing_key_from_file(&temp_path, passphrase).expect("should read encrypted key");

        assert_eq!(
            signing_key.to_bytes(),
            decrypted_key.to_bytes(),
            "decrypted key should match original"
        );

        fs::remove_file(&temp_path).ok();
    }

    #[test]
    fn decrypt_with_wrong_passphrase_fails() {
        use std::fs;
        use std::path::PathBuf;

        let (_verifying, signing_key) = generate_keypair();
        let correct_passphrase = b"correct_password".to_vec();
        let wrong_passphrase = b"wrong_password".to_vec();

        let temp_path = PathBuf::from("/tmp/test_encrypted_key.bin");

        write_signing_key_to_file(&signing_key, &temp_path, correct_passphrase)
            .expect("should write encrypted key");

        let result = read_signing_key_from_file(&temp_path, wrong_passphrase);

        if let Err(e) = result {
            assert!(e.to_string().contains("incorrect passphrase"));
        } else {
            panic!("decryption should fail with wrong passphrase");
        }
        fs::remove_file(&temp_path).ok();
    }

    #[test]
    fn decrypt_with_tampered_file_fails() {
        use std::fs;
        use std::path::PathBuf;

        let (_verifying, signing_key) = generate_keypair();
        let passphrase = b"secure_password".to_vec();

        let temp_path = PathBuf::from("/tmp/test_encrypted_key.bin");

        write_signing_key_to_file(&signing_key, &temp_path, passphrase.clone())
            .expect("should write encrypted key");

        // Tamper with the file by flipping a byte
        let mut file_content = fs::read(&temp_path).expect("should read file");
        file_content[20] ^= 0xFF; // Flip a byte in the ciphertext
        fs::write(&temp_path, &file_content).expect("should write tampered file");

        let result = read_signing_key_from_file(&temp_path, passphrase);

        assert!(result.is_err(), "decryption should fail with tampered file");

        fs::remove_file(&temp_path).ok();
    }

    #[test]
    fn derive_key_from_passphrase_is_consistent() {
        let passphrase = b"consistent_passphrase".to_vec();
        let salt = b"fixed_salt_12345"; // 16 bytes

        let key1 = derive_key_from_passphrase(passphrase.clone(), salt).expect("should derive key");
        let key2 = derive_key_from_passphrase(passphrase, salt).expect("should derive key");

        assert_eq!(key1, key2, "derived keys should be consistent");
    }

    #[test]
    fn invalid_file_size_returns_error() {
        use std::fs;
        use std::path::PathBuf;

        let temp_path = PathBuf::from("/tmp/invalid_size_key.bin");
        fs::write(&temp_path, b"too_short").expect("should write invalid file");

        let passphrase = b"any_password".to_vec();
        let result = read_signing_key_from_file(&temp_path, passphrase);

        assert!(result.is_err(), "should return error for invalid file size");

        fs::remove_file(&temp_path).ok();
    }
}
