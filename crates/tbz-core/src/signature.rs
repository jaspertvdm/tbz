//! Ed25519 signing and verification for TBZ blocks

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SignError {
    #[error("Signing failed: {0}")]
    SigningFailed(String),
    #[error("Verification failed: invalid signature")]
    VerificationFailed,
    #[error("Invalid key: {0}")]
    InvalidKey(String),
}

/// Generate a SHA-256 hash of arbitrary data
pub fn sha256_hash(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("sha256:{:x}", hasher.finalize())
}

/// Sign data with an Ed25519 signing key
pub fn sign(data: &[u8], signing_key: &SigningKey) -> Vec<u8> {
    let signature = signing_key.sign(data);
    signature.to_bytes().to_vec()
}

/// Verify an Ed25519 signature
pub fn verify(data: &[u8], signature_bytes: &[u8], verifying_key: &VerifyingKey) -> Result<(), SignError> {
    let signature = ed25519_dalek::Signature::from_slice(signature_bytes)
        .map_err(|e| SignError::InvalidKey(e.to_string()))?;

    verifying_key
        .verify(data, &signature)
        .map_err(|_| SignError::VerificationFailed)
}

/// Generate a new Ed25519 keypair
pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let mut rng = rand::thread_rng();
    let signing_key = SigningKey::generate(&mut rng);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify() {
        let (signing_key, verifying_key) = generate_keypair();
        let data = b"TBZ block data";

        let sig = sign(data, &signing_key);
        assert!(verify(data, &sig, &verifying_key).is_ok());
    }

    #[test]
    fn test_tampered_data_fails() {
        let (signing_key, verifying_key) = generate_keypair();
        let data = b"TBZ block data";
        let tampered = b"TBZ block tampered";

        let sig = sign(data, &signing_key);
        assert!(verify(tampered, &sig, &verifying_key).is_err());
    }

    #[test]
    fn test_sha256_hash() {
        let hash = sha256_hash(b"hello");
        assert!(hash.starts_with("sha256:"));
    }
}
