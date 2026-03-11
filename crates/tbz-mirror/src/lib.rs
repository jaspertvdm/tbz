//! tbz-mirror: TIBET Transparency Mirror
//!
//! A sled-backed local trust database that stores cryptographic fingerprints,
//! TIBET provenance chains, and attestations for known packages.
//! Designed to participate in a DHT network for distributed verification.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum MirrorError {
    #[error("Storage error: {0}")]
    Storage(String),
    #[error("Entry not found: {0}")]
    NotFound(String),
    #[error("Serialization error: {0}")]
    Serialization(String),
}

/// A trust entry in the Transparency Mirror
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustEntry {
    /// SHA-256 hash of the original archive/package
    pub content_hash: String,
    /// TIBET provenance chain (list of token IDs)
    pub provenance_chain: Vec<String>,
    /// Source identity (JIS ID of the publisher)
    pub source_jis_id: Option<String>,
    /// Known vulnerabilities (CVE IDs)
    pub vulnerabilities: Vec<String>,
    /// Attestations from other nodes
    pub attestations: Vec<Attestation>,
    /// First seen timestamp
    pub first_seen: String,
    /// Last verified timestamp
    pub last_verified: String,
}

/// An attestation from a mirror node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    /// JIS ID of the attesting node
    pub attester: String,
    /// Verdict: safe, suspicious, malicious
    pub verdict: Verdict,
    /// Timestamp of attestation
    pub timestamp: String,
    /// Optional evidence/notes
    pub notes: Option<String>,
}

/// Trust verdict
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Verdict {
    Safe,
    Suspicious,
    Malicious,
    Unknown,
}

/// The local Transparency Mirror backed by sled
pub struct Mirror {
    db: sled::Db,
}

impl Mirror {
    /// Open or create a mirror database at the given path
    pub fn open(path: &str) -> Result<Self, MirrorError> {
        let db = sled::open(path).map_err(|e| MirrorError::Storage(e.to_string()))?;
        Ok(Self { db })
    }

    /// Store a trust entry
    pub fn store(&self, entry: &TrustEntry) -> Result<(), MirrorError> {
        let key = entry.content_hash.as_bytes();
        let value = serde_json::to_vec(entry)
            .map_err(|e| MirrorError::Serialization(e.to_string()))?;
        self.db
            .insert(key, value)
            .map_err(|e| MirrorError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Look up a trust entry by content hash
    pub fn lookup(&self, content_hash: &str) -> Result<Option<TrustEntry>, MirrorError> {
        match self.db.get(content_hash.as_bytes()) {
            Ok(Some(value)) => {
                let entry: TrustEntry = serde_json::from_slice(&value)
                    .map_err(|e| MirrorError::Serialization(e.to_string()))?;
                Ok(Some(entry))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(MirrorError::Storage(e.to_string())),
        }
    }

    /// Add an attestation to an existing entry
    pub fn attest(
        &self,
        content_hash: &str,
        attestation: Attestation,
    ) -> Result<(), MirrorError> {
        if let Some(mut entry) = self.lookup(content_hash)? {
            entry.attestations.push(attestation);
            self.store(&entry)?;
            Ok(())
        } else {
            Err(MirrorError::NotFound(content_hash.to_string()))
        }
    }

    /// Compute SHA-256 hash for raw data
    pub fn hash_data(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("sha256:{:x}", hasher.finalize())
    }

    /// Get total number of entries
    pub fn count(&self) -> usize {
        self.db.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env::temp_dir;

    #[test]
    fn test_mirror_store_and_lookup() {
        let path = temp_dir().join("tbz_mirror_test");
        let mirror = Mirror::open(path.to_str().unwrap()).unwrap();

        let entry = TrustEntry {
            content_hash: "sha256:abc123".to_string(),
            provenance_chain: vec!["token:1".to_string()],
            source_jis_id: Some("jis:ed25519:test".to_string()),
            vulnerabilities: vec![],
            attestations: vec![],
            first_seen: "2026-03-11T00:00:00Z".to_string(),
            last_verified: "2026-03-11T00:00:00Z".to_string(),
        };

        mirror.store(&entry).unwrap();
        let found = mirror.lookup("sha256:abc123").unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().source_jis_id, entry.source_jis_id);

        // Cleanup
        let _ = std::fs::remove_dir_all(path);
    }
}
