//! tbz-jis: JIS integration for TBZ
//!
//! Parses .jis.json repository identity manifests, handles authorization
//! checks per block, and binds repository identity to TBZ provenance chains.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum JisError {
    #[error("No .jis.json found in repository root")]
    ManifestNotFound,
    #[error("Invalid .jis.json: {0}")]
    InvalidManifest(String),
    #[error("Signature verification failed for .jis.json")]
    SignatureInvalid,
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// .jis.json repository identity manifest
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JisManifest {
    /// TBZ version this manifest targets
    pub tbz: String,
    /// JIS identity (e.g., "jis:ed25519:zK3a9fB2...")
    pub jis_id: String,
    /// Identity claim
    pub claim: JisClaim,
    /// TIBET provenance metadata
    pub tibet: JisTibet,
    /// Ed25519 signature over the manifest
    pub signature: String,
    /// ISO 8601 timestamp
    pub timestamp: String,
}

/// Identity claim in .jis.json
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JisClaim {
    /// Platform (e.g., "github", "gitlab")
    pub platform: String,
    /// Account name
    pub account: String,
    /// Repository name
    pub repo: String,
    /// Intent declaration
    pub intent: String,
    /// Per-path sector authorization levels
    #[serde(default)]
    pub sectors: HashMap<String, SectorConfig>,
}

/// Sector configuration for a path pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectorConfig {
    /// JIS authorization level
    pub jis_level: u8,
    /// Human-readable description
    pub description: String,
}

/// TIBET metadata in .jis.json
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JisTibet {
    pub erin: String,
    pub eraan: Vec<String>,
    pub erachter: String,
}

impl JisManifest {
    /// Load .jis.json from a repository root
    pub fn load(repo_root: &Path) -> Result<Self, JisError> {
        let manifest_path = repo_root.join(".jis.json");
        if !manifest_path.exists() {
            return Err(JisError::ManifestNotFound);
        }

        let content = std::fs::read_to_string(&manifest_path)?;
        let manifest: JisManifest = serde_json::from_str(&content)
            .map_err(|e| JisError::InvalidManifest(e.to_string()))?;

        Ok(manifest)
    }

    /// Determine JIS level for a given file path based on sector mapping
    pub fn jis_level_for_path(&self, path: &str) -> u8 {
        for (pattern, config) in &self.claim.sectors {
            if path_matches_glob(path, pattern) {
                return config.jis_level;
            }
        }
        // Default: level 0 (public)
        0
    }

    /// Get the full repository identifier (platform/account/repo)
    pub fn repo_identifier(&self) -> String {
        format!(
            "{}/{}/{}",
            self.claim.platform, self.claim.account, self.claim.repo
        )
    }
}

/// Simple glob matching for sector patterns
fn path_matches_glob(path: &str, pattern: &str) -> bool {
    if pattern.ends_with("/*") {
        let prefix = &pattern[..pattern.len() - 2];
        path.starts_with(prefix)
    } else if pattern.ends_with("/**") {
        let prefix = &pattern[..pattern.len() - 3];
        path.starts_with(prefix)
    } else {
        path == pattern
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_matching() {
        assert!(path_matches_glob("src/main.rs", "src/*"));
        assert!(path_matches_glob("src/lib/deep.rs", "src/**"));
        assert!(!path_matches_glob("keys/secret.key", "src/*"));
        assert!(path_matches_glob("data/model.bin", "data/*"));
    }

    #[test]
    fn test_jis_level_for_path() {
        let manifest = JisManifest {
            tbz: "1.0".to_string(),
            jis_id: "jis:ed25519:test".to_string(),
            claim: JisClaim {
                platform: "github".to_string(),
                account: "jaspertvdm".to_string(),
                repo: "tbz".to_string(),
                intent: "official_releases".to_string(),
                sectors: HashMap::from([
                    ("src/*".to_string(), SectorConfig {
                        jis_level: 0,
                        description: "Public source".to_string(),
                    }),
                    ("keys/*".to_string(), SectorConfig {
                        jis_level: 2,
                        description: "Signing keys".to_string(),
                    }),
                ]),
            },
            tibet: JisTibet {
                erin: "test".to_string(),
                eraan: vec![],
                erachter: "test".to_string(),
            },
            signature: "test".to_string(),
            timestamp: "2026-03-11T00:00:00Z".to_string(),
        };

        assert_eq!(manifest.jis_level_for_path("src/main.rs"), 0);
        assert_eq!(manifest.jis_level_for_path("keys/signing.key"), 2);
        assert_eq!(manifest.jis_level_for_path("README.md"), 0); // default
    }
}
