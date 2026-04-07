use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// MANIFEST.json — compatible with Python tibet_triage.zip_bundle
///
/// Protocol: "TIBET-ZIP", Version: "1.0"
/// bundle_hash = SHA256 of sorted "key:hash" pairs joined by "|"

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub protocol: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event: Option<String>,
    pub created_at: String,
    pub created_by: String,
    /// BTreeMap for deterministic key ordering (critical for bundle_hash)
    pub hashes: BTreeMap<String, String>,
    pub stats: BundleStats,
    pub bundle_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleStats {
    pub total_files: usize,
    pub total_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipoll_messages: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tibet_tokens: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upip_bundles: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fork_tokens: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResult {
    pub valid: bool,
    pub manifest: Option<Manifest>,
    pub verified_files: usize,
    pub failed_files: Vec<String>,
    pub missing_files: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractResult {
    pub valid: bool,
    pub forced: bool,
    pub manifest: Option<Manifest>,
    pub extracted_files: Vec<String>,
    pub output_dir: String,
    pub verified_files: usize,
}

/// Metadata provided by user when creating a bundle
#[derive(Debug, Clone)]
pub struct BundleMeta {
    pub agent: Option<String>,
    pub title: Option<String>,
}

impl Manifest {
    pub fn new(hashes: BTreeMap<String, String>, stats: BundleStats, meta: BundleMeta) -> Self {
        let bundle_hash = compute_bundle_hash(&hashes);
        Self {
            protocol: "TIBET-ZIP".to_string(),
            version: "1.0".to_string(),
            agent: meta.agent,
            title: meta.title,
            event: None,
            created_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
            created_by: format!("TBZ Desktop v{}", env!("CARGO_PKG_VERSION")),
            hashes,
            stats,
            bundle_hash,
        }
    }
}

/// Compute bundle_hash: SHA256 of sorted "key:hash" pairs joined by "|"
/// This is identical to the Python implementation in tibet_triage.zip_bundle
pub fn compute_bundle_hash(hashes: &BTreeMap<String, String>) -> String {
    use sha2::{Digest, Sha256};
    // BTreeMap is already sorted by key
    let combined: String = hashes
        .iter()
        .map(|(k, v)| format!("{}:{}", k, v))
        .collect::<Vec<_>>()
        .join("|");
    let mut hasher = Sha256::new();
    hasher.update(combined.as_bytes());
    hex::encode(hasher.finalize())
}
