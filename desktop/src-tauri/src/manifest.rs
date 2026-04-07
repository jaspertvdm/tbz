use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ── Frontend-facing types (returned by Tauri commands) ─────────────

/// Bundle info returned to the frontend
///
/// Adapter between tbz-core internals and the TypeScript UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleInfo {
    pub protocol: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub created_at: String,
    pub created_by: String,
    /// Ed25519 public key (hex) — used to verify all block signatures
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_key: Option<String>,
    pub stats: BundleStats,
    /// Per-file entries from the archive
    pub files: Vec<FileEntry>,
    /// Archive format detected
    pub format: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleStats {
    pub total_files: usize,
    pub total_bytes: u64,
    pub total_blocks: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub path: String,
    pub size: u64,
    pub jis_level: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResult {
    pub valid: bool,
    pub info: Option<BundleInfo>,
    pub verified_blocks: usize,
    pub failed_blocks: Vec<String>,
    pub format: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractResult {
    pub valid: bool,
    pub forced: bool,
    pub info: Option<BundleInfo>,
    pub extracted_files: Vec<String>,
    pub output_dir: String,
    pub verified_blocks: usize,
}

/// Metadata provided by user when creating a bundle
#[derive(Debug, Clone)]
pub struct BundleMeta {
    pub agent: Option<String>,
    pub title: Option<String>,
}

// ── Conversion from tbz-core types ─────────────────────────────────

/// Convert tbz-core Manifest into frontend BundleInfo
pub fn info_from_core_manifest(
    manifest: &tbz_core::manifest::Manifest,
    created_at: &str,
    agent: Option<String>,
) -> BundleInfo {
    let files: Vec<FileEntry> = manifest
        .blocks
        .iter()
        .filter_map(|b| {
            b.path.as_ref().map(|p| FileEntry {
                path: p.clone(),
                size: b.uncompressed_size,
                jis_level: b.jis_level,
            })
        })
        .collect();

    BundleInfo {
        protocol: "TBZ".to_string(),
        version: format!("{}", manifest.tbz_version),
        agent,
        title: None,
        created_at: created_at.to_string(),
        created_by: format!("TBZ Desktop v{}", env!("CARGO_PKG_VERSION")),
        signing_key: manifest.signing_key.clone(),
        stats: BundleStats {
            total_files: files.len(),
            total_bytes: manifest.total_uncompressed_size,
            total_blocks: manifest.block_count,
        },
        files,
        format: "tbz".to_string(),
    }
}

// ── Legacy TIBET-ZIP support (old Desktop ZIP+MANIFEST format) ─────

/// Legacy MANIFEST.json from old TIBET-ZIP format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyManifest {
    pub protocol: String,
    pub version: String,
    #[serde(default)]
    pub agent: Option<String>,
    #[serde(default)]
    pub title: Option<String>,
    pub created_at: String,
    pub created_by: String,
    pub hashes: BTreeMap<String, String>,
    pub stats: LegacyStats,
    pub bundle_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyStats {
    pub total_files: usize,
    pub total_bytes: u64,
}

/// Compute bundle_hash for legacy format verification
pub fn compute_legacy_bundle_hash(hashes: &BTreeMap<String, String>) -> String {
    use sha2::{Digest, Sha256};
    let combined: String = hashes
        .iter()
        .map(|(k, v)| format!("{}:{}", k, v))
        .collect::<Vec<_>>()
        .join("|");
    let mut hasher = Sha256::new();
    hasher.update(combined.as_bytes());
    hex::encode(hasher.finalize())
}

/// Convert legacy manifest into frontend BundleInfo
pub fn info_from_legacy(manifest: &LegacyManifest) -> BundleInfo {
    let files: Vec<FileEntry> = manifest
        .hashes
        .keys()
        .map(|p| FileEntry {
            path: p.clone(),
            size: 0,
            jis_level: 0,
        })
        .collect();

    BundleInfo {
        protocol: "TIBET-ZIP (legacy)".to_string(),
        version: manifest.version.clone(),
        agent: manifest.agent.clone(),
        title: manifest.title.clone(),
        created_at: manifest.created_at.clone(),
        created_by: manifest.created_by.clone(),
        signing_key: None,
        stats: BundleStats {
            total_files: manifest.stats.total_files,
            total_bytes: manifest.stats.total_bytes,
            total_blocks: 0,
        },
        files,
        format: "tibet-zip".to_string(),
    }
}
