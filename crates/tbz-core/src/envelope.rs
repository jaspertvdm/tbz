//! TIBET envelope: provenance metadata per block
//!
//! Every TBZ block carries a TIBET token with four dimensions:
//! - ERIN:     What's IN the block (content hash, type)
//! - ERAAN:    What's attached (dependencies, parent blocks)
//! - EROMHEEN: Context around it (origin, timestamp)
//! - ERACHTER: Intent behind it (why this block exists)

use serde::{Deserialize, Serialize};

/// TIBET envelope embedded in every TBZ block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TibetEnvelope {
    pub erin: Erin,
    pub eraan: Vec<String>,
    pub eromheen: Eromheen,
    pub erachter: String,
}

/// ERIN: what's inside this block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Erin {
    /// SHA-256 hash of the uncompressed content
    pub content_hash: String,
    /// Block content type
    pub block_type: String,
    /// MIME type of the uncompressed content
    pub mime_type: String,
}

/// EROMHEEN: context surrounding this block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Eromheen {
    /// ISO 8601 timestamp of block creation
    pub created: String,
    /// Identity of the packager (JIS ID or human-readable)
    pub origin: String,
    /// TBZ format version used
    pub tbz_version: String,
    /// Source repository (from .jis.json, if available)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_repo: Option<String>,
}

impl TibetEnvelope {
    /// Create a new TIBET envelope for a data block
    pub fn new(
        content_hash: String,
        block_type: &str,
        mime_type: &str,
        origin: &str,
        intent: &str,
        dependencies: Vec<String>,
    ) -> Self {
        Self {
            erin: Erin {
                content_hash,
                block_type: block_type.to_string(),
                mime_type: mime_type.to_string(),
            },
            eraan: dependencies,
            eromheen: Eromheen {
                created: chrono_now(),
                origin: origin.to_string(),
                tbz_version: format!("{}", crate::VERSION),
                source_repo: None,
            },
            erachter: intent.to_string(),
        }
    }

    /// Attach source repository info (from .jis.json)
    pub fn with_source_repo(mut self, repo: &str) -> Self {
        self.eromheen.source_repo = Some(repo.to_string());
        self
    }
}

/// Get current timestamp as ISO 8601 string (no chrono dependency, keep it simple)
fn chrono_now() -> String {
    // Using std::time for now — no external chrono dependency needed
    use std::time::SystemTime;
    let duration = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}Z", duration.as_secs())
}
