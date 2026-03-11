//! TBZ Manifest: Block 0 of every archive
//!
//! The manifest is the cryptographically signed index of the archive.
//! It declares all blocks, their types, sizes, and JIS authorization levels.
//! Always JIS level 0 (publicly readable).

use crate::JisLevel;
use serde::{Deserialize, Serialize};

/// The manifest — always Block 0, always JIS level 0
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    /// TBZ format version
    pub tbz_version: u8,
    /// Total number of blocks (including manifest)
    pub block_count: u32,
    /// Per-block metadata
    pub blocks: Vec<BlockEntry>,
    /// Archive structure: flat or deep (nested)
    pub structure: ArchiveStructure,
    /// Total uncompressed size of all data blocks (bomb protection)
    pub total_uncompressed_size: u64,
    /// Maximum nesting depth (only relevant for TBZ-deep)
    pub max_nesting_depth: u8,
    /// Capabilities required to process this archive
    pub capabilities: Vec<String>,
}

/// Metadata for a single block in the manifest
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockEntry {
    /// Block index
    pub index: u32,
    /// Block type name
    pub block_type: String,
    /// Compressed size in bytes
    pub compressed_size: u64,
    /// Uncompressed size in bytes
    pub uncompressed_size: u64,
    /// JIS authorization level required
    pub jis_level: JisLevel,
    /// Human-readable description
    pub description: String,
    /// Original file path (for file-based archives)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

/// Archive structure type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ArchiveStructure {
    /// Flat: no nested TBZ blocks
    Flat,
    /// Deep: contains nested TBZ archives (matroesjka)
    Deep { max_depth: u8 },
}

impl Manifest {
    /// Create a new empty manifest
    pub fn new() -> Self {
        Self {
            tbz_version: crate::VERSION,
            block_count: 1, // manifest itself
            blocks: Vec::new(),
            structure: ArchiveStructure::Flat,
            total_uncompressed_size: 0,
            max_nesting_depth: 0,
            capabilities: Vec::new(),
        }
    }

    /// Add a block entry to the manifest
    pub fn add_block(&mut self, entry: BlockEntry) {
        self.total_uncompressed_size += entry.uncompressed_size;
        self.blocks.push(entry);
        self.block_count = self.blocks.len() as u32 + 1; // +1 for manifest
    }

    /// Get the highest JIS level required by any block
    pub fn max_jis_level(&self) -> JisLevel {
        self.blocks.iter().map(|b| b.jis_level).max().unwrap_or(0)
    }
}

impl Default for Manifest {
    fn default() -> Self {
        Self::new()
    }
}
