//! tbz-core: Block format, TIBET envelope, and zstd frame handling
//!
//! This crate defines the TBZ wire format — per-block authenticated
//! compression built on zstd frames with TIBET provenance.

pub mod block;
pub mod envelope;
pub mod manifest;
pub mod signature;
pub mod stream;

/// TBZ magic bytes: 0x54425A (ASCII "TBZ")
pub const MAGIC: [u8; 3] = [0x54, 0x42, 0x5A];

/// Current TBZ format version
pub const VERSION: u8 = 1;

/// Block types
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum BlockType {
    /// Block 0: archive manifest (always JIS level 0)
    Manifest = 0,
    /// Data block with compressed payload
    Data = 1,
    /// Nested TBZ archive (TBZ-deep / matroesjka)
    Nested = 2,
}

/// JIS authorization level for a block
pub type JisLevel = u8;

// Re-export ed25519 types for consumers
pub use ed25519_dalek::{SigningKey, VerifyingKey};
