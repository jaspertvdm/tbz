//! tbz-core: Block format, TIBET envelope, and zstd frame handling
//!
//! This crate defines the TBZ wire format — per-block authenticated
//! compression built on zstd frames with TIBET provenance.

pub mod block;
pub mod envelope;
pub mod manifest;
pub mod signature;
pub mod stream;
/// TBZ v2 wire-format: confidential block encryption + SSM routing header.
/// See `python/tbz/SPEC-V2.md` for the canonical specification. This Rust
/// implementation is byte-for-byte compatible with the Python reference
/// (`tbz/v2.py`) and validated against `tibet-conformance-vectors v0.2.0`.
pub mod v2;

/// TBZ magic bytes: 0x54425A (ASCII "TBZ")
pub const MAGIC: [u8; 3] = [0x54, 0x42, 0x5A];

/// Current TBZ format version (v1 transparent / v2 confidential — selected
/// per archive via the v2 header capability flags).
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
