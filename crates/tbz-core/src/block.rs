//! TBZ block: header + TIBET envelope + zstd payload + signature

use crate::{BlockType, JisLevel, MAGIC, VERSION};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum BlockError {
    #[error("Invalid magic bytes: expected TBZ (0x54425A)")]
    InvalidMagic,
    #[error("Unsupported version: {0}")]
    UnsupportedVersion(u8),
    #[error("Block validation failed: {0}")]
    ValidationFailed(String),
    #[error("Decompression failed: {0}")]
    DecompressionFailed(String),
    #[error("Signature verification failed")]
    SignatureInvalid,
    #[error("JIS authorization insufficient: required level {required}, got {provided}")]
    Unauthorized { required: JisLevel, provided: JisLevel },
}

/// Block header — fixed-size prefix for every TBZ block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    /// Magic bytes: must be 0x54425A
    pub magic: [u8; 3],
    /// Format version
    pub version: u8,
    /// Block index within archive (0 = manifest)
    pub block_index: u32,
    /// Block type (manifest, data, nested)
    pub block_type: BlockType,
    /// JIS authorization level required to decompress
    pub jis_level: JisLevel,
    /// Size of uncompressed payload
    pub uncompressed_size: u64,
    /// Size of compressed payload (zstd frame)
    pub compressed_size: u64,
}

impl BlockHeader {
    /// Create a new block header
    pub fn new(
        block_index: u32,
        block_type: BlockType,
        jis_level: JisLevel,
        uncompressed_size: u64,
        compressed_size: u64,
    ) -> Self {
        Self {
            magic: MAGIC,
            version: VERSION,
            block_index,
            block_type,
            jis_level,
            uncompressed_size,
            compressed_size,
        }
    }

    /// Validate the header
    pub fn validate(&self) -> Result<(), BlockError> {
        if self.magic != MAGIC {
            return Err(BlockError::InvalidMagic);
        }
        if self.version != VERSION {
            return Err(BlockError::UnsupportedVersion(self.version));
        }
        Ok(())
    }
}

/// A complete TBZ block: header + envelope + payload + signature
#[derive(Debug, Clone)]
pub struct Block {
    pub header: BlockHeader,
    pub envelope: crate::envelope::TibetEnvelope,
    /// zstd-compressed payload
    pub payload: Vec<u8>,
    /// Ed25519 signature over header + envelope + payload
    pub signature: Vec<u8>,
}

impl Block {
    /// Validate this block's integrity (header + signature)
    pub fn validate(&self) -> Result<(), BlockError> {
        self.header.validate()?;
        // Signature verification delegated to signature module
        Ok(())
    }

    /// Decompress the payload via zstd
    pub fn decompress(&self) -> Result<Vec<u8>, BlockError> {
        zstd::decode_all(self.payload.as_slice())
            .map_err(|e| BlockError::DecompressionFailed(e.to_string()))
    }

    /// Check if the caller has sufficient JIS authorization
    pub fn check_authorization(&self, caller_level: JisLevel) -> Result<(), BlockError> {
        if caller_level < self.header.jis_level {
            return Err(BlockError::Unauthorized {
                required: self.header.jis_level,
                provided: caller_level,
            });
        }
        Ok(())
    }
}
