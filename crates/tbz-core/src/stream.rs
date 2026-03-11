//! Streaming TBZ reader and writer
//!
//! Supports block-by-block reading and writing for pipeline decompression.
//! Block N validates while block N+1 downloads.

use crate::block::{Block, BlockError, BlockHeader};
use crate::envelope::TibetEnvelope;
use crate::manifest::Manifest;
use crate::{BlockType, MAGIC};
use std::io::{Read, Write};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum StreamError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Block error: {0}")]
    Block(#[from] BlockError),
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Unexpected end of stream")]
    UnexpectedEof,
    #[error("Not a TBZ archive")]
    NotTbz,
}

/// Streaming TBZ writer — writes blocks one at a time
pub struct TbzWriter<W: Write> {
    inner: W,
    block_count: u32,
}

impl<W: Write> TbzWriter<W> {
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            block_count: 0,
        }
    }

    /// Write the manifest as block 0
    pub fn write_manifest(&mut self, manifest: &Manifest) -> Result<(), StreamError> {
        let manifest_json = serde_json::to_vec(manifest)
            .map_err(|e| StreamError::Serialization(e.to_string()))?;

        let compressed = zstd::encode_all(manifest_json.as_slice(), 3)
            .map_err(|e| StreamError::Io(e))?;

        let envelope = TibetEnvelope::new(
            crate::signature::sha256_hash(&manifest_json),
            "manifest",
            "application/json",
            "tbz-packer",
            "Archive manifest — index of all blocks",
            vec![],
        );

        let header = BlockHeader::new(
            0,
            BlockType::Manifest,
            0, // Manifest is always JIS level 0
            manifest_json.len() as u64,
            compressed.len() as u64,
        );

        self.write_block_raw(&header, &envelope, &compressed)?;
        self.block_count += 1;
        Ok(())
    }

    /// Write a data block
    pub fn write_data_block(
        &mut self,
        data: &[u8],
        jis_level: u8,
        envelope: &TibetEnvelope,
    ) -> Result<(), StreamError> {
        let compressed = zstd::encode_all(data, 3)
            .map_err(|e| StreamError::Io(e))?;

        let header = BlockHeader::new(
            self.block_count,
            BlockType::Data,
            jis_level,
            data.len() as u64,
            compressed.len() as u64,
        );

        self.write_block_raw(&header, envelope, &compressed)?;
        self.block_count += 1;
        Ok(())
    }

    fn write_block_raw(
        &mut self,
        header: &BlockHeader,
        envelope: &TibetEnvelope,
        compressed_payload: &[u8],
    ) -> Result<(), StreamError> {
        // Write magic
        self.inner.write_all(&MAGIC)?;

        // Write header as JSON (will be replaced with binary format later)
        let header_json = serde_json::to_vec(header)
            .map_err(|e| StreamError::Serialization(e.to_string()))?;
        self.inner.write_all(&(header_json.len() as u32).to_le_bytes())?;
        self.inner.write_all(&header_json)?;

        // Write envelope as JSON
        let envelope_json = serde_json::to_vec(envelope)
            .map_err(|e| StreamError::Serialization(e.to_string()))?;
        self.inner.write_all(&(envelope_json.len() as u32).to_le_bytes())?;
        self.inner.write_all(&envelope_json)?;

        // Write compressed payload
        self.inner.write_all(&(compressed_payload.len() as u64).to_le_bytes())?;
        self.inner.write_all(compressed_payload)?;

        // Signature placeholder (TODO: real signing)
        let sig_placeholder = vec![0u8; 64];
        self.inner.write_all(&sig_placeholder)?;

        Ok(())
    }

    /// Finalize and return the inner writer
    pub fn finish(self) -> W {
        self.inner
    }
}

/// Streaming TBZ reader — reads and validates blocks one at a time
pub struct TbzReader<R: Read> {
    inner: R,
}

impl<R: Read> TbzReader<R> {
    pub fn new(inner: R) -> Self {
        Self { inner }
    }

    /// Read the next block from the stream
    pub fn read_block(&mut self) -> Result<Option<Block>, StreamError> {
        // Read magic bytes
        let mut magic = [0u8; 3];
        match self.inner.read_exact(&mut magic) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(StreamError::Io(e)),
        }

        if magic != MAGIC {
            return Err(StreamError::NotTbz);
        }

        // Read header
        let mut header_len_bytes = [0u8; 4];
        self.inner.read_exact(&mut header_len_bytes)?;
        let header_len = u32::from_le_bytes(header_len_bytes) as usize;
        let mut header_buf = vec![0u8; header_len];
        self.inner.read_exact(&mut header_buf)?;
        let header: BlockHeader = serde_json::from_slice(&header_buf)
            .map_err(|e| StreamError::Serialization(e.to_string()))?;

        // Read envelope
        let mut envelope_len_bytes = [0u8; 4];
        self.inner.read_exact(&mut envelope_len_bytes)?;
        let envelope_len = u32::from_le_bytes(envelope_len_bytes) as usize;
        let mut envelope_buf = vec![0u8; envelope_len];
        self.inner.read_exact(&mut envelope_buf)?;
        let envelope: TibetEnvelope = serde_json::from_slice(&envelope_buf)
            .map_err(|e| StreamError::Serialization(e.to_string()))?;

        // Read payload
        let mut payload_len_bytes = [0u8; 8];
        self.inner.read_exact(&mut payload_len_bytes)?;
        let payload_len = u64::from_le_bytes(payload_len_bytes) as usize;
        let mut payload = vec![0u8; payload_len];
        self.inner.read_exact(&mut payload)?;

        // Read signature
        let mut signature = vec![0u8; 64];
        self.inner.read_exact(&mut signature)?;

        // Validate header
        header.validate()?;

        Ok(Some(Block {
            header,
            envelope,
            payload,
            signature,
        }))
    }
}
