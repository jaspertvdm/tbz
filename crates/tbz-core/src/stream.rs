//! Streaming TBZ reader and writer
//!
//! Supports block-by-block reading and writing for pipeline decompression.
//! Block N validates while block N+1 downloads.

use crate::block::{Block, BlockError, BlockHeader};
use crate::envelope::TibetEnvelope;
use crate::manifest::Manifest;
use crate::signature;
use crate::{BlockType, MAGIC};
use ed25519_dalek::SigningKey;
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
    signing_key: SigningKey,
}

impl<W: Write> TbzWriter<W> {
    pub fn new(inner: W, signing_key: SigningKey) -> Self {
        Self {
            inner,
            block_count: 0,
            signing_key,
        }
    }

    /// Write the manifest as block 0
    pub fn write_manifest(&mut self, manifest: &Manifest) -> Result<(), StreamError> {
        let manifest_json = serde_json::to_vec(manifest)
            .map_err(|e| StreamError::Serialization(e.to_string()))?;

        let compressed = zstd::encode_all(manifest_json.as_slice(), 3)
            .map_err(|e| StreamError::Io(e))?;

        let envelope = TibetEnvelope::new(
            signature::sha256_hash(&manifest_json),
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
        // Serialize header and envelope
        let header_json = serde_json::to_vec(header)
            .map_err(|e| StreamError::Serialization(e.to_string()))?;
        let envelope_json = serde_json::to_vec(envelope)
            .map_err(|e| StreamError::Serialization(e.to_string()))?;

        // Build signing payload: header + envelope + compressed data
        let mut sign_data = Vec::new();
        sign_data.extend_from_slice(&header_json);
        sign_data.extend_from_slice(&envelope_json);
        sign_data.extend_from_slice(compressed_payload);
        let sig = signature::sign(&sign_data, &self.signing_key);

        // Write magic
        self.inner.write_all(&MAGIC)?;

        // Write header
        self.inner.write_all(&(header_json.len() as u32).to_le_bytes())?;
        self.inner.write_all(&header_json)?;

        // Write envelope
        self.inner.write_all(&(envelope_json.len() as u32).to_le_bytes())?;
        self.inner.write_all(&envelope_json)?;

        // Write compressed payload
        self.inner.write_all(&(compressed_payload.len() as u64).to_le_bytes())?;
        self.inner.write_all(compressed_payload)?;

        // Write Ed25519 signature (64 bytes)
        self.inner.write_all(&sig)?;

        Ok(())
    }

    /// Get the number of blocks written
    pub fn block_count(&self) -> u32 {
        self.block_count
    }

    /// Get the verifying (public) key for this writer
    pub fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.signing_key.verifying_key()
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

        // Read signature (64 bytes Ed25519)
        let mut sig = vec![0u8; 64];
        self.inner.read_exact(&mut sig)?;

        // Validate header
        header.validate()?;

        Ok(Some(Block {
            header,
            envelope,
            payload,
            signature: sig,
            header_raw: header_buf,
            envelope_raw: envelope_buf,
        }))
    }

    /// Read all blocks from the stream
    pub fn read_all_blocks(&mut self) -> Result<Vec<Block>, StreamError> {
        let mut blocks = Vec::new();
        while let Some(block) = self.read_block()? {
            blocks.push(block);
        }
        Ok(blocks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_write_read() {
        let (signing_key, _) = signature::generate_keypair();

        // Write a TBZ archive to memory
        let mut buf = Vec::new();
        {
            let mut writer = TbzWriter::new(&mut buf, signing_key);

            // Write manifest
            let manifest = Manifest::new();
            writer.write_manifest(&manifest).unwrap();

            // Write a data block
            let data = b"Hello from TBZ! This is block-level authenticated compression.";
            let envelope = TibetEnvelope::new(
                signature::sha256_hash(data),
                "data",
                "text/plain",
                "test",
                "Test data block",
                vec!["block:0".to_string()],
            );
            writer.write_data_block(data, 0, &envelope).unwrap();

            assert_eq!(writer.block_count(), 2);
        }

        // Read it back
        let mut reader = TbzReader::new(buf.as_slice());
        let blocks = reader.read_all_blocks().unwrap();

        assert_eq!(blocks.len(), 2);

        // Block 0: manifest
        assert_eq!(blocks[0].header.block_type, BlockType::Manifest);
        assert_eq!(blocks[0].header.jis_level, 0);

        // Block 1: data
        assert_eq!(blocks[1].header.block_type, BlockType::Data);
        let decompressed = blocks[1].decompress().unwrap();
        assert_eq!(
            String::from_utf8(decompressed).unwrap(),
            "Hello from TBZ! This is block-level authenticated compression."
        );
    }

    #[test]
    fn test_signature_verification_roundtrip() {
        let (signing_key, _) = signature::generate_keypair();
        let verifying_key = signing_key.verifying_key();

        // Build manifest with embedded public key
        let mut manifest = Manifest::new();
        manifest.set_signing_key(&verifying_key);

        let mut buf = Vec::new();
        {
            let mut writer = TbzWriter::new(&mut buf, signing_key);
            writer.write_manifest(&manifest).unwrap();

            let data = b"Signed content";
            let envelope = TibetEnvelope::new(
                signature::sha256_hash(data),
                "data",
                "text/plain",
                "test",
                "Signed data block",
                vec!["block:0".to_string()],
            );
            writer.write_data_block(data, 0, &envelope).unwrap();
        }

        // Read and verify all blocks
        let mut reader = TbzReader::new(buf.as_slice());
        let blocks = reader.read_all_blocks().unwrap();

        // Extract verifying key from manifest
        let manifest_data = blocks[0].decompress().unwrap();
        let parsed_manifest: Manifest = serde_json::from_slice(&manifest_data).unwrap();
        let vk = parsed_manifest.get_verifying_key().expect("signing key in manifest");

        // Every block must pass signature verification
        for block in &blocks {
            block.verify_signature(&vk).expect("signature must be valid");
        }

        // Verify content hash for data block
        let decompressed = blocks[1].decompress().unwrap();
        let hash = signature::sha256_hash(&decompressed);
        assert_eq!(hash, blocks[1].envelope.erin.content_hash);
    }

    #[test]
    fn test_tampered_block_fails_signature() {
        let (signing_key, _) = signature::generate_keypair();
        let verifying_key = signing_key.verifying_key();

        let mut buf = Vec::new();
        {
            let mut manifest = Manifest::new();
            manifest.set_signing_key(&verifying_key);
            let mut writer = TbzWriter::new(&mut buf, signing_key);
            writer.write_manifest(&manifest).unwrap();

            let data = b"Original content";
            let envelope = TibetEnvelope::new(
                signature::sha256_hash(data),
                "data",
                "text/plain",
                "test",
                "Test block",
                vec!["block:0".to_string()],
            );
            writer.write_data_block(data, 0, &envelope).unwrap();
        }

        // Read blocks
        let mut reader = TbzReader::new(buf.as_slice());
        let mut blocks = reader.read_all_blocks().unwrap();

        // Tamper with the data block payload
        if let Some(last_byte) = blocks[1].payload.last_mut() {
            *last_byte ^= 0xFF;
        }

        // Extract key and verify — should fail for tampered block
        let manifest_data = blocks[0].decompress().unwrap();
        let parsed: Manifest = serde_json::from_slice(&manifest_data).unwrap();
        let vk = parsed.get_verifying_key().unwrap();

        // Manifest block should still verify
        assert!(blocks[0].verify_signature(&vk).is_ok());

        // Tampered data block must fail
        assert!(blocks[1].verify_signature(&vk).is_err());
    }
}
