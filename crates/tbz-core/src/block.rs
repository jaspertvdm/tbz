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
    /// The signature is well-formed and this block belongs to a DIFFERENT archive.
    ///
    /// Distinct from SignatureInvalid on purpose. "these bytes were altered" and "these bytes are
    /// genuine and were never authorised HERE" are different findings with different repairs, and
    /// collapsing them would lose exactly the distinction the transplant vector exists to make.
    #[error("Block does not belong to this archive (wrong archive context)")]
    ArchiveBindingInvalid,
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
    /// Which archive this block DECLARES it belongs to. `None` on a legacy/unbound block.
    ///
    /// The declaration is cheap to check and, on its own, worth nothing — anyone can write a
    /// string. What makes it load-bearing is that `header_raw` is inside the signature, so editing
    /// this field breaks the signature. DECLARED is checkable; SIGNED is what makes the check mean
    /// something. That split is also why the reader can distinguish a RELOCATED block (declaration
    /// mismatches, signature intact) from a TAMPERED one (signature broken) -- two different
    /// findings that a single verdict would have merged.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub archive_id: Option<String>,
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
            archive_id: None,
        }
    }

    /// The same header, declaring the archive it belongs to.
    pub fn in_archive(mut self, archive_id: &str) -> Self {
        self.archive_id = Some(archive_id.to_string());
        self
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
    /// Raw JSON bytes of header (needed for signature verification)
    pub header_raw: Vec<u8>,
    /// Raw JSON bytes of envelope (needed for signature verification)
    pub envelope_raw: Vec<u8>,
}

impl Block {
    /// Validate this block's integrity (header only, no signature check)
    pub fn validate(&self) -> Result<(), BlockError> {
        self.header.validate()?;
        Ok(())
    }

    /// Verify the Ed25519 signature of this block against a verifying key.
    /// Reconstructs the signing payload from raw header + envelope + compressed payload.
    pub fn verify_signature(
        &self,
        verifying_key: &ed25519_dalek::VerifyingKey,
    ) -> Result<(), BlockError> {
        let mut sign_data = Vec::new();
        sign_data.extend_from_slice(&self.header_raw);
        sign_data.extend_from_slice(&self.envelope_raw);
        sign_data.extend_from_slice(&self.payload);
        crate::signature::verify(&sign_data, &self.signature, verifying_key)
            .map_err(|_| BlockError::SignatureInvalid)
    }

    /// Verify this block AS PART OF a named archive.
    ///
    /// The archive-bound check. `verify_signature` remains for legacy/unbound blocks and must never
    /// be read as archive-bound proof: it answers "were these bytes altered", not "do these bytes
    /// belong here".
    pub fn verify_signature_in_archive(
        &self,
        verifying_key: &ed25519_dalek::VerifyingKey,
        archive_id: &str,
    ) -> Result<(), BlockError> {
        // 1. THE DECLARATION, checked before any crypto. A block that names a different archive --
        //    or names none at all -- is not a signature problem, and saying so cheaply is what lets
        //    a reader tell a RELOCATED block from a CORRUPTED one.
        //
        //    My first attempt tried to derive that distinction from the signature alone, by
        //    re-checking the legacy target when the bound one failed. It cannot work: a bound block
        //    was never signed over the legacy shape, so both checks fail and every relocation reads
        //    as tampering. The difference has to be DECLARED to be observable -- and the signature
        //    over header_raw is what stops the declaration from being editable.
        match self.header.archive_id.as_deref() {
            Some(mine) if mine == archive_id => {}
            Some(_) => return Err(BlockError::ArchiveBindingInvalid),
            None => return Err(BlockError::ArchiveBindingInvalid),
        }

        // 2. AND THE SIGNATURE OVER THAT DECLARATION. Without this the header field is a label
        //    anyone can write, which is the failure this whole binding exists to end.
        let target = crate::manifest::block_signing_target(
            archive_id, self.header.block_index,
            &self.header_raw, &self.envelope_raw, &self.payload);
        crate::signature::verify(&target, &self.signature, verifying_key)
            .map_err(|_| BlockError::SignatureInvalid)
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
