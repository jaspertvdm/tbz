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
    /// Ed25519 verifying (public) key in hex — used to verify all block signatures
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_key: Option<String>,
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

    // ── Producer identity binding (v1) ───────────────────────────────────────────────────────
    //
    // WHY THESE EXIST. Until now a TBZ archive proved its bytes were not altered and said nothing
    // about WHO made it: swap the identity claimed anywhere in the metadata and the artefact was
    // byte-identical with a different name on it. The inversion is to put the identity INSIDE what
    // is hashed and signed, so a different producer yields a different ARTEFACT rather than a
    // different label — then there is nothing beside the bytes left to swap.
    //
    // The shape is taken from tibet-drop rather than invented: manifest-first identity binding,
    // signed over a canonical serialisation, with block commitments underneath. tibet-drop proves
    // the shape; this crate proves the carrier crypto; canonical TBZ converges them.
    /// The producer's `.aint` identity. `None` on a legacy archive — absent, not broken.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub producer_identity: Option<String>,
    /// Which key of that identity signed — a fingerprint, not the key itself.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub producer_key_id: Option<String>,
    /// Which identity generation was current when this was produced. Necessary because an
    /// identity-bound archive must not replay cleanly across a reseed or a revoke.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_epoch: Option<u64>,
    /// Ed25519 over `PRODUCER_DOMAIN || archive_root`. Excluded from the commitment it signs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub producer_sig: Option<String>,
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
    /// Chunking: a file larger than the airlock per-block cap is split at pack time into ordered
    /// chunks, each its own signed/hashed block (so every block still fits the airlock's bounded RAM).
    /// `chunk_of` is the logical file these chunks reassemble into; `chunk_index`/`chunk_total` give
    /// the order/count; `whole_sha256` verifies the concatenation at unpack. None = a whole file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chunk_of: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chunk_index: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chunk_total: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub whole_sha256: Option<String>,
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
            signing_key: None,
            blocks: Vec::new(),
            structure: ArchiveStructure::Flat,
            total_uncompressed_size: 0,
            max_nesting_depth: 0,
            capabilities: Vec::new(),
            producer_identity: None,
            producer_key_id: None,
            identity_epoch: None,
            producer_sig: None,
        }
    }

    /// Set the Ed25519 verifying key for this manifest
    pub fn set_signing_key(&mut self, verifying_key: &ed25519_dalek::VerifyingKey) {
        let hex: String = verifying_key.to_bytes().iter().map(|b| format!("{:02x}", b)).collect();
        self.signing_key = Some(hex);
    }

    /// Parse the verifying key from the manifest
    pub fn get_verifying_key(&self) -> Option<ed25519_dalek::VerifyingKey> {
        let hex = self.signing_key.as_ref()?;
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .filter_map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
            .collect();
        if bytes.len() != 32 {
            return None;
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&bytes);
        ed25519_dalek::VerifyingKey::from_bytes(&key_bytes).ok()
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

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// Producer identity binding
// ═══════════════════════════════════════════════════════════════════════════════════════════════

/// Domain separator for the producer commitment.
///
/// Follows the style already used across this stack (`tibet-genesis:v1:<candidate_hash>`,
/// `cmail.message.sealed.v1`, `tbz-unseal.v1`). It is not cosmetic: without it, an `archive_root`
/// could one day be read as some other structure that happens to hash the same way. A signature is
/// only meaningful together with a statement of what it was a signature OVER.
pub const PRODUCER_DOMAIN: &str = "tbz-producer-archive:v1:";

/// What went wrong when a producer binding did not hold.
///
/// Distinct variants on purpose. `Unsigned` and `Invalid` stop a consumer the same way and are
/// repaired completely differently, and collapsing them into one boolean is how "no proof" starts
/// reading like "failed proof".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProducerError {
    /// No producer binding present at all — a legacy archive, not a broken one.
    Unsigned,
    /// A binding is declared but incomplete; the missing fields are named.
    Incomplete(Vec<&'static str>),
    /// The signature does not verify over this archive's canonical root.
    Invalid,
    /// The manifest carries no verifying key, so the signature cannot be checked at all.
    NoVerifyingKey,
}

impl std::fmt::Display for ProducerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsigned => write!(f, "no producer binding — this archive does not name its maker"),
            Self::Incomplete(m) => write!(f, "producer binding declared but missing {m:?} — a named binding without its fields is a label"),
            Self::Invalid => write!(f, "producer signature does not verify over this archive's root"),
            Self::NoVerifyingKey => write!(f, "no verifying key in the manifest — the binding cannot be checked, which is not the same as satisfied"),
        }
    }
}

impl Manifest {
    /// The bytes the producer commits to.
    ///
    /// EXPLICITLY ORDERED AND NAMED rather than struct-serialisation order, because a Python
    /// implementation has to reproduce this byte for byte — this crate already claims that
    /// compatibility for v2 and it would be lost the moment someone reorders a Rust field. A
    /// `BTreeMap` gives sorted keys; the key names are the contract.
    ///
    /// `producer_sig` is excluded, because a signature cannot be part of what it signs.
    pub fn producer_commitment(&self) -> Vec<u8> {
        use std::collections::BTreeMap;
        let mut m: BTreeMap<&str, serde_json::Value> = BTreeMap::new();
        m.insert("format_version", serde_json::json!(self.tbz_version));
        m.insert("producer_identity", serde_json::json!(self.producer_identity));
        m.insert("producer_key_id", serde_json::json!(self.producer_key_id));
        m.insert("identity_epoch", serde_json::json!(self.identity_epoch));
        m.insert("producer_pubkey", serde_json::json!(self.signing_key));
        m.insert("block_count", serde_json::json!(self.block_count));
        m.insert("ordered_block_root", serde_json::json!(self.ordered_block_root()));
        serde_json::to_vec(&m).unwrap_or_default()
    }

    /// Hash over the ordered block content hashes.
    ///
    /// NAMED FOR WHAT IT IS. This is an ordered hash chain, NOT a Merkle root: it cannot produce
    /// inclusion proofs and calling it a merkle root would be a name claiming more than the
    /// mechanism delivers — the exact failure this stack spent two days finding elsewhere. Order is
    /// part of the commitment, so reordering blocks changes the root.
    pub fn ordered_block_root(&self) -> String {
        let mut acc = String::new();
        for b in &self.blocks {
            acc.push_str(&b.index.to_string());
            acc.push(':');
            acc.push_str(b.whole_sha256.as_deref().unwrap_or(""));
            acc.push(';');
        }
        crate::signature::sha256_hash(acc.as_bytes())
    }

    /// The archive root: a hash of the producer commitment.
    pub fn archive_root(&self) -> String {
        crate::signature::sha256_hash(&self.producer_commitment())
    }

    /// Exactly what gets signed — domain separator plus root, never the root alone.
    pub fn producer_signing_target(&self) -> Vec<u8> {
        format!("{}{}", PRODUCER_DOMAIN, self.archive_root()).into_bytes()
    }

    /// Bind this archive to a producer.
    ///
    /// Must be called AFTER every block is added and after `set_signing_key`: the commitment covers
    /// the ordered block root, so signing early would bind an archive that does not exist yet.
    pub fn sign_producer(
        &mut self,
        identity: &str,
        key_id: &str,
        epoch: u64,
        signing_key: &ed25519_dalek::SigningKey,
    ) {
        self.producer_identity = Some(identity.to_string());
        self.producer_key_id = Some(key_id.to_string());
        self.identity_epoch = Some(epoch);
        self.producer_sig = None; // never sign over a previous signature
        let sig = crate::signature::sign(&self.producer_signing_target(), signing_key);
        self.producer_sig = Some(sig.iter().map(|b| format!("{:02x}", b)).collect());
    }

    /// Does the producer binding hold.
    ///
    /// Refuses in four distinguishable ways rather than returning a bool, because a consumer that
    /// must CHOOSE a repair cannot act on a sentence — and "unsigned" and "invalid" are different
    /// repairs entirely.
    pub fn verify_producer(&self) -> Result<(), ProducerError> {
        if self.producer_sig.is_none()
            && self.producer_identity.is_none()
            && self.producer_key_id.is_none()
            && self.identity_epoch.is_none()
        {
            return Err(ProducerError::Unsigned);
        }
        let mut missing = Vec::new();
        if self.producer_identity.is_none() { missing.push("producer_identity"); }
        if self.producer_key_id.is_none() { missing.push("producer_key_id"); }
        if self.identity_epoch.is_none() { missing.push("identity_epoch"); }
        if self.producer_sig.is_none() { missing.push("producer_sig"); }
        if !missing.is_empty() {
            return Err(ProducerError::Incomplete(missing));
        }

        let vk = self.get_verifying_key().ok_or(ProducerError::NoVerifyingKey)?;
        let hex = self.producer_sig.as_ref().unwrap();
        let sig: Vec<u8> = (0..hex.len())
            .step_by(2)
            .filter_map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
            .collect();

        // The signature is recomputed over a commitment built from the CURRENT manifest. Change the
        // identity, the epoch, the key, the block count or the block order, and the target moves.
        crate::signature::verify(&self.producer_signing_target(), &sig, &vk)
            .map_err(|_| ProducerError::Invalid)
    }
}
