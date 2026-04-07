//! TBZ block-format reader — handles CLI-created .tza archives
//!
//! The CLI tool creates block-based archives with:
//! - Magic bytes: 0x54425A ("TBZ")
//! - Per-block: JSON header + JSON envelope + zstd payload + Ed25519 signature
//!
//! This module lets the Desktop app verify and extract CLI-created archives.

use crate::manifest::{BundleStats, Manifest, VerifyResult, ExtractResult};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::Path;

/// TBZ magic bytes
const TBZ_MAGIC: [u8; 3] = [0x54, 0x42, 0x5A];

/// Parsed block header from CLI format
#[derive(Debug, serde::Deserialize)]
struct BlockHeader {
    magic: [u8; 3],
    version: u8,
    block_index: u32,
    block_type: u8,     // 0=Manifest, 1=Data, 2=Nested
    jis_level: u8,
    uncompressed_size: u64,
    compressed_size: u64,
}

/// TIBET envelope — provenance per block
#[derive(Debug, serde::Deserialize)]
struct TibetEnvelope {
    erin: Erin,
    erachter: String,
}

#[derive(Debug, serde::Deserialize)]
struct Erin {
    content_hash: String,
}

/// CLI manifest (block 0 content after decompression)
#[derive(Debug, serde::Deserialize)]
struct CliManifest {
    tbz_version: Option<u8>,
    block_count: Option<u32>,
    blocks: Vec<CliBlockEntry>,
    signing_key: Option<String>,
    total_uncompressed_size: Option<u64>,
}

#[derive(Debug, serde::Deserialize)]
struct CliBlockEntry {
    index: u32,
    block_type: String,
    compressed_size: u64,
    uncompressed_size: u64,
    jis_level: u8,
    description: String,
    path: Option<String>,
}

/// Read a single block from a reader, returns (header, envelope, decompressed_data, content_hash_ok)
fn read_block(reader: &mut impl Read) -> Result<Option<(BlockHeader, TibetEnvelope, Vec<u8>, bool)>, String> {
    // Read magic
    let mut magic = [0u8; 3];
    match reader.read_exact(&mut magic) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(format!("IO error: {}", e)),
    }

    if magic != TBZ_MAGIC {
        return Err("Not a TBZ block-format archive".to_string());
    }

    // Read header (length-prefixed JSON)
    let mut header_len_bytes = [0u8; 4];
    reader.read_exact(&mut header_len_bytes).map_err(|e| format!("Read error: {}", e))?;
    let header_len = u32::from_le_bytes(header_len_bytes) as usize;
    let mut header_buf = vec![0u8; header_len];
    reader.read_exact(&mut header_buf).map_err(|e| format!("Read error: {}", e))?;
    let header: BlockHeader = serde_json::from_slice(&header_buf)
        .map_err(|e| format!("Invalid block header: {}", e))?;

    // Read envelope (length-prefixed JSON)
    let mut envelope_len_bytes = [0u8; 4];
    reader.read_exact(&mut envelope_len_bytes).map_err(|e| format!("Read error: {}", e))?;
    let envelope_len = u32::from_le_bytes(envelope_len_bytes) as usize;
    let mut envelope_buf = vec![0u8; envelope_len];
    reader.read_exact(&mut envelope_buf).map_err(|e| format!("Read error: {}", e))?;
    let envelope: TibetEnvelope = serde_json::from_slice(&envelope_buf)
        .map_err(|e| format!("Invalid envelope: {}", e))?;

    // Read compressed payload (u64 length-prefixed)
    let mut payload_len_bytes = [0u8; 8];
    reader.read_exact(&mut payload_len_bytes).map_err(|e| format!("Read error: {}", e))?;
    let payload_len = u64::from_le_bytes(payload_len_bytes) as usize;
    let mut payload = vec![0u8; payload_len];
    reader.read_exact(&mut payload).map_err(|e| format!("Read error: {}", e))?;

    // Read Ed25519 signature (64 bytes) — we store but don't verify (no ed25519 dep)
    let mut _sig = [0u8; 64];
    reader.read_exact(&mut _sig).map_err(|e| format!("Read error: {}", e))?;

    // Decompress zstd payload
    let decompressed = zstd::decode_all(payload.as_slice())
        .map_err(|e| format!("Decompression error: {}", e))?;

    // Verify content hash (SHA-256)
    let actual_hash = sha256_hex(&decompressed);
    let hash_ok = actual_hash == envelope.erin.content_hash;

    Ok(Some((header, envelope, decompressed, hash_ok)))
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("sha256:{:x}", hasher.finalize())
}

/// Verify a CLI block-format .tza archive
pub fn verify_block_archive(tza_path: &Path) -> Result<VerifyResult, String> {
    let file = fs::File::open(tza_path).map_err(|e| format!("Cannot open: {}", e))?;
    let mut reader = std::io::BufReader::new(file);

    let mut cli_manifest: Option<CliManifest> = None;
    let mut verified_files: usize = 0;
    let mut failed_files: Vec<String> = Vec::new();
    let mut total_bytes: u64 = 0;

    loop {
        match read_block(&mut reader)? {
            None => break,
            Some((header, _envelope, decompressed, hash_ok)) => {
                if header.block_type == 0 {
                    // Manifest block
                    cli_manifest = serde_json::from_slice(&decompressed).ok();
                    if hash_ok {
                        verified_files += 1;
                    } else {
                        failed_files.push("manifest".to_string());
                    }
                } else if header.block_type == 1 {
                    // Data block
                    let name = cli_manifest
                        .as_ref()
                        .and_then(|m| {
                            m.blocks.iter()
                                .find(|b| b.index == header.block_index)
                                .and_then(|b| b.path.clone())
                        })
                        .unwrap_or_else(|| format!("block_{}", header.block_index));

                    total_bytes += decompressed.len() as u64;
                    if hash_ok {
                        verified_files += 1;
                    } else {
                        failed_files.push(name);
                    }
                }
            }
        }
    }

    let data_files = if verified_files > 0 { verified_files - 1 } else { 0 }; // subtract manifest
    let valid = failed_files.is_empty();

    // Build a TIBET-ZIP-compatible manifest for the UI
    let hashes: BTreeMap<String, String> = BTreeMap::new(); // block format doesn't use file-level hashes the same way
    let manifest = Manifest {
        protocol: "TBZ-BLOCK".to_string(),
        version: "1".to_string(),
        agent: None,
        title: cli_manifest.as_ref().and_then(|m| {
            m.blocks.first().map(|b| b.description.clone())
        }),
        event: None,
        created_at: String::new(),
        created_by: "TBZ CLI".to_string(),
        hashes,
        stats: BundleStats {
            total_files: data_files,
            total_bytes,
            ipoll_messages: None,
            tibet_tokens: None,
            upip_bundles: None,
            fork_tokens: None,
        },
        bundle_hash: String::new(),
    };

    Ok(VerifyResult {
        valid,
        manifest: Some(manifest),
        verified_files,
        failed_files,
        missing_files: Vec::new(),
    })
}

/// Extract a CLI block-format .tza archive
pub fn extract_block_archive(
    tza_path: &Path,
    output_dir: &Path,
    force: bool,
) -> Result<ExtractResult, String> {
    // Step 1: Verify
    let verify_result = verify_block_archive(tza_path)?;

    if !verify_result.valid && !force {
        return Err(format!(
            "AIRLOCK BLOCKED: Archive failed verification. Failed: {:?}",
            verify_result.failed_files
        ));
    }

    // Step 2: Extract
    fs::create_dir_all(output_dir).map_err(|e| format!("Cannot create output dir: {}", e))?;

    let file = fs::File::open(tza_path).map_err(|e| format!("Cannot open: {}", e))?;
    let mut reader = std::io::BufReader::new(file);

    let mut cli_manifest: Option<CliManifest> = None;
    let mut extracted_files: Vec<String> = Vec::new();

    loop {
        match read_block(&mut reader)? {
            None => break,
            Some((header, _envelope, decompressed, _hash_ok)) => {
                if header.block_type == 0 {
                    // Manifest block — parse but don't extract
                    cli_manifest = serde_json::from_slice(&decompressed).ok();
                } else if header.block_type == 1 {
                    // Data block — extract
                    let file_path = cli_manifest
                        .as_ref()
                        .and_then(|m| {
                            m.blocks.iter()
                                .find(|b| b.index == header.block_index)
                                .and_then(|b| b.path.clone())
                        })
                        .unwrap_or_else(|| format!("block_{}", header.block_index));

                    // Security: reject path traversal
                    if file_path.contains("..") || file_path.starts_with('/') {
                        continue;
                    }

                    let out_path = output_dir.join(&file_path);
                    if let Some(parent) = out_path.parent() {
                        fs::create_dir_all(parent)
                            .map_err(|e| format!("Cannot create dir: {}", e))?;
                    }

                    fs::write(&out_path, &decompressed)
                        .map_err(|e| format!("Cannot write {}: {}", file_path, e))?;
                    extracted_files.push(file_path);
                }
            }
        }
    }

    Ok(ExtractResult {
        valid: verify_result.valid,
        forced: !verify_result.valid && force,
        manifest: verify_result.manifest,
        extracted_files: extracted_files.clone(),
        output_dir: output_dir.to_string_lossy().to_string(),
        verified_files: verify_result.verified_files,
    })
}
