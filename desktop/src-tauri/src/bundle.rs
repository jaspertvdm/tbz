// ── TBZ Desktop bundle operations ────────────────────────────────────
//
// Creates, verifies, and extracts .tza archives using the REAL TBZ block
// format: per-block Ed25519 signatures, zstd compression, TIBET envelopes.
//
// Also reads legacy TIBET-ZIP (old Desktop format) for backwards compat.

use crate::manifest::{
    info_from_core_manifest, info_from_legacy, compute_legacy_bundle_hash,
    BundleInfo, BundleMeta, ExtractResult, LegacyManifest, VerifyResult,
};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::Path;
use tbz_core::envelope::TibetEnvelope;
use tbz_core::manifest::{BlockEntry, Manifest as CoreManifest};
use tbz_core::stream::{TbzReader, TbzWriter};
use tbz_core::{signature, BlockType};
use walkdir::WalkDir;

// ── Format detection ────────────────────────────────────────────────

/// Detect archive format by reading the first 4 bytes.
/// Returns "tbz" for real TBZ block format, "tibet_zip" for legacy ZIP, or "unknown".
fn detect_format(path: &Path) -> Result<&'static str, String> {
    let mut file = fs::File::open(path).map_err(|e| format!("Cannot open: {}", e))?;
    let mut magic = [0u8; 4];
    let n = std::io::Read::read(&mut file, &mut magic)
        .map_err(|e| format!("Read error: {}", e))?;
    if n < 3 {
        return Ok("unknown");
    }
    if magic[0..3] == [0x54, 0x42, 0x5A] {
        Ok("tbz")
    } else if magic == [0x50, 0x4B, 0x03, 0x04] {
        Ok("tibet_zip")
    } else {
        Ok("unknown")
    }
}

// ── Create (real TBZ block format) ──────────────────────────────────

/// Create a .tza bundle using real TBZ block format.
///
/// - Generates Ed25519 keypair (signs every block)
/// - Each file → one data block with TIBET envelope + zstd compression
/// - Block 0 = manifest (index of all blocks)
pub fn create_bundle(
    source_path: &Path,
    output_path: &Path,
    meta: BundleMeta,
) -> Result<BundleInfo, String> {
    // Collect files to pack
    let files = collect_files(source_path)?;
    if files.is_empty() {
        return Err("No files to bundle".to_string());
    }

    // Generate Ed25519 keypair — every block will be signed
    let (signing_key, verifying_key) = signature::generate_keypair();

    // Build manifest with block entries
    let mut manifest = CoreManifest::new();
    manifest.set_signing_key(&verifying_key);

    let origin = meta.agent.as_deref().unwrap_or("TBZ Desktop");
    let created_at = chrono::Utc::now().to_rfc3339();

    // Pre-read all files and build block entries for the manifest
    let mut file_data: Vec<(String, Vec<u8>)> = Vec::new();
    for (rel_path, full_path) in &files {
        let data = fs::read(full_path)
            .map_err(|e| format!("Cannot read {}: {}", rel_path, e))?;

        let compressed = zstd::encode_all(data.as_slice(), 3)
            .map_err(|e| format!("Compression failed for {}: {}", rel_path, e))?;

        manifest.add_block(BlockEntry {
            index: manifest.blocks.len() as u32 + 1, // +1 because manifest is block 0
            block_type: "Data".to_string(),
            compressed_size: compressed.len() as u64,
            uncompressed_size: data.len() as u64,
            jis_level: 0,
            description: rel_path.clone(),
            path: Some(rel_path.clone()),
        });

        file_data.push((rel_path.clone(), data));
    }

    // Write TBZ archive
    let out_file = fs::File::create(output_path)
        .map_err(|e| format!("Cannot create output: {}", e))?;
    let mut writer = TbzWriter::new(out_file, signing_key);

    // Block 0: manifest
    writer.write_manifest(&manifest)
        .map_err(|e| format!("Failed to write manifest block: {}", e))?;

    // Data blocks: one per file
    for (rel_path, data) in &file_data {
        let content_hash = signature::sha256_hash(data);
        let mime = guess_mime(rel_path);
        let envelope = TibetEnvelope::new(
            content_hash,
            "data",
            &mime,
            origin,
            &format!("Pack file: {}", rel_path),
            vec!["block:0".to_string()],
        );
        writer.write_data_block(data, 0, &envelope)
            .map_err(|e| format!("Failed to write block for {}: {}", rel_path, e))?;
    }

    writer.finish();

    // Build frontend response
    Ok(info_from_core_manifest(&manifest, &created_at, meta.agent))
}

// ── Verify ──────────────────────────────────────────────────────────

/// Verify a .tza archive. Auto-detects format (TBZ block or legacy ZIP).
pub fn verify_bundle(tza_path: &Path) -> Result<VerifyResult, String> {
    match detect_format(tza_path)? {
        "tbz" => verify_tbz(tza_path),
        "tibet_zip" => verify_legacy_zip(tza_path),
        _ => Err("Not a recognized TBZ archive format".to_string()),
    }
}

/// Verify a real TBZ block-format archive.
///
/// 1. Read all blocks
/// 2. Extract verifying key from manifest (block 0)
/// 3. Verify Ed25519 signature on every block
/// 4. Verify content hash (ERIN) matches decompressed payload
fn verify_tbz(tza_path: &Path) -> Result<VerifyResult, String> {
    let file = fs::File::open(tza_path)
        .map_err(|e| format!("Cannot open: {}", e))?;
    let mut reader = TbzReader::new(file);
    let blocks = reader.read_all_blocks()
        .map_err(|e| format!("Failed to read TBZ archive: {}", e))?;

    if blocks.is_empty() {
        return Err("Empty TBZ archive".to_string());
    }

    // Block 0 must be the manifest
    if blocks[0].header.block_type != BlockType::Manifest {
        return Err("First block is not a manifest".to_string());
    }

    // Parse manifest and extract verifying key
    let manifest_data = blocks[0].decompress()
        .map_err(|e| format!("Cannot decompress manifest: {}", e))?;
    let manifest: CoreManifest = serde_json::from_slice(&manifest_data)
        .map_err(|e| format!("Invalid manifest JSON: {}", e))?;

    let verifying_key = manifest.get_verifying_key()
        .ok_or_else(|| "No signing key in manifest — cannot verify signatures".to_string())?;

    let mut verified_blocks: usize = 0;
    let mut failed_blocks: Vec<String> = Vec::new();

    for block in &blocks {
        // Verify Ed25519 signature
        match block.verify_signature(&verifying_key) {
            Ok(()) => {}
            Err(_) => {
                failed_blocks.push(format!("block:{} (signature invalid)", block.header.block_index));
                continue;
            }
        }

        // For data blocks: verify content hash matches ERIN
        if block.header.block_type == BlockType::Data {
            match block.decompress() {
                Ok(decompressed) => {
                    let actual_hash = signature::sha256_hash(&decompressed);
                    if actual_hash != block.envelope.erin.content_hash {
                        failed_blocks.push(format!(
                            "block:{} (content hash mismatch)",
                            block.header.block_index
                        ));
                        continue;
                    }
                }
                Err(e) => {
                    failed_blocks.push(format!(
                        "block:{} (decompress failed: {})",
                        block.header.block_index, e
                    ));
                    continue;
                }
            }
        }

        verified_blocks += 1;
    }

    let valid = failed_blocks.is_empty();
    let created_at = blocks[0].envelope.eromheen.created.clone();
    let agent = Some(blocks[0].envelope.eromheen.origin.clone());
    let info = info_from_core_manifest(&manifest, &created_at, agent);

    Ok(VerifyResult {
        valid,
        info: Some(info),
        verified_blocks,
        failed_blocks,
        format: "tbz".to_string(),
    })
}

/// Verify a legacy TIBET-ZIP archive (old Desktop format, ZIP + MANIFEST.json).
fn verify_legacy_zip(tza_path: &Path) -> Result<VerifyResult, String> {
    let file = fs::File::open(tza_path)
        .map_err(|e| format!("Cannot open: {}", e))?;
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|e| format!("Not a valid ZIP: {}", e))?;

    // Read MANIFEST.json
    let manifest: LegacyManifest = {
        let mut mf = archive.by_name("MANIFEST.json")
            .map_err(|_| "No MANIFEST.json in archive".to_string())?;
        let mut buf = String::new();
        mf.read_to_string(&mut buf)
            .map_err(|e| format!("Cannot read MANIFEST.json: {}", e))?;
        serde_json::from_str(&buf)
            .map_err(|e| format!("Invalid MANIFEST.json: {}", e))?
    };

    let mut verified: usize = 0;
    let mut failed: Vec<String> = Vec::new();

    for (path, expected_hash) in &manifest.hashes {
        match archive.by_name(path) {
            Ok(mut entry) => {
                // Security: reject path traversal (zip-slip)
                if path.contains("..") || path.starts_with('/') {
                    failed.push(format!("{} (path traversal blocked)", path));
                    continue;
                }
                let mut data = Vec::new();
                entry.read_to_end(&mut data)
                    .map_err(|e| format!("Cannot read {}: {}", path, e))?;
                let actual = sha256_hex(&data);
                if actual == *expected_hash {
                    verified += 1;
                } else {
                    failed.push(path.clone());
                }
            }
            Err(_) => {
                failed.push(format!("{} (missing)", path));
            }
        }
    }

    // Verify bundle_hash
    let expected_bh = compute_legacy_bundle_hash(&manifest.hashes);
    if manifest.bundle_hash != expected_bh {
        failed.push("bundle_hash mismatch".to_string());
    }

    let valid = failed.is_empty();
    let info = info_from_legacy(&manifest);

    Ok(VerifyResult {
        valid,
        info: Some(info),
        verified_blocks: verified,
        failed_blocks: failed,
        format: "tibet-zip".to_string(),
    })
}

// ── Extract ─────────────────────────────────────────────────────────

/// Extract a .tza archive. Auto-detects format. Airlock-gated: verifies first.
pub fn extract_bundle(
    tza_path: &Path,
    output_dir: &Path,
    force: bool,
) -> Result<ExtractResult, String> {
    match detect_format(tza_path)? {
        "tbz" => extract_tbz(tza_path, output_dir, force),
        "tibet_zip" => extract_legacy_zip(tza_path, output_dir, force),
        _ => Err("Not a recognized TBZ archive format".to_string()),
    }
}

/// Extract a real TBZ block-format archive.
///
/// Airlock gate: full verification must pass before any file is written.
fn extract_tbz(
    tza_path: &Path,
    output_dir: &Path,
    force: bool,
) -> Result<ExtractResult, String> {
    // Step 1: Verify (airlock gate)
    let verify_result = verify_tbz(tza_path)?;

    if !verify_result.valid && !force {
        return Err(format!(
            "AIRLOCK BLOCKED: Archive failed verification. Failed blocks: {:?}",
            verify_result.failed_blocks
        ));
    }

    // Step 2: Read all blocks again for extraction
    let file = fs::File::open(tza_path)
        .map_err(|e| format!("Cannot open: {}", e))?;
    let mut reader = TbzReader::new(file);
    let blocks = reader.read_all_blocks()
        .map_err(|e| format!("Failed to read TBZ archive: {}", e))?;

    // Parse manifest for file paths
    let manifest_data = blocks[0].decompress()
        .map_err(|e| format!("Cannot decompress manifest: {}", e))?;
    let manifest: CoreManifest = serde_json::from_slice(&manifest_data)
        .map_err(|e| format!("Invalid manifest: {}", e))?;

    fs::create_dir_all(output_dir)
        .map_err(|e| format!("Cannot create output dir: {}", e))?;

    let mut extracted_files: Vec<String> = Vec::new();

    // Extract data blocks — match block index to manifest entries for file paths
    for block in &blocks {
        if block.header.block_type != BlockType::Data {
            continue;
        }

        // Find the file path from manifest block entries
        let path = manifest.blocks.iter()
            .find(|b| b.index == block.header.block_index)
            .and_then(|b| b.path.as_ref());

        let file_path = match path {
            Some(p) => p.clone(),
            None => {
                // Fallback: use block description or index
                format!("block_{}", block.header.block_index)
            }
        };

        // Security: reject path traversal
        if file_path.contains("..") || file_path.starts_with('/') {
            continue;
        }

        let out_path = output_dir.join(&file_path);

        // Create parent directories
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Cannot create dir for {}: {}", file_path, e))?;
        }

        // Decompress and write
        let data = block.decompress()
            .map_err(|e| format!("Cannot decompress {}: {}", file_path, e))?;
        fs::write(&out_path, &data)
            .map_err(|e| format!("Cannot write {}: {}", file_path, e))?;

        extracted_files.push(file_path);
    }

    Ok(ExtractResult {
        valid: verify_result.valid,
        forced: !verify_result.valid && force,
        info: verify_result.info,
        extracted_files,
        output_dir: output_dir.to_string_lossy().to_string(),
        verified_blocks: verify_result.verified_blocks,
    })
}

/// Extract a legacy TIBET-ZIP archive (old Desktop format).
fn extract_legacy_zip(
    tza_path: &Path,
    output_dir: &Path,
    force: bool,
) -> Result<ExtractResult, String> {
    // Step 1: Verify
    let verify_result = verify_legacy_zip(tza_path)?;

    if !verify_result.valid && !force {
        return Err(format!(
            "AIRLOCK BLOCKED: Legacy archive failed verification. Failed: {:?}",
            verify_result.failed_blocks
        ));
    }

    // Step 2: Extract
    fs::create_dir_all(output_dir)
        .map_err(|e| format!("Cannot create output dir: {}", e))?;

    let file = fs::File::open(tza_path)
        .map_err(|e| format!("Cannot open: {}", e))?;
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|e| format!("Not a valid ZIP: {}", e))?;

    let mut extracted_files: Vec<String> = Vec::new();

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)
            .map_err(|e| format!("Archive read error: {}", e))?;
        let name = entry.name().to_string();

        if name == "MANIFEST.json" {
            continue;
        }

        // Security: reject path traversal
        if name.contains("..") || name.starts_with('/') {
            continue;
        }

        let out_path = output_dir.join(&name);

        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Cannot create dir for {}: {}", name, e))?;
        }

        if entry.is_dir() {
            fs::create_dir_all(&out_path)
                .map_err(|e| format!("Cannot create dir {}: {}", name, e))?;
        } else {
            let mut data = Vec::new();
            entry.read_to_end(&mut data)
                .map_err(|e| format!("Cannot read {}: {}", name, e))?;
            fs::write(&out_path, &data)
                .map_err(|e| format!("Cannot write {}: {}", name, e))?;
            extracted_files.push(name);
        }
    }

    Ok(ExtractResult {
        valid: verify_result.valid,
        forced: !verify_result.valid && force,
        info: verify_result.info,
        extracted_files,
        output_dir: output_dir.to_string_lossy().to_string(),
        verified_blocks: verify_result.verified_blocks,
    })
}

// ── Helpers ─────────────────────────────────────────────────────────

/// Collect files from a path (file or directory).
/// Returns Vec of (relative_path, full_path).
fn collect_files(source: &Path) -> Result<Vec<(String, std::path::PathBuf)>, String> {
    let mut files = Vec::new();

    if source.is_file() {
        let name = source.file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        files.push((name, source.to_path_buf()));
    } else if source.is_dir() {
        for entry in WalkDir::new(source)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let rel = entry.path()
                .strip_prefix(source)
                .map_err(|e| format!("Path strip error: {}", e))?;
            let rel_str = rel.to_string_lossy().replace('\\', "/");

            // Skip hidden files
            if rel_str.starts_with('.') {
                continue;
            }

            files.push((rel_str, entry.path().to_path_buf()));
        }
    } else {
        return Err(format!("Source does not exist: {}", source.display()));
    }

    Ok(files)
}

/// Simple MIME type guessing based on file extension
fn guess_mime(path: &str) -> String {
    match path.rsplit('.').next().unwrap_or("") {
        "txt" | "md" | "log" => "text/plain",
        "json" => "application/json",
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "js" | "ts" => "application/javascript",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "rs" => "text/x-rust",
        "py" => "text/x-python",
        _ => "application/octet-stream",
    }
    .to_string()
}

/// SHA256 hex digest (for legacy ZIP verification)
fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_dir(suffix: &str) -> PathBuf {
        let dir = std::env::temp_dir()
            .join(format!("tbz_test_{}_{}", suffix, std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("hello.txt"), "Hello TBZ").unwrap();
        fs::write(dir.join("readme.md"), "# Test").unwrap();
        fs::write(dir.join("data.json"), r#"{"key":"value"}"#).unwrap();
        dir
    }

    #[test]
    fn test_create_real_tbz() {
        let input = test_dir("create");
        let output = std::env::temp_dir()
            .join(format!("tbz_create_{}.tza", std::process::id()));
        let _ = fs::remove_file(&output);

        let meta = BundleMeta {
            agent: Some("test_agent".to_string()),
            title: None,
        };
        let info = create_bundle(&input, &output, meta).unwrap();

        assert_eq!(info.protocol, "TBZ");
        assert_eq!(info.format, "tbz");
        assert_eq!(info.stats.total_files, 3);
        assert!(info.signing_key.is_some());

        // Verify it's actually TBZ format (magic bytes)
        let data = fs::read(&output).unwrap();
        assert_eq!(&data[0..3], &[0x54, 0x42, 0x5A]);

        let _ = fs::remove_file(&output);
        let _ = fs::remove_dir_all(&input);
    }

    #[test]
    fn test_create_and_verify_tbz() {
        let input = test_dir("verify");
        let output = std::env::temp_dir()
            .join(format!("tbz_verify_{}.tza", std::process::id()));
        let _ = fs::remove_file(&output);

        let meta = BundleMeta {
            agent: Some("verifier".to_string()),
            title: None,
        };
        create_bundle(&input, &output, meta).unwrap();

        // Verify
        let result = verify_bundle(&output).unwrap();
        assert!(result.valid, "Failed blocks: {:?}", result.failed_blocks);
        assert_eq!(result.format, "tbz");
        // manifest block + 3 data blocks = 4
        assert_eq!(result.verified_blocks, 4);
        assert!(result.failed_blocks.is_empty());

        let _ = fs::remove_file(&output);
        let _ = fs::remove_dir_all(&input);
    }

    #[test]
    fn test_create_verify_extract_tbz() {
        let input = test_dir("extract");
        let tza = std::env::temp_dir()
            .join(format!("tbz_extract_{}.tza", std::process::id()));
        let out_dir = std::env::temp_dir()
            .join(format!("tbz_extracted_{}", std::process::id()));
        let _ = fs::remove_file(&tza);
        let _ = fs::remove_dir_all(&out_dir);

        let meta = BundleMeta { agent: None, title: None };
        create_bundle(&input, &tza, meta).unwrap();

        let result = extract_bundle(&tza, &out_dir, false).unwrap();
        assert!(result.valid);
        assert!(!result.forced);
        assert_eq!(result.extracted_files.len(), 3);

        // Verify extracted content
        assert_eq!(
            fs::read_to_string(out_dir.join("hello.txt")).unwrap(),
            "Hello TBZ"
        );
        assert_eq!(
            fs::read_to_string(out_dir.join("readme.md")).unwrap(),
            "# Test"
        );

        let _ = fs::remove_file(&tza);
        let _ = fs::remove_dir_all(&out_dir);
        let _ = fs::remove_dir_all(&input);
    }

    #[test]
    fn test_tampered_tbz_blocked() {
        let input = test_dir("tamper");
        let tza = std::env::temp_dir()
            .join(format!("tbz_tamper_{}.tza", std::process::id()));
        let _ = fs::remove_file(&tza);

        let meta = BundleMeta { agent: None, title: None };
        create_bundle(&input, &tza, meta).unwrap();

        // Tamper: flip a byte in the payload area
        let mut data = fs::read(&tza).unwrap();
        if data.len() > 100 {
            data[100] ^= 0xFF;
        }
        fs::write(&tza, &data).unwrap();

        // Verify should fail or error
        let result = verify_bundle(&tza);
        match result {
            Ok(r) => assert!(!r.valid, "Tampered archive should not be valid"),
            Err(_) => {} // Parse error is also acceptable
        }

        // Extract should be blocked
        let out_dir = std::env::temp_dir()
            .join(format!("tbz_tamper_out_{}", std::process::id()));
        let extract = extract_bundle(&tza, &out_dir, false);
        assert!(extract.is_err(), "Tampered archive extraction should be blocked");

        let _ = fs::remove_file(&tza);
        let _ = fs::remove_dir_all(&input);
        let _ = fs::remove_dir_all(&out_dir);
    }

    #[test]
    fn test_single_file_tbz() {
        let file = std::env::temp_dir()
            .join(format!("tbz_single_{}.txt", std::process::id()));
        let tza = std::env::temp_dir()
            .join(format!("tbz_single_{}.tza", std::process::id()));
        let _ = fs::remove_file(&tza);
        fs::write(&file, "Single file test").unwrap();

        let meta = BundleMeta {
            agent: None,
            title: Some("Single".to_string()),
        };
        let info = create_bundle(&file, &tza, meta).unwrap();
        assert_eq!(info.stats.total_files, 1);

        let result = verify_bundle(&tza).unwrap();
        assert!(result.valid);
        // 1 manifest + 1 data = 2 verified blocks
        assert_eq!(result.verified_blocks, 2);

        let _ = fs::remove_file(&file);
        let _ = fs::remove_file(&tza);
    }
}
