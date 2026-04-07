use crate::manifest::{
    compute_bundle_hash, BundleMeta, BundleStats, ExtractResult, Manifest, VerifyResult,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use walkdir::WalkDir;
use zip::write::SimpleFileOptions;

/// Create a .tza bundle from files/directories
///
/// Walks source_dir, SHA256-hashes every file, writes them into a ZIP
/// with MANIFEST.json as the last entry.
pub fn create_bundle(
    source_path: &Path,
    output_path: &Path,
    meta: BundleMeta,
) -> Result<Manifest, String> {
    let file =
        fs::File::create(output_path).map_err(|e| format!("Cannot create output: {}", e))?;
    let mut zip = zip::ZipWriter::new(file);
    let options = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o644);

    let mut hashes: BTreeMap<String, String> = BTreeMap::new();
    let mut total_bytes: u64 = 0;
    let mut total_files: usize = 0;

    if source_path.is_file() {
        // Single file bundle
        let filename = source_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let data = fs::read(source_path).map_err(|e| format!("Cannot read {}: {}", filename, e))?;
        let hash = sha256_hex(&data);
        total_bytes += data.len() as u64;
        total_files += 1;

        zip.start_file(&filename, options)
            .map_err(|e| format!("ZIP write error: {}", e))?;
        zip.write_all(&data)
            .map_err(|e| format!("ZIP write error: {}", e))?;
        hashes.insert(filename, hash);
    } else if source_path.is_dir() {
        // Directory bundle — walk recursively
        let base = source_path;
        for entry in WalkDir::new(base)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let full_path = entry.path();
            let rel_path = full_path
                .strip_prefix(base)
                .map_err(|e| format!("Path strip error: {}", e))?;
            let rel_str = rel_path.to_string_lossy().replace('\\', "/");

            // Skip hidden files and MANIFEST.json itself
            if rel_str.starts_with('.') || rel_str == "MANIFEST.json" {
                continue;
            }

            let data =
                fs::read(full_path).map_err(|e| format!("Cannot read {}: {}", rel_str, e))?;
            let hash = sha256_hex(&data);
            total_bytes += data.len() as u64;
            total_files += 1;

            zip.start_file(&rel_str, options)
                .map_err(|e| format!("ZIP write error: {}", e))?;
            zip.write_all(&data)
                .map_err(|e| format!("ZIP write error: {}", e))?;
            hashes.insert(rel_str, hash);
        }
    } else {
        return Err(format!(
            "Source path does not exist: {}",
            source_path.display()
        ));
    }

    // Build manifest
    let stats = BundleStats {
        total_files,
        total_bytes,
        ipoll_messages: None,
        tibet_tokens: None,
        upip_bundles: None,
        fork_tokens: None,
    };
    let manifest = Manifest::new(hashes, stats, meta);

    // Write MANIFEST.json as last entry
    let manifest_json =
        serde_json::to_string_pretty(&manifest).map_err(|e| format!("JSON error: {}", e))?;
    zip.start_file("MANIFEST.json", options)
        .map_err(|e| format!("ZIP write error: {}", e))?;
    zip.write_all(manifest_json.as_bytes())
        .map_err(|e| format!("ZIP write error: {}", e))?;

    zip.finish()
        .map_err(|e| format!("ZIP finalize error: {}", e))?;

    Ok(manifest)
}

/// Verify a .tza bundle — the airlock gate
///
/// Reads MANIFEST.json, re-hashes every file, compares.
/// Returns VerifyResult with valid=true only if ALL files match.
pub fn verify_bundle(tza_path: &Path) -> Result<VerifyResult, String> {
    let file = fs::File::open(tza_path).map_err(|e| format!("Cannot open: {}", e))?;
    let mut archive = zip::ZipArchive::new(file).map_err(|e| format!("Not a valid ZIP: {}", e))?;

    // Read MANIFEST.json
    let manifest: Manifest = {
        let mut manifest_file = archive
            .by_name("MANIFEST.json")
            .map_err(|_| "No MANIFEST.json in archive".to_string())?;
        let mut buf = String::new();
        manifest_file
            .read_to_string(&mut buf)
            .map_err(|e| format!("Cannot read MANIFEST.json: {}", e))?;
        serde_json::from_str(&buf).map_err(|e| format!("Invalid MANIFEST.json: {}", e))?
    };

    let mut verified_files: usize = 0;
    let mut failed_files: Vec<String> = Vec::new();
    let mut missing_files: Vec<String> = Vec::new();

    // Check each file listed in manifest
    for (path, expected_hash) in &manifest.hashes {
        match archive.by_name(path) {
            Ok(mut entry) => {
                // Security: reject path traversal (zip-slip)
                if path.contains("..") || path.starts_with('/') {
                    failed_files.push(format!("{} (path traversal blocked)", path));
                    continue;
                }

                let mut data = Vec::new();
                entry
                    .read_to_end(&mut data)
                    .map_err(|e| format!("Cannot read {}: {}", path, e))?;
                let actual_hash = sha256_hex(&data);

                if actual_hash == *expected_hash {
                    verified_files += 1;
                } else {
                    failed_files.push(path.clone());
                }
            }
            Err(_) => {
                missing_files.push(path.clone());
            }
        }
    }

    // Verify bundle_hash
    let expected_bundle_hash = compute_bundle_hash(&manifest.hashes);
    let bundle_hash_valid = manifest.bundle_hash == expected_bundle_hash;

    let valid = failed_files.is_empty() && missing_files.is_empty() && bundle_hash_valid;

    Ok(VerifyResult {
        valid,
        manifest: Some(manifest),
        verified_files,
        failed_files,
        missing_files,
    })
}

/// Extract a .tza bundle — airlock-gated
///
/// Always verifies first. Blocks extraction if tampered (unless force=true).
pub fn extract_bundle(
    tza_path: &Path,
    output_dir: &Path,
    force: bool,
) -> Result<ExtractResult, String> {
    // Step 1: Verify
    let verify_result = verify_bundle(tza_path)?;

    if !verify_result.valid && !force {
        return Err(format!(
            "AIRLOCK BLOCKED: Archive failed verification. Failed: {:?}, Missing: {:?}",
            verify_result.failed_files, verify_result.missing_files
        ));
    }

    // Step 2: Extract
    fs::create_dir_all(output_dir).map_err(|e| format!("Cannot create output dir: {}", e))?;

    let file = fs::File::open(tza_path).map_err(|e| format!("Cannot open: {}", e))?;
    let mut archive = zip::ZipArchive::new(file).map_err(|e| format!("Not a valid ZIP: {}", e))?;

    let mut extracted_files: Vec<String> = Vec::new();

    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| format!("Archive read error: {}", e))?;
        let name = entry.name().to_string();

        // Skip MANIFEST.json from extraction (keep in archive only)
        if name == "MANIFEST.json" {
            continue;
        }

        // Security: reject path traversal
        if name.contains("..") || name.starts_with('/') {
            continue;
        }

        let out_path = output_dir.join(&name);

        // Create parent directories
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Cannot create dir for {}: {}", name, e))?;
        }

        if entry.is_dir() {
            fs::create_dir_all(&out_path)
                .map_err(|e| format!("Cannot create dir {}: {}", name, e))?;
        } else {
            let mut data = Vec::new();
            entry
                .read_to_end(&mut data)
                .map_err(|e| format!("Cannot read {}: {}", name, e))?;
            fs::write(&out_path, &data)
                .map_err(|e| format!("Cannot write {}: {}", name, e))?;
            extracted_files.push(name);
        }
    }

    Ok(ExtractResult {
        valid: verify_result.valid,
        forced: !verify_result.valid && force,
        manifest: verify_result.manifest,
        extracted_files,
        output_dir: output_dir.to_string_lossy().to_string(),
        verified_files: verify_result.verified_files,
    })
}

/// SHA256 hex digest of bytes
fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::BundleMeta;
    use std::fs;
    use std::path::PathBuf;

    fn test_dir() -> PathBuf {
        let dir = std::env::temp_dir().join("tbz_test_input");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("hello.txt"), "Hello TBZ").unwrap();
        fs::write(dir.join("readme.md"), "# Test").unwrap();
        fs::write(dir.join("data.json"), r#"{"key":"value"}"#).unwrap();
        dir
    }

    #[test]
    fn test_create_and_verify() {
        let input = test_dir();
        let output = std::env::temp_dir().join("tbz_test.tza");
        let _ = fs::remove_file(&output);

        let meta = BundleMeta { agent: Some("test_agent".to_string()), title: None };
        let manifest = create_bundle(&input, &output, meta).unwrap();

        assert_eq!(manifest.protocol, "TIBET-ZIP");
        assert_eq!(manifest.version, "1.0");
        assert_eq!(manifest.stats.total_files, 3);
        assert_eq!(manifest.hashes.len(), 3);
        assert!(manifest.agent.as_deref() == Some("test_agent"));

        // Verify
        let result = verify_bundle(&output).unwrap();
        assert!(result.valid, "Bundle should be valid: {:?}", result.failed_files);
        assert_eq!(result.verified_files, 3);
        assert!(result.failed_files.is_empty());
        assert!(result.missing_files.is_empty());

        let _ = fs::remove_file(&output);
        let _ = fs::remove_dir_all(&input);
    }

    #[test]
    fn test_extract() {
        let input = test_dir();
        let tza_path = std::env::temp_dir().join("tbz_test_extract.tza");
        let extract_dir = std::env::temp_dir().join("tbz_test_extracted");
        let _ = fs::remove_file(&tza_path);
        let _ = fs::remove_dir_all(&extract_dir);

        let meta = BundleMeta { agent: None, title: None };
        create_bundle(&input, &tza_path, meta).unwrap();

        let result = extract_bundle(&tza_path, &extract_dir, false).unwrap();
        assert!(result.valid);
        assert!(!result.forced);
        assert_eq!(result.extracted_files.len(), 3);

        // Verify extracted content matches
        assert_eq!(fs::read_to_string(extract_dir.join("hello.txt")).unwrap(), "Hello TBZ");
        assert_eq!(fs::read_to_string(extract_dir.join("readme.md")).unwrap(), "# Test");

        let _ = fs::remove_file(&tza_path);
        let _ = fs::remove_dir_all(&extract_dir);
        let _ = fs::remove_dir_all(&input);
    }

    #[test]
    fn test_tampered_archive_blocked() {
        let input = test_dir();
        let tza_path = std::env::temp_dir().join("tbz_test_tamper.tza");
        let _ = fs::remove_file(&tza_path);

        let meta = BundleMeta { agent: None, title: None };
        create_bundle(&input, &tza_path, meta).unwrap();

        // Tamper: flip a byte in the archive
        let mut data = fs::read(&tza_path).unwrap();
        if data.len() > 50 {
            data[50] ^= 0xFF;
        }
        fs::write(&tza_path, &data).unwrap();

        // Verify should fail or error
        let result = verify_bundle(&tza_path);
        match result {
            Ok(r) => assert!(!r.valid, "Tampered archive should not be valid"),
            Err(_) => {} // Parse error is also acceptable for corrupted archive
        }

        let _ = fs::remove_file(&tza_path);
        let _ = fs::remove_dir_all(&input);
    }

    #[test]
    fn test_single_file_bundle() {
        let file = std::env::temp_dir().join("tbz_single_test.txt");
        let tza_path = std::env::temp_dir().join("tbz_single.tza");
        let _ = fs::remove_file(&tza_path);
        fs::write(&file, "Single file test").unwrap();

        let meta = BundleMeta { agent: None, title: Some("Single".to_string()) };
        let manifest = create_bundle(&file, &tza_path, meta).unwrap();
        assert_eq!(manifest.stats.total_files, 1);

        let result = verify_bundle(&tza_path).unwrap();
        assert!(result.valid);

        let _ = fs::remove_file(&file);
        let _ = fs::remove_file(&tza_path);
    }
}
