//! TIBET-ZIP format support — handles ZIP+MANIFEST.json archives
//! created by TBZ Desktop (Tauri app).
//!
//! The Desktop app creates standard ZIP files with a MANIFEST.json entry
//! containing SHA-256 hashes per file and a bundle_hash.
//!
//! This module lets the CLI `tbz verify` / `tbz unpack` work with
//! Desktop-created .tza files seamlessly.

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::Path;

/// Parsed MANIFEST.json from a TIBET-ZIP archive
#[derive(Debug, serde::Deserialize)]
pub struct TibetZipManifest {
    pub protocol: String,
    pub version: String,
    pub agent: Option<String>,
    pub title: Option<String>,
    pub event: Option<String>,
    pub created_at: String,
    pub created_by: String,
    pub hashes: BTreeMap<String, String>,
    pub stats: TibetZipStats,
    pub bundle_hash: String,
}

#[derive(Debug, serde::Deserialize)]
pub struct TibetZipStats {
    pub total_files: usize,
    pub total_bytes: u64,
    pub ipoll_messages: Option<usize>,
    pub tibet_tokens: Option<usize>,
    pub upip_bundles: Option<usize>,
    pub fork_tokens: Option<usize>,
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

fn compute_bundle_hash(hashes: &BTreeMap<String, String>) -> String {
    let combined: String = hashes
        .iter()
        .map(|(k, v)| format!("{}:{}", k, v))
        .collect::<Vec<_>>()
        .join("|");
    sha256_hex(combined.as_bytes())
}

/// Verify a TIBET-ZIP (Desktop) archive
pub fn verify(archive: &str) -> anyhow::Result<()> {
    let file = fs::File::open(archive)?;
    let mut zip = zip::ZipArchive::new(file)?;

    // Read MANIFEST.json
    let manifest: TibetZipManifest = {
        let mut mf = zip
            .by_name("MANIFEST.json")
            .map_err(|_| anyhow::anyhow!("No MANIFEST.json in archive"))?;
        let mut buf = String::new();
        mf.read_to_string(&mut buf)?;
        serde_json::from_str(&buf)?
    };

    println!("TBZ verify: {} (TIBET-ZIP format)\n", archive);
    println!("  Protocol:   {} v{}", manifest.protocol, manifest.version);
    println!("  Created by: {}", manifest.created_by);
    println!("  Created at: {}", manifest.created_at);
    if let Some(ref agent) = manifest.agent {
        println!("  Agent:      {}", agent);
    }
    if let Some(ref title) = manifest.title {
        println!("  Title:      {}", title);
    }
    println!(
        "  Files:      {} ({} bytes)\n",
        manifest.stats.total_files, manifest.stats.total_bytes
    );

    let mut errors = 0;
    let mut verified = 0;

    for (path, expected_hash) in &manifest.hashes {
        match zip.by_name(path) {
            Ok(mut entry) => {
                if path.contains("..") || path.starts_with('/') {
                    println!("  [!] {} — path traversal BLOCKED", path);
                    errors += 1;
                    continue;
                }

                let mut data = Vec::new();
                entry.read_to_end(&mut data)?;
                let actual_hash = sha256_hex(&data);

                if actual_hash == *expected_hash {
                    println!("  [OK] {} ({} bytes)", path, data.len());
                    verified += 1;
                } else {
                    println!(
                        "  [FAIL] {} — hash mismatch\n    expected: {}\n    actual:   {}",
                        path, expected_hash, actual_hash
                    );
                    errors += 1;
                }
            }
            Err(_) => {
                println!("  [MISS] {} — not in archive", path);
                errors += 1;
            }
        }
    }

    // Verify bundle_hash
    let expected_bh = compute_bundle_hash(&manifest.hashes);
    let bh_ok = manifest.bundle_hash == expected_bh;
    if !bh_ok {
        println!("\n  [FAIL] bundle_hash mismatch");
        errors += 1;
    }

    println!();
    if errors == 0 {
        println!(
            "  Result: ALL {} FILES VERIFIED (SHA-256 + bundle_hash) ✓",
            verified
        );
    } else {
        println!(
            "  Result: {} ERRORS in {} files ✗",
            errors,
            manifest.hashes.len()
        );
    }

    Ok(())
}

/// Inspect a TIBET-ZIP (Desktop) archive
pub fn inspect(archive: &str) -> anyhow::Result<()> {
    let file = fs::File::open(archive)?;
    let mut zip = zip::ZipArchive::new(file)?;

    // Read MANIFEST.json
    let manifest: TibetZipManifest = {
        let mut mf = zip
            .by_name("MANIFEST.json")
            .map_err(|_| anyhow::anyhow!("No MANIFEST.json in archive"))?;
        let mut buf = String::new();
        mf.read_to_string(&mut buf)?;
        serde_json::from_str(&buf)?
    };

    println!("TBZ inspect: {} (TIBET-ZIP format)\n", archive);
    println!("  Protocol:    {} v{}", manifest.protocol, manifest.version);
    println!("  Created by:  {}", manifest.created_by);
    println!("  Created at:  {}", manifest.created_at);
    if let Some(ref agent) = manifest.agent {
        println!("  Agent:       {}", agent);
    }
    if let Some(ref title) = manifest.title {
        println!("  Title:       {}", title);
    }
    println!("  Bundle hash: {}", manifest.bundle_hash);
    println!(
        "  Total:       {} files, {} bytes",
        manifest.stats.total_files, manifest.stats.total_bytes
    );
    println!("\n  Files:");
    for (path, hash) in &manifest.hashes {
        println!("    {} — sha256:{}", path, &hash[..16]);
    }

    println!("\n  ZIP entries: {}", zip.len());
    Ok(())
}

/// Unpack a TIBET-ZIP (Desktop) archive via airlock verification
pub fn unpack(archive: &str, output_dir: &str) -> anyhow::Result<()> {
    println!("TBZ unpack: {} → {} (TIBET-ZIP format)\n", archive, output_dir);
    println!("  Airlock pre-check: verifying archive integrity...\n");

    // Step 1: Verify first
    let file = fs::File::open(archive)?;
    let mut zip = zip::ZipArchive::new(file)?;

    let manifest: TibetZipManifest = {
        let mut mf = zip
            .by_name("MANIFEST.json")
            .map_err(|_| anyhow::anyhow!("No MANIFEST.json in archive"))?;
        let mut buf = String::new();
        mf.read_to_string(&mut buf)?;
        serde_json::from_str(&buf)?
    };

    let mut errors = 0;
    for (path, expected_hash) in &manifest.hashes {
        match zip.by_name(path) {
            Ok(mut entry) => {
                if path.contains("..") || path.starts_with('/') {
                    errors += 1;
                    continue;
                }
                let mut data = Vec::new();
                entry.read_to_end(&mut data)?;
                let actual_hash = sha256_hex(&data);
                if actual_hash != *expected_hash {
                    errors += 1;
                }
            }
            Err(_) => {
                errors += 1;
            }
        }
    }

    let expected_bh = compute_bundle_hash(&manifest.hashes);
    if manifest.bundle_hash != expected_bh {
        errors += 1;
    }

    if errors > 0 {
        anyhow::bail!(
            "AIRLOCK BREACH BLOCKED — archive corrupt: {} ({} errors in {} files)",
            archive,
            errors,
            manifest.hashes.len()
        );
    }

    println!(
        "  Airlock pre-check: {} files verified ✓\n",
        manifest.hashes.len()
    );

    // Step 2: Extract
    fs::create_dir_all(output_dir)?;

    // Re-open for extraction
    let file = fs::File::open(archive)?;
    let mut zip = zip::ZipArchive::new(file)?;

    for i in 0..zip.len() {
        let mut entry = zip.by_index(i)?;
        let name = entry.name().to_string();

        if name == "MANIFEST.json" {
            continue;
        }
        if name.contains("..") || name.starts_with('/') {
            continue;
        }

        let out_path = Path::new(output_dir).join(&name);
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)?;
        }

        if entry.is_dir() {
            fs::create_dir_all(&out_path)?;
        } else {
            let mut data = Vec::new();
            entry.read_to_end(&mut data)?;
            fs::write(&out_path, &data)?;
            println!("  [{}] {} ({} bytes) ✓", i, name, data.len());
        }
    }

    println!(
        "\n  Extracted {} files via Airlock (TIBET-ZIP format)",
        manifest.hashes.len()
    );
    Ok(())
}
