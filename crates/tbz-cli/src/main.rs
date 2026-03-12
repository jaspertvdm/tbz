//! tbz — TBZ command-line tool
//!
//! Usage:
//!   tbz pack <path> -o output.tza    Create a TBZ archive
//!   tbz unpack <archive.tza>         Extract via TIBET Airlock
//!   tbz verify <archive.tza>         Validate without extracting
//!   tbz inspect <archive.tza>        Show manifest and block info
//!   tbz init                         Generate .jis.json for current repo
//!
//! Short aliases (because life is too short for tar -xvf):
//!   tbz p  = tbz pack
//!   tbz x  = tbz unpack    (x for eXtract, like tar)
//!   tbz v  = tbz verify
//!   tbz i  = tbz inspect
//!
//! Smart defaults:
//!   tbz archive.tza          → auto-detects: verify + unpack
//!   tbz ./src                → auto-detects: pack

use clap::{Parser, Subcommand};
use std::fs;
use std::io::{BufReader, BufWriter, Read as _};
use std::path::Path;

use sha2::{Digest, Sha256};
use tbz_core::envelope::TibetEnvelope;
use tbz_core::manifest::{BlockEntry, Manifest};
use tbz_core::stream::{TbzReader, TbzWriter};
use tbz_core::{signature, BlockType};

// ---------------------------------------------------------------------------
// Transparency Mirror client (best-effort HTTP, never a hard error)
// ---------------------------------------------------------------------------
mod mirror_client {
    use serde::{Deserialize, Serialize};

    const TIMEOUT_SECS: u64 = 5;

    #[derive(Serialize)]
    pub struct RegisterPayload {
        pub content_hash: String,
        pub signing_key: String,
        pub jis_id: Option<String>,
        pub source_repo: Option<String>,
        pub block_count: u32,
        pub total_size: u64,
    }

    #[derive(Deserialize)]
    pub struct RegisterResponse {
        pub status: String, // "registered" | "already_registered"
    }

    #[derive(Deserialize)]
    pub struct LookupEntry {
        pub content_hash: String,
        pub first_seen: String,
        pub attestations: Vec<LookupAttestation>,
    }

    #[derive(Deserialize)]
    pub struct LookupAttestation {
        pub verdict: String,
    }

    pub fn register(base_url: &str, payload: &RegisterPayload) -> Result<RegisterResponse, String> {
        let url = format!("{}/api/tbz-mirror/register", base_url.trim_end_matches('/'));
        let resp = ureq::post(&url)
            .timeout(std::time::Duration::from_secs(TIMEOUT_SECS))
            .send_json(serde_json::json!({
                "content_hash": payload.content_hash,
                "signing_key": payload.signing_key,
                "jis_id": payload.jis_id,
                "source_repo": payload.source_repo,
                "block_count": payload.block_count,
                "total_size": payload.total_size,
            }))
            .map_err(|e| e.to_string())?;

        resp.into_json::<RegisterResponse>().map_err(|e| e.to_string())
    }

    pub fn lookup(base_url: &str, hash: &str) -> Result<Option<LookupEntry>, String> {
        let url = format!(
            "{}/api/tbz-mirror/lookup/{}",
            base_url.trim_end_matches('/'),
            hash,
        );
        let resp = ureq::get(&url)
            .timeout(std::time::Duration::from_secs(TIMEOUT_SECS))
            .call();

        match resp {
            Ok(r) => {
                let entry = r.into_json::<LookupEntry>().map_err(|e| e.to_string())?;
                Ok(Some(entry))
            }
            Err(ureq::Error::Status(404, _)) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }
}

/// Compute SHA-256 of a file on disk (streaming, 8 KB chunks).
fn hash_file(path: &Path) -> anyhow::Result<String> {
    let file = fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

#[derive(Parser)]
#[command(name = "tbz")]
#[command(about = "TBZ (TIBET-zip) — Block-level authenticated compression")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Smart mode: pass a .tza file to verify+unpack, or a directory to pack
    #[arg(global = false)]
    path: Option<String>,

    /// Transparency Mirror base URL (also via TBZ_MIRROR_URL env)
    #[arg(long, global = true, env = "TBZ_MIRROR_URL",
          default_value = "https://brein.jaspervandemeent.nl")]
    mirror_url: String,

    /// Disable Transparency Mirror lookups/registration
    #[arg(long, global = true, default_value_t = false)]
    no_mirror: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a TBZ archive from a file or directory
    #[command(alias = "p")]
    Pack {
        /// Path to file or directory to archive
        path: String,
        /// Output file path
        #[arg(short, long, default_value = "output.tza")]
        output: String,
        /// JIS authorization level for all blocks (default: 0)
        #[arg(long, default_value = "0")]
        jis_level: u8,
    },

    /// Extract a TBZ archive via the TIBET Airlock
    #[command(alias = "x")]
    Unpack {
        /// Path to the TBZ archive
        archive: String,
        /// Output directory
        #[arg(short, long, default_value = ".")]
        output: String,
    },

    /// Validate a TBZ archive without extracting
    #[command(alias = "v")]
    Verify {
        /// Path to the TBZ archive
        archive: String,
    },

    /// Show manifest and block information
    #[command(alias = "i")]
    Inspect {
        /// Path to the TBZ archive
        archive: String,
    },

    /// Generate .jis.json for the current repository
    Init {
        /// Platform (github, gitlab, etc.)
        #[arg(long, default_value = "github")]
        platform: String,
        /// Account name
        #[arg(long)]
        account: Option<String>,
        /// Repository name
        #[arg(long)]
        repo: Option<String>,
    },
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    // Resolve mirror URL once (None = disabled)
    let mirror_url: Option<&str> = if cli.no_mirror {
        None
    } else {
        Some(&cli.mirror_url)
    };

    // If a subcommand was given, use it directly
    if let Some(command) = cli.command {
        return match command {
            Commands::Pack { path, output, jis_level } => cmd_pack(&path, &output, jis_level, mirror_url),
            Commands::Unpack { archive, output } => cmd_unpack(&archive, &output),
            Commands::Verify { archive } => cmd_verify(&archive, mirror_url),
            Commands::Inspect { archive } => cmd_inspect(&archive),
            Commands::Init { platform, account, repo } => cmd_init(&platform, account, repo),
        };
    }

    // Smart auto-detection: tbz <path>
    if let Some(path) = cli.path {
        let p = Path::new(&path);
        if (path.ends_with(".tza") || path.ends_with(".tbz")) && p.is_file() {
            // .tza file → verify, then unpack
            println!("Auto-detected: .tza archive → verify + unpack\n");
            cmd_verify(&path, mirror_url)?;
            println!();
            let out_dir = p.file_stem()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "tbz_out".to_string());
            cmd_unpack(&path, &out_dir)?;
            return Ok(());
        } else if p.is_dir() {
            // Directory → pack
            let dir_name = p.file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "output".to_string());
            let output = format!("{}.tza", dir_name);
            println!("Auto-detected: directory → pack to {}\n", output);
            cmd_pack(&path, &output, 0, mirror_url)?;
            return Ok(());
        } else if p.is_file() {
            // Single file → pack
            let file_name = p.file_stem()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "output".to_string());
            let output = format!("{}.tza", file_name);
            println!("Auto-detected: file → pack to {}\n", output);
            cmd_pack(&path, &output, 0, mirror_url)?;
            return Ok(());
        } else {
            anyhow::bail!("Path not found: {}", path);
        }
    }

    // No subcommand and no path — show help
    Cli::parse_from(["tbz", "--help"]);
    Ok(())
}

/// Pack files into a TBZ archive
fn cmd_pack(path: &str, output: &str, default_jis_level: u8, mirror_url: Option<&str>) -> anyhow::Result<()> {
    let source = Path::new(path);
    if !source.exists() {
        anyhow::bail!("Source path does not exist: {}", path);
    }

    // Collect files to pack
    let files = collect_files(source)?;
    println!("TBZ pack: {} file(s) from {}", files.len(), path);

    // Check for .jis.json
    let jis_manifest = tbz_jis::JisManifest::load(Path::new(".")).ok();
    if let Some(ref jis) = jis_manifest {
        println!("  .jis.json found: {}", jis.repo_identifier());
    }

    // Generate signing keypair for this archive
    let (signing_key, verifying_key) = signature::generate_keypair();

    // Build manifest
    let mut manifest = Manifest::new();
    for (i, (file_path, data)) in files.iter().enumerate() {
        let jis_level = jis_manifest
            .as_ref()
            .map(|j| j.jis_level_for_path(file_path))
            .unwrap_or(default_jis_level);

        manifest.add_block(BlockEntry {
            index: (i + 1) as u32,
            block_type: "data".to_string(),
            compressed_size: 0, // filled after compression
            uncompressed_size: data.len() as u64,
            jis_level,
            description: file_path.clone(),
            path: Some(file_path.clone()),
        });
    }

    // Embed verifying key in manifest
    manifest.set_signing_key(&verifying_key);

    // Write TBZ archive
    let out_file = fs::File::create(output)?;
    let mut writer = TbzWriter::new(BufWriter::new(out_file), signing_key);

    // Block 0: manifest
    writer.write_manifest(&manifest)?;
    println!("  [0] manifest ({} block entries)", manifest.blocks.len());

    // Block 1..N: data
    for (file_path, data) in &files {
        let jis_level = jis_manifest
            .as_ref()
            .map(|j| j.jis_level_for_path(file_path))
            .unwrap_or(default_jis_level);

        let envelope = TibetEnvelope::new(
            signature::sha256_hash(data),
            "data",
            mime_for_path(file_path),
            "tbz-cli",
            &format!("Pack file: {}", file_path),
            vec!["block:0".to_string()],
        );

        let envelope = if let Some(ref jis) = jis_manifest {
            envelope.with_source_repo(&jis.repo_identifier())
        } else {
            envelope
        };

        writer.write_data_block(data, jis_level, &envelope)?;
        println!(
            "  [{}] {} ({} bytes, JIS level {})",
            writer.block_count() - 1,
            file_path,
            data.len(),
            jis_level,
        );
    }

    let total_blocks = writer.block_count();
    writer.finish();

    // Show public key (for verification)
    let vk_hex = hex_encode(&verifying_key.to_bytes());

    println!("\nArchive written: {}", output);
    println!("  Blocks: {}", total_blocks);
    println!("  Signing key (Ed25519 public): {}", vk_hex);
    println!("  Format: TBZ v{}", tbz_core::VERSION);

    // --- Transparency Mirror registration (best-effort) ---
    if let Some(url) = mirror_url {
        let archive_hash = hash_file(Path::new(output))?;
        println!("\n  Mirror: registering {} ...", archive_hash);

        let jis_id = jis_manifest.as_ref().map(|_| {
            format!("jis:ed25519:{}", &vk_hex[..16])
        });
        let source_repo = jis_manifest.as_ref().map(|j| j.repo_identifier());

        let payload = mirror_client::RegisterPayload {
            content_hash: archive_hash,
            signing_key: vk_hex.clone(),
            jis_id,
            source_repo,
            block_count: total_blocks as u32,
            total_size: fs::metadata(output).map(|m| m.len()).unwrap_or(0),
        };

        match mirror_client::register(url, &payload) {
            Ok(resp) => println!("  Mirror: {} ({})", resp.status, url),
            Err(e) => println!("  Mirror: WARNING — {}", e),
        }
    }

    Ok(())
}

/// Inspect a TBZ archive
fn cmd_inspect(archive: &str) -> anyhow::Result<()> {
    let file = fs::File::open(archive)?;
    let mut reader = TbzReader::new(std::io::BufReader::new(file));

    println!("TBZ inspect: {}\n", archive);
    println!("  Magic: 0x54425A (TBZ)");
    println!("  Format: v{}\n", tbz_core::VERSION);

    let mut block_idx = 0;
    while let Some(block) = reader.read_block()? {
        let type_str = match block.header.block_type {
            BlockType::Manifest => "MANIFEST",
            BlockType::Data => "DATA",
            BlockType::Nested => "NESTED",
        };

        println!("  Block {} [{}]", block.header.block_index, type_str);
        println!("    JIS level:         {}", block.header.jis_level);
        println!("    Compressed:        {} bytes", block.header.compressed_size);
        println!("    Uncompressed:      {} bytes", block.header.uncompressed_size);
        println!("    TIBET ERIN hash:   {}", block.envelope.erin.content_hash);
        println!("    TIBET ERACHTER:    {}", block.envelope.erachter);

        if let Some(ref repo) = block.envelope.eromheen.source_repo {
            println!("    Source repo:       {}", repo);
        }

        // For manifest block, show the parsed manifest
        if block.header.block_type == BlockType::Manifest {
            if let Ok(decompressed) = block.decompress() {
                if let Ok(manifest) = serde_json::from_slice::<Manifest>(&decompressed) {
                    println!("    --- Manifest ---");
                    println!("    Total blocks:      {}", manifest.block_count);
                    println!("    Total uncompressed: {} bytes", manifest.total_uncompressed_size);
                    println!("    Max JIS level:     {}", manifest.max_jis_level());
                    for entry in &manifest.blocks {
                        println!(
                            "      [{:>3}] {} — {} bytes, JIS {}",
                            entry.index,
                            entry.path.as_deref().unwrap_or(&entry.description),
                            entry.uncompressed_size,
                            entry.jis_level,
                        );
                    }
                }
            }
        }

        // Signature present?
        let sig_nonzero = block.signature.iter().any(|&b| b != 0);
        println!("    Signature:         {}", if sig_nonzero { "Ed25519 (present)" } else { "none" });
        println!();

        block_idx += 1;
    }

    println!("  Total: {} blocks", block_idx);
    Ok(())
}

/// Unpack a TBZ archive through the Airlock
fn cmd_unpack(archive: &str, output_dir: &str) -> anyhow::Result<()> {
    let file = fs::File::open(archive)?;
    let mut reader = TbzReader::new(std::io::BufReader::new(file));

    // Create Airlock
    let mut airlock = tbz_airlock::Airlock::new(256 * 1024 * 1024, 30);
    println!("TBZ unpack: {} → {}", archive, output_dir);
    println!("  Airlock mode: {:?}\n", airlock.mode());

    fs::create_dir_all(output_dir)?;

    let mut block_idx = 0;
    let mut manifest: Option<Manifest> = None;

    while let Some(block) = reader.read_block()? {
        match block.header.block_type {
            BlockType::Manifest => {
                let decompressed = block.decompress()?;
                manifest = Some(serde_json::from_slice(&decompressed)
                    .map_err(|e| anyhow::anyhow!("Invalid manifest: {}", e))?);
                println!("  [0] Manifest parsed ({} entries)", manifest.as_ref().unwrap().blocks.len());
            }
            BlockType::Data => {
                // Decompress into Airlock
                let decompressed = block.decompress()?;
                airlock.allocate(decompressed.len() as u64)?;
                airlock.receive(&decompressed)?;

                // Determine output path from manifest
                let file_path = manifest
                    .as_ref()
                    .and_then(|m| {
                        m.blocks.iter()
                            .find(|e| e.index == block.header.block_index)
                            .and_then(|e| e.path.clone())
                    })
                    .unwrap_or_else(|| format!("block_{}", block.header.block_index));

                // Write from Airlock to filesystem
                let out_path = Path::new(output_dir).join(&file_path);
                if let Some(parent) = out_path.parent() {
                    fs::create_dir_all(parent)?;
                }

                let data = airlock.release(); // returns data + wipes buffer
                fs::write(&out_path, &data)?;

                println!(
                    "  [{}] {} ({} bytes) ✓",
                    block.header.block_index,
                    file_path,
                    data.len(),
                );
            }
            BlockType::Nested => {
                println!("  [{}] Nested TBZ (not yet supported)", block.header.block_index);
            }
        }
        block_idx += 1;
    }

    println!("\n  Extracted {} blocks via Airlock", block_idx);
    println!("  Airlock buffer: wiped (0x00)");
    Ok(())
}

/// Verify a TBZ archive without extracting
fn cmd_verify(archive: &str, mirror_url: Option<&str>) -> anyhow::Result<()> {
    let file = fs::File::open(archive)?;
    let mut reader = TbzReader::new(std::io::BufReader::new(file));

    println!("TBZ verify: {}\n", archive);

    let mut errors = 0;
    let mut block_idx = 0;
    let mut verifying_key: Option<tbz_core::VerifyingKey> = None;

    while let Some(block) = reader.read_block()? {
        // Validate header
        if let Err(e) = block.validate() {
            println!("  [{}] FAIL header: {}", block.header.block_index, e);
            errors += 1;
            block_idx += 1;
            continue;
        }

        // Extract verifying key from manifest (block 0)
        if block.header.block_type == BlockType::Manifest {
            if let Ok(decompressed) = block.decompress() {
                if let Ok(manifest) = serde_json::from_slice::<Manifest>(&decompressed) {
                    verifying_key = manifest.get_verifying_key();
                    if let Some(ref vk) = verifying_key {
                        let vk_hex = hex_encode(&vk.to_bytes());
                        println!("  Signing key: Ed25519 {}", &vk_hex[..16]);
                        println!();
                    } else {
                        println!("  WARNING: No signing key in manifest — signature checks skipped\n");
                    }
                }
            }
        }

        // 1. Verify Ed25519 signature (cryptographic proof of block integrity)
        let sig_ok = if let Some(ref vk) = verifying_key {
            match block.verify_signature(vk) {
                Ok(()) => true,
                Err(e) => {
                    println!("  [{}] FAIL signature: {}", block.header.block_index, e);
                    errors += 1;
                    false
                }
            }
        } else {
            true // no key available, skip
        };

        // 2. Verify content hash matches TIBET ERIN
        match block.decompress() {
            Ok(decompressed) => {
                let actual_hash = signature::sha256_hash(&decompressed);
                if actual_hash == block.envelope.erin.content_hash {
                    let sig_status = if verifying_key.is_some() && sig_ok {
                        "hash + signature"
                    } else if verifying_key.is_some() {
                        "hash only (sig FAILED)"
                    } else {
                        "hash only (no key)"
                    };
                    println!("  [{}] OK — {} verified", block.header.block_index, sig_status);
                } else {
                    println!(
                        "  [{}] FAIL — hash mismatch\n    expected: {}\n    actual:   {}",
                        block.header.block_index,
                        block.envelope.erin.content_hash,
                        actual_hash,
                    );
                    errors += 1;
                }
            }
            Err(e) => {
                println!("  [{}] FAIL — decompress error: {}", block.header.block_index, e);
                errors += 1;
            }
        }

        block_idx += 1;
    }

    println!();
    if errors == 0 {
        if verifying_key.is_some() {
            println!("  Result: ALL {} BLOCKS VERIFIED (hash + Ed25519) ✓", block_idx);
        } else {
            println!("  Result: ALL {} BLOCKS VERIFIED (hash only, no signing key) ✓", block_idx);
        }
    } else {
        println!("  Result: {} ERRORS in {} blocks ✗", errors, block_idx);
    }

    // --- Transparency Mirror lookup (best-effort) ---
    if let Some(url) = mirror_url {
        let archive_hash = hash_file(Path::new(archive))?;
        match mirror_client::lookup(url, &archive_hash) {
            Ok(Some(entry)) => {
                let verdicts: Vec<&str> = entry.attestations.iter()
                    .map(|a| a.verdict.as_str())
                    .collect();
                println!("\n  Mirror: KNOWN");
                println!("    Hash:         {}", entry.content_hash);
                println!("    First seen:   {}", entry.first_seen);
                println!(
                    "    Attestations: {} ({})",
                    entry.attestations.len(),
                    if verdicts.is_empty() { "none".to_string() } else { verdicts.join(", ") },
                );
            }
            Ok(None) => {
                println!("\n  Mirror: UNKNOWN — not registered in Transparency Mirror");
            }
            Err(e) => {
                println!("\n  Mirror: WARNING — {}", e);
            }
        }
    }

    Ok(())
}

/// Generate .jis.json and Ed25519 keypair for current repo
fn cmd_init(platform: &str, account: Option<String>, repo: Option<String>) -> anyhow::Result<()> {
    let account = account.unwrap_or_else(|| "<your-account>".to_string());
    let repo = repo.unwrap_or_else(|| {
        std::env::current_dir()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
            .unwrap_or_else(|| "<repo>".to_string())
    });

    // Check if .tbz/ already exists
    let tbz_dir = Path::new(".tbz");
    let key_path = tbz_dir.join("signing.key");
    let pub_path = tbz_dir.join("signing.pub");

    let (signing_key, verifying_key) = if key_path.exists() {
        // Load existing keypair
        let sk_hex = fs::read_to_string(&key_path)?;
        let sk_bytes: Vec<u8> = (0..sk_hex.trim().len())
            .step_by(2)
            .filter_map(|i| u8::from_str_radix(&sk_hex.trim()[i..i + 2], 16).ok())
            .collect();
        if sk_bytes.len() != 32 {
            anyhow::bail!("Invalid signing key in .tbz/signing.key");
        }
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&sk_bytes);
        let sk = tbz_core::SigningKey::from_bytes(&key_array);
        let vk = sk.verifying_key();
        println!("Using existing keypair from .tbz/");
        (sk, vk)
    } else {
        // Generate new keypair
        let (sk, vk) = signature::generate_keypair();

        fs::create_dir_all(tbz_dir)?;
        fs::write(&key_path, hex_encode(&sk.to_bytes()))?;
        fs::write(&pub_path, hex_encode(&vk.to_bytes()))?;

        println!("Generated Ed25519 keypair:");
        println!("  Private: .tbz/signing.key (KEEP SECRET — add to .gitignore!)");
        println!("  Public:  .tbz/signing.pub");
        (sk, vk)
    };

    let vk_hex = hex_encode(&verifying_key.to_bytes());
    let jis_id = format!("jis:ed25519:{}", &vk_hex[..16]);

    // Sign the JIS identity claim
    let claim_data = format!("{}:{}:{}:{}", platform, account, repo, vk_hex);
    let claim_sig = signature::sign(claim_data.as_bytes(), &signing_key);

    let jis_json = serde_json::json!({
        "tbz": "1.0",
        "jis_id": jis_id,
        "signing_key": vk_hex,
        "claim": {
            "platform": platform,
            "account": account,
            "repo": repo,
            "intent": "official_releases",
            "sectors": {
                "src/*": { "jis_level": 0, "description": "Public source code" },
                "keys/*": { "jis_level": 2, "description": "Signing keys" }
            }
        },
        "tibet": {
            "erin": "Repository identity binding",
            "eraan": [&jis_id],
            "erachter": format!("Provenance root for TBZ packages from {}/{}", account, repo)
        },
        "signature": hex_encode(&claim_sig),
        "timestamp": chrono_now()
    });

    let output = serde_json::to_string_pretty(&jis_json)?;
    fs::write(".jis.json", &output)?;

    // Ensure .tbz/signing.key is in .gitignore
    let gitignore = Path::new(".gitignore");
    if gitignore.exists() {
        let content = fs::read_to_string(gitignore)?;
        if !content.contains(".tbz/signing.key") {
            fs::write(gitignore, format!("{}\n# TBZ signing key (NEVER commit!)\n.tbz/signing.key\n", content.trim_end()))?;
            println!("\n  Added .tbz/signing.key to .gitignore");
        }
    }

    println!("\nGenerated .jis.json:");
    println!("  JIS ID: {}", jis_id);
    println!("  Claim: {}/{}/{}", platform, account, repo);
    println!("  Signature: Ed25519 (signed)");

    Ok(())
}

/// Collect files from a path (file or directory, recursive)
fn collect_files(path: &Path) -> anyhow::Result<Vec<(String, Vec<u8>)>> {
    let mut files = Vec::new();

    if path.is_file() {
        let data = fs::read(path)?;
        let name = path.file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "file".to_string());
        files.push((name, data));
    } else if path.is_dir() {
        collect_dir_recursive(path, path, &mut files)?;
    }

    Ok(files)
}

fn collect_dir_recursive(
    base: &Path,
    current: &Path,
    files: &mut Vec<(String, Vec<u8>)>,
) -> anyhow::Result<()> {
    let mut entries: Vec<_> = fs::read_dir(current)?.collect::<Result<_, _>>()?;
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let path = entry.path();
        // Skip hidden files and common non-essential dirs
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with('.') || name == "target" || name == "node_modules" {
            continue;
        }

        if path.is_file() {
            let rel = path.strip_prefix(base)
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|_| name);
            let data = fs::read(&path)?;
            files.push((rel, data));
        } else if path.is_dir() {
            collect_dir_recursive(base, &path, files)?;
        }
    }
    Ok(())
}

/// Simple MIME type detection
fn mime_for_path(path: &str) -> &str {
    match path.rsplit('.').next() {
        Some("rs") => "text/x-rust",
        Some("toml") => "application/toml",
        Some("json") => "application/json",
        Some("md") => "text/markdown",
        Some("txt") => "text/plain",
        Some("py") => "text/x-python",
        Some("js") => "text/javascript",
        Some("html") => "text/html",
        Some("css") => "text/css",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("bin") => "application/octet-stream",
        _ => "application/octet-stream",
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn chrono_now() -> String {
    use std::time::SystemTime;
    let duration = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}Z", duration.as_secs())
}
