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
use tbz_core::v2;
use tbz_core::{signature, BlockType};

mod tibet_zip;

// ---------------------------------------------------------------------------
// Format detection: TBZ block-format vs TIBET-ZIP (Desktop ZIP+MANIFEST)
// ---------------------------------------------------------------------------

/// Archive format detected by magic bytes
#[derive(Debug, Clone, Copy, PartialEq)]
enum ArchiveFormat {
    /// CLI block format: magic 0x54425A ("TBZ"), zstd+Ed25519
    TbzBlock,
    /// Desktop ZIP format: magic 0x504B0304 (PK), MANIFEST.json with SHA-256
    TibetZip,
    /// Unknown format
    Unknown,
}

/// Detect archive format by reading the first 4 bytes
fn detect_format(path: &str) -> anyhow::Result<ArchiveFormat> {
    let mut file = fs::File::open(path)?;
    let mut magic = [0u8; 4];
    let n = std::io::Read::read(&mut file, &mut magic)?;
    if n < 3 {
        return Ok(ArchiveFormat::Unknown);
    }
    if magic[0..3] == [0x54, 0x42, 0x5A] {
        Ok(ArchiveFormat::TbzBlock)
    } else if magic == [0x50, 0x4B, 0x03, 0x04] {
        Ok(ArchiveFormat::TibetZip)
    } else {
        Ok(ArchiveFormat::Unknown)
    }
}

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

    /// Enable Transparency Mirror registration/lookups (opt-in)
    #[arg(long, global = true, default_value_t = false)]
    mirror: bool,

    /// Transparency Mirror base URL (also via TBZ_MIRROR_URL env)
    #[arg(long, global = true, env = "TBZ_MIRROR_URL",
          default_value = "https://brein.jaspervandemeent.nl")]
    mirror_url: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a TBZ archive from a file or directory
    ///
    /// Default = v1 transparent archive. Pass --seal --to <pubkey-hex> to
    /// produce a v2 sealed envelope (AES-256-GCM, identity-bound).
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
        /// Seal the archive (= v2): wrap in an AES-256-GCM envelope.
        #[arg(long)]
        seal: bool,
        /// Receiver's Ed25519 public key (hex, 64 chars). Required with --seal.
        #[arg(long, value_name = "PUBKEY_HEX")]
        to: Option<String>,
        /// Sender's Ed25519 private key file (hex). Optional; ephemeral if absent.
        #[arg(long, value_name = "PRIVKEY_PATH")]
        from: Option<String>,
    },

    /// Extract a TBZ archive via the TIBET Airlock
    ///
    /// Auto-detects v1 vs v2 from magic bytes. For v2 sealed archives,
    /// pass --as <privkey-path> to decrypt as the named receiver.
    #[command(alias = "x")]
    Unpack {
        /// Path to the TBZ archive
        archive: String,
        /// Output directory
        #[arg(short, long, default_value = ".")]
        output: String,
        /// Receiver's Ed25519 private key file (hex). Required for v2 sealed archives.
        #[arg(long = "as", value_name = "PRIVKEY_PATH")]
        as_key: Option<String>,
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

    /// Generate an Ed25519 keypair for v2 sealed archives
    ///
    /// Writes <output>.priv (32-byte hex, mode 0600) and <output>.pub (32-byte hex).
    Keygen {
        /// Output basename — produces <output>.priv and <output>.pub
        #[arg(short, long, default_value = "tbz-key")]
        output: String,
    },
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    // Resolve mirror URL once (None = disabled, opt-in only)
    let mirror_url: Option<&str> = if cli.mirror {
        Some(&cli.mirror_url)
    } else {
        None
    };

    // If a subcommand was given, use it directly
    if let Some(command) = cli.command {
        return match command {
            Commands::Pack { path, output, jis_level, seal, to, from } => {
                if seal {
                    let to_hex = to.ok_or_else(|| anyhow::anyhow!(
                        "--seal requires --to <pubkey-hex> (64 hex chars)"))?;
                    cmd_pack_sealed(&path, &output, jis_level, mirror_url, &to_hex, from.as_deref())
                } else {
                    cmd_pack(&path, &output, jis_level, mirror_url)
                }
            }
            Commands::Unpack { archive, output, as_key } => {
                cmd_unpack_dispatch(&archive, &output, as_key.as_deref())
            }
            Commands::Verify { archive } => cmd_verify(&archive, mirror_url),
            Commands::Inspect { archive } => cmd_inspect(&archive),
            Commands::Init { platform, account, repo } => cmd_init(&platform, account, repo),
            Commands::Keygen { output } => cmd_keygen(&output),
        };
    }

    // Smart auto-detection: tbz <path>
    //
    // v1.0.2: magic-bytes-FIRST. We read the first 4 bytes and check
    // for the TBZ magic (0x54 0x42 0x5A 0x01 / TBZ\x01) BEFORE looking
    // at the file extension. This prevents accidental double-wrap when
    // a sealed envelope was renamed for human navigation
    // (e.g. `vergadering-dinsdag.pdf`) — `tbz <file>` will now correctly
    // route to unpack instead of re-packing the sealed bundle inside a
    // new TBZ container.
    //
    // Bug reported by Jasper in cross-host vloedtest 12 mei 2026:
    //   tbz superbelangrijk-doc-LEES-DIT-EERST.pdf
    //   → Auto-detected: file → pack to ...tza    (= WRONG: re-wrapping a TBZ)
    if let Some(path) = cli.path {
        let p = Path::new(&path);

        // Magic-bytes precheck (= content is truth, name is hint)
        let is_tbz_by_magic = if p.is_file() {
            match std::fs::File::open(p) {
                Ok(mut f) => {
                    use std::io::Read;
                    let mut buf = [0u8; 4];
                    matches!(f.read(&mut buf), Ok(n) if n == 4)
                        && buf == [0x54, 0x42, 0x5A, 0x01]
                }
                Err(_) => false,
            }
        } else {
            false
        };

        if is_tbz_by_magic {
            // Sealed envelope identified by magic bytes — route to unpack
            // regardless of extension. Plus warn the operator if the
            // filename doesn't carry the typical .tza/.tbz suffix, so
            // they know we detected a rename-recovered bundle.
            let extension_matches =
                path.ends_with(".tza") || path.ends_with(".tbz");
            if !extension_matches {
                println!(
                    "✓ TBZ magic bytes detected — treating as sealed bundle"
                );
                println!(
                    "  (filename does not carry .tza/.tbz suffix; this may be"
                );
                println!(
                    "   an operator-renamed bundle. Content is truth, name is hint.)"
                );
            }
            println!("Auto-detected: TBZ envelope → unpack (with airlock verification)\n");
            let out_dir = p.file_stem()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "tbz_out".to_string());
            cmd_unpack(&path, &out_dir)?;
            return Ok(());
        }

        if (path.ends_with(".tza") || path.ends_with(".tbz")) && p.is_file() {
            // Has TBZ-style extension but NO magic match. Could be a
            // truncated/corrupt bundle, or a non-TBZ file with a
            // misleading extension. Fail loudly.
            anyhow::bail!(
                "File '{}' has .tza/.tbz extension but does NOT carry the TBZ magic bytes. \n  Refusing to treat as a sealed archive. Use `tbz inspect {}` for details.",
                path, path
            );
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
    // Format detection: route to TIBET-ZIP handler if Desktop format
    match detect_format(archive)? {
        ArchiveFormat::TibetZip => return tibet_zip::inspect(archive),
        ArchiveFormat::Unknown => anyhow::bail!("Not a TBZ archive: unrecognized format"),
        ArchiveFormat::TbzBlock => {} // continue with block format below
    }

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
///
/// AIRLOCK GATE: Runs full verification BEFORE extraction.
/// Corrupt or tampered archives are BLOCKED.
fn cmd_unpack(archive: &str, output_dir: &str) -> anyhow::Result<()> {
    // Format detection: route to TIBET-ZIP handler if Desktop format
    match detect_format(archive)? {
        ArchiveFormat::TibetZip => return tibet_zip::unpack(archive, output_dir),
        ArchiveFormat::Unknown => anyhow::bail!("Not a TBZ archive: unrecognized format"),
        ArchiveFormat::TbzBlock => {} // continue with block format below
    }

    // =========================================================================
    // AIRLOCK GATE — Verify BEFORE extraction. No exceptions.
    // =========================================================================
    println!("TBZ unpack: {} → {}\n", archive, output_dir);
    println!("  Airlock pre-check: verifying archive integrity...\n");

    {
        let vfile = fs::File::open(archive)?;
        let mut vreader = TbzReader::new(std::io::BufReader::new(vfile));
        let mut errors = 0u32;
        let mut block_count = 0u32;
        let mut verifying_key: Option<tbz_core::VerifyingKey> = None;

        while let Some(block) = vreader.read_block()? {
            if let Err(_) = block.validate() {
                errors += 1;
                block_count += 1;
                continue;
            }

            if block.header.block_type == BlockType::Manifest {
                if let Ok(decompressed) = block.decompress() {
                    if let Ok(manifest) = serde_json::from_slice::<Manifest>(&decompressed) {
                        verifying_key = manifest.get_verifying_key();
                    }
                }
            }

            // Verify signature
            if let Some(ref vk) = verifying_key {
                if block.verify_signature(vk).is_err() {
                    errors += 1;
                }
            }

            // Verify content hash
            match block.decompress() {
                Ok(decompressed) => {
                    let actual_hash = signature::sha256_hash(&decompressed);
                    if actual_hash != block.envelope.erin.content_hash {
                        errors += 1;
                    }
                }
                Err(_) => { errors += 1; }
            }

            block_count += 1;
        }

        if errors > 0 {
            anyhow::bail!(
                "AIRLOCK BREACH BLOCKED — archive corrupt: {} ({} block errors in {} blocks). \
                 Use `tbz verify` to inspect, or fix the archive.",
                archive, errors, block_count
            );
        }

        println!("  Airlock pre-check: {} blocks verified ✓\n", block_count);
    }

    // =========================================================================
    // Extraction — only reached if all blocks verified
    // =========================================================================
    let file = fs::File::open(archive)?;
    let mut reader = TbzReader::new(std::io::BufReader::new(file));

    // Create Airlock
    let mut airlock = tbz_airlock::Airlock::new(256 * 1024 * 1024, 30);
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
    // Format detection: route to TIBET-ZIP handler if Desktop format
    match detect_format(archive)? {
        ArchiveFormat::TibetZip => return tibet_zip::verify(archive),
        ArchiveFormat::Unknown => anyhow::bail!("Not a TBZ archive: unrecognized format"),
        ArchiveFormat::TbzBlock => {} // continue with block format below
    }

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

fn hex_decode_32(s: &str) -> anyhow::Result<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 {
        anyhow::bail!("expected 64 hex characters, got {}", s.len());
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let pair = std::str::from_utf8(chunk).map_err(|_| anyhow::anyhow!("invalid utf8"))?;
        out[i] = u8::from_str_radix(pair, 16)
            .map_err(|e| anyhow::anyhow!("invalid hex pair '{}': {}", pair, e))?;
    }
    Ok(out)
}

fn read_signing_key_from_file(path: &str) -> anyhow::Result<ed25519_dalek::SigningKey> {
    let raw = fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("cannot read key file {}: {}", path, e))?;
    let bytes = hex_decode_32(&raw)?;
    Ok(ed25519_dalek::SigningKey::from_bytes(&bytes))
}

fn chrono_now() -> String {
    use std::time::SystemTime;
    let duration = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}Z", duration.as_secs())
}

// ---------------------------------------------------------------------------
// v2.1.0 NEW SUBCOMMANDS — Keygen, Pack --seal, Unpack --as
// ---------------------------------------------------------------------------

fn cmd_keygen(output: &str) -> anyhow::Result<()> {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let priv_path = format!("{}.priv", output);
    let pub_path = format!("{}.pub", output);

    // Write private key (hex) with 0600 permissions
    let priv_hex = hex_encode(&signing_key.to_bytes());
    fs::write(&priv_path, &priv_hex)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o600);
        fs::set_permissions(&priv_path, perms)?;
    }

    let pub_hex = hex_encode(&verifying_key.to_bytes());
    fs::write(&pub_path, &pub_hex)?;

    println!("TBZ keygen: Ed25519 keypair generated\n");
    println!("  Private: {} (mode 0600)", priv_path);
    println!("  Public:  {}", pub_path);
    println!("\n  Pubkey (share this): {}", pub_hex);
    println!("\n  Use with:");
    println!("    tibet-zip pack <dir> -o sealed.tza --seal --to {} --from {}", pub_hex, priv_path);
    println!("    tibet-zip unpack sealed.tza -o out/ --as {}", priv_path);
    Ok(())
}

fn cmd_pack_sealed(
    path: &str,
    output: &str,
    default_jis_level: u8,
    mirror_url: Option<&str>,
    receiver_hex: &str,
    sender_priv_path: Option<&str>,
) -> anyhow::Result<()> {
    let source = Path::new(path);
    if !source.exists() {
        anyhow::bail!("Source path does not exist: {}", path);
    }
    let receiver_pubkey = hex_decode_32(receiver_hex)
        .map_err(|e| anyhow::anyhow!("--to pubkey: {}", e))?;

    // Sender key: from --from or ephemeral
    let sender_key = match sender_priv_path {
        Some(p) => read_signing_key_from_file(p)?,
        None => {
            use rand::rngs::OsRng;
            ed25519_dalek::SigningKey::generate(&mut OsRng)
        }
    };

    println!("TBZ pack (sealed v2): {} → {}", path, output);
    println!("  Sender pubkey:   {}", hex_encode(&sender_key.verifying_key().to_bytes()));
    println!("  Receiver pubkey: {}", receiver_hex);

    // Build the v1 archive in memory (Vec<u8> buffer)
    let v1_bytes = build_v1_archive_bytes(source, default_jis_level, mirror_url)?;
    println!("\n  Inner v1 archive: {} bytes", v1_bytes.len());

    // Wrap in v2 sealed container
    let container = v2::write_sealed_container(&sender_key, &receiver_pubkey, &v1_bytes)
        .map_err(|e| anyhow::anyhow!("v2 seal failed: {}", e))?;

    fs::write(output, &container)?;
    println!("  Outer v2 envelope: {} bytes (overhead: {} bytes)", container.len(), container.len() - v1_bytes.len());
    println!("\n  Sealed: {} ✓", output);
    println!("  Format: TBZ v2 (AES-256-GCM, Ed25519-signed)");
    Ok(())
}

/// Build a v1 archive in memory as Vec<u8>. Refactored from cmd_pack so we
/// can wrap the bytes in a v2 sealed envelope.
fn build_v1_archive_bytes(
    source: &Path,
    default_jis_level: u8,
    _mirror_url: Option<&str>,
) -> anyhow::Result<Vec<u8>> {
    let files = collect_files(source)?;
    let jis_manifest = tbz_jis::JisManifest::load(Path::new(".")).ok();

    let (signing_key, verifying_key) = signature::generate_keypair();

    let mut manifest = Manifest::new();
    for (i, (file_path, data)) in files.iter().enumerate() {
        let jis_level = jis_manifest
            .as_ref()
            .map(|j| j.jis_level_for_path(file_path))
            .unwrap_or(default_jis_level);

        manifest.add_block(BlockEntry {
            index: (i + 1) as u32,
            block_type: "data".to_string(),
            compressed_size: 0,
            uncompressed_size: data.len() as u64,
            jis_level,
            description: file_path.clone(),
            path: Some(file_path.clone()),
        });
    }
    manifest.set_signing_key(&verifying_key);

    let mut buf: Vec<u8> = Vec::new();
    {
        let mut writer = TbzWriter::new(&mut buf, signing_key);
        writer.write_manifest(&manifest)?;
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
        }
        writer.finish();
    }
    Ok(buf)
}

/// Dispatch unpack: detect v1 vs v2 and route accordingly.
fn cmd_unpack_dispatch(archive: &str, output_dir: &str, as_key: Option<&str>) -> anyhow::Result<()> {
    // Peek first 32 bytes to detect version
    let mut head = [0u8; 32];
    let n = {
        let mut f = fs::File::open(archive)?;
        std::io::Read::read(&mut f, &mut head)?
    };
    let version = if n >= 7 { v2::detect_version(&head[..n]) } else { 0 };

    if version == 2 {
        let priv_path = as_key.ok_or_else(|| anyhow::anyhow!(
            "{} is a v2 sealed archive — pass --as <privkey-path> to decrypt", archive))?;
        let receiver_key = read_signing_key_from_file(priv_path)?;
        println!("TBZ unpack (v2 sealed): {} → {}", archive, output_dir);
        let container = fs::read(archive)?;
        let (env, plain) = v2::read_sealed_container(&container, &receiver_key)
            .map_err(|e| anyhow::anyhow!("v2 unseal failed: {}", e))?;
        println!("  Sender:   {}", hex_encode(&env.sender_pubkey));
        println!("  Receiver: {} ✓", hex_encode(&env.receiver_pubkey));
        println!("  Inner v1 archive: {} bytes\n", plain.len());

        // Write to temp file, then call cmd_unpack with that file
        let tmp = std::env::temp_dir().join(format!("tbz-v2-inner-{}.tza", std::process::id()));
        fs::write(&tmp, &plain)?;
        let result = cmd_unpack(tmp.to_str().unwrap(), output_dir);
        let _ = fs::remove_file(&tmp);
        result
    } else {
        cmd_unpack(archive, output_dir)
    }
}
