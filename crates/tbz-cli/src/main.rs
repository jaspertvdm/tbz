//! tbz — TBZ command-line tool
//!
//! Usage:
//!   tbz pack <path> -o output.tbz    Create a TBZ archive
//!   tbz unpack <archive.tbz>         Extract via TIBET Airlock
//!   tbz verify <archive.tbz>         Validate without extracting
//!   tbz inspect <archive.tbz>        Show manifest and block info
//!   tbz init                         Generate .jis.json for current repo

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "tbz")]
#[command(about = "TBZ (TIBET-zip) — Block-level authenticated compression")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a TBZ archive from a file or directory
    Pack {
        /// Path to file or directory to archive
        path: String,
        /// Output file path
        #[arg(short, long, default_value = "output.tbz")]
        output: String,
        /// JIS authorization level for all blocks (default: 0)
        #[arg(long, default_value = "0")]
        jis_level: u8,
    },

    /// Extract a TBZ archive via the TIBET Airlock
    Unpack {
        /// Path to the TBZ archive
        archive: String,
        /// Output directory
        #[arg(short, long, default_value = ".")]
        output: String,
    },

    /// Validate a TBZ archive without extracting
    Verify {
        /// Path to the TBZ archive
        archive: String,
    },

    /// Show manifest and block information
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
    // Initialize tracing
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Pack { path, output, jis_level } => {
            println!("TBZ pack: {} → {}", path, output);
            println!("  JIS level: {}", jis_level);

            // Check for .jis.json
            let jis_path = std::path::Path::new(".jis.json");
            if jis_path.exists() {
                println!("  .jis.json found — binding repository identity");
            }

            // TODO: implement packing
            println!("  [not yet implemented — scaffold only]");
            Ok(())
        }

        Commands::Unpack { archive, output } => {
            println!("TBZ unpack: {} → {}", archive, output);

            // Show Airlock mode
            let airlock = tbz_airlock::Airlock::new(256 * 1024 * 1024, 30);
            println!("  Airlock mode: {:?}", airlock.mode());

            // TODO: implement unpacking
            println!("  [not yet implemented — scaffold only]");
            Ok(())
        }

        Commands::Verify { archive } => {
            println!("TBZ verify: {}", archive);
            // TODO: implement verification
            println!("  [not yet implemented — scaffold only]");
            Ok(())
        }

        Commands::Inspect { archive } => {
            println!("TBZ inspect: {}", archive);
            // TODO: implement inspection
            println!("  [not yet implemented — scaffold only]");
            Ok(())
        }

        Commands::Init { platform, account, repo } => {
            println!("TBZ init: generating .jis.json");
            println!("  Platform: {}", platform);
            println!("  Account: {}", account.as_deref().unwrap_or("<detect>"));
            println!("  Repo: {}", repo.as_deref().unwrap_or("<detect>"));
            // TODO: implement init
            println!("  [not yet implemented — scaffold only]");
            Ok(())
        }
    }
}
