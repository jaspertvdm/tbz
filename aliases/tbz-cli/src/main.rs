//! tbz-cli — short-name alias for tibet-zip-cli.
//!
//! Both binaries delegate to `tibet_zip_cli::run()`, the single source
//! of truth in the canonical `tibet-zip-cli` crate. Installing this
//! package is functionally identical to installing `tibet-zip-cli`.

fn main() -> anyhow::Result<()> {
    tibet_zip_cli::run()
}
