//! tibet-zip / tbz binary entry point.
//!
//! All CLI logic lives in `tibet_zip_cli::run()` (the library crate),
//! so the canonical binary and the `tbz-cli` short-name alias share
//! one source of truth. See `lib.rs` for the actual implementation.

fn main() -> anyhow::Result<()> {
    tibet_zip_cli::run()
}
