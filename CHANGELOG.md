# Changelog

All notable changes to TBZ (TIBET-zip) are documented here.

## [2.2.0] — 2026-05-17

### Added — L2 semantic typing + audit trail (iddrop foundation)

This release lays the groundwork for the iddrop protocol layer
(request-driven identity transfer, MITM-resistant). Three quick wins
in TBZ v2 that make the surface-attack story honest:

- **`PayloadClass` byte in V2 header** — the reserved byte
  (always `0x00` in v2.1) now declares one of: `identity`, `code`,
  `document`, `command`, `receipt`. v2.1 archives decode as
  `Unspecified` (byte was 0) — fully backwards compatible.
- **`tibet-zip pack --type <class>`** — declare the payload class
  on the wire. Aliases: `id` / `exec` / `doc` / `cmd` / `ack`.
- **Inner-manifest preview on unpack** — always shown before any
  bytes touch disk; use `--no-preview` to suppress.
- **Payload-class / extension mismatch warning** — e.g. an envelope
  declared `identity` written to `logboek.txt` triggers a hint.
  Use `--strict-type` to make mismatches and inner-executable
  warnings (`.bat` / `.exe` / `.sh` inside a `document` envelope)
  fatal.
- **`tbz-unseal.v1` audit JSONL** — every v2 unseal (success or
  failure) emits a record with sender / receiver / archive_uuid /
  payload_class / outcome. Destination: `$TBZ_UNSEAL_AUDIT_LOG`
  override, then `/var/log/tibet/tbz-unseal.jsonl`, then
  `$XDG_STATE_HOME/tbz/audit.jsonl`. Soft-fail — never blocks a
  legitimate unseal.

### New library API

- `v2::PayloadClass` enum + `from_label` / `as_byte` / `label`.
- `v2::encode_v2_header_with_class` + `v2::decode_v2_header_full`.
- `v2::write_sealed_container_with_class`.
- `v2::read_sealed_container_full` (returns `(env, plain, class)`).

### Tests

- 31 unit tests in `tbz-core` (= 6 new: 3 payload-class roundtrip
  + backward-compat with v2.1 archives + label parse).
- 5 integration tests in `tbz-cli` (unchanged from 2.1.1).

### Frame

Why this release: Jasper's iddrop-spec ([[project-iddrop-protocol-spec]])
identifies that sealed transport bypassed wire-level AV by design —
that is the *point* of confidentiality. v2.2 adds the user-facing
hint surface that lets receivers refuse the wrong *kind* of payload,
audit every unseal, and refuse extraction of executables inside a
non-code envelope. iddrop (L3) builds on top of this.

## [2.1.1] — 2026-05-17

### Fixed

- **`tbz-cli` alias was a stale copy from April, not a real alias.**
  Bumping the alias version did not sync the code, so users who ran
  `cargo install tbz-cli@2.1.0` got the pre-v2 CLI without `keygen`
  or `--seal` flags despite the version string showing 2.1.0.

### Refactored

- `tibet-zip-cli` is now both a library (`pub fn run()`) and a binary
  crate. The canonical binary is a 3-line shim:
  `fn main() -> anyhow::Result<()> { tibet_zip_cli::run() }`.
- The `tbz-cli` alias also becomes a 3-line shim depending on
  `tibet-zip-cli` as a library. No more source duplication, no more
  drift possible between alias and canonical.

### Yanked

- `tbz-cli@2.1.0` was yanked from crates.io (stale code from April).
  Use `tibet-zip-cli@2.1.1` or `tbz-cli@2.1.1` — both are functionally
  identical and call the same `tibet_zip_cli::run()`.

## [2.1.0] — 2026-05-17

### Added — v2 sealed-archive CLI

- **`tibet-zip keygen`** — generate Ed25519 keypairs for v2 sealed archives.
  Writes `<name>.priv` (hex, mode `0600`) + `<name>.pub` (hex).
- **`tibet-zip pack --seal --to <pubkey> [--from <privkey-path>]`** —
  wrap a v1 archive in an AES-256-GCM-sealed v2 envelope bound to the
  receiver's Ed25519 identity. Sender key optional (ephemeral if absent).
- **`tibet-zip unpack --as <privkey-path>`** — auto-detects v2 from
  magic bytes and decrypts using the receiver's private key.
  Missing `--as` on a v2 archive produces a helpful error.

### Added — v2 wire-format container

- `tbz_core::v2::write_sealed_container` / `read_sealed_container` —
  single-block AES-256-GCM container that wraps an existing v1 archive.
  155-byte fixed overhead + 16-byte AEAD tag.
- HKDF-SHA256 receiver-bound key derivation
  (`tbz.v2.aes256gcm.aead` info string).
- Sender Ed25519 signature over the ciphertext (sign-then-encrypt).
- 7 new container roundtrip tests + 5 new CLI integration tests
  (`v2_full_roundtrip_with_correct_receiver`,
  `v2_wrong_receiver_is_rejected`, `v2_missing_as_key_is_rejected`,
  `v2_seal_requires_to_flag`, `v1_unaffected_by_v2_dispatch`).

### Compatibility

- v1 transparent archives continue to work unchanged through all
  subcommands. v2 path is opt-in via `--seal` / `--as`.
- Magic bytes are detected first; v1 readers will reject v2 files with
  a clean error (no silent fallback).

### Companion releases

- `tibet-conformance-vectors 0.2.1` (PyPI) — v2.jsonl converted to
  true JSONL format (one record per line), backwards-compatible with
  the package's brace-walking parser.

## [2.0.0] — 2026-05-16

### Added — v2 crypto primitives (library)

- `tbz_core::v2` module: `encode_v2_header`, `decode_v2_header`,
  `detect_version`, `derive_aes_key`, `block_nonce`, `SealedEnvelope`.
- AES-256-GCM per-block encryption (`aes-gcm` 0.10).
- HKDF-SHA256 key derivation (`hkdf` 0.12).
- 15 unit tests covering roundtrip, wrong-receiver, tampering,
  multi-block, Python-compat.

### Added — five short-name alias crates

- `tbz-core`, `tbz-airlock`, `tbz-mirror`, `tbz-jis`, `tbz-cli`
  published as aliases for the canonical `tibet-zip-*` crates.

### Note

- v2.0.0 ships the v2 *primitives* (in-memory library API). The on-disk
  v2 container and CLI integration land in 2.1.0.

## [1.0.2] — 2026-05-12

### Fixed

- `tbz <file>` smart-mode now reads magic bytes first, before file
  extension. Prevents accidental double-wrapping when a sealed
  envelope was renamed for human navigation
  (e.g. `vergadering-dinsdag.pdf`).

## [1.0.1] — 2026-04-XX

- Initial workspace polish; README expansion.

## [1.0.0] — 2026-03-XX

- First stable release of the Rust workspace. v1 transparent
  block-format with per-block Ed25519 signatures, zstd compression,
  TIBET envelopes, .jis.json sector mapping, Airlock kernel-mode
  verification, and Transparency Mirror integration.
