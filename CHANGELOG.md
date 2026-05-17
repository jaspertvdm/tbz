# Changelog

All notable changes to TBZ (TIBET-zip) are documented here.

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
