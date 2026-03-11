# TBZ — TIBET-zip

**Block-level authenticated compression for the Zero-Trust era.**

[![Rust](https://img.shields.io/badge/rust-pure-orange.svg)](https://www.rust-lang.org/)
[![Status](https://img.shields.io/badge/status-working_prototype-green.svg)]()
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)]()

Classic archive formats (`.zip`, `.tar.gz`) are semantically empty — no cryptographic proof of origin, intent, or authorization. This leads to supply chain attacks like "Zombie ZIP" exploits and AI model poisoning.

**TBZ** redesigns compression from Zero-Trust first principles. Every block carries its own [TIBET](https://github.com/jaspertvdm/tbz/blob/main/ARCHITECTURE.md) provenance envelope and Ed25519 signature. Invalid blocks are rejected before decompression touches memory.

## Features

- **Streaming Fail-Fast** — blocks validate on-the-fly. Tampered block? Stop immediately. Malware never reaches executable memory.
- **Ed25519 per block** — every block is cryptographically signed. Signatures are verified against the public key embedded in the manifest.
- **TIBET Envelope** — per-block provenance: ERIN (content hash), ERAAN (dependencies), EROMHEEN (context), ERACHTER (intent).
- **JIS Sector Authorization** — one archive, multiple views. Control who can decompress which blocks via bilateral identity claims.
- **TIBET Airlock** — quarantine buffer with 0x00 wipe on failure. eBPF kernel-level enforcement when available, userspace fallback otherwise.
- **Transparency Mirror** — distributed trust database (sled-backed) for verifying package provenance across the supply chain.
- **100% Pure Rust** — no C/C++ dependencies. Memory-safe, fast, portable.

## Quick Start

```bash
# Build
cargo build --release

# Initialize a repo with Ed25519 keypair + .jis.json
tbz init --platform github --account you --repo yourproject

# Pack a directory into a TBZ archive
tbz pack ./src -o release.tbz

# Inspect the archive structure
tbz inspect release.tbz

# Verify integrity (SHA-256 hashes + Ed25519 signatures)
tbz verify release.tbz

# Extract through the TIBET Airlock
tbz unpack release.tbz -o ./extracted
```

## Example Output

```
$ tbz verify release.tbz

TBZ verify: release.tbz

  Signing key: Ed25519 77214ce9c262843e

  [0] OK — hash + signature verified
  [1] OK — hash + signature verified
  [2] OK — hash + signature verified

  Result: ALL 3 BLOCKS VERIFIED (hash + Ed25519) ✓
```

Tampered archive detection:
```
$ tbz verify tampered.tbz

  [0] OK — hash + signature verified
  [1] OK — hash + signature verified
  [2] FAIL signature: Signature verification failed
  [2] FAIL — decompress error: ...

  Result: 2 ERRORS in 3 blocks ✗
```

## Block Format

```
┌─────────────────────────────────────────────────┐
│ Magic: 0x54425A ("TBZ")                         │
│ Header (JSON): version, block_index, type, JIS  │
│ TIBET Envelope (JSON): ERIN, ERAAN, EROMHEEN,    │
│   ERACHTER — full provenance per block          │
│ Payload: zstd-compressed data                   │
│ Signature: Ed25519 (64 bytes) over all above    │
└─────────────────────────────────────────────────┘
```

Block 0 is always the **Manifest** — the signed index of the archive containing the Ed25519 public key, block metadata, and total sizes (zip-bomb protection).

## Workspace Structure

```
crates/
  tbz-core/      Block format, TIBET envelope, zstd, Ed25519, streaming reader/writer
  tbz-cli/       Command-line tool: pack, unpack, verify, inspect, init
  tbz-airlock/   Quarantine buffer, eBPF detection, 0x00 wipe
  tbz-mirror/    sled-backed trust database, attestations
  tbz-jis/       .jis.json parser, sector mapping, JIS authorization
```

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full design document including:
- Threat model and attack surface analysis
- IETF draft considerations
- eBPF Airlock kernel hook design
- JIS bilateral identity protocol
- Transparency Mirror DHT design

## Author

**Jasper van de Meent** — [HumoticaOS](https://humotica.nl)

## License

MIT / Apache-2.0
