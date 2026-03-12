# TBZ — TIBET-zip

**Block-level authenticated compression for the Zero-Trust era.**

[![crates.io](https://img.shields.io/crates/v/tbz-cli.svg)](https://crates.io/crates/tbz-cli)
[![PyPI](https://img.shields.io/pypi/v/tbz.svg)](https://pypi.org/project/tbz/)
[![Rust](https://img.shields.io/badge/rust-pure-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)]()

Classic archive formats (`.zip`, `.tar.gz`) have no cryptographic binding between headers and data. [CVE-2026-0866 (Zombie ZIP)](https://www.bleepingcomputer.com/news/security/new-zombie-zip-technique-lets-malware-slip-past-security-tools/) proves this: flip one byte in a ZIP header, and 50 out of 51 antivirus engines see noise instead of malware.

**TBZ** redesigns compression from Zero-Trust first principles. Every block carries its own [TIBET](ARCHITECTURE.md) provenance envelope and Ed25519 signature. Invalid blocks are rejected before decompression touches memory.

## Install

```bash
cargo install tbz-cli       # Rust (full features)
pip install tbz              # Python (inspect + Mirror client)
```

## Features

- **Ed25519 per block** — every block is cryptographically signed. Header + envelope + payload bound together. Change one bit, signature fails.
- **Streaming Fail-Fast** — blocks validate on-the-fly. Tampered block? Stop immediately. Malware never reaches executable memory.
- **TIBET Envelope** — per-block provenance: ERIN (content hash), ERAAN (dependencies), EROMHEEN (context), ERACHTER (intent).
- **JIS Sector Authorization** — one archive, multiple views. Control who can decompress which blocks via bilateral identity claims.
- **TIBET Airlock** — quarantine buffer with 0x00 wipe on failure. eBPF kernel-level enforcement when available, userspace fallback otherwise.
- **Transparency Mirror** — distributed trust database for verifying package provenance across the supply chain.
- **100% Pure Rust** — no C/C++ dependencies. Memory-safe, fast, portable.

## Quick Start

```bash
# Initialize a repo with Ed25519 keypair + .jis.json
tbz init --platform github --account you --repo yourproject

# Pack a directory into a TBZ archive
tbz pack ./src -o release.tza

# Verify integrity (SHA-256 hashes + Ed25519 signatures)
tbz verify release.tza

# Extract through the TIBET Airlock
tbz unpack release.tza -o ./extracted

# Inspect the archive structure
tbz inspect release.tza
```

### Short aliases

Because life is too short for `tar -xvf`:

```bash
tbz p ./src -o release.tza    # pack
tbz x release.tza             # extract (unpack)
tbz v release.tza             # verify
tbz i release.tza             # inspect
```

### Smart mode

Just give it a path — TBZ figures out what you want:

```bash
tbz release.tza     # .tza file → verify + unpack
tbz ./src            # directory → pack
```

## Example Output

```
$ tbz verify release.tza

TBZ verify: release.tza

  Signing key: Ed25519 77214ce9c262843e

  [0] OK — hash + signature verified
  [1] OK — hash + signature verified
  [2] OK — hash + signature verified

  Result: ALL 3 BLOCKS VERIFIED (hash + Ed25519) ✓
```

Tampered archive detection:
```
$ tbz verify tampered.tza

  [0] OK — hash + signature verified
  [1] FAIL signature: block header tampered
  [1] FAIL — hash mismatch

  Result: 2 ERRORS in 2 blocks ✗
  Airlock: buffer wiped (0x00)
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

## Python

```python
from tbz import TBZArchive, Mirror

# Inspect (pure Python, no binary needed)
archive = TBZArchive("release.tza")
info = archive.inspect()
print(f"Blocks: {info['block_count']}, Hash: {info['content_hash']}")

# Verify (uses Rust CLI if available, falls back to Python)
result = archive.verify()
print(result)  # TBZ VERIFIED: 3 blocks (hash + Ed25519), 0 errors

# Transparency Mirror (public, no auth)
mirror = Mirror()
entry = mirror.lookup("sha256:abc123...")
stats = mirror.stats()
```

## Transparency Mirror

Public supply chain verification. The bootstrap node runs at `brein.jaspervandemeent.nl`.

- **Lookup**: `GET /api/tbz-mirror/lookup/{sha256:hash}`
- **Search**: `GET /api/tbz-mirror/search?verdict=safe`
- **Stats**: `GET /api/tbz-mirror/stats`
- **Analytics**: `GET /api/tbz-mirror/analytics`

## Workspace Structure

```
crates/
  tbz-core/      Block format, TIBET envelope, zstd, Ed25519, streaming reader/writer
  tbz-cli/       Command-line tool: pack, unpack, verify, inspect, init
  tbz-airlock/   Quarantine buffer, eBPF detection, 0x00 wipe
  tbz-mirror/    sled-backed trust database, attestations
  tbz-jis/       .jis.json parser, sector mapping, JIS authorization
python/
  tbz/           Python client: archive reader + Mirror client (pip install tbz)
```

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full design document including:
- Threat model and attack surface analysis
- IETF draft considerations
- eBPF Airlock kernel hook design
- JIS bilateral identity protocol
- Transparency Mirror DHT design

## Author

**Jasper van de Meent** — [Humotica](https://humotica.com)

## License

MIT / Apache-2.0
