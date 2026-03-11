# tbz — TIBET-zip for Python

**Block-level authenticated compression for the Zero-Trust era.**

Every block carries its own TIBET provenance envelope and Ed25519 signature. Tampered blocks are rejected before decompression touches memory. Built as a response to [CVE-2026-0866 (Zombie ZIP)](https://www.bleepingcomputer.com/news/security/new-zombie-zip-technique-lets-malware-slip-past-security-tools/) — where a single header flip fools 50 out of 51 antivirus engines.

## Install

```bash
pip install tbz
```

## What you get

| Feature | Pure Python | With Rust CLI |
|---------|:-----------:|:-------------:|
| Read block headers | yes | yes |
| Inspect archive structure | yes | yes |
| SHA-256 hash verification | yes | yes |
| Ed25519 signature verification | — | yes |
| Pack files into .tbz | — | yes |
| Unpack via TIBET Airlock | — | yes |
| Transparency Mirror client | yes | yes |

Pure Python works standalone — no binary needed. Add the Rust CLI for full cryptographic verification and pack/unpack.

## Quick Start

### Inspect and verify

```python
from tbz import TBZArchive

archive = TBZArchive("release.tbz")

# Inspect: read block headers (pure Python)
info = archive.inspect()
print(f"Blocks: {info['block_count']}")
print(f"Hash:   {info['content_hash']}")
for block in info["blocks"]:
    sig = "signed" if block["signed"] else "unsigned"
    print(f"  [{block['index']}] {block['type']} — {block['compressed_size']} bytes, {sig}")

# Verify: SHA-256 + Ed25519 (uses Rust CLI if available)
result = archive.verify()
print(result)  # TBZ VERIFIED: 3 blocks (hash + Ed25519), 0 errors
```

### Transparency Mirror — supply chain lookup

```python
from tbz import Mirror

mirror = Mirror()  # connects to bootstrap node

# Look up any TBZ archive by its hash (public, no auth)
entry = mirror.lookup("sha256:abc123...")
if entry:
    print(f"Source: {entry['source_repo']}")
    print(f"Attestations: {len(entry['attestations'])}")

# Search by publisher
results = mirror.search(jis_id="jis:ed25519:77214ce9c262843e")

# Search by verdict
safe_packages = mirror.search(verdict="safe")

# Mirror node stats
stats = mirror.stats()
print(f"Node: {stats['node']}, entries: {stats['total_entries']}")
```

### Pack and unpack (requires Rust CLI)

```python
# Pack
archive = TBZArchive.pack("./src", output="release.tbz")

# Unpack through TIBET Airlock (quarantine buffer, 0x00 wipe on failure)
archive.unpack("./extracted")
```

## Rust CLI

For full features, install the Rust CLI:

```bash
cargo install tbz-cli
```

Then you get short aliases and smart mode:

```bash
tbz p ./src -o release.tbz    # pack
tbz x release.tbz             # extract
tbz v release.tbz             # verify
tbz i release.tbz             # inspect

tbz release.tbz               # smart: verify + unpack
tbz ./src                     # smart: pack
```

## Transparency Mirror

The Mirror is a distributed trust database for verifying TBZ package provenance. The bootstrap node runs at `brein.jaspervandemeent.nl`.

```python
from tbz import Mirror

# Default: bootstrap node
mirror = Mirror()

# Custom node
mirror = Mirror(node_url="https://your-mirror.example.com")

# Public endpoints (no auth required)
mirror.lookup("sha256:...")       # look up by content hash
mirror.search(verdict="safe")     # search attestations
mirror.search(signing_key="77")   # search by key prefix
mirror.stats()                    # node statistics
```

## Why TBZ?

ZIP, tar.gz, and 7z have no cryptographic binding between headers and data. CVE-2026-0866 proves this: flip one byte in a ZIP header, and 50 out of 51 antivirus engines see noise instead of malware.

TBZ fixes this by design:
- **Ed25519 signature** covers header + envelope + payload together
- **SHA-256 hash** in TIBET envelope is the source of truth
- **Quarantine buffer** wipes to 0x00 on verification failure

No header trust. Verify first, decompress second.

## Links

- [GitHub](https://github.com/jaspertvdm/tbz)
- [crates.io](https://crates.io/crates/tbz-cli)
- [Architecture](https://github.com/jaspertvdm/tbz/blob/main/ARCHITECTURE.md)
- [Mirror API](https://brein.jaspervandemeent.nl/api/tbz-mirror/stats)
- [Mirror Analytics](https://brein.jaspervandemeent.nl/api/tbz-mirror/analytics)

## License

MIT / Apache-2.0
