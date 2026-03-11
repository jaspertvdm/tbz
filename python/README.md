# tbz — TIBET-zip for Python

**Block-level authenticated compression for the Zero-Trust era.**

Python client for TBZ archives and the Transparency Mirror network. Every block carries its own TIBET provenance envelope and Ed25519 signature. Tampered blocks are rejected before decompression touches memory.

## Install

```bash
pip install tbz
```

## Quick Start

```python
from tbz import TBZArchive, Mirror

# Read and inspect a TBZ archive (pure Python, no binary needed)
archive = TBZArchive("release.tbz")
info = archive.inspect()
print(f"Blocks: {info['block_count']}, Hash: {info['content_hash']}")

# Verify integrity (uses Rust CLI if available, falls back to Python)
result = archive.verify()
print(result)  # TBZ VERIFIED: 3 blocks (hash + Ed25519), 0 errors

# Look up in the Transparency Mirror (public, no auth needed)
mirror = Mirror()
entry = mirror.lookup("sha256:abc123...")
if entry:
    print(f"Source: {entry['source_repo']}, Attestations: {len(entry['attestations'])}")

# Search by publisher
results = mirror.search(jis_id="jis:ed25519:77214ce9c262843e")

# Mirror stats
stats = mirror.stats()
print(f"Mirror node: {stats['node']}, entries: {stats['total_entries']}")
```

## With Rust CLI (full features)

For full Ed25519 signature verification and pack/unpack support, install the Rust binary:

```bash
# From source
git clone https://github.com/jaspertvdm/tbz
cd tbz && cargo build --release
export PATH=$PATH:$(pwd)/target/release

# Short aliases (because life is too short for tar -xvf)
tbz p ./src -o release.tbz    # pack
tbz x release.tbz             # extract
tbz v release.tbz             # verify
tbz i release.tbz             # inspect

# Smart mode — just give it a path
tbz release.tbz               # .tbz file → verify + unpack
tbz ./src                     # directory → pack

# Then in Python
archive = TBZArchive("release.tbz")
result = archive.verify()  # Full Ed25519 + SHA-256 verification
archive.unpack("./extracted")  # Extract through TIBET Airlock
```

## Transparency Mirror

The Mirror is a distributed trust database for verifying TBZ package provenance. The bootstrap node runs at `brein.jaspervandemeent.nl`.

```python
from tbz import Mirror

# Default: connects to bootstrap node
mirror = Mirror()

# Custom node
mirror = Mirror(node_url="https://your-mirror.example.com")

# Public endpoints (no auth)
mirror.lookup("sha256:...")   # Look up by hash
mirror.search(verdict="safe") # Search attestations
mirror.stats()                # Node statistics
```

## Links

- [GitHub](https://github.com/jaspertvdm/tbz)
- [Architecture](https://github.com/jaspertvdm/tbz/blob/main/ARCHITECTURE.md)
- [Mirror API](https://brein.jaspervandemeent.nl/api/tbz-mirror/stats)

## License

MIT / Apache-2.0
