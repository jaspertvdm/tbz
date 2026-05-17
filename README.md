# TBZ — TIBET-zip

**Block-level authenticated compression for the Zero-Trust era.**

[![crates.io](https://img.shields.io/crates/v/tbz-cli.svg)](https://crates.io/crates/tbz-cli)
[![PyPI](https://img.shields.io/pypi/v/tbz.svg)](https://pypi.org/project/tbz/)
[![Rust](https://img.shields.io/badge/rust-pure-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)]()

Classic archive formats (`.zip`, `.tar.gz`) have no cryptographic binding between headers and data. [CVE-2026-0866 (Zombie ZIP)](https://www.bleepingcomputer.com/news/security/new-zombie-zip-technique-lets-malware-slip-past-security-tools/) proves this: flip one byte in a ZIP header, and 50 out of 51 antivirus engines see noise instead of malware.

**TBZ** redesigns compression from Zero-Trust first principles. Every block carries its own [TIBET](ARCHITECTURE.md) provenance envelope and Ed25519 signature. Invalid blocks are rejected before decompression touches memory.

**Why now:**

In March 2026, researchers demonstrated that 50 of 51 antivirus engines failed to detect malware in manipulated ZIP archives — because the format has no cryptographic binding between headers and payload. The same month, supply chain attacks via compromised Python packages on PyPI hit 12,000+ downloads before detection. Both attacks exploit the same gap: archive formats that trust structure without proof.
TBZ closes that gap. Not with a wrapper. Not with a sidecar signature. At the block level, inside the format itself.



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

## Where it works

Where TBZ applies

- **Software supply chain** — every package you distribute is signed at the block level. No more "was this tarball tampered with between CI and PyPI?"
- **AI model transport** — LLM weights, LoRA adapters, GGUF files. Models are the new executables. An unsigned model is an unsigned binary — you're running someone else's code on your inference stack without proof of origin.
- **Agent-to-agent messaging** — on AInternet, every I-Poll message is TBZ-wrapped. No valid signature = message rejected before parsing. This is how you prevent prompt injection at the transport layer.
- **Data at rest** — archives on disk carry their own provenance. No external signature file to lose, no GPG keyring to manage. The proof lives inside the file.
- **Data in transit** — streaming fail-fast means a tampered block kills the connection mid-transfer. Malware never fully arrives.
- **Regulatory compliance** — EU AI Act requires traceability for AI systems. TBZ gives you a per-block audit trail that proves what was shipped, by whom, and when.

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

## Sealed archives (v2)

v1 archives are transparent: anyone can read the bytes, but tampering is detected by the per-block Ed25519 signature. v2 adds **confidentiality**: AES-256-GCM block encryption bound to the receiver's Ed25519 identity via HKDF-SHA256.

**Three-layer hash truth:**

| Layer | Says |
|---|---|
| SHA-256 | the file moved |
| Ed25519 | the sender sealed it (v1 + v2) |
| AES-256-GCM | only the named receiver can read it (v2 only) |

The receiver's AES key is *derived*, never transmitted:

```
AES_key = HKDF-SHA256(
  ikm    = receiver_ed25519_pubkey,
  salt   = sender_ed25519_pubkey ‖ archive_uuid,
  info   = "tbz.v2.aes256gcm.aead",
  length = 32
)
```

Same archive, wrong receiver → different key → AEAD authentication fails. No "decrypt then check"; the wrong identity literally cannot produce the right plaintext.

### v2 workflow

```bash
# Generate Ed25519 keypair (Ed25519, hex-encoded, mode 0600 on private)
tibet-zip keygen -o bob
# → bob.priv + bob.pub

# Seal a folder to Bob with a declared payload class (v2.2+)
tibet-zip pack ./secrets -o jasper.aint \
  --seal \
  --to <bob_pubkey_hex> \
  --from alice.priv     # optional; ephemeral if absent
  --type identity       # one of: identity / code / document / command / receipt

# Bob unpacks with his private key (auto-detects v2 from magic bytes)
tibet-zip unpack jasper.aint -o ./out --as bob.priv
```

Anyone other than Bob trying `--as wrong.priv` gets `AEAD decryption failed (wrong receiver or tampered)`. The bytes never become plaintext.

### v2.2 — declared payload class, mismatch warnings, audit trail

v2.2 adds first-class semantic typing in the v2 header so the receiver
sees *what kind* of payload is being delivered before any bytes touch
disk. Three layers of hint:

```bash
# Pack with declared class
tibet-zip pack ./id-bundle -o jasper.aint \
  --seal --to <pub> --type identity

# Unpack shows declared class + previews the inner manifest BEFORE extract
tibet-zip unpack jasper.aint -o out/ --as bob.priv
#   Declared payload class: identity
#   Preview (= no disk write yet):
#     [  1] data.txt    24 bytes   JIS 0

# If the filename extension doesn't match the declared class, warn
tibet-zip unpack logboek.txt -o out/ --as bob.priv
#   ⚠ payload-class hint: outer .txt but declared class = identity

# --strict-type makes mismatches and inner-executable warnings fatal
tibet-zip unpack onschuldig.txt -o out/ --as bob.priv --strict-type
#   ⚠ executable file(s) found inside a non-code envelope: virus.bat
#   Error: strict-type: ...
```

Every v2 unseal (success or failure) is logged as a
`tbz-unseal.v1` JSONL record so a SOC can monitor identity-bound
extractions. Set `$TBZ_UNSEAL_AUDIT_LOG` to override the path,
default falls back to `/var/log/tibet/tbz-unseal.jsonl` or
`$XDG_STATE_HOME/tbz/audit.jsonl`.

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

### v1 (transparent)

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

### v2 (sealed envelope around v1)

```
┌─────────────────────────────────────────────────┐
│ Magic:           "TBZ"           (3 bytes)      │
│ V2 header:       major minor flags reserved (4) │
│ Sender pubkey:                  (32 bytes)      │
│ Receiver pubkey:                (32 bytes)      │
│ Archive UUID:                   (16 bytes)      │
│ Ciphertext len:  u32 BE          (4 bytes)      │
│ Ciphertext:      AES-256-GCM(v1_archive_bytes)  │
│ Sender sig:      Ed25519 over ciphertext (64)   │
└─────────────────────────────────────────────────┘
```

Fixed overhead: 155 bytes + 16-byte AEAD tag.

## What TBZ replaces

| Traditional workflow | TBZ equivalent |
|---|---|
| `tar czf` + `gpg --sign` + `sha256sum` | `tbz pack` |
| `gpg --verify` + `sha256sum --check` + `tar xzf` | `tbz unpack` |
| Separate .sig + .sha256 + .tar.gz files | Single .tza file |
| Trust the archive, scan after extraction | Reject before decompression |
| No per-file provenance | Per-block TIBET envelope |

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

The Mirror serves the same purpose as Sigstore for containers, but for any file format. The difference: Sigstore signs the artifact externally. TBZ signs every block internally. The Mirror adds a public attestation layer on top — belt and suspenders.

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
