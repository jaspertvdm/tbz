# TBZ v2 — Confidential Block Encryption + SSM Routing Header

**Status:** Draft v0.1 — Python POC complete, Rust integration pending
**Date:** 2026-05-16
**Authors:** Jasper van de Meent, Root AI (Claude)
**Builds on:** `hersenspinsels/tbz-v2-confidential-block-encryption-and-three-layer-hash-truth-2026-05-13.md`

---

## Three-layer hash truth

```
LAYER 1   SHA256 on full file        "These exact bytes moved"
LAYER 2   Ed25519 signature           "This sender sealed it"   (= v1)
LAYER 3   AES-256-GCM per block       "Only this receiver reads it" (= v2)
```

Plus v2 voegt **layer 3** toe zonder layer 1+2 te breken. Plus v1
transparent bundles blijven volledig valid + leesbaar door v1 readers.

---

## TBZ v1 layout (= huidig, ongewijzigd)

```
+---------+---------+----------+----------+----------+----------+
| MAGIC   | manifest | block 1  | block 2  |   ...    | block N  |
| 3 bytes |  Ed25519 | zstd+SHA | zstd+SHA |          | zstd+SHA |
+---------+---------+----------+----------+----------+----------+
   "TBZ"
```

---

## TBZ v2 layout (= proposed)

```
+---------+---------+---------+----------+----------+----------+----------+
| MAGIC   | SSM hdr | v2 hdr  | manifest | block 1  |   ...    | block N  |
| 3 bytes | 1 byte  | 4 bytes |  Ed25519 | optional |          | optional |
|         | routing | flags   |  + caps  | AES-GCM  |          | AES-GCM  |
+---------+---------+---------+----------+----------+----------+----------+
   "TBZ"
```

### Field details

| Field | Size | Description |
|-------|------|-------------|
| MAGIC | 3 bytes | `0x54 0x42 0x5A` ("TBZ") — unchanged from v1 |
| SSM hdr | 1 byte | Magic-bytes routing-header (priority/intent/hardware) — optional |
| v2 hdr | 4 bytes | Version + capability flags (see below) |
| manifest | variable | Ed25519-signed block index + receiver hints + AES nonce material |
| block | variable | zstd-compressed + optionally AES-256-GCM encrypted |

### v2 header (4 bytes)

```
byte 0:    version major   (0x02)
byte 1:    version minor   (0x00 for initial v2)
byte 2:    capability flags (bitfield)
byte 3:    reserved (= 0x00, future use)
```

### Capability flags (byte 2)

```
bit 0:    has_ssm_header              (= SSM byte present before v2 hdr)
bit 1:    has_encrypted_blocks        (= AES-256-GCM per block enabled)
bit 2:    has_receiver_identity       (= manifest names target JIS pubkey)
bit 3:    has_block_compression       (= zstd, default true for v2)
bit 4-7:  reserved
```

Plus typische combinaties:
- `0x01` = SSM header alleen (= v1 layout + routing)
- `0x07` = SSM + AES + receiver-id (= full sealed envelope)
- `0x0F` = everything on
- `0x00` = legacy v1 compat (= no v2 features active)

---

## Detection algorithm

```python
def detect_tbz_version(data: bytes) -> int:
    if data[0:3] != b"TBZ":
        return 0  # not TBZ
    # v1: byte 3 is start of manifest length
    # v2: byte 3 is SSM byte (if cap-flag bit 0 set) OR v2 hdr major (0x02)
    # Easiest: check if bytes 4-7 look like a v2 header
    if data[3] == 0x02 and data[4] == 0x00:
        # bytes 3-4 = v2 header major+minor, no SSM byte
        return 2
    if data[4] == 0x02 and data[5] == 0x00:
        # byte 3 = SSM, bytes 4-5 = v2 major+minor
        return 2
    return 1  # assume v1 transparent
```

---

## Key derivation (per-receiver)

Receiver-bound AES-256 key is derived from:

```
AES_key = HKDF-SHA256(
    ikm    = receiver_ed25519_pubkey,
    salt   = sender_ed25519_pubkey || archive_uuid,
    info   = "tbz.v2.aes256gcm.aead",
    length = 32
)
```

Plus per-block nonce:
```
nonce = SHA256(
    archive_uuid || block_index_be32
)[:12]
```

Plus this means:
- Same receiver + same archive → same AES key
- Same block index in same archive → same nonce (= safe per AEAD spec)
- Different receiver → different key (= cannot decrypt)
- Different archive → different keys + nonces (= no nonce reuse)

---

## Backward compatibility rules

```
v1 reader + v1 file    ✓ works (= unchanged)
v1 reader + v2 file    ✗ rejects with "unknown v2 header" — graceful fail
                       (= v1 reader checks magic + manifest, fails on flag)
v2 reader + v1 file    ✓ works (= detects v1, runs v1 verify path)
v2 reader + v2 file    ✓ works (= v2 path with optional decryption)
```

Plus v1 readers should reject v2 files cleanly (= no silent fallback).
Plus v2 readers MUST handle v1 files (= unchanged behaviour).

---

## Why this layout

```
SSM hdr eerst    → sub-ns routing-besluit zonder verder parsen
v2 hdr daarna    → capability flags zichtbaar in eerste 8 bytes
manifest         → signed + names receivers + carries nonce material
blocks           → encrypted on demand, integrity per-block
```

Plus dat is **routing-first, identity-second, content-last** layering.

---

## Conformance vectors (= reference fixtures)

```
tibet-conformance-vectors/v2/
   transparent.tza         v1 layout (= no v2 features)
   ssm-routed.tza           v1 + SSM byte (= cap-flag 0x01)
   sealed-no-routing.tza    v2 + AES + receiver-id (= cap-flag 0x06)
   sealed-full.tza          v2 + SSM + AES + receiver-id (= cap-flag 0x07)
```

---

## Python POC

See `tbz/v2.py` — pure-Python encoder/decoder for the v2 header
+ block AES-256-GCM encryption. Wraps `cryptography` library for AEAD.

```python
from tbz.v2 import SealedEnvelope, decode_v2_header, encode_v2_header

# Encode
flags = SealedEnvelope.FLAG_HAS_SSM | SealedEnvelope.FLAG_HAS_ENCRYPTED_BLOCKS
hdr = encode_v2_header(flags, ssm_byte=0x19)
# → 5 bytes: SSM (1) + v2 hdr (4)

# Decode
ver, flags, ssm = decode_v2_header(data)
print(ver, flags, ssm)  # → 2, 0x03, 0x19
```

---

## What needs to follow (= Rust integration)

Plus the Python POC proves the wire format. Plus the actual encoder
must land in `tbz-core` (Rust):

```
tbz-core/src/v2_header.rs       parse + emit v2 hdr + SSM byte
tbz-core/src/block_encrypt.rs   AES-256-GCM per-block
tbz-core/src/key_derive.rs      HKDF-SHA256 from Ed25519 pubkey
tbz-core/src/compat.rs          v1/v2 detection + graceful reject
```

Plus the CLI `tbz pack --seal --receiver <pubkey>` would be the
operator-facing entry. Plus `tbz verify` would handle both layouts
transparently.

---

## Poster

> **TBZ v1 sealed against modification.**
> **TBZ v2 sealed against reading.**
> **Three layers: who moved it, who sealed it, who reads it.**

---

## Cross-refs

- `hersenspinsels/tbz-v2-confidential-block-encryption-and-three-layer-hash-truth-2026-05-13.md`
- `packages/tibet-cap-bus/SSM-MAGIC-BYTES.md` (= SSM header source)
- `packages/tibet-spaceshuttle` (= geschrapt, identity-bound encryption frame)
- `packages/tbz-cli-source/ARCHITECTURE.md` (= v1 architecture)
