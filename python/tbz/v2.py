"""TBZ v2 — Confidential block encryption + SSM routing header (Python POC).

Implements the wire format described in SPEC-V2.md:

    +-------+-------+--------+----------+--------+--------+
    | MAGIC | SSM   | v2 hdr | manifest | blocks |  ...   |
    | "TBZ" | 1 B   | 4 B    | Ed25519  | optional        |
    +-------+-------+--------+----------+--------+--------+
            (opt)
            cap-flag
            bit 0

Per-block AES-256-GCM with HKDF-SHA256 key derivation from a
receiver Ed25519 pubkey. Backward-compatible: v1 readers reject v2
cleanly, v2 readers handle both layouts.

This module is the wire-format reference; the actual TBZ packer/unpacker
remains the Rust CLI (`tbz` crate). When that CLI gains v2 support, it
should agree with this module byte-for-byte.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
import uuid
from dataclasses import dataclass, field
from typing import Optional

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _AEAD_AVAILABLE = True
except ImportError:
    AESGCM = None  # type: ignore
    _AEAD_AVAILABLE = False


# ── Constants ────────────────────────────────────────────────────────────────

MAGIC = b"TBZ"
V2_HEADER_LEN = 4

V2_VERSION_MAJOR = 0x02
V2_VERSION_MINOR = 0x00

# Capability flags (byte 2 of v2 header)
FLAG_HAS_SSM_HEADER = 0x01
FLAG_HAS_ENCRYPTED_BLOCKS = 0x02
FLAG_HAS_RECEIVER_IDENTITY = 0x04
FLAG_HAS_BLOCK_COMPRESSION = 0x08


class TBZv2Error(Exception):
    """Base class for v2-specific errors."""


class TBZVersionMismatch(TBZv2Error):
    """Raised when a v1 reader meets a v2 file (or vice-versa)."""


class TBZv2DecryptError(TBZv2Error):
    """Raised when AES-256-GCM authentication fails."""


# ── Header encode/decode ─────────────────────────────────────────────────────


def encode_v2_header(flags: int, ssm_byte: Optional[int] = None) -> bytes:
    """Build the v2 wire-format prefix that follows MAGIC.

    Returns:
        bytes — [SSM (1B, optional)] [v2_hdr (4B)]

    If ssm_byte is provided, FLAG_HAS_SSM_HEADER is auto-set.
    """
    if ssm_byte is not None:
        if not 0 <= ssm_byte <= 0xFF:
            raise TBZv2Error(f"ssm_byte must be 0-255, got {ssm_byte}")
        flags |= FLAG_HAS_SSM_HEADER

    if not 0 <= flags <= 0xFF:
        raise TBZv2Error(f"flags must be 0-255, got {flags}")

    parts = []
    if ssm_byte is not None:
        parts.append(bytes([ssm_byte]))
    # v2 header: major (1) + minor (1) + flags (1) + reserved (1)
    parts.append(bytes([V2_VERSION_MAJOR, V2_VERSION_MINOR, flags, 0x00]))
    return b"".join(parts)


def decode_v2_header(data: bytes) -> tuple[int, int, Optional[int]]:
    """Parse v2 wire-format prefix immediately following MAGIC.

    Returns:
        (version_major, flags, ssm_byte_or_None)

    Raises:
        TBZVersionMismatch — if data doesn't look like v2 layout
    """
    if len(data) < V2_HEADER_LEN:
        raise TBZVersionMismatch("too short for v2 header")

    # Two layouts possible:
    #   A. [v2_hdr(4)]            ssm absent → data[0]=0x02, data[1]=0x00
    #   B. [ssm(1)][v2_hdr(4)]    ssm present → data[1]=0x02, data[2]=0x00
    if data[0] == V2_VERSION_MAJOR and data[1] == V2_VERSION_MINOR:
        flags = data[2]
        if flags & FLAG_HAS_SSM_HEADER:
            raise TBZv2Error(
                "flag claims SSM header but layout-A has no SSM byte slot"
            )
        return (V2_VERSION_MAJOR, flags, None)

    if len(data) >= 1 + V2_HEADER_LEN:
        if data[1] == V2_VERSION_MAJOR and data[2] == V2_VERSION_MINOR:
            ssm = data[0]
            flags = data[3]
            if not (flags & FLAG_HAS_SSM_HEADER):
                raise TBZv2Error(
                    "SSM byte present but FLAG_HAS_SSM_HEADER not set"
                )
            return (V2_VERSION_MAJOR, flags, ssm)

    raise TBZVersionMismatch("does not match v2 header layout")


def detect_version(data: bytes) -> int:
    """Detect TBZ version from the first ~8 bytes.

    Returns:
        0 — not a TBZ file (magic mismatch)
        1 — TBZ v1 (transparent, signed only)
        2 — TBZ v2 (with v2 header)
    """
    if len(data) < 4 or data[0:3] != MAGIC:
        return 0
    after_magic = data[3:]
    try:
        decode_v2_header(after_magic)
        return 2
    except (TBZVersionMismatch, TBZv2Error):
        return 1


# ── Key derivation ───────────────────────────────────────────────────────────


def _hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """HKDF-SHA256 — RFC 5869."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


def derive_aes_key(
    receiver_pubkey: bytes,
    sender_pubkey: bytes,
    archive_uuid: bytes,
) -> bytes:
    """Derive a 32-byte AES-256 key for a specific receiver in this archive."""
    if len(receiver_pubkey) != 32:
        raise TBZv2Error(
            f"receiver Ed25519 pubkey must be 32 bytes, got {len(receiver_pubkey)}"
        )
    if len(sender_pubkey) != 32:
        raise TBZv2Error(
            f"sender Ed25519 pubkey must be 32 bytes, got {len(sender_pubkey)}"
        )
    return _hkdf_sha256(
        ikm=receiver_pubkey,
        salt=sender_pubkey + archive_uuid,
        info=b"tbz.v2.aes256gcm.aead",
        length=32,
    )


def block_nonce(archive_uuid: bytes, block_index: int) -> bytes:
    """Derive a 12-byte AEAD nonce for a given block in this archive."""
    h = hashlib.sha256()
    h.update(archive_uuid)
    h.update(block_index.to_bytes(4, "big"))
    return h.digest()[:12]


# ── SealedEnvelope — high-level API ──────────────────────────────────────────


@dataclass
class SealedEnvelope:
    """A v2 sealed envelope ready to encode or decode.

    Usage (seal-side):
        env = SealedEnvelope(
            sender_pubkey=alice_pubkey,
            receiver_pubkey=bob_pubkey,
            ssm_byte=0x19,
        )
        encrypted = [env.encrypt_block(plain, i) for i, plain in enumerate(blocks)]
        header = env.encode_header()

    Usage (open-side, as Bob):
        env = SealedEnvelope.from_header(data_after_magic, my_pubkey=bob_pubkey,
                                         sender_pubkey=alice_pubkey)
        plain = env.decrypt_block(encrypted, 0)
    """

    # Constants exported on the class for ergonomic use
    FLAG_HAS_SSM = FLAG_HAS_SSM_HEADER
    FLAG_HAS_ENCRYPTED_BLOCKS = FLAG_HAS_ENCRYPTED_BLOCKS
    FLAG_HAS_RECEIVER_IDENTITY = FLAG_HAS_RECEIVER_IDENTITY
    FLAG_HAS_BLOCK_COMPRESSION = FLAG_HAS_BLOCK_COMPRESSION

    sender_pubkey: bytes
    receiver_pubkey: bytes
    archive_uuid: bytes = field(default_factory=lambda: uuid.uuid4().bytes)
    ssm_byte: Optional[int] = None
    flags: int = (
        FLAG_HAS_ENCRYPTED_BLOCKS
        | FLAG_HAS_RECEIVER_IDENTITY
        | FLAG_HAS_BLOCK_COMPRESSION
    )

    def __post_init__(self):
        if self.ssm_byte is not None:
            self.flags |= FLAG_HAS_SSM_HEADER

    @property
    def _aes_key(self) -> bytes:
        return derive_aes_key(
            receiver_pubkey=self.receiver_pubkey,
            sender_pubkey=self.sender_pubkey,
            archive_uuid=self.archive_uuid,
        )

    def encode_header(self) -> bytes:
        """Return the full prefix that follows MAGIC."""
        return encode_v2_header(self.flags, ssm_byte=self.ssm_byte)

    def encrypt_block(self, plain: bytes, block_index: int) -> bytes:
        """Encrypt one block with AES-256-GCM bound to this envelope."""
        if not _AEAD_AVAILABLE:
            raise TBZv2Error(
                "cryptography library not installed; pip install cryptography"
            )
        if not (self.flags & FLAG_HAS_ENCRYPTED_BLOCKS):
            raise TBZv2Error("envelope does not have FLAG_HAS_ENCRYPTED_BLOCKS")
        aesgcm = AESGCM(self._aes_key)
        nonce = block_nonce(self.archive_uuid, block_index)
        return aesgcm.encrypt(nonce, plain, associated_data=None)

    def decrypt_block(self, cipher: bytes, block_index: int) -> bytes:
        """Decrypt one block. Raises TBZv2DecryptError on wrong identity."""
        if not _AEAD_AVAILABLE:
            raise TBZv2Error("cryptography library not installed")
        aesgcm = AESGCM(self._aes_key)
        nonce = block_nonce(self.archive_uuid, block_index)
        try:
            return aesgcm.decrypt(nonce, cipher, associated_data=None)
        except Exception as exc:
            raise TBZv2DecryptError(
                f"block {block_index}: AEAD authentication failed — "
                f"wrong identity or tampered ciphertext"
            ) from exc


# ── Module exports ───────────────────────────────────────────────────────────

__all__ = [
    "MAGIC",
    "V2_HEADER_LEN",
    "V2_VERSION_MAJOR",
    "V2_VERSION_MINOR",
    "FLAG_HAS_SSM_HEADER",
    "FLAG_HAS_ENCRYPTED_BLOCKS",
    "FLAG_HAS_RECEIVER_IDENTITY",
    "FLAG_HAS_BLOCK_COMPRESSION",
    "TBZv2Error",
    "TBZVersionMismatch",
    "TBZv2DecryptError",
    "encode_v2_header",
    "decode_v2_header",
    "detect_version",
    "derive_aes_key",
    "block_nonce",
    "SealedEnvelope",
]


# ── Cap-bus integration — payload.tza_* fields (Codex 16:10) ─────────────────


def gateway_event_payload_fields(envelope: "SealedEnvelope") -> dict:
    """Produce payload.tza_* fields for a tibet-cap-bus.gateway-event.v1 record.

    Following Codex's 2026-05-16 mapping:
    - top-level event contract stays generic
    - .tza/TBZ v2 richness lands inside payload.tza_*
    """
    caps = []
    if envelope.flags & FLAG_HAS_ENCRYPTED_BLOCKS:
        caps.append("encrypted_blocks")
    if envelope.flags & FLAG_HAS_RECEIVER_IDENTITY:
        caps.append("receiver_identity")
    if envelope.flags & FLAG_HAS_BLOCK_COMPRESSION:
        caps.append("block_compression")

    return {
        "tza_wire_format": "tbz-v2",
        "tza_artifact_ext": ".tza",
        "tza_magic": "TBZ",
        "tza_version_major": V2_VERSION_MAJOR,
        "tza_version_minor": V2_VERSION_MINOR,
        "tza_has_ssm_header": envelope.ssm_byte is not None,
        "tza_ssm_header": envelope.ssm_byte,
        "tza_capabilities": caps,
        "tza_encryption_mode": (
            "aes-256-gcm-per-block"
            if envelope.flags & FLAG_HAS_ENCRYPTED_BLOCKS
            else None
        ),
        "tza_receiver_identity_bound": bool(
            envelope.flags & FLAG_HAS_RECEIVER_IDENTITY
        ),
        "tza_block_compression": bool(
            envelope.flags & FLAG_HAS_BLOCK_COMPRESSION
        ),
        "tza_archive_uuid": envelope.archive_uuid.hex(),
        "tza_confidentiality_scope": "per-block",
        "tza_block_nonce_scheme": "archive_uuid+block_index",
        "tza_signature_layer": "ed25519",
        "tza_hash_truth": ["sha256", "ed25519", "aes256gcm"],
    }


__all__.append("gateway_event_payload_fields")
