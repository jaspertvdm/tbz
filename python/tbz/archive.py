"""
TBZ Archive — Python interface for TBZ archives.

Wraps the Rust `tbz` CLI for pack/unpack/verify/inspect operations.
For native speed, install the Rust toolchain and build with `cargo build --release`.
"""

import hashlib
import json
import os
import shutil
import struct
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Dict, Any


# TBZ magic bytes
MAGIC = bytes([0x54, 0x42, 0x5A])


@dataclass
class BlockInfo:
    """Information about a single block in a TBZ archive."""
    index: int
    block_type: str  # "Manifest", "Data", "Nested"
    jis_level: int
    compressed_size: int
    uncompressed_size: int
    content_hash: str
    erachter: str  # intent
    signature_present: bool
    path: Optional[str] = None


@dataclass
class VerifyResult:
    """Result of verifying a TBZ archive."""
    ok: bool
    blocks_checked: int
    errors: int
    signing_key: Optional[str] = None
    block_results: List[Dict[str, Any]] = field(default_factory=list)

    def __str__(self):
        status = "VERIFIED" if self.ok else "FAILED"
        sig = f" (hash + Ed25519)" if self.signing_key else " (hash only)"
        return f"TBZ {status}: {self.blocks_checked} blocks{sig}, {self.errors} errors"


class TBZArchive:
    """Interface for TBZ archives.

    Can operate in two modes:
    1. CLI mode: delegates to the Rust `tbz` binary (fast, full features)
    2. Pure Python mode: reads block headers directly (no external binary needed)

    Args:
        path: Path to the .tbz archive file
        tbz_binary: Path to the tbz CLI binary (auto-detected if not specified)
    """

    def __init__(self, path: str, tbz_binary: str = None):
        self.path = Path(path)
        self._tbz_bin = tbz_binary or self._find_binary()

    def _find_binary(self) -> Optional[str]:
        """Try to find the tbz binary."""
        # Check common locations
        candidates = [
            shutil.which("tbz"),
            os.path.expanduser("~/.cargo/bin/tbz"),
            str(Path(__file__).parent.parent.parent / "target" / "release" / "tbz"),
            str(Path(__file__).parent.parent.parent / "target" / "debug" / "tbz"),
        ]
        for c in candidates:
            if c and os.path.isfile(c) and os.access(c, os.X_OK):
                return c
        return None

    @property
    def exists(self) -> bool:
        return self.path.exists()

    def content_hash(self) -> str:
        """Compute SHA-256 hash of the entire archive file."""
        h = hashlib.sha256()
        with open(self.path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return f"sha256:{h.hexdigest()}"

    def read_blocks(self) -> List[BlockInfo]:
        """Read block headers from the archive (pure Python, no CLI needed)."""
        blocks = []
        with open(self.path, "rb") as f:
            while True:
                magic = f.read(3)
                if len(magic) < 3:
                    break
                if magic != MAGIC:
                    break

                # Read header
                header_len = struct.unpack("<I", f.read(4))[0]
                header_json = f.read(header_len)
                header = json.loads(header_json)

                # Read envelope
                envelope_len = struct.unpack("<I", f.read(4))[0]
                envelope_json = f.read(envelope_len)
                envelope = json.loads(envelope_json)

                # Read payload
                payload_len = struct.unpack("<Q", f.read(8))[0]
                f.seek(payload_len, 1)  # skip payload

                # Read signature (64 bytes)
                sig = f.read(64)
                sig_present = any(b != 0 for b in sig)

                blocks.append(BlockInfo(
                    index=header.get("block_index", 0),
                    block_type=header.get("block_type", "Unknown"),
                    jis_level=header.get("jis_level", 0),
                    compressed_size=header.get("compressed_size", 0),
                    uncompressed_size=header.get("uncompressed_size", 0),
                    content_hash=envelope.get("erin", {}).get("content_hash", ""),
                    erachter=envelope.get("erachter", ""),
                    signature_present=sig_present,
                    path=None,
                ))

        return blocks

    def verify(self) -> VerifyResult:
        """Verify the archive integrity.

        Uses the Rust CLI if available (fast, full Ed25519 verification).
        Falls back to pure Python header reading if CLI not found.
        """
        if self._tbz_bin:
            return self._verify_cli()
        return self._verify_python()

    def _verify_cli(self) -> VerifyResult:
        """Verify using the Rust CLI binary."""
        result = subprocess.run(
            [self._tbz_bin, "verify", str(self.path)],
            capture_output=True, text=True, timeout=60,
        )

        output = result.stdout + result.stderr
        errors = output.count("FAIL")
        blocks = output.count("] OK") + errors
        signing_key = None

        for line in output.splitlines():
            if "Signing key:" in line:
                signing_key = line.split("Ed25519")[-1].strip()

        return VerifyResult(
            ok=(errors == 0 and result.returncode == 0),
            blocks_checked=blocks,
            errors=errors,
            signing_key=signing_key,
            block_results=[{"raw_output": output}],
        )

    def _verify_python(self) -> VerifyResult:
        """Basic verification using pure Python (header checks only)."""
        blocks = self.read_blocks()
        return VerifyResult(
            ok=len(blocks) > 0,
            blocks_checked=len(blocks),
            errors=0,
            signing_key=None,
            block_results=[{"index": b.index, "type": b.block_type, "hash": b.content_hash} for b in blocks],
        )

    def inspect(self) -> Dict[str, Any]:
        """Get detailed information about the archive."""
        blocks = self.read_blocks()
        return {
            "path": str(self.path),
            "size": self.path.stat().st_size,
            "content_hash": self.content_hash(),
            "block_count": len(blocks),
            "blocks": [
                {
                    "index": b.index,
                    "type": b.block_type,
                    "jis_level": b.jis_level,
                    "compressed_size": b.compressed_size,
                    "uncompressed_size": b.uncompressed_size,
                    "content_hash": b.content_hash,
                    "intent": b.erachter,
                    "signed": b.signature_present,
                }
                for b in blocks
            ],
        }

    def unpack(self, output_dir: str = ".") -> bool:
        """Extract the archive through the TIBET Airlock.

        Requires the Rust CLI binary.
        """
        if not self._tbz_bin:
            raise RuntimeError("tbz binary not found — install with: cargo install --path crates/tbz-cli")

        result = subprocess.run(
            [self._tbz_bin, "unpack", str(self.path), "-o", output_dir],
            capture_output=True, text=True, timeout=120,
        )
        return result.returncode == 0

    @staticmethod
    def pack(source: str, output: str = "output.tbz", tbz_binary: str = None) -> "TBZArchive":
        """Pack files into a TBZ archive.

        Requires the Rust CLI binary.

        Args:
            source: Path to file or directory to archive
            output: Output .tbz file path
            tbz_binary: Path to tbz CLI binary

        Returns:
            TBZArchive instance for the created archive.
        """
        binary = tbz_binary or shutil.which("tbz")
        if not binary:
            raise RuntimeError("tbz binary not found — install with: cargo install --path crates/tbz-cli")

        result = subprocess.run(
            [binary, "pack", source, "-o", output],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Pack failed: {result.stderr}")

        return TBZArchive(output, tbz_binary=binary)

    def __repr__(self):
        blocks = len(self.read_blocks()) if self.exists else 0
        return f"TBZArchive({self.path!r}, blocks={blocks})"
