"""
TBZ (TIBET-zip) — Block-level authenticated compression for the Zero-Trust era.

Every block carries its own TIBET provenance envelope and Ed25519 signature.
Invalid blocks are rejected before decompression touches memory.

Usage:
    from tbz import TBZArchive, Mirror

    # Verify an archive
    archive = TBZArchive("release.tza")
    result = archive.verify()
    print(result)

    # Look up in Transparency Mirror
    mirror = Mirror()
    entry = mirror.lookup("sha256:abc123...")
"""

__version__ = "0.1.4"
__author__ = "Jasper van de Meent"

from tbz.archive import TBZArchive
from tbz.mirror import Mirror

__all__ = ["TBZArchive", "Mirror", "__version__"]
