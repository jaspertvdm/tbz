"""
TBZ Transparency Mirror client.

Query the distributed trust database for package provenance verification.
"""

from typing import Optional, Dict, Any, List
import requests


DEFAULT_MIRROR = "https://brein.jaspervandemeent.nl"


class MirrorError(Exception):
    """Error communicating with a Transparency Mirror node."""
    pass


class Mirror:
    """Client for the TBZ Transparency Mirror network.

    The Mirror is a distributed trust database that stores content hashes,
    Ed25519 signing keys, and attestations for TBZ archives.

    Args:
        node_url: Base URL of the mirror node (default: bootstrap node)
        timeout: Request timeout in seconds
    """

    def __init__(self, node_url: str = DEFAULT_MIRROR, timeout: float = 10.0):
        self.node_url = node_url.rstrip("/")
        self.timeout = timeout
        self._base = f"{self.node_url}/api/tbz-mirror"

    def lookup(self, content_hash: str) -> Optional[Dict[str, Any]]:
        """Look up a TBZ archive by its content hash.

        Args:
            content_hash: SHA-256 hash (format: "sha256:<hex>")

        Returns:
            Trust entry dict if found, None if not found.

        Raises:
            MirrorError: On network or server errors.
        """
        try:
            resp = requests.get(
                f"{self._base}/lookup/{content_hash}",
                timeout=self.timeout,
            )
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            return resp.json().get("entry")
        except requests.ConnectionError as e:
            raise MirrorError(f"Cannot reach mirror node {self.node_url}: {e}")
        except requests.HTTPError as e:
            raise MirrorError(f"Mirror error: {e}")

    def register(self, content_hash: str, signing_key: str = None,
                 jis_id: str = None, source_repo: str = None,
                 block_count: int = 0, total_size: int = 0,
                 auth_token: str = None) -> Dict[str, Any]:
        """Register a TBZ archive in the Transparency Mirror.

        Requires authentication on the mirror node.

        Args:
            content_hash: SHA-256 hash of the archive
            signing_key: Ed25519 public key (hex)
            jis_id: JIS identity string
            source_repo: Repository identifier
            block_count: Number of blocks in the archive
            total_size: Total uncompressed size in bytes
            auth_token: JWT bearer token for authentication

        Returns:
            Registration result from the mirror.
        """
        headers = {"Content-Type": "application/json"}
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"

        payload = {"content_hash": content_hash}
        if signing_key:
            payload["signing_key"] = signing_key
        if jis_id:
            payload["jis_id"] = jis_id
        if source_repo:
            payload["source_repo"] = source_repo
        if block_count:
            payload["block_count"] = block_count
        if total_size:
            payload["total_size"] = total_size

        try:
            resp = requests.post(
                f"{self._base}/register",
                json=payload,
                headers=headers,
                timeout=self.timeout,
            )
            resp.raise_for_status()
            return resp.json()
        except requests.HTTPError as e:
            raise MirrorError(f"Registration failed: {e}")

    def attest(self, content_hash: str, attester: str,
               verdict: str = "safe", notes: str = None,
               auth_token: str = None) -> Dict[str, Any]:
        """Add an attestation to an existing entry.

        Args:
            content_hash: SHA-256 hash of the archive
            attester: JIS ID or name of the attester
            verdict: "safe", "suspicious", "malicious", or "unknown"
            notes: Optional evidence/notes
            auth_token: JWT bearer token for authentication

        Returns:
            Attestation result from the mirror.
        """
        headers = {"Content-Type": "application/json"}
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"

        payload = {"attester": attester, "verdict": verdict}
        if notes:
            payload["notes"] = notes

        try:
            resp = requests.post(
                f"{self._base}/attest/{content_hash}",
                json=payload,
                headers=headers,
                timeout=self.timeout,
            )
            resp.raise_for_status()
            return resp.json()
        except requests.HTTPError as e:
            raise MirrorError(f"Attestation failed: {e}")

    def search(self, jis_id: str = None, verdict: str = None,
               signing_key: str = None, limit: int = 50) -> List[Dict[str, Any]]:
        """Search the Transparency Mirror.

        All parameters are optional filters.

        Returns:
            List of matching trust entries.
        """
        params = {}
        if jis_id:
            params["jis_id"] = jis_id
        if verdict:
            params["verdict"] = verdict
        if signing_key:
            params["signing_key"] = signing_key
        params["limit"] = limit

        try:
            resp = requests.get(
                f"{self._base}/search",
                params=params,
                timeout=self.timeout,
            )
            resp.raise_for_status()
            return resp.json().get("results", [])
        except requests.HTTPError as e:
            raise MirrorError(f"Search failed: {e}")

    def stats(self) -> Dict[str, Any]:
        """Get mirror node statistics.

        Returns:
            Dict with node info, entry counts, attestation counts.
        """
        resp = requests.get(f"{self._base}/stats", timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()

    def __repr__(self):
        return f"Mirror(node={self.node_url!r})"
