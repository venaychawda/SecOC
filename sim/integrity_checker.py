"""Computes and verifies firmware/config/key-metadata hashes (SR-19)."""
from sim.cryif import CryIf


class IntegrityChecker:
    """Computes SHA-256 hashes over firmware snapshots via the HSM."""

    def __init__(self, cryif: CryIf) -> None:
        self._cryif = cryif

    def compute_hash(self, data: bytes) -> bytes:
        """Compute the SHA-256 hash of data via the HSM.

        Args:
            data: Snapshot bytes to hash.

        Returns:
            32-byte SHA-256 digest.
        """
        return self._cryif.sha256(data)

    def verify_integrity(self, data: bytes, golden_hash: bytes) -> bool:
        """Verify that data hashes to the expected golden value.

        Args:
            data: Snapshot bytes to verify.
            golden_hash: Expected SHA-256 digest.

        Returns:
            True if the computed hash matches golden_hash.
        """
        return self.compute_hash(data) == golden_hash
