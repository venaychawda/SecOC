"""HMAC-SHA256-based CryptoInterface implementation, routed through CSM."""
import hmac

from sim.crypto_interface import CryptoInterface
from sim.csm import CSM


class HmacCrypto(CryptoInterface):
    """CryptoInterface implementation backed by CSM.compute_mac (HMAC-SHA256)."""

    def __init__(self, csm: CSM) -> None:
        self._csm = csm

    def generate_mac(self, key_id: str, data: bytes) -> bytes:
        """Generate the full HMAC-SHA256 digest over data.

        Args:
            key_id: Symmetric key identifier.
            data: Protected-region bytes.

        Returns:
            32-byte HMAC-SHA256 digest.
        """
        return self._csm.compute_mac(key_id, data)

    def verify_mac(self, key_id: str, data: bytes, mac: bytes) -> bool:
        """Verify mac (full or truncated) against the recomputed digest.

        Args:
            key_id: Symmetric key identifier.
            data: Protected-region bytes.
            mac: MAC bytes to verify (full 32 bytes or a truncated prefix).

        Returns:
            True if mac matches the corresponding prefix of the recomputed
            digest.
        """
        expected = self.generate_mac(key_id, data)
        return hmac.compare_digest(expected[: len(mac)], mac)
