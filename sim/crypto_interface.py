"""Algorithm-agnostic crypto abstraction for SecOC MAC operations (SR-10)."""
from abc import ABC, abstractmethod


class CryptoInterface(ABC):
    """Abstract MAC generation/verification contract.

    Concrete implementations (e.g. HmacCrypto) bind this contract to a
    specific algorithm without the SecOC core depending on algorithm
    details (SW-SecOC-07, SR-10).
    """

    @abstractmethod
    def generate_mac(self, key_id: str, data: bytes) -> bytes:
        """Generate a MAC over data using key_id.

        Args:
            key_id: Logical key identifier.
            data: Protected-region bytes.

        Returns:
            MAC bytes (algorithm-defined length).
        """
        raise NotImplementedError

    @abstractmethod
    def verify_mac(self, key_id: str, data: bytes, mac: bytes) -> bool:
        """Verify a MAC over data using key_id.

        Args:
            key_id: Logical key identifier.
            data: Protected-region bytes.
            mac: MAC bytes to verify (may be truncated).

        Returns:
            True if mac matches.
        """
        raise NotImplementedError
