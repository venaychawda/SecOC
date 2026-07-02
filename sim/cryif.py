"""CryIf — Crypto Interface abstraction layer routing jobs to HSM.

Drop-in stub for AUTOSAR CryIf. Routing layer only — no crypto logic here.
"""
from sim.hsm import HSM


class CryIf:
    """Routes crypto requests from CSM to the registered HSM driver."""

    def __init__(self, hsm: HSM) -> None:
        self._hsm = hsm

    def ecdsa_verify(self, data: bytes, signature: bytes, key_id: str) -> bool:
        """Verify ECDSA signature via HSM.

        Args:
            data: Signed data.
            signature: DER-encoded signature.
            key_id: Key pair identifier.

        Returns:
            True if valid.
        """
        return self._hsm.verify(key_id, data, signature)

    def sha256(self, data: bytes) -> bytes:
        """Compute SHA-256 via HSM.

        Args:
            data: Input bytes.

        Returns:
            32-byte digest.
        """
        return self._hsm.sha256(data)

    def aes_gcm_encrypt(self, key_id: str, plaintext: bytes) -> tuple[bytes, bytes, bytes]:
        """AES-GCM encrypt via HSM.

        Args:
            key_id: AES key identifier.
            plaintext: Data to encrypt.

        Returns:
            (ciphertext, nonce, tag).
        """
        return self._hsm.aes_gcm_encrypt(key_id, plaintext)

    def aes_gcm_decrypt(self, key_id: str, ciphertext: bytes, nonce: bytes, tag: bytes) -> bytes:
        """AES-GCM decrypt via HSM.

        Args:
            key_id: AES key identifier.
            ciphertext: Encrypted bytes.
            nonce: 12-byte nonce.
            tag: 16-byte authentication tag.

        Returns:
            Plaintext bytes.
        """
        return self._hsm.aes_gcm_decrypt(key_id, ciphertext, nonce, tag)

    def generate_nonce(self) -> bytes:
        """Generate a random nonce via HSM.

        Returns:
            32 random bytes.
        """
        return self._hsm.generate_nonce()

    def hmac_sha256(self, key_id: str, data: bytes) -> bytes:
        """Compute HMAC-SHA256 via HSM.

        Args:
            key_id: Symmetric key identifier.
            data: Input bytes to authenticate.

        Returns:
            32-byte HMAC-SHA256 digest.
        """
        return self._hsm.hmac_sha256(key_id, data)

    def generate_symmetric_key(self, key_id: str) -> str:
        """Generate a symmetric key via HSM.

        Args:
            key_id: Logical name for the key.

        Returns:
            The key_id.
        """
        return self._hsm.generate_symmetric_key(key_id)
