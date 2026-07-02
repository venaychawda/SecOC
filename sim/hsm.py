"""HSM simulator — ECDSA P-256, SHA-256, AES-256-GCM.

Key bytes never leave this module.
Drop-in stub for AUTOSAR CryptoDriver / HSM simulation.
"""
import hashlib
import hmac
import os
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class HSMError(Exception):
    pass


class HSM:
    """Simulates an HSM: key generation, ECDSA signing/verification, AES-GCM, SHA-256."""

    def __init__(self) -> None:
        self._key_store: dict[str, Any] = {}
        self._fail_mode: bool = False

    def _check_fail(self) -> None:
        if self._fail_mode:
            raise HSMError("unavailable")

    def generate_key_pair(self, key_id: str) -> str:
        """Generate an ECDSA P-256 key pair and store internally.

        Args:
            key_id: Logical name for the key pair.

        Returns:
            The key_id.
        """
        self._check_fail()
        private_key = ec.generate_private_key(ec.SECP256R1())
        self._key_store[key_id] = private_key
        return key_id

    def get_public_key_pem(self, key_id: str) -> bytes:
        """Return PEM-encoded public key for the given key_id.

        Args:
            key_id: Key pair identifier.

        Returns:
            PEM bytes of the public key.

        Raises:
            HSMError: If key_id not found.
        """
        self._check_fail()
        key = self._key_store.get(key_id)
        if key is None:
            raise HSMError("unknown_key")
        return key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def sign(self, key_id: str, data: bytes) -> bytes:
        """Sign data with the private key identified by key_id.

        Args:
            key_id: Signing key identifier.
            data: Raw bytes to sign.

        Returns:
            DER-encoded ECDSA signature.

        Raises:
            HSMError: If unavailable or key unknown.
        """
        self._check_fail()
        key = self._key_store.get(key_id)
        if key is None:
            raise HSMError("unknown_key")
        return key.sign(data, ec.ECDSA(hashes.SHA256()))

    def verify(self, key_id: str, data: bytes, signature: bytes) -> bool:
        """Verify an ECDSA signature against data using the public key.

        Args:
            key_id: Key pair whose public key to use.
            data: Original signed data.
            signature: DER-encoded ECDSA signature.

        Returns:
            True if valid, False otherwise.

        Raises:
            HSMError: If unavailable or key unknown.
        """
        self._check_fail()
        key = self._key_store.get(key_id)
        if key is None:
            raise HSMError("unknown_key")
        try:
            key.public_key().verify(signature, data, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False

    def sha256(self, data: bytes) -> bytes:
        """Compute SHA-256 hash.

        Args:
            data: Input bytes.

        Returns:
            32-byte hash digest.
        """
        self._check_fail()
        digest = hashes.Hash(hashes.SHA256())
        digest.update(data)
        return digest.finalize()

    def aes_gcm_encrypt(self, key_id: str, plaintext: bytes) -> tuple[bytes, bytes, bytes]:
        """AES-256-GCM encrypt.

        Args:
            key_id: AES key identifier (must be a bytes key, not ECDSA).
            plaintext: Data to encrypt.

        Returns:
            (ciphertext, nonce, tag) tuple.
        """
        self._check_fail()
        raw_key = self._key_store.get(key_id)
        if raw_key is None:
            raw_key = AESGCM.generate_key(bit_length=256)
            self._key_store[key_id] = raw_key
        if isinstance(raw_key, ec.EllipticCurvePrivateKey):
            raise HSMError("wrong_key_type")
        nonce = os.urandom(12)
        aesgcm = AESGCM(raw_key)
        ct = aesgcm.encrypt(nonce, plaintext, None)
        ciphertext = ct[:-16]
        tag = ct[-16:]
        return ciphertext, nonce, tag

    def aes_gcm_decrypt(self, key_id: str, ciphertext: bytes, nonce: bytes, tag: bytes) -> bytes:
        """AES-256-GCM decrypt.

        Args:
            key_id: AES key identifier.
            ciphertext: Encrypted bytes.
            nonce: 12-byte nonce used during encryption.
            tag: 16-byte authentication tag.

        Returns:
            Plaintext bytes.

        Raises:
            HSMError: On decryption failure.
        """
        self._check_fail()
        raw_key = self._key_store.get(key_id)
        if raw_key is None or isinstance(raw_key, ec.EllipticCurvePrivateKey):
            raise HSMError("unknown_key")
        aesgcm = AESGCM(raw_key)
        try:
            return aesgcm.decrypt(nonce, ciphertext + tag, None)
        except Exception as exc:
            raise HSMError("decrypt_failed") from exc

    def generate_nonce(self) -> bytes:
        """Generate a cryptographically random nonce.

        Returns:
            32 random bytes.
        """
        self._check_fail()
        return os.urandom(32)

    def generate_symmetric_key(self, key_id: str) -> str:
        """Generate and store a 256-bit symmetric key for HMAC/AES use.

        Args:
            key_id: Logical name for the key.

        Returns:
            The key_id.
        """
        self._check_fail()
        self._key_store[key_id] = os.urandom(32)
        return key_id

    def hmac_sha256(self, key_id: str, data: bytes) -> bytes:
        """Compute HMAC-SHA256 over data using the symmetric key key_id.

        If key_id is not yet provisioned, a new symmetric key is generated
        and stored on first use (mirrors aes_gcm_encrypt's lazy provisioning).

        Args:
            key_id: Symmetric key identifier.
            data: Input bytes to authenticate.

        Returns:
            32-byte HMAC-SHA256 digest.

        Raises:
            HSMError: If unavailable or key_id refers to a non-symmetric key.
        """
        self._check_fail()
        key = self._key_store.get(key_id)
        if key is None:
            key = os.urandom(32)
            self._key_store[key_id] = key
        if isinstance(key, ec.EllipticCurvePrivateKey):
            raise HSMError("wrong_key_type")
        return hmac.new(key, data, hashlib.sha256).digest()

    def simulate_failure(self, fail: bool) -> None:
        """Enable or disable HSM failure simulation for testing.

        Args:
            fail: True to make all subsequent operations raise HSMError.
        """
        self._fail_mode = fail
