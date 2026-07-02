"""CSM — Crypto Service Manager with job state machine.

Drop-in stub for AUTOSAR CSM. Dispatches crypto jobs to CryIf;
manages IDLE → ACTIVE → FINISHED / FAILED state machine.
"""
from enum import Enum

from sim.cryif import CryIf


class CSMState(str, Enum):
    IDLE = "IDLE"
    ACTIVE = "ACTIVE"
    FINISHED = "FINISHED"
    FAILED = "FAILED"


class CSMError(Exception):
    pass


class CSM:
    """Dispatches crypto jobs to CryIf; manages IDLE→ACTIVE→FINISHED/FAILED state."""

    def __init__(self, cryif: CryIf) -> None:
        self._cryif = cryif
        self._state = CSMState.IDLE
        self._hash_contexts: dict[str, list[bytes]] = {}

    def verify_signature(self, data: bytes, signature: bytes, key_id: str) -> bool:
        """Verify an ECDSA signature.

        Args:
            data: Data that was signed.
            signature: DER-encoded signature bytes.
            key_id: Key pair identifier in HSM.

        Returns:
            True if signature is valid.

        Raises:
            CSMError: On underlying crypto failure.
        """
        self._state = CSMState.ACTIVE
        try:
            result = self._cryif.ecdsa_verify(data, signature, key_id)
            self._state = CSMState.FINISHED
            return result
        except Exception as exc:
            self._state = CSMState.FAILED
            raise CSMError("job_failed") from exc

    def compute_hash(self, data: bytes) -> bytes:
        """Compute SHA-256 of data.

        Args:
            data: Input bytes.

        Returns:
            32-byte digest.

        Raises:
            CSMError: On underlying crypto failure.
        """
        self._state = CSMState.ACTIVE
        try:
            result = self._cryif.sha256(data)
            self._state = CSMState.FINISHED
            return result
        except Exception as exc:
            self._state = CSMState.FAILED
            raise CSMError("job_failed") from exc

    def hash_update(self, ctx_id: str, chunk: bytes) -> None:
        """Accumulate a chunk into a streaming hash context.

        Args:
            ctx_id: Hash context identifier.
            chunk: Data chunk to add.
        """
        if ctx_id not in self._hash_contexts:
            self._hash_contexts[ctx_id] = []
        self._hash_contexts[ctx_id].append(chunk)

    def hash_finish(self, ctx_id: str) -> bytes:
        """Finalise streaming hash and return digest.

        Args:
            ctx_id: Hash context identifier.

        Returns:
            SHA-256 digest of all accumulated chunks.

        Raises:
            CSMError: If context unknown.
        """
        if ctx_id not in self._hash_contexts:
            raise CSMError("no_context")
        accumulated = b"".join(self._hash_contexts.pop(ctx_id))
        return self._cryif.sha256(accumulated)

    def compute_mac(self, key_id: str, data: bytes) -> bytes:
        """Compute an HMAC-SHA256 MAC over data using key_id.

        Args:
            key_id: Symmetric key identifier.
            data: Input bytes to authenticate.

        Returns:
            32-byte HMAC-SHA256 digest.

        Raises:
            CSMError: On underlying crypto failure.
        """
        self._state = CSMState.ACTIVE
        try:
            result = self._cryif.hmac_sha256(key_id, data)
            self._state = CSMState.FINISHED
            return result
        except Exception as exc:
            self._state = CSMState.FAILED
            raise CSMError("job_failed") from exc

    def wrap_key(self, key_id: str, plaintext: bytes) -> bytes:
        """AES-GCM wrap a key blob.

        Args:
            key_id: Wrapping key identifier.
            plaintext: Key material to wrap.

        Returns:
            Wrapped key bytes (ciphertext || nonce || tag).

        Raises:
            CSMError: On failure.
        """
        self._state = CSMState.ACTIVE
        try:
            ct, nonce, tag = self._cryif.aes_gcm_encrypt(key_id, plaintext)
            self._state = CSMState.FINISHED
            return ct + nonce + tag
        except Exception as exc:
            self._state = CSMState.FAILED
            raise CSMError("job_failed") from exc
