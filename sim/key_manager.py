"""KeyManager -- provisioning, resolution, and rotation of logical keys.

Application-layer code interacts with keys only through this module's
logical key_id strings; raw key material never crosses this boundary
(SR-08, SR-09, SW-SecOC-10).
"""
from sim.cryif import CryIf
from sim.key_storage import KeyLifecycleState, KeyMetadata, KeyStorage

__all__ = ["KeyManager", "KeyMetadata", "KeyLifecycleState"]


class KeyManager:
    """Provisions, resolves, and rotates logical keys for SecOC PDUs."""

    def __init__(self, key_storage: KeyStorage, cryif: CryIf) -> None:
        self._key_storage = key_storage
        self._cryif = cryif

    def provision_key(self, pdu_id: str, key_id: str) -> KeyMetadata:
        """Provision the initial (version 1) ACTIVE key for pdu_id.

        Args:
            pdu_id: Logical PDU identifier.
            key_id: Logical key identifier.

        Returns:
            The newly provisioned KeyMetadata.
        """
        self._cryif.generate_symmetric_key(key_id)
        metadata = KeyMetadata(
            pdu_id=pdu_id,
            key_id=key_id,
            version=1,
            lifecycle_state=KeyLifecycleState.ACTIVE,
        )
        self._key_storage.save_key_metadata(metadata)
        return metadata

    def resolve_key(self, pdu_id: str) -> str:
        """Return the logical key_id of the ACTIVE key for pdu_id.

        Args:
            pdu_id: Logical PDU identifier.

        Returns:
            The active key_id string.

        Raises:
            KeyError: If pdu_id has no provisioned key.
        """
        metadata = self._key_storage.get_key_metadata(pdu_id)
        if metadata is None:
            raise KeyError(f"no key provisioned for pdu_id '{pdu_id}'")
        return metadata.key_id

    def rotate_key(self, pdu_id: str, new_key_id: str) -> KeyMetadata:
        """Rotate to a new ACTIVE key, retiring the previous one (SR-17).

        Args:
            pdu_id: Logical PDU identifier.
            new_key_id: Logical key identifier for the new key version.

        Returns:
            The newly provisioned, ACTIVE KeyMetadata.

        Raises:
            KeyError: If pdu_id has no existing provisioned key.
        """
        current = self._key_storage.get_key_metadata(pdu_id)
        if current is None:
            raise KeyError(f"no key provisioned for pdu_id '{pdu_id}'")

        self._cryif.generate_symmetric_key(new_key_id)
        new_metadata = KeyMetadata(
            pdu_id=pdu_id,
            key_id=new_key_id,
            version=current.version + 1,
            lifecycle_state=KeyLifecycleState.ACTIVE,
        )
        self._key_storage.save_key_metadata(new_metadata)
        return new_metadata
