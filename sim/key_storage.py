"""Persistent storage of key metadata (never raw key material) (SR-08, SR-09)."""
from dataclasses import asdict, dataclass
from enum import Enum

from sim.nvm import NvM


class KeyLifecycleState(str, Enum):
    """Lifecycle state of a logical key."""

    ACTIVE = "ACTIVE"
    RETIRED = "RETIRED"


@dataclass
class KeyMetadata:
    """Metadata describing a logical key. Never contains raw key bytes."""

    pdu_id: str
    key_id: str
    version: int
    lifecycle_state: KeyLifecycleState


class KeyStorage:
    """Persists KeyMetadata records to NvM, keyed by pdu_id."""

    def __init__(self, nvm: NvM) -> None:
        self._nvm = nvm

    def _nvm_key(self, pdu_id: str) -> str:
        return f"key_meta_{pdu_id}"

    def save_key_metadata(self, metadata: KeyMetadata) -> None:
        """Persist key metadata for a PDU.

        Args:
            metadata: KeyMetadata to persist.
        """
        record = asdict(metadata)
        record["lifecycle_state"] = metadata.lifecycle_state.value
        self._nvm.write(self._nvm_key(metadata.pdu_id), record)

    def get_key_metadata(self, pdu_id: str) -> KeyMetadata | None:
        """Return the persisted key metadata for pdu_id, or None.

        Args:
            pdu_id: Logical PDU identifier.

        Returns:
            KeyMetadata if provisioned, else None.
        """
        record = self._nvm.read(self._nvm_key(pdu_id))
        if record is None:
            return None
        return KeyMetadata(
            pdu_id=record["pdu_id"],
            key_id=record["key_id"],
            version=record["version"],
            lifecycle_state=KeyLifecycleState(record["lifecycle_state"]),
        )
