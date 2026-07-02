"""Generic byte-level (de)serialization helpers for PDU payloads."""


class Serialization:
    """Pass-through serializer for raw byte payloads.

    Provided as the pluggable `serializer` collaborator for PduManager.
    Phase 1 PDUs are already raw bytes, so encode/decode are identity
    operations; future signal-based payloads can extend this class.
    """

    def encode(self, payload: bytes) -> bytes:
        """Encode a payload to wire bytes.

        Args:
            payload: Raw payload bytes.

        Returns:
            Encoded bytes (identity for Phase 1).
        """
        return bytes(payload)

    def decode(self, raw: bytes) -> bytes:
        """Decode wire bytes to a payload.

        Args:
            raw: Raw wire bytes.

        Returns:
            Decoded bytes (identity for Phase 1).
        """
        return bytes(raw)
