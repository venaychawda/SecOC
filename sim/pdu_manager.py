"""Builds and parses Secured I-PDUs (authentic_pdu || freshness || mac)."""
from sim.security_profile import Transport
from sim.serialization import Serialization


class PduManager:
    """Builds/parses the SecOC Secured I-PDU wire layout (SR-11, SR-21)."""

    def __init__(self, serializer: Serialization | None = None) -> None:
        self._serializer = serializer or Serialization()

    def build_secured_pdu(self, authentic_pdu: bytes, freshness_value: int,
                           mac: bytes, profile, transport: Transport = Transport.CAN_FD) -> bytes:
        """Build a Secured I-PDU: authentic_pdu || freshness || mac.

        Args:
            authentic_pdu: Authentic I-PDU payload bytes.
            freshness_value: Full (untruncated) freshness counter value.
            mac: Authenticator (MAC) bytes, already truncated to the
                transport's authenticator length.
            profile: SecurityProfileEntry defining the truncation lengths.
            transport: CLASSIC_CAN uses profile.tfv_length/tmac_length;
                CAN_FD (default) uses profile.freshness_length/
                authenticator_length, identical to prior behavior.

        Returns:
            The Secured I-PDU bytes.
        """
        fresh_len, _mac_len = profile.truncation_lengths(transport)
        truncated_freshness = freshness_value % (1 << (fresh_len * 8))
        freshness_bytes = truncated_freshness.to_bytes(fresh_len, "big")
        return self._serializer.encode(authentic_pdu) + freshness_bytes + mac

    def parse_secured_pdu(self, secured_pdu: bytes, profile,
                           transport: Transport = Transport.CAN_FD) -> tuple[bytes, int, bytes]:
        """Parse a Secured I-PDU into (authentic_pdu, freshness_value, mac).

        Args:
            secured_pdu: Secured I-PDU bytes.
            profile: SecurityProfileEntry defining the truncation lengths.
            transport: CLASSIC_CAN uses profile.tfv_length/tmac_length;
                CAN_FD (default) uses profile.freshness_length/
                authenticator_length.

        Returns:
            Tuple of (authentic_pdu, truncated freshness value, mac bytes).

        Raises:
            ValueError: If secured_pdu is too short to contain the
                freshness and authenticator trailer (malformed structure),
                or (CLASSIC_CAN only) the recovered authentic_pdu is not
                exactly 4 bytes.
        """
        fresh_len, mac_len = profile.truncation_lengths(transport)
        trailer_len = fresh_len + mac_len
        if len(secured_pdu) < trailer_len:
            raise ValueError("secured_pdu shorter than freshness+authenticator trailer")

        authentic_pdu = secured_pdu[: -trailer_len] if trailer_len else secured_pdu
        if transport == Transport.CLASSIC_CAN and len(authentic_pdu) != 4:
            raise ValueError(
                f"CLASSIC_CAN secured_pdu authentic_pdu segment must be exactly "
                f"4 bytes, got {len(authentic_pdu)}"
            )
        freshness_bytes = secured_pdu[-trailer_len: len(secured_pdu) - mac_len]
        mac = secured_pdu[-mac_len:] if mac_len else b""
        freshness_value = int.from_bytes(freshness_bytes, "big")

        return self._serializer.decode(authentic_pdu), freshness_value, mac
