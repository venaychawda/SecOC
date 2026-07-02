"""AUTOSAR COM signal <-> Authentic I-PDU (de)serialization layer (SR-11).

Adapted from design/lld/LLD_signal_packager.md: the signal layout table is
passed in explicitly by the caller (this project has no established
signal-layout config file, unlike config/secoc_profiles.json for crypto
profiles), rather than being loaded from disk by __init__. Not wired into the
live SenderECU/ReceiverECU Tx/Rx path -- design/diagrams/seq_primary_happy_path_SecOC.md
has no separate packer hop; SenderECU/ReceiverECU pass authentic_pdu bytes
directly to/from secoc.py. This module stands alone, satisfying SR-11's
pack/unpack round-trip requirement for callers that want signal-level access.
"""
from dataclasses import dataclass
from typing import Any, Callable, Optional


class UnknownSignalError(Exception):
    """Raised for an unrecognized signal_name or a pdu_bytes length mismatch."""


class SignalValueOutOfRangeError(Exception):
    """Raised when a scaled raw value does not fit within its configured bit width."""


@dataclass(frozen=True)
class SignalLayout:
    """Configuration for one application signal's position within a PDU."""

    signal_name: str
    pdu_id: int
    pdu_length_bytes: int
    offset_bits: int
    width_bits: int
    factor: float
    offset: float


def _set_bits(buf: bytearray, offset_bits: int, width_bits: int, raw: int) -> None:
    for i in range(width_bits):
        bit_index = offset_bits + i
        byte_index, bit_in_byte = divmod(bit_index, 8)
        bit_value = (raw >> (width_bits - 1 - i)) & 1
        if bit_value:
            buf[byte_index] |= 1 << (7 - bit_in_byte)
        else:
            buf[byte_index] &= ~(1 << (7 - bit_in_byte))


def _get_bits(data: bytes, offset_bits: int, width_bits: int) -> int:
    raw = 0
    for i in range(width_bits):
        bit_index = offset_bits + i
        byte_index, bit_in_byte = divmod(bit_index, 8)
        bit_value = (data[byte_index] >> (7 - bit_in_byte)) & 1
        raw = (raw << 1) | bit_value
    return raw


class SignalPackager:
    """Maps application-layer signals to/from Authentic I-PDU byte payloads.

    Attributes:
        ecu_id: Identifier of the owning ECU.
    """

    def __init__(self, ecu_id: str, signal_table: dict[str, SignalLayout]) -> None:
        """Initializes the packager with its signal layout table.

        Args:
            ecu_id: Identifier of the owning ECU.
            signal_table: Mapping of signal_name -> SignalLayout.
        """
        self.ecu_id = ecu_id
        self._signal_table = dict(signal_table)
        self._tx_buffers: dict[int, bytearray] = {}
        self._signal_handler: Optional[Callable[[str, Any], None]] = None

    def _get_layout(self, signal_name: str) -> SignalLayout:
        try:
            return self._signal_table[signal_name]
        except KeyError:
            raise UnknownSignalError(signal_name) from None

    def pack_signal(self, signal_name: str, value: Any) -> bytes:
        """Packs a single application-layer signal value into its Authentic I-PDU.

        Args:
            signal_name: Name of the application signal.
            value: The application-layer value to pack.

        Returns:
            The complete Authentic I-PDU byte buffer for signal_name's pdu_id.

        Raises:
            UnknownSignalError: If signal_name is not configured.
            SignalValueOutOfRangeError: If the scaled raw value does not fit
                in the signal's configured bit width.
        """
        layout = self._get_layout(signal_name)
        raw = round((value - layout.offset) / layout.factor)
        if not (0 <= raw < 2**layout.width_bits):
            raise SignalValueOutOfRangeError(
                f"{signal_name}: value {value} (raw {raw}) out of range "
                f"for width {layout.width_bits}"
            )
        buf = self._tx_buffers.setdefault(
            layout.pdu_id, bytearray(layout.pdu_length_bytes)
        )
        _set_bits(buf, layout.offset_bits, layout.width_bits, raw)
        return bytes(buf)

    def unpack_signal(self, pdu_bytes: bytes, signal_name: str) -> Any:
        """Unpacks a single application-layer signal value from an Authentic I-PDU.

        Args:
            pdu_bytes: The verified Authentic I-PDU byte buffer.
            signal_name: Name of the application signal to extract.

        Returns:
            The decoded application-layer value.

        Raises:
            UnknownSignalError: If signal_name is not configured, or
                pdu_bytes length does not match the configured PDU length.
        """
        layout = self._get_layout(signal_name)
        if len(pdu_bytes) != layout.pdu_length_bytes:
            raise UnknownSignalError(
                f"{signal_name}: pdu_bytes length {len(pdu_bytes)} != "
                f"configured {layout.pdu_length_bytes}"
            )
        raw = _get_bits(pdu_bytes, layout.offset_bits, layout.width_bits)
        return raw * layout.factor + layout.offset

    def send_signal(self, signal_name: str, value: Any) -> bytes:
        """Packs value into its Authentic I-PDU and clears the Tx buffer.

        Args:
            signal_name: Name of the application signal to send.
            value: The application-layer value to pack.

        Returns:
            The packed Authentic I-PDU byte buffer, ready for a caller (e.g.
            SenderECU.send_signal()) to transmit via secoc.py.

        Raises:
            UnknownSignalError: If signal_name is not configured.
            SignalValueOutOfRangeError: Propagated from pack_signal().
        """
        authentic_pdu = self.pack_signal(signal_name, value)
        pdu_id = self._get_layout(signal_name).pdu_id
        self._tx_buffers.pop(pdu_id, None)
        return authentic_pdu

    def unpack_signal_from_pdu(self, pdu_id: int, authentic_pdu: bytes) -> None:
        """Decodes every signal mapped to pdu_id and forwards to the registered handler.

        Args:
            pdu_id: Identifier of the verified Secured I-PDU's Authentic I-PDU.
            authentic_pdu: The verified Authentic I-PDU byte buffer.
        """
        for signal_name, layout in self._signal_table.items():
            if layout.pdu_id == pdu_id:
                value = self.unpack_signal(authentic_pdu, signal_name)
                if self._signal_handler is not None:
                    self._signal_handler(signal_name, value)

    def register_signal_handler(self, handler: Callable[[str, Any], None]) -> None:
        """Registers the application-layer callback for decoded signals.

        Args:
            handler: Callable invoked as handler(signal_name, value).
        """
        self._signal_handler = handler

    def get_status(self) -> dict:
        """Returns a snapshot of the signal layout table for the dashboard.

        Returns:
            A dict with ecu_id and signals (list of layout dicts).
        """
        return {
            "ecu_id": self.ecu_id,
            "signals": [
                {
                    "signal_name": layout.signal_name,
                    "pdu_id": layout.pdu_id,
                    "offset_bits": layout.offset_bits,
                    "width_bits": layout.width_bits,
                    "factor": layout.factor,
                    "offset": layout.offset,
                }
                for layout in self._signal_table.values()
            ],
        }
