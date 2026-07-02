"""Classic CAN transport abstraction over the simulated CanBus (SR-16)."""
import asyncio

from sim.can_bus import CanBus
from sim.config import CAN_MAX_PAYLOAD_BYTES


class PayloadTooLargeError(Exception):
    """Raised when a frame payload exceeds the transport's max size."""


class CanInterface:
    """Classic CAN (<=8 byte payload) transport over a shared CanBus."""

    TRANSPORT = "CLASSIC_CAN"
    MAX_PAYLOAD_BYTES = CAN_MAX_PAYLOAD_BYTES

    def __init__(self, ecu_id: str, bus: CanBus) -> None:
        self._ecu_id = ecu_id
        self._bus = bus

    def get_status(self) -> dict:
        """Return the interface's transport metadata.

        Returns:
            Dict with "transport", "ecu_id", and "max_payload_bytes".
        """
        return {
            "transport": self.TRANSPORT,
            "ecu_id": self._ecu_id,
            "max_payload_bytes": self.MAX_PAYLOAD_BYTES,
        }

    async def send_frame(self, pdu_id, data: bytes) -> None:
        """Send a frame onto the bus, enforcing the transport's payload limit.

        Args:
            pdu_id: Logical or numeric PDU identifier.
            data: Frame payload bytes.

        Raises:
            PayloadTooLargeError: If len(data) exceeds MAX_PAYLOAD_BYTES.
        """
        if len(data) > self.MAX_PAYLOAD_BYTES:
            raise PayloadTooLargeError(
                f"{self.TRANSPORT}: payload of {len(data)} bytes exceeds "
                f"{self.MAX_PAYLOAD_BYTES}-byte limit"
            )
        self._bus.publish(pdu_id, data)

    async def receive_frame(self):
        """Receive the next queued frame from the bus.

        Returns:
            (pdu_id, data) tuple, or None if the queue is empty.
        """
        frame = self._bus.consume()
        if frame is None:
            await asyncio.sleep(0)
            frame = self._bus.consume()
        return frame
