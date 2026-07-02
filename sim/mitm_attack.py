"""Man-in-the-middle attack: intercept and tamper a frame in transit (SR-02)."""
from dataclasses import dataclass

from sim.can_bus import CanBus
from sim.message_frame import MessageFrame
from sim.message_injector import MessageInjector


@dataclass
class TamperedFrame:
    """A MessageFrame after MitmAttack interception."""

    pdu_id: str
    original_raw_bytes: bytes
    tampered_raw_bytes: bytes
    timestamp: float


class MitmAttack:
    """Intercepts a frame and flips bits in its authentic_pdu region."""

    def __init__(self, can_bus: CanBus, injector: MessageInjector,
                 bit_flip_mask: int = 0x01) -> None:
        self._can_bus = can_bus
        self._injector = injector
        self._bit_flip_mask = bit_flip_mask

    def intercept(self, frame: MessageFrame) -> TamperedFrame:
        """Flip a bit in the first byte of frame.data (SR-02 payload tamper).

        Args:
            frame: The intercepted MessageFrame.

        Returns:
            TamperedFrame with original and tampered raw bytes.
        """
        original = bytes(frame.data)
        tampered = bytearray(original)
        if tampered:
            tampered[0] ^= self._bit_flip_mask
        return TamperedFrame(
            pdu_id=frame.pdu_id,
            original_raw_bytes=original,
            tampered_raw_bytes=bytes(tampered),
            timestamp=frame.timestamp,
        )

    def forward(self, tampered_frame: TamperedFrame) -> None:
        """Forward the tampered frame onto the bus.

        Args:
            tampered_frame: TamperedFrame produced by intercept().
        """
        self._injector.inject(tampered_frame.pdu_id, tampered_frame.tampered_raw_bytes)
