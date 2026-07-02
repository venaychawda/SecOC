"""Replay attack: capture and re-inject a previously observed frame (SR-03)."""
from dataclasses import dataclass

from sim.can_bus import CanBus
from sim.message_injector import MessageInjector


@dataclass
class CapturedFrame:
    """A captured Secured I-PDU frame for later replay."""

    pdu_id: str
    raw_bytes: bytes


class ReplayAttack:
    """Captures the most recently observed valid frame for a PDU and replays it."""

    def __init__(self, can_bus: CanBus, injector: MessageInjector) -> None:
        self._can_bus = can_bus
        self._injector = injector
        self._captured: dict = {}

    def capture(self, pdu_id) -> CapturedFrame:
        """Capture the most recently observed valid frame for pdu_id.

        Args:
            pdu_id: Logical PDU identifier.

        Returns:
            CapturedFrame holding the captured raw bytes.
        """
        raw_bytes = self._can_bus.get_last(pdu_id)
        self._captured[pdu_id] = raw_bytes
        return CapturedFrame(pdu_id=pdu_id, raw_bytes=raw_bytes)

    def replay(self, pdu_id) -> None:
        """Re-inject the previously captured frame for pdu_id.

        Args:
            pdu_id: Logical PDU identifier.
        """
        raw_bytes = self._captured.get(pdu_id)
        if raw_bytes is not None:
            self._injector.inject(pdu_id, raw_bytes)
