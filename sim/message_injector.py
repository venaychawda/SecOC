"""Injects raw frames onto the simulated CAN bus (attack-simulation support)."""
from sim.can_bus import CanBus


class MessageInjector:
    """Injects attacker-controlled frames onto a CanBus."""

    def __init__(self, can_bus: CanBus) -> None:
        self._can_bus = can_bus

    def inject(self, pdu_id, data: bytes) -> None:
        """Publish data onto the bus under pdu_id.

        Args:
            pdu_id: Logical or numeric PDU identifier.
            data: Frame payload bytes.
        """
        self._can_bus.publish(pdu_id, data)
