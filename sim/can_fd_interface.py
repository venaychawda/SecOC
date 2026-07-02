"""CAN FD transport abstraction over the simulated CanBus (SR-16)."""
from sim.can_interface import CanInterface
from sim.config import CAN_FD_MAX_PAYLOAD_BYTES


class CanFdInterface(CanInterface):
    """CAN FD (<=64 byte payload) transport over a shared CanBus."""

    TRANSPORT = "CAN_FD"
    MAX_PAYLOAD_BYTES = CAN_FD_MAX_PAYLOAD_BYTES
