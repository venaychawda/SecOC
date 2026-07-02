"""Generic CAN/CAN-FD message frame representation."""
from dataclasses import dataclass


@dataclass
class MessageFrame:
    """A single CAN/CAN-FD frame carrying a (Secured) I-PDU."""

    pdu_id: str
    data: bytes
    timestamp: float
