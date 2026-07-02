"""Central ECU state machine shared by all SecOC modules."""
from enum import Enum


class EcuStateValue(str, Enum):
    """ECU operating states (SecOC-relevant subset)."""

    NORMAL_OPERATION = "NORMAL_OPERATION"
    SECURITY_VIOLATION_LOCKOUT = "SECURITY_VIOLATION_LOCKOUT"
    BOOT_BLOCKED = "BOOT_BLOCKED"


class EcuState:
    """Holds the current ECU state, shared by reference across modules."""

    def __init__(self) -> None:
        self.current_state: EcuStateValue = EcuStateValue.NORMAL_OPERATION

    def transition(self, new_state: EcuStateValue) -> None:
        """Transition the ECU to a new state.

        Args:
            new_state: Target state.
        """
        self.current_state = new_state
