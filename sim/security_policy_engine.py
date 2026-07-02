"""Evaluates fault state against escalation policy and drives ECU lockout."""
from sim.config import MAX_AUTH_FAILURES
from sim.dem import Severity
from sim.ecu_state import EcuState, EcuStateValue
from sim.event_logger import EventLogger


class SecurityPolicyEngine:
    """Transitions the ECU into SECURITY_VIOLATION_LOCKOUT on repeated failures."""

    def __init__(self, ecu_state: EcuState, event_logger: EventLogger) -> None:
        self._ecu_state = ecu_state
        self._event_logger = event_logger
        self._locked_out = False

    def evaluate(self, failure_count: int) -> None:
        """Evaluate the current failure count against the lockout threshold.

        Args:
            failure_count: Current consecutive AUTH-category failure count.
        """
        if self._locked_out:
            return
        if failure_count >= MAX_AUTH_FAILURES:
            self._locked_out = True
            self._ecu_state.transition(EcuStateValue.SECURITY_VIOLATION_LOCKOUT)
            self._event_logger.log(Severity.CRITICAL, "SAFE_STATE_ENTERED", swr_ref="SR-14")

    def is_locked_out(self) -> bool:
        """Return True if the ECU is in SECURITY_VIOLATION_LOCKOUT.

        Returns:
            True if locked out.
        """
        return self._locked_out

    def reset(self) -> None:
        """Clear lockout and return the ECU to NORMAL_OPERATION (SR-14 recovery).

        Used by ECUBase.on_reset() to recover from SECURITY_VIOLATION_LOCKOUT.
        """
        self._locked_out = False
        self._ecu_state.transition(EcuStateValue.NORMAL_OPERATION)
