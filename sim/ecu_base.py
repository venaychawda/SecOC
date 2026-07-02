"""Abstract base class for all simulated ECUs (Application SWC + RTE wrapper).

Adapted from design/lld/LLD_ecu_base.md to the real sim/ecu_state.py contract
(EcuStateValue: NORMAL_OPERATION / SECURITY_VIOLATION_LOCKOUT / BOOT_BLOCKED)
rather than the LLD's aspirational INIT/RUNNING/DEGRADED/RESET_PENDING/STOPPED
lifecycle -- SecurityPolicyEngine and FaultManager, which own the real state
transitions, only ever use the 3-value enum.
"""
from abc import ABC, abstractmethod

from sim import logger as secoc_logger
from sim.ecu_state import EcuState, EcuStateValue

_log = secoc_logger.get_logger(__name__)


class ECUBaseError(Exception):
    """Raised for invalid ECU lifecycle transitions."""


class ECUBase(ABC):
    """Abstract base class for all simulated ECUs.

    Holds the ECU identity, the per-ECU SecOC orchestrator instance, the
    shared PduRouter reference, and the common lifecycle hooks shared by
    SenderECU and ReceiverECU.

    Attributes:
        ecu_id: Unique identifier of this ECU (e.g. "AirbagECU", "BrakeECU").
        secoc: The SecOC orchestrator instance bound to this ECU.
        pdu_router: Shared PduRouter used to send/receive Secured I-PDUs.
        ecu_state: Shared ECUState reference for this ECU's lifecycle state.
    """

    def __init__(self, ecu_id: str, secoc, pdu_router, ecu_state: EcuState) -> None:
        """Initializes the ECU with its identity and shared infrastructure references.

        Args:
            ecu_id: Unique identifier of this ECU.
            secoc: The SecOC orchestrator instance bound to this ECU.
            pdu_router: Shared PduRouter for Secured I-PDU transport.
            ecu_state: Shared ECUState instance for this ECU's lifecycle state.
        """
        self.ecu_id = ecu_id
        self.secoc = secoc
        self.pdu_router = pdu_router
        self.ecu_state = ecu_state
        self._running = False

    @property
    def state(self) -> EcuStateValue:
        """Returns the current lifecycle state of this ECU.

        Returns:
            The current EcuStateValue, mirrored from ecu_state.
        """
        return self.ecu_state.current_state

    def on_startup(self) -> None:
        """Registers this ECU with pdu_router and marks it started.

        Raises:
            ECUBaseError: If the ECU is already running.
        """
        if self._running:
            raise ECUBaseError("already_running")
        self.pdu_router.register_ecu(self.ecu_id, self)
        self._running = True
        _log.info("%s started", self.ecu_id)

    def on_reset(self) -> None:
        """Recovers the ECU from SECURITY_VIOLATION_LOCKOUT via secoc.reset()
        (SR-14) and (re-)registers it with pdu_router if not already running.
        """
        self.secoc.reset()
        if not self._running:
            self.pdu_router.register_ecu(self.ecu_id, self)
            self._running = True
        _log.info("%s reset", self.ecu_id)

    def shutdown(self) -> None:
        """Deregisters this ECU from pdu_router. Idempotent."""
        self.pdu_router.deregister_ecu(self.ecu_id)
        self._running = False
        _log.info("%s shutdown", self.ecu_id)

    @abstractmethod
    def on_frame_received(self, pdu_id: str, secured_pdu: bytes):
        """Hook invoked by pdu_router when a frame addressed to this ECU arrives.

        Args:
            pdu_id: Identifier of the Secured I-PDU received.
            secured_pdu: Raw bytes of the Secured I-PDU as delivered by the bus.
        """

    def get_status(self) -> dict:
        """Returns a snapshot of this ECU's identity and lifecycle state.

        Returns:
            A dict with keys ecu_id, state, and secoc_status.
        """
        return {
            "ecu_id": self.ecu_id,
            "state": self.state.value,
            "secoc_status": self.secoc.get_status(),
        }
