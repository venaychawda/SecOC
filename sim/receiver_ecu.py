"""Concrete ECU that verifies and consumes Secured I-PDUs (SW-SecOC-02).

Adapted from design/lld/LLD_receiver_ecu.md to the real sim/secoc.py contract:
SecOC.receive_secured() returns None on verification failure (it does not
raise SecOCVerificationError). Rejection/DEM logging already happens inside
secoc.py before it returns; this module never logs to DEM itself.
"""
from typing import Callable

from sim import logger as secoc_logger
from sim.ecu_base import ECUBase
from sim.ecu_state import EcuState, EcuStateValue

_log = secoc_logger.get_logger(__name__)

SignalHandler = Callable[[str, bytes], None]


class ReceiverECUError(Exception):
    """Raised for ReceiverECU configuration/usage errors."""


class ReceiverECU(ECUBase):
    """Concrete ECU that receives, verifies, and consumes Secured I-PDUs
    (SW-SecOC-02).

    Attributes:
        managed_pdu_ids: PDU IDs this ECU is registered to receive.
        signal_handlers: pdu_id -> application callback, invoked on success.
        rx_accepted_count: Per-pdu_id count of successful verifications.
        rx_rejected_count: Per-pdu_id count of dropped/rejected frames.
    """

    def __init__(
        self,
        ecu_id: str,
        secoc,
        pdu_router,
        ecu_state: EcuState,
        managed_pdu_ids: tuple[str, ...],
    ) -> None:
        """Initializes the receiving ECU.

        Args:
            ecu_id: Unique identifier of this ECU.
            secoc: SecOC orchestrator instance bound to this ECU.
            pdu_router: Shared PduRouter from which Secured I-PDUs are delivered.
            ecu_state: Shared ECUState instance for this ECU's lifecycle state.
            managed_pdu_ids: PDU IDs this ECU is registered to receive.
        """
        super().__init__(ecu_id, secoc, pdu_router, ecu_state)
        self.managed_pdu_ids = tuple(managed_pdu_ids)
        self.signal_handlers: dict[str, SignalHandler] = {}
        self.rx_accepted_count: dict[str, int] = {pdu_id: 0 for pdu_id in self.managed_pdu_ids}
        self.rx_rejected_count: dict[str, int] = {pdu_id: 0 for pdu_id in self.managed_pdu_ids}

    def register_signal_handler(self, pdu_id: str, handler: SignalHandler) -> None:
        """Registers the application-level callback invoked on successful verification.

        Args:
            pdu_id: Identifier of the Secured I-PDU for which handler should
                be invoked once secoc.receive_secured() succeeds.
            handler: Callable (pdu_id, authentic_pdu) -> None.

        Raises:
            ReceiverECUError: If pdu_id is not in managed_pdu_ids.
        """
        if pdu_id not in self.managed_pdu_ids:
            raise ReceiverECUError(f"unmanaged_pdu_id: {pdu_id}")
        self.signal_handlers[pdu_id] = handler

    def on_frame_received(self, pdu_id: str, secured_pdu: bytes) -> bool:
        """Handles an inbound Secured I-PDU delivered by pdu_router.

        Calls secoc.receive_secured(pdu_id, secured_pdu). On success, invokes
        the registered signal handler (if any) for pdu_id. On failure
        (freshness rejection, MAC mismatch, malformed PDU, unmanaged pdu_id,
        or ECU not in NORMAL_OPERATION), the frame is dropped without any
        application-level callback.

        Args:
            pdu_id: Identifier of the Secured I-PDU received.
            secured_pdu: Raw bytes of the Secured I-PDU as delivered by the bus.

        Returns:
            True if the frame was successfully verified and (if a handler is
            registered) delivered; False if the frame was dropped.
        """
        if pdu_id not in self.managed_pdu_ids:
            return False
        if self.state != EcuStateValue.NORMAL_OPERATION:
            self.rx_rejected_count[pdu_id] = self.rx_rejected_count.get(pdu_id, 0) + 1
            _log.info(
                "%s: frame for %s dropped, state=%s", self.ecu_id, pdu_id, self.state
            )
            return False

        authentic_pdu = self.secoc.receive_secured(pdu_id, secured_pdu)
        if authentic_pdu is None:
            self.rx_rejected_count[pdu_id] = self.rx_rejected_count.get(pdu_id, 0) + 1
            return False

        self.rx_accepted_count[pdu_id] = self.rx_accepted_count.get(pdu_id, 0) + 1
        handler = self.signal_handlers.get(pdu_id)
        if handler is not None:
            handler(pdu_id, authentic_pdu)
        return True

    def get_status(self) -> dict:
        """Returns a snapshot including the base ECU status plus Rx counters.

        Returns:
            A dict extending ECUBase.get_status() with rx_accepted_count,
            rx_rejected_count, and managed_pdu_ids.
        """
        status = super().get_status()
        status["rx_accepted_count"] = dict(self.rx_accepted_count)
        status["rx_rejected_count"] = dict(self.rx_rejected_count)
        status["managed_pdu_ids"] = list(self.managed_pdu_ids)
        return status
