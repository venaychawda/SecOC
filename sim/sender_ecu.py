"""Concrete ECU that transmits Secured I-PDUs (SW-SecOC-01, SR-03, SR-06)."""
from typing import Callable

from sim import logger as secoc_logger
from sim.ecu_base import ECUBase
from sim.ecu_state import EcuState, EcuStateValue

_log = secoc_logger.get_logger(__name__)


class SenderECUError(Exception):
    """Raised for SenderECU configuration/usage errors."""


class SenderECU(ECUBase):
    """Concrete ECU that originates Authentic I-PDUs and transmits them as
    Secured I-PDUs (SW-SecOC-01).

    Attributes:
        managed_pdu_ids: PDU IDs this ECU is authorized to transmit.
        tx_count: Per-pdu_id count of successful transmissions.
    """

    def __init__(
        self,
        ecu_id: str,
        secoc,
        pdu_router,
        ecu_state: EcuState,
        managed_pdu_ids: tuple[str, ...],
    ) -> None:
        """Initializes the sending ECU.

        Args:
            ecu_id: Unique identifier of this ECU.
            secoc: SecOC orchestrator instance bound to this ECU.
            pdu_router: Shared PduRouter for Secured I-PDU transport.
            ecu_state: Shared ECUState instance for this ECU's lifecycle state.
            managed_pdu_ids: PDU IDs this ECU is authorized to transmit.
        """
        super().__init__(ecu_id, secoc, pdu_router, ecu_state)
        self.managed_pdu_ids = tuple(managed_pdu_ids)
        self.tx_count: dict[str, int] = {pdu_id: 0 for pdu_id in self.managed_pdu_ids}

    async def send_signal(self, pdu_id: str, authentic_pdu: bytes) -> bool:
        """Transmits an Authentic I-PDU as a Secured I-PDU on the bus.

        Args:
            pdu_id: Identifier of the Secured I-PDU to transmit. Must be a
                member of managed_pdu_ids.
            authentic_pdu: Raw application payload bytes (pre-securing).

        Returns:
            True if transmitted; False if suppressed because the ECU is not
            in NORMAL_OPERATION (e.g. SECURITY_VIOLATION_LOCKOUT, SR-14).

        Raises:
            SenderECUError: If pdu_id is not in managed_pdu_ids.
        """
        if pdu_id not in self.managed_pdu_ids:
            raise SenderECUError(f"unmanaged_pdu_id: {pdu_id}")
        if self.state != EcuStateValue.NORMAL_OPERATION:
            _log.info(
                "%s: send_signal(%s) suppressed, state=%s", self.ecu_id, pdu_id, self.state
            )
            return False
        secured_pdu = self.secoc.transmit_secured(pdu_id, authentic_pdu)
        await self.pdu_router.transmit(pdu_id, secured_pdu)
        self.tx_count[pdu_id] = self.tx_count.get(pdu_id, 0) + 1
        return True

    async def transmit_periodic(
        self, pdu_id: str, authentic_pdu_provider: Callable[[], bytes]
    ) -> None:
        """Per-tick handler for periodic transmission of pdu_id.

        Intended to be invoked by a BusScheduler callback on each period:
        obtains the current payload from authentic_pdu_provider() and sends it.

        Args:
            pdu_id: Identifier of the Secured I-PDU to transmit. Must be a
                member of managed_pdu_ids.
            authentic_pdu_provider: Zero-argument callable returning the
                current Authentic I-PDU payload bytes for this cycle.

        Raises:
            SenderECUError: If pdu_id is not in managed_pdu_ids.
        """
        if pdu_id not in self.managed_pdu_ids:
            raise SenderECUError(f"unmanaged_pdu_id: {pdu_id}")
        await self.send_signal(pdu_id, authentic_pdu_provider())

    def on_frame_received(self, pdu_id: str, secured_pdu: bytes) -> None:
        """No-op for a sender-only ECU.

        Args:
            pdu_id: Identifier of the Secured I-PDU received.
            secured_pdu: Raw bytes of the Secured I-PDU as delivered by the bus.
        """

    def get_status(self) -> dict:
        """Returns a snapshot including the base ECU status plus Tx counters.

        Returns:
            A dict extending ECUBase.get_status() with tx_count and
            managed_pdu_ids.
        """
        status = super().get_status()
        status["tx_count"] = dict(self.tx_count)
        status["managed_pdu_ids"] = list(self.managed_pdu_ids)
        return status
