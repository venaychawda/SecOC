"""PduR-equivalent routing layer between ECUs and the CAN/CAN FD bus (SR-16).

Adapted from design/lld/LLD_pdu_router.md to the flat sim/ package layout and
to the actual primary-path contract already implemented by sim/secoc.py and
sim/sender_ecu.py: transmit() receives an already-secured PDU (SecOC has
already run) and this router's sole Tx-path job is the SR-16 CAN vs. CAN FD
transport selection. Secured I-PDU construction/verification stays entirely
inside sim/secoc.py, matching design/diagrams/seq_primary_happy_path_SecOC.md
(which has no separate router hop on the wire).
"""
from typing import Optional

from sim import logger as secoc_logger
from sim.can_fd_interface import CanFdInterface
from sim.can_interface import CanInterface, PayloadTooLargeError
from sim.config import CAN_FD_MAX_PAYLOAD_BYTES, CAN_MAX_PAYLOAD_BYTES

_log = secoc_logger.get_logger(__name__)

__all__ = ["PduRouter", "PayloadTooLargeError"]


class PduRouter:
    """Routes already-secured PDUs to the CAN/CAN FD bus and dispatches inbound frames.

    Attributes:
        ecu_id: Identifier of the owning ECU.
        can_if: Classic CAN transport adapter (8-byte payload).
        can_fd_if: CAN FD transport adapter (64-byte payload), or None.
    """

    def __init__(
        self,
        ecu_id: str,
        can_if: CanInterface,
        can_fd_if: Optional[CanFdInterface] = None,
    ) -> None:
        """Initializes the router with its transport references.

        Args:
            ecu_id: Identifier of the owning ECU.
            can_if: Classic CAN interface for this ECU.
            can_fd_if: Optional CAN FD interface for this ECU.
        """
        self.ecu_id = ecu_id
        self.can_if = can_if
        self.can_fd_if = can_fd_if
        self._registered_ecus: dict[str, object] = {}

    def register_ecu(self, ecu_id: str, ecu: object) -> None:
        """Registers an ECU (SenderECU/ReceiverECU) with this router.

        Args:
            ecu_id: Identifier of the ECU to register.
            ecu: The ECU instance (any object exposing on_frame_received()).
        """
        self._registered_ecus[ecu_id] = ecu

    def deregister_ecu(self, ecu_id: str) -> None:
        """Removes a previously registered ECU.

        Args:
            ecu_id: Identifier of the ECU to deregister.
        """
        self._registered_ecus.pop(ecu_id, None)

    def is_registered(self, ecu_id: str) -> bool:
        """Returns True if ecu_id is currently registered.

        Args:
            ecu_id: Identifier to check.

        Returns:
            True if registered.
        """
        return ecu_id in self._registered_ecus

    async def transmit(self, pdu_id: int, secured_pdu: bytes) -> None:
        """Entry point for an already-secured outbound Secured I-PDU.

        Args:
            pdu_id: Identifier of the Secured I-PDU being transmitted.
            secured_pdu: Fully-constructed Secured I-PDU bytes from secoc.py.

        Raises:
            PayloadTooLargeError: Propagated from route_to_bus().
        """
        await self.route_to_bus(pdu_id, secured_pdu)

    async def route_to_bus(self, pdu_id: int, secured_pdu: bytes) -> None:
        """Selects a transport and transmits a Secured I-PDU onto the bus.

        Implements the CAN vs. CAN FD selection algorithm (SR-16): if
        len(secured_pdu) <= CAN_MAX_PAYLOAD_BYTES, uses can_if; otherwise, if
        it fits within CAN_FD_MAX_PAYLOAD_BYTES and can_fd_if is configured,
        uses can_fd_if.

        Args:
            pdu_id: Identifier of the Secured I-PDU.
            secured_pdu: Fully-constructed Secured I-PDU bytes.

        Raises:
            PayloadTooLargeError: If secured_pdu exceeds CAN_MAX_PAYLOAD_BYTES
                and no can_fd_if is configured, or exceeds
                CAN_FD_MAX_PAYLOAD_BYTES even with CAN FD available.
        """
        size = len(secured_pdu)
        if size <= CAN_MAX_PAYLOAD_BYTES:
            await self.can_if.send_frame(pdu_id, secured_pdu)
            return
        if self.can_fd_if is not None and size <= CAN_FD_MAX_PAYLOAD_BYTES:
            await self.can_fd_if.send_frame(pdu_id, secured_pdu)
            return
        if self.can_fd_if is None:
            raise PayloadTooLargeError(
                f"secured_pdu size {size} > {CAN_MAX_PAYLOAD_BYTES} and no "
                f"CAN FD interface configured for ecu {self.ecu_id}"
            )
        raise PayloadTooLargeError(
            f"secured_pdu size {size} exceeds CAN FD capacity "
            f"({CAN_FD_MAX_PAYLOAD_BYTES})"
        )

    def route_from_bus(self, pdu_id: int, secured_pdu: bytes) -> bool:
        """Delivers a Secured I-PDU received from the bus to its registered ECU.

        Args:
            pdu_id: Identifier of the Secured I-PDU.
            secured_pdu: Raw Secured I-PDU bytes as received from the bus.

        Returns:
            True if a registered ECU handled the frame, False if no ECU is
            registered for this router (dropped).
        """
        ecu = self._registered_ecus.get(self.ecu_id)
        if ecu is None:
            _log.info("router %s: no registered ECU, dropping pdu_id=%s", self.ecu_id, pdu_id)
            return False
        ecu.on_frame_received(pdu_id, secured_pdu)
        return True

    def get_status(self) -> dict:
        """Returns a snapshot of router configuration for the dashboard.

        Returns:
            Dict with ecu_id, has_can_fd, and transports status.
        """
        return {
            "ecu_id": self.ecu_id,
            "has_can_fd": self.can_fd_if is not None,
            "transports": {
                "CLASSIC_CAN": self.can_if.get_status(),
                "CAN_FD": self.can_fd_if.get_status() if self.can_fd_if else None,
            },
        }
