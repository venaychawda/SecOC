"""SecOC core orchestrator: builds/validates Secured I-PDUs (SR-01..SR-04, SR-14, SR-21)."""
from sim.authenticator import Authenticator
from sim.can_bus import CanBus
from sim.ecu_state import EcuState
from sim.event_logger import EventLogger
from sim.fault_manager import FailureCategory, FaultManager
from sim.freshness_manager import FreshnessManager
from sim.pdu_manager import PduManager
from sim.security_events import RejectionReason
from sim.security_policy_engine import SecurityPolicyEngine
from sim.security_profile import SecurityProfile, Transport

_CLASSIC_CAN_PAYLOAD_BYTES = 4


class SecOCTransportError(Exception):
    """Raised for transport-specific Secured I-PDU construction errors (SR-21).

    E.g. an authentic_pdu longer than 4 bytes supplied for CLASSIC_CAN
    transport, which has no room for it within the 8-byte frame budget.
    """


class SecOC:
    """Top-level SecOC module: transmit/receive Secured I-PDUs (SW-SecOC-01..06)."""

    def __init__(self, profile_provider: SecurityProfile,
                 freshness_manager: FreshnessManager,
                 authenticator: Authenticator,
                 pdu_manager: PduManager,
                 event_logger: EventLogger,
                 ecu_state: EcuState) -> None:
        self._profile_provider = profile_provider
        self._freshness_manager = freshness_manager
        self._authenticator = authenticator
        self._pdu_manager = pdu_manager
        self._event_logger = event_logger
        self._ecu_state = ecu_state
        self._security_policy_engine = SecurityPolicyEngine(
            ecu_state=ecu_state, event_logger=event_logger
        )
        self._fault_manager = FaultManager(
            security_policy_engine=self._security_policy_engine
        )

    def reset(self) -> None:
        """Recover the ECU from SECURITY_VIOLATION_LOCKOUT (SR-14, SW-SecOC-09).

        Used by ECUBase.on_reset() to clear a crypto-failure lockout.
        """
        self._security_policy_engine.reset()

    def get_status(self) -> dict:
        """Return current SecOC/ECU status.

        Returns:
            Dict with "ecu_state" and "locked_out".
        """
        return {
            "ecu_state": self._ecu_state.current_state.value,
            "locked_out": self._security_policy_engine.is_locked_out(),
        }

    def transmit_secured(self, pdu_id: str, authentic_pdu: bytes,
                          transport: Transport = Transport.CAN_FD) -> bytes:
        """Build a Secured I-PDU for transmission (SW-SecOC-01, SR-21).

        Args:
            pdu_id: Logical PDU identifier.
            authentic_pdu: Authentic I-PDU payload bytes. For CLASSIC_CAN,
                must be 0-4 bytes; shorter input is zero-padded (right-pad)
                to exactly 4 bytes.
            transport: CLASSIC_CAN builds the fixed 8-byte TFV/TMAC frame
                (SW-SecOC-11); CAN_FD (default) is the existing variable-
                length scheme, unaffected.

        Returns:
            The Secured I-PDU bytes (authentic_pdu || freshness || mac).

        Raises:
            SecOCTransportError: If transport is CLASSIC_CAN and
                authentic_pdu is longer than 4 bytes.
        """
        profile = self._profile_provider.get_profile(pdu_id)
        if transport == Transport.CLASSIC_CAN:
            if len(authentic_pdu) > _CLASSIC_CAN_PAYLOAD_BYTES:
                raise SecOCTransportError(
                    f"authentic_pdu ({len(authentic_pdu)} bytes) exceeds the "
                    f"{_CLASSIC_CAN_PAYLOAD_BYTES}-byte CLASSIC_CAN payload budget "
                    f"for pdu_id '{pdu_id}'"
                )
            authentic_pdu = authentic_pdu.ljust(_CLASSIC_CAN_PAYLOAD_BYTES, b"\x00")

        freshness_value = self._freshness_manager.load_last_valid_freshness(pdu_id) + 1
        mac = self._authenticator.generate_mac(
            pdu_id, authentic_pdu, freshness_value, transport=transport
        )
        return self._pdu_manager.build_secured_pdu(
            authentic_pdu, freshness_value, mac, profile, transport=transport
        )

    def receive_secured(self, pdu_id: str, secured_pdu: bytes,
                         transport: Transport = Transport.CAN_FD) -> bytes | None:
        """Parse and validate a received Secured I-PDU (SW-SecOC-02..06, SR-21).

        Args:
            pdu_id: Logical PDU identifier.
            secured_pdu: Received Secured I-PDU bytes.
            transport: CLASSIC_CAN parses the fixed 8-byte TFV/TMAC frame;
                CAN_FD (default) is the existing variable-length scheme.

        Returns:
            The authentic_pdu bytes if accepted (4 zero-padded bytes for
            CLASSIC_CAN), otherwise None.
        """
        profile = self._profile_provider.get_profile(pdu_id)

        try:
            authentic_pdu, truncated_freshness, mac = self._pdu_manager.parse_secured_pdu(
                secured_pdu, profile, transport=transport
            )
        except ValueError:
            return self._reject(pdu_id, RejectionReason.MALFORMED_STRUCTURE)

        freshness_ok, full_freshness = self._freshness_manager.validate_freshness(
            pdu_id, truncated_freshness
        )
        if not freshness_ok:
            return self._reject(pdu_id, RejectionReason.FRESHNESS_OUT_OF_WINDOW)

        if not self._authenticator.verify_mac(
            pdu_id, authentic_pdu, full_freshness, mac, transport=transport
        ):
            return self._reject(pdu_id, RejectionReason.MAC_MISMATCH)

        self._freshness_manager.commit_freshness(pdu_id, full_freshness)
        CanBus().publish(pdu_id, secured_pdu)
        return authentic_pdu

    def _reject(self, pdu_id: str, reason: RejectionReason) -> None:
        self._event_logger.log_rejection(pdu_id, reason)
        self._fault_manager.record_failure(pdu_id, FailureCategory.AUTH)
        return None
