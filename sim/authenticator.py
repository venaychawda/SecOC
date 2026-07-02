"""Computes/verifies MAC over the SecOC protected region (SR-06, SR-07, SR-11, SR-12, SR-21)."""
import hmac

from sim.config import MAC_WCET_BUDGET_MS
from sim.crypto_interface import CryptoInterface
from sim.csm import CSM
from sim.cryif import CryIf
from sim.dem import Severity
from sim.hmac_crypto import HmacCrypto
from sim.hsm import HSM
from sim.security_profile import Transport


class _NullProfiler:
    """No-op profiler used when no PerformanceProfiler is supplied."""

    def start(self, operation_id: str) -> None:
        return None

    def stop(self, operation_id: str) -> float:
        return 0.0


class Authenticator:
    """Generates and verifies MACs over authentic_pdu || freshness (SR-11).

    If crypto_interface/key_manager/profiler are not supplied, a
    self-contained HMAC-SHA256 crypto stack and no-op profiler are created
    internally so the Authenticator remains usable in isolation.
    """

    def __init__(self, key_manager, crypto_interface: CryptoInterface | None,
                 profiler, event_logger, profile_provider) -> None:
        self._key_manager = key_manager
        self._crypto_interface = crypto_interface or HmacCrypto(csm=CSM(cryif=CryIf(hsm=HSM())))
        self._profiler = profiler or _NullProfiler()
        self._event_logger = event_logger
        self._profile_provider = profile_provider
        self._op_seq = 0

    def _resolve_key_id(self, pdu_id: str, profile) -> str:
        if self._key_manager is not None:
            return self._key_manager.resolve_key(pdu_id)
        return profile.key_id

    def generate_mac(self, pdu_id: str, authentic_pdu: bytes, freshness_value: int,
                      transport: Transport = Transport.CAN_FD) -> bytes:
        """Generate a truncated MAC over authentic_pdu || freshness (SR-06, SR-11, SR-21).

        Args:
            pdu_id: Logical PDU identifier.
            authentic_pdu: Authentic I-PDU payload bytes.
            freshness_value: Full (untruncated) freshness counter value.
            transport: CLASSIC_CAN uses profile.tfv_length/tmac_length; CAN_FD
                (default) uses profile.freshness_length/authenticator_length,
                identical to prior behavior.

        Returns:
            MAC bytes truncated (MSB) to the transport's authenticator length.
        """
        profile = self._profile_provider.get_profile(pdu_id)
        key_id = self._resolve_key_id(pdu_id, profile)
        fresh_len, mac_len = profile.truncation_lengths(transport)
        truncated_freshness = freshness_value % (1 << (fresh_len * 8))
        data = authentic_pdu + truncated_freshness.to_bytes(fresh_len, "big")

        op_id = f"{pdu_id}:generate_mac:{self._op_seq}"
        self._op_seq += 1
        self._profiler.start(op_id)
        full_mac = self._crypto_interface.generate_mac(key_id, data)
        elapsed_ms = self._profiler.stop(op_id)

        if elapsed_ms > MAC_WCET_BUDGET_MS and self._event_logger is not None:
            self._event_logger.log(Severity.WARNING, "WCET_EXCEEDED", swr_ref="SW-SecOC-08")

        return full_mac[:mac_len]

    def verify_mac(self, pdu_id: str, authentic_pdu: bytes, freshness_value: int,
                    mac: bytes, transport: Transport = Transport.CAN_FD) -> bool:
        """Verify a (truncated) MAC over authentic_pdu || freshness (SR-02, SR-07, SR-21).

        Args:
            pdu_id: Logical PDU identifier.
            authentic_pdu: Authentic I-PDU payload bytes.
            freshness_value: Full (untruncated) freshness counter value.
            mac: Received MAC bytes (transport's authenticator length long).
            transport: CLASSIC_CAN uses profile.tfv_length/tmac_length; CAN_FD
                (default) uses profile.freshness_length/authenticator_length.

        Returns:
            True if mac matches the recomputed MAC.
        """
        profile = self._profile_provider.get_profile(pdu_id)
        key_id = self._resolve_key_id(pdu_id, profile)
        fresh_len, mac_len = profile.truncation_lengths(transport)
        truncated_freshness = freshness_value % (1 << (fresh_len * 8))
        data = authentic_pdu + truncated_freshness.to_bytes(fresh_len, "big")

        full_mac = self._crypto_interface.generate_mac(key_id, data)
        expected = full_mac[:mac_len]
        return hmac.compare_digest(expected, mac)
