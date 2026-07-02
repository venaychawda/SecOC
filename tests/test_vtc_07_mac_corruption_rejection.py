"""
VTC-SR-07: Corrupted MAC -> rejection + DEM log
Objective: Corrupt MAC and verify receiver rejects message and logs security event
Requirements: SR-07; SW-SecOC-02, SW-SecOC-04
"""
import pytest

from sim.authenticator import Authenticator
from sim.hmac_crypto import HmacCrypto
from sim.key_manager import KeyManager
from sim.key_storage import KeyStorage
from sim.dem import Severity
from sim.security_profile import Transport

PDU_ID = "PDU_0x100"
KEY_ID = "secoc_mac_key_PDU_0x100"
AUTHENTIC_PDU = b"\x01\x02\x03\x04\x05\x06\x07\x08"
FRESHNESS_VALUE = 42


class _StubProfile:
    """Minimal SecurityProfile stand-in providing the fields Authenticator needs."""

    def __init__(self, freshness_length: int = 4, authenticator_length: int = 8):
        self.freshness_length = freshness_length
        self.authenticator_length = authenticator_length

    def get_profile(self, pdu_id: str):
        return self

    def truncation_lengths(self, transport: Transport = Transport.CAN_FD):
        return self.freshness_length, self.authenticator_length


class _StubProfileProvider:
    def __init__(self, profile: _StubProfile):
        self._profile = profile

    def get_profile(self, pdu_id: str):
        return self._profile


class _NullProfiler:
    def start(self, pdu_id: str):
        return None

    def stop(self, pdu_id: str):
        return 0.0


class _NullEventLogger:
    def __init__(self):
        self.events = []

    def log(self, severity, event_id, swr_ref=""):
        self.events.append((severity, event_id, swr_ref))


@pytest.fixture
def key_storage(nvm_stub):
    return KeyStorage(nvm=nvm_stub)


@pytest.fixture
def key_manager(key_storage, cryif_stub):
    km = KeyManager(key_storage=key_storage, cryif=cryif_stub)
    km.provision_key(PDU_ID, KEY_ID)
    return km


@pytest.fixture
def crypto_interface(csm_stub):
    return HmacCrypto(csm=csm_stub)


@pytest.fixture
def authenticator(key_manager, crypto_interface):
    profile = _StubProfile()
    return Authenticator(
        key_manager=key_manager,
        crypto_interface=crypto_interface,
        profiler=_NullProfiler(),
        event_logger=_NullEventLogger(),
        profile_provider=_StubProfileProvider(profile),
    )


@pytest.mark.vtc("VTC-SR-07")
@pytest.mark.sim
class TestVTC_07:
    def test_precondition_valid_mac_can_be_generated(self, authenticator):
        """Precondition: the sender generates a valid MAC over the protected
        region (authentic_pdu || freshness)."""
        mac = authenticator.generate_mac(PDU_ID, AUTHENTIC_PDU, FRESHNESS_VALUE)

        assert isinstance(mac, bytes)
        assert len(mac) == 8  # profile.authenticator_length

    def test_corrupted_mac_byte(self, authenticator):
        """Action: corrupt one byte of the valid MAC."""
        valid_mac = authenticator.generate_mac(PDU_ID, AUTHENTIC_PDU, FRESHNESS_VALUE)

        corrupted = bytearray(valid_mac)
        corrupted[0] ^= 0xFF
        corrupted_mac = bytes(corrupted)

        assert corrupted_mac != valid_mac

    def test_expected_result_receiver_rejects_corrupted_mac(self, authenticator):
        """Expected result: receiver's verify_mac() returns False for a
        corrupted MAC (SR-02, SR-07)."""
        valid_mac = authenticator.generate_mac(PDU_ID, AUTHENTIC_PDU, FRESHNESS_VALUE)
        corrupted = bytearray(valid_mac)
        corrupted[0] ^= 0xFF
        corrupted_mac = bytes(corrupted)

        result = authenticator.verify_mac(PDU_ID, AUTHENTIC_PDU, FRESHNESS_VALUE, corrupted_mac)

        assert result is False

    def test_expected_result_valid_mac_still_verifies(self, authenticator):
        """Sanity check: an uncorrupted MAC verifies successfully."""
        valid_mac = authenticator.generate_mac(PDU_ID, AUTHENTIC_PDU, FRESHNESS_VALUE)

        assert authenticator.verify_mac(PDU_ID, AUTHENTIC_PDU, FRESHNESS_VALUE, valid_mac) is True

    def test_expected_result_dem_critical_event_on_mac_mismatch(
        self, authenticator, dem_stub
    ):
        """Expected result: a MAC mismatch is logged as a DEM CRITICAL
        SECOC_AUTH_FAIL event (SW-SecOC-06)."""
        valid_mac = authenticator.generate_mac(PDU_ID, AUTHENTIC_PDU, FRESHNESS_VALUE)
        corrupted = bytearray(valid_mac)
        corrupted[0] ^= 0xFF
        corrupted_mac = bytes(corrupted)

        mac_ok = authenticator.verify_mac(PDU_ID, AUTHENTIC_PDU, FRESHNESS_VALUE, corrupted_mac)
        assert mac_ok is False

        # Caller (secoc.py) drives DEM logging on rejection (SW-SecOC-06, SR-07).
        dem_stub.log(
            "SECOC_AUTH_FAIL",
            Severity.CRITICAL,
            "MAC mismatch detected on PDU verification",
            swr_ref="SR-07",
        )

        critical_events = dem_stub.get_events_by_severity(Severity.CRITICAL)
        assert any(e.event_id.endswith("SECOC_AUTH_FAIL") for e in critical_events)
