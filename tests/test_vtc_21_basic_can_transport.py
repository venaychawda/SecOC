"""
VTC-SR-21: Classic CAN 8-byte TFV/TMAC transport mode
Objective: Configure per-PDU TFV/TMAC truncation lengths for Classic CAN,
verify the TFV_length + TMAC_length = 4 bytes constraint is enforced at load
time, and verify a Classic CAN Secured I-PDU is exactly 8 bytes (4-byte
zero-padded Authentic I-PDU + TFV + TMAC) that round-trips correctly, while
CAN FD transport remains unaffected.
Requirements: SR-21; SW-SecOC-11
"""
import json

import pytest

from sim.authenticator import Authenticator
from sim.event_logger import EventLogger
from sim.freshness_manager import FreshnessManager
from sim.pdu_manager import PduManager
from sim.secoc import SecOC, SecOCTransportError
from sim.security_profile import (
    SecurityProfile,
    SecurityProfileConfigError,
    Transport,
)


PDU_ID = "PDU_BRAKE_TORQUE"


def _write_profile(tmp_path, entry: dict) -> str:
    config_path = tmp_path / "secoc_profiles.json"
    config_path.write_text(json.dumps({PDU_ID: entry}), encoding="utf-8")
    return str(config_path)


def _base_entry(**overrides) -> dict:
    entry = {
        "algorithm": "HMAC-SHA256",
        "key_id": "secoc_mac_key_PDU_BRAKE_TORQUE",
        "freshness_length": 2,
        "authenticator_length": 8,
        "profile_version": "v1",
    }
    entry.update(overrides)
    return entry


@pytest.mark.vtc("VTC-SR-21")
@pytest.mark.sim
class TestVTC_21_ConfigValidation:
    def test_precondition_profile_without_tfv_tmac_still_loads(self, tmp_path):
        """Precondition: a profile with no tfv_length/tmac_length (CAN FD
        only) continues to load exactly as before (backward compatible)."""
        path = _write_profile(tmp_path, _base_entry())
        profile_provider = SecurityProfile(config_path=path)
        entry = profile_provider.get_profile(PDU_ID)

        assert entry.tfv_length is None
        assert entry.tmac_length is None

    def test_valid_tfv_tmac_summing_to_four_loads(self, tmp_path):
        path = _write_profile(tmp_path, _base_entry(tfv_length=1, tmac_length=3))
        profile_provider = SecurityProfile(config_path=path)
        entry = profile_provider.get_profile(PDU_ID)

        assert entry.tfv_length == 1
        assert entry.tmac_length == 3

    def test_tfv_tmac_not_summing_to_four_raises(self, tmp_path):
        path = _write_profile(tmp_path, _base_entry(tfv_length=1, tmac_length=2))
        with pytest.raises(SecurityProfileConfigError):
            SecurityProfile(config_path=path)

    def test_tfv_without_tmac_raises(self, tmp_path):
        path = _write_profile(tmp_path, _base_entry(tfv_length=2))
        with pytest.raises(SecurityProfileConfigError):
            SecurityProfile(config_path=path)

    def test_tmac_without_tfv_raises(self, tmp_path):
        path = _write_profile(tmp_path, _base_entry(tmac_length=4))
        with pytest.raises(SecurityProfileConfigError):
            SecurityProfile(config_path=path)

    def test_zero_length_tfv_or_tmac_is_allowed_if_sum_is_four(self, tmp_path):
        """A 0-byte TFV or TMAC is a valid (if degenerate) configuration as
        long as the sum is exactly 4."""
        path = _write_profile(tmp_path, _base_entry(tfv_length=0, tmac_length=4))
        profile_provider = SecurityProfile(config_path=path)
        entry = profile_provider.get_profile(PDU_ID)

        assert entry.tfv_length == 0
        assert entry.tmac_length == 4

    def test_truncation_lengths_for_classic_can_returns_tfv_tmac(self, tmp_path):
        path = _write_profile(tmp_path, _base_entry(tfv_length=1, tmac_length=3))
        entry = SecurityProfile(config_path=path).get_profile(PDU_ID)

        assert entry.truncation_lengths(Transport.CLASSIC_CAN) == (1, 3)

    def test_truncation_lengths_for_can_fd_returns_freshness_authenticator(self, tmp_path):
        path = _write_profile(tmp_path, _base_entry(tfv_length=1, tmac_length=3))
        entry = SecurityProfile(config_path=path).get_profile(PDU_ID)

        assert entry.truncation_lengths(Transport.CAN_FD) == (2, 8)

    def test_truncation_lengths_for_classic_can_without_config_raises(self, tmp_path):
        path = _write_profile(tmp_path, _base_entry())
        entry = SecurityProfile(config_path=path).get_profile(PDU_ID)

        with pytest.raises(SecurityProfileConfigError):
            entry.truncation_lengths(Transport.CLASSIC_CAN)


@pytest.fixture
def profile_path(tmp_path):
    return _write_profile(tmp_path, _base_entry(tfv_length=1, tmac_length=3))


@pytest.fixture
def secoc(profile_path, nvm_stub, dem_stub, hsm_stub, cryif_stub, csm_stub, ecu_state):
    profile_provider = SecurityProfile(config_path=profile_path)
    freshness_manager = FreshnessManager(nvm=nvm_stub, window_size=16, freshness_length=2)
    event_logger = EventLogger(dem=dem_stub)
    authenticator = Authenticator(
        key_manager=None,
        crypto_interface=None,
        profiler=None,
        event_logger=event_logger,
        profile_provider=profile_provider,
    )
    pdu_manager = PduManager(serializer=None)
    return SecOC(
        profile_provider=profile_provider,
        freshness_manager=freshness_manager,
        authenticator=authenticator,
        pdu_manager=pdu_manager,
        event_logger=event_logger,
        ecu_state=ecu_state,
    )


@pytest.fixture
def ecu_state():
    from sim.ecu_state import EcuState
    return EcuState()


@pytest.mark.vtc("VTC-SR-21")
@pytest.mark.sim
class TestVTC_21_ClassicCanWireFormat:
    def test_classic_can_secured_pdu_is_exactly_eight_bytes(self, secoc):
        """Step: transmit_secured() with transport=CLASSIC_CAN produces an
        8-byte Secured I-PDU regardless of input payload length."""
        secured = secoc.transmit_secured(PDU_ID, b"\x01\x02", transport=Transport.CLASSIC_CAN)
        assert len(secured) == 8

    def test_zero_byte_payload_is_valid_and_zero_padded(self, secoc):
        """0 bytes of Authentic I-PDU data is valid -- padded to 4 zero bytes."""
        secured = secoc.transmit_secured(PDU_ID, b"", transport=Transport.CLASSIC_CAN)
        assert len(secured) == 8
        assert secured[:4] == b"\x00\x00\x00\x00"

    def test_four_byte_payload_is_valid_unpadded(self, secoc):
        secured = secoc.transmit_secured(PDU_ID, b"\xAA\xBB\xCC\xDD", transport=Transport.CLASSIC_CAN)
        assert secured[:4] == b"\xAA\xBB\xCC\xDD"

    def test_payload_shorter_than_four_bytes_is_right_padded_with_zeros(self, secoc):
        secured = secoc.transmit_secured(PDU_ID, b"\x01\x02", transport=Transport.CLASSIC_CAN)
        assert secured[:4] == b"\x01\x02\x00\x00"

    def test_payload_longer_than_four_bytes_raises(self, secoc):
        with pytest.raises(SecOCTransportError):
            secoc.transmit_secured(PDU_ID, b"\x01\x02\x03\x04\x05", transport=Transport.CLASSIC_CAN)

    def test_trailer_is_one_byte_tfv_plus_three_byte_tmac(self, secoc):
        secured = secoc.transmit_secured(PDU_ID, b"\x01\x02\x03\x04", transport=Transport.CLASSIC_CAN)
        # bytes[4] = TFV (1 byte), bytes[5:8] = TMAC (3 bytes)
        assert len(secured[4:5]) == 1
        assert len(secured[5:8]) == 3

    def test_classic_can_round_trip_is_accepted(self, secoc):
        secured = secoc.transmit_secured(PDU_ID, b"\x01\x02\x03\x04", transport=Transport.CLASSIC_CAN)
        result = secoc.receive_secured(PDU_ID, secured, transport=Transport.CLASSIC_CAN)
        assert result == b"\x01\x02\x03\x04"

    def test_classic_can_tampered_tmac_is_rejected(self, secoc):
        secured = bytearray(
            secoc.transmit_secured(PDU_ID, b"\x01\x02\x03\x04", transport=Transport.CLASSIC_CAN)
        )
        secured[-1] ^= 0xFF  # corrupt one TMAC byte
        result = secoc.receive_secured(PDU_ID, bytes(secured), transport=Transport.CLASSIC_CAN)
        assert result is None

    def test_classic_can_replayed_stale_tfv_is_rejected(self, secoc):
        first = secoc.transmit_secured(PDU_ID, b"\x01", transport=Transport.CLASSIC_CAN)
        assert secoc.receive_secured(PDU_ID, first, transport=Transport.CLASSIC_CAN) is not None

        second = secoc.transmit_secured(PDU_ID, b"\x02", transport=Transport.CLASSIC_CAN)
        assert secoc.receive_secured(PDU_ID, second, transport=Transport.CLASSIC_CAN) is not None

        # Replay the stale first frame -- must be rejected.
        assert secoc.receive_secured(PDU_ID, first, transport=Transport.CLASSIC_CAN) is None

    def test_expected_result_can_fd_transport_unaffected(self, secoc):
        """Expected result: the default (CAN FD) transport still uses the
        existing freshness_length/authenticator_length scheme, unaffected by
        the presence of tfv_length/tmac_length in the profile."""
        secured = secoc.transmit_secured(PDU_ID, b"\x01\x02\x03\x04\x05\x06")
        # authentic_pdu(6) + freshness_length(2) + authenticator_length(8) = 16
        assert len(secured) == 16
        result = secoc.receive_secured(PDU_ID, secured)
        assert result == b"\x01\x02\x03\x04\x05\x06"
