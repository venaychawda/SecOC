"""
VTC-SR-11: Protected region config matches MAC computation input bytes
Objective: Verify configured protected region matches MAC computation input bytes
Requirements: SR-11; — (no derived SWR; implemented by design intent as part of
SW-SecOC-07; see traceability_matrix.md section 6)
"""
import json

import pytest

from sim.security_profile import SecurityProfile
from sim.pdu_manager import PduManager
from sim.authenticator import Authenticator
from sim.serialization import Serialization
from sim.can_bus import CanBus
from sim.can_interface import CanInterface, PayloadTooLargeError
from sim.pdu_router import PduRouter


PDU_ID = "PDU_BRAKE_TORQUE"


@pytest.fixture
def profile_config_path(tmp_path):
    config_path = tmp_path / "secoc_profiles.json"
    profiles = {
        PDU_ID: {
            "algorithm": "HMAC-SHA256",
            "key_id": "secoc_mac_key_PDU_BRAKE_TORQUE",
            "freshness_length": 2,
            "authenticator_length": 8,
            "profile_version": "v1",
        }
    }
    config_path.write_text(json.dumps(profiles), encoding="utf-8")
    return str(config_path)


@pytest.fixture
def profile_provider(profile_config_path):
    return SecurityProfile(config_path=profile_config_path)


@pytest.fixture
def pdu_manager():
    return PduManager(serializer=Serialization())


@pytest.fixture
def pdu_router_no_canfd():
    bus = CanBus()
    bus.start()
    can_if = CanInterface(ecu_id="ECU_OVERSIZED", bus=bus)
    return PduRouter(ecu_id="ECU_OVERSIZED", can_if=can_if, can_fd_if=None)


@pytest.fixture
def authenticator(profile_provider):
    return Authenticator(
        key_manager=None,
        crypto_interface=None,
        profiler=None,
        event_logger=None,
        profile_provider=profile_provider,
    )


@pytest.mark.vtc("VTC-SR-11")
@pytest.mark.sim
class TestVTC_11:
    def test_precondition_security_profile_defines_protected_region_lengths(
        self, profile_provider
    ):
        """Precondition: the security profile for PDU_BRAKE_TORQUE explicitly
        defines freshness_length and authenticator_length, which together
        with authentic_pdu describe the protected region (SR-11)."""
        entry = profile_provider.get_profile(PDU_ID)

        assert entry.freshness_length == 2
        assert entry.authenticator_length == 8

    def test_build_secured_pdu_layout_matches_protected_region_definition(
        self, pdu_manager, profile_provider
    ):
        """Step: Build a Secured I-PDU and verify the wire layout
        (authentic_pdu || freshness || mac) matches the field lengths
        declared by the security profile."""
        profile = profile_provider.get_profile(PDU_ID)
        authentic_pdu = b"\x01\x02\x03\x04"
        freshness_value = 0x00FF
        mac = b"\xAA" * profile.authenticator_length

        secured_pdu = pdu_manager.build_secured_pdu(
            authentic_pdu, freshness_value, mac, profile
        )

        trailer = profile.freshness_length + profile.authenticator_length
        assert len(secured_pdu) == len(authentic_pdu) + trailer
        assert secured_pdu[-profile.authenticator_length:] == mac

    def test_authenticator_mac_input_bytes_equal_authentic_pdu_plus_freshness(
        self, authenticator, profile_provider, monkeypatch
    ):
        """Step: Verify the bytes passed to the MAC computation
        (authentic_pdu || freshness_value) exactly match the protected
        region defined by the security profile -- no extra bytes (e.g. the
        MAC field itself) are included."""
        profile = profile_provider.get_profile(PDU_ID)
        authentic_pdu = b"\x10\x20\x30\x40"
        freshness_value = 0x0001

        captured = {}

        class CapturingCryptoInterface:
            def generate_mac(self, key_id, data):
                captured["key_id"] = key_id
                captured["data"] = data
                return b"\x00" * 32

            def verify_mac(self, key_id, data, mac):
                return True

        class StubKeyManager:
            def resolve_key(self, pdu_id):
                return profile.key_id

        class StubProfiler:
            def start(self, operation_id):
                pass

            def stop(self, operation_id):
                return 0.0

        authenticator._key_manager = StubKeyManager()
        authenticator._crypto_interface = CapturingCryptoInterface()
        authenticator._profiler = StubProfiler()

        authenticator.generate_mac(PDU_ID, authentic_pdu, freshness_value)

        expected_protected_region = authentic_pdu + freshness_value.to_bytes(
            profile.freshness_length, "big"
        )
        assert captured["data"] == expected_protected_region

    def test_protected_region_excludes_authenticator_field(
        self, pdu_manager, profile_provider
    ):
        """Step: Verify the protected region used for MAC computation never
        includes the authenticator (MAC) field itself -- only authentic_pdu
        and the freshness value."""
        profile = profile_provider.get_profile(PDU_ID)
        authentic_pdu = b"\x01\x02\x03\x04"
        freshness_value = 0x00FF
        mac = b"\xBB" * profile.authenticator_length

        secured_pdu = pdu_manager.build_secured_pdu(
            authentic_pdu, freshness_value, mac, profile
        )
        parsed_authentic_pdu, parsed_freshness, parsed_mac = (
            pdu_manager.parse_secured_pdu(secured_pdu, profile)
        )

        protected_region = parsed_authentic_pdu + parsed_freshness.to_bytes(
            profile.freshness_length, "big"
        )

        assert mac not in protected_region

    def test_expected_result_protected_region_consistent_across_build_and_mac(
        self, pdu_manager, authenticator, profile_provider
    ):
        """Expected result: the protected region bytes used by
        Authenticator.generate_mac() are identical to authentic_pdu plus the
        truncated freshness field as defined in the security profile and
        produced/consumed by PduManager (SR-11)."""
        profile = profile_provider.get_profile(PDU_ID)
        authentic_pdu = b"\xDE\xAD\xBE\xEF"
        freshness_value = 0x0042

        captured = {}

        class CapturingCryptoInterface:
            def generate_mac(self, key_id, data):
                captured["data"] = data
                return b"\x00" * 32

            def verify_mac(self, key_id, data, mac):
                return True

        class StubKeyManager:
            def resolve_key(self, pdu_id):
                return profile.key_id

        class StubProfiler:
            def start(self, operation_id):
                pass

            def stop(self, operation_id):
                return 0.0

        authenticator._key_manager = StubKeyManager()
        authenticator._crypto_interface = CapturingCryptoInterface()
        authenticator._profiler = StubProfiler()

        mac = authenticator.generate_mac(PDU_ID, authentic_pdu, freshness_value)
        secured_pdu = pdu_manager.build_secured_pdu(
            authentic_pdu, freshness_value, mac, profile
        )

        freshness_bytes = freshness_value.to_bytes(profile.freshness_length, "big")
        assert captured["data"] == authentic_pdu + freshness_bytes
        assert secured_pdu == authentic_pdu + freshness_bytes + mac

    @pytest.mark.asyncio
    async def test_pdu_router_rejects_secured_pdu_exceeding_can_fd_capacity(
        self, pdu_manager, profile_provider, pdu_router_no_canfd
    ):
        """Expected result (PduRouter layer, SR-11/SR-16): a Secured I-PDU
        whose protected-region layout produces a wire size exceeding CAN FD
        capacity (64 bytes) -- a security_profile.py misconfiguration --
        raises PayloadTooLargeError at route_to_bus() (design/lld/LLD_pdu_router.md)."""
        profile = profile_provider.get_profile(PDU_ID)
        oversized_authentic_pdu = b"\x00" * 60
        mac = b"\xCC" * profile.authenticator_length

        secured_pdu = pdu_manager.build_secured_pdu(
            oversized_authentic_pdu, 0x00FF, mac, profile
        )
        assert len(secured_pdu) > 64

        with pytest.raises(PayloadTooLargeError):
            await pdu_router_no_canfd.route_to_bus(0x100, secured_pdu)
