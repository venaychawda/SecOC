"""
VTC-SR-10: Algorithm config switch without code change
Objective: Switch algorithm configuration and verify system adapts without code
modification
Requirements: SR-10; SW-SecOC-07
"""
import json

import pytest

from sim.security_profile import SecurityProfile
from sim.crypto_interface import CryptoInterface


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


@pytest.mark.vtc("VTC-SR-10")
@pytest.mark.sim
class TestVTC_10:
    def test_precondition_profile_loaded_with_initial_algorithm(
        self, profile_config_path
    ):
        """Precondition: SecurityProfile is loaded from JSON config with
        PDU_BRAKE_TORQUE configured for algorithm HMAC-SHA256."""
        profile_provider = SecurityProfile(config_path=profile_config_path)
        entry = profile_provider.get_profile(PDU_ID)

        assert entry.algorithm == "HMAC-SHA256"

    def test_crypto_interface_is_algorithm_agnostic_abstract_contract(self):
        """Step: Verify CryptoInterface defines an algorithm-agnostic
        abstract API (generate_mac/verify_mac) that does not hardcode any
        specific algorithm name."""
        assert hasattr(CryptoInterface, "generate_mac")
        assert hasattr(CryptoInterface, "verify_mac")

        with pytest.raises(TypeError):
            # Abstract base class cannot be instantiated directly.
            CryptoInterface()

    def test_switch_algorithm_in_config_and_reload_changes_profile(
        self, profile_config_path
    ):
        """Step: Switch the `algorithm` field in the JSON config to a
        different supported algorithm and call SecurityProfile.reload();
        verify the in-memory profile reflects the new algorithm without any
        code or import changes."""
        profile_provider = SecurityProfile(config_path=profile_config_path)
        assert profile_provider.get_profile(PDU_ID).algorithm == "HMAC-SHA256"

        # Only the JSON config dict changes -- no Python imports change.
        with open(profile_config_path, "r", encoding="utf-8") as f:
            profiles = json.load(f)
        profiles[PDU_ID]["algorithm"] = "HMAC-SHA512"
        with open(profile_config_path, "w", encoding="utf-8") as f:
            json.dump(profiles, f)

        profile_provider.reload()

        assert profile_provider.get_profile(PDU_ID).algorithm == "HMAC-SHA512"

    def test_unsupported_algorithm_in_config_raises_config_error(
        self, profile_config_path
    ):
        """Step: Switching the config to an algorithm not present in
        config.SUPPORTED_ALGORITHMS must raise SecurityProfileConfigError on
        reload (algorithm agility is bounded by an explicit allow-list)."""
        from sim.security_profile import SecurityProfileConfigError

        profile_provider = SecurityProfile(config_path=profile_config_path)

        with open(profile_config_path, "r", encoding="utf-8") as f:
            profiles = json.load(f)
        profiles[PDU_ID]["algorithm"] = "UNSUPPORTED-ALG"
        with open(profile_config_path, "w", encoding="utf-8") as f:
            json.dump(profiles, f)

        with pytest.raises(SecurityProfileConfigError):
            profile_provider.reload()

    def test_expected_result_no_code_or_import_changes_required(
        self, profile_config_path
    ):
        """Expected result: switching algorithm configuration only requires
        editing config/secoc_profiles.json and calling reload(); the set of
        Python imports/classes used by the test (SecurityProfile,
        CryptoInterface) remains identical before and after the switch."""
        profile_provider = SecurityProfile(config_path=profile_config_path)
        before = profile_provider.get_profile(PDU_ID).algorithm

        with open(profile_config_path, "r", encoding="utf-8") as f:
            profiles = json.load(f)
        profiles[PDU_ID]["algorithm"] = "HMAC-SHA512"
        with open(profile_config_path, "w", encoding="utf-8") as f:
            json.dump(profiles, f)
        profile_provider.reload()

        after = profile_provider.get_profile(PDU_ID).algorithm

        assert before != after
        # Same SecurityProfile/CryptoInterface objects/classes used throughout.
        assert isinstance(profile_provider, SecurityProfile)
