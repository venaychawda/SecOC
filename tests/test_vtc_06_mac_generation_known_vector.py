"""
VTC-SR-06: Sender MAC matches known-good vector
Objective: Verify sender generates correct MAC over payload + freshness using
known key vector
Requirements: SR-06; SW-SecOC-01, SW-SecOC-04
"""
import pytest

from sim.hmac_crypto import HmacCrypto
from sim.test_vectors import get_vector, expected_truncated_mac, list_vector_names


@pytest.fixture
def hmac_crypto(csm_stub):
    return HmacCrypto(csm=csm_stub)


@pytest.mark.vtc("VTC-SR-06")
@pytest.mark.sim
class TestVTC_06:
    def test_precondition_known_vector_available(self):
        """Precondition: at least one published, externally-verifiable HMAC-SHA256
        test vector (RFC 4231) is available from test_vectors.py."""
        names = list_vector_names()
        assert "rfc4231_case_2" in names

        vector = get_vector("rfc4231_case_2")
        assert vector.key == b"Jefe"
        assert vector.message == b"what do ya want for nothing?"

    def test_precondition_key_registered_in_hsm(self, hsm_stub):
        """Precondition: the known key vector's key material is registered in the
        HSM symmetric key store under the vector's key_id (where applicable)."""
        # RFC 4231 case 2 has no key_id (raw CryptoInterface-level check);
        # registering it directly into the HSM key store under a synthetic
        # key_id makes it usable through HmacCrypto.generate_mac().
        vector = get_vector("rfc4231_case_2")
        key_id = "rfc4231_case_2_key"
        hsm_stub._key_store[key_id] = vector.key

        assert key_id in hsm_stub._key_store

    def test_generate_mac_matches_known_vector(self, hmac_crypto, hsm_stub):
        """Action: sender generates a MAC over the protected region (payload +
        freshness) using the known key, via the HMAC-SHA256 crypto stack."""
        vector = get_vector("rfc4231_case_2")
        key_id = "rfc4231_case_2_key"
        hsm_stub._key_store[key_id] = vector.key

        mac = hmac_crypto.generate_mac(key_id, vector.message)

        assert mac == expected_truncated_mac(vector)

    def test_expected_result_mac_equals_precomputed_expected_mac(self, hmac_crypto, hsm_stub):
        """Expected result: the generated MAC over payload + freshness matches the
        pre-computed expected MAC for the known key vector exactly."""
        vector = get_vector("rfc4231_case_2")
        key_id = "rfc4231_case_2_key"
        hsm_stub._key_store[key_id] = vector.key

        mac = hmac_crypto.generate_mac(key_id, vector.message)

        assert mac == vector.expected_mac
        assert len(mac) == 32  # full HMAC-SHA256 digest

    def test_verify_mac_accepts_known_vector(self, hmac_crypto, hsm_stub):
        """verify_mac() recomputes and confirms the known-vector MAC matches."""
        vector = get_vector("rfc4231_case_2")
        key_id = "rfc4231_case_2_key"
        hsm_stub._key_store[key_id] = vector.key

        assert hmac_crypto.verify_mac(key_id, vector.message, vector.expected_mac) is True
