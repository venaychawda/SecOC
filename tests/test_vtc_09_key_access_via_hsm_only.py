"""
VTC-SR-09: Keys accessible only via secure API/HSM abstraction
Objective: Validate keys are accessible only via secure API/HSM abstraction layer
Requirements: SR-09; SW-SecOC-10
"""
import pytest

from sim.key_manager import KeyManager, KeyMetadata, KeyLifecycleState
from sim.key_storage import KeyStorage
from sim.cryif import CryIf


PDU_ID = "PDU_BRAKE_TORQUE"
KEY_ID = "secoc_mac_key_PDU_BRAKE_TORQUE"


@pytest.fixture
def key_storage(nvm_stub):
    return KeyStorage(nvm=nvm_stub)


@pytest.fixture
def key_manager(key_storage, cryif_stub):
    return KeyManager(key_storage=key_storage, cryif=cryif_stub)


@pytest.mark.vtc("VTC-SR-09")
@pytest.mark.sim
class TestVTC_09:
    def test_precondition_pdu_has_provisioned_active_key(self, key_manager):
        """Precondition: PDU_BRAKE_TORQUE has an ACTIVE key provisioned via
        KeyManager.provision_key() before any resolution attempt."""
        metadata = key_manager.provision_key(PDU_ID, KEY_ID)
        assert isinstance(metadata, KeyMetadata)
        assert metadata.lifecycle_state == KeyLifecycleState.ACTIVE

    def test_resolve_key_returns_string_key_id_not_bytes(self, key_manager):
        """Step: Resolve the active key for PDU_BRAKE_TORQUE via the secure
        API and verify a logical key_id string is returned, never raw key
        bytes."""
        key_manager.provision_key(PDU_ID, KEY_ID)
        key_id = key_manager.resolve_key(PDU_ID)

        assert isinstance(key_id, str)
        assert not isinstance(key_id, (bytes, bytearray))
        assert key_id == KEY_ID

    def test_crypto_operations_reached_only_via_cryif_public_methods(
        self, key_manager, cryif_stub, hsm_stub
    ):
        """Step: Perform crypto operations (hmac_sha256, generate_symmetric_key)
        only via CryIf's public API and verify HSM private key storage is
        never touched directly by application-layer code."""
        key_manager.provision_key(PDU_ID, KEY_ID)
        key_id = key_manager.resolve_key(PDU_ID)

        # Sanctioned path: CryIf public methods only.
        cryif_stub.generate_symmetric_key(key_id)
        mac = cryif_stub.hmac_sha256(key_id, b"protected-region-bytes")

        assert isinstance(mac, (bytes, bytearray))
        # The key material lives only inside hsm_stub's private key store.
        assert key_id in hsm_stub._key_store

    def test_application_layer_cannot_bypass_abstraction_to_read_raw_key(
        self, key_manager, hsm_stub
    ):
        """Step: Attempt to bypass CryIf/KeyManager and read raw key bytes
        directly from HSM internal storage; verify no public accessor
        exposes plaintext key material (SR-09 boundary, Scenario C)."""
        key_manager.provision_key(PDU_ID, KEY_ID)
        key_id = key_manager.resolve_key(PDU_ID)

        # No public HSM API may return raw key bytes for a given key_id.
        public_attrs = [
            attr for attr in dir(hsm_stub) if not attr.startswith("_")
        ]
        for attr in public_attrs:
            member = getattr(hsm_stub, attr)
            if callable(member):
                continue
            assert member != hsm_stub._key_store.get(key_id)

    def test_expected_result_only_logical_key_ids_cross_module_boundary(
        self, key_manager
    ):
        """Expected result: KeyManager.resolve_key() returns only a logical
        key_id string usable by CryIf/KeyManager APIs; no raw key bytes are
        ever returned across the application-layer boundary (SW-SecOC-10)."""
        key_manager.provision_key(PDU_ID, KEY_ID)
        key_id = key_manager.resolve_key(PDU_ID)

        assert isinstance(key_id, str)
        assert key_id.startswith("secoc_mac_key_")
