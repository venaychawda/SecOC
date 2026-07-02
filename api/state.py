"""Shared, process-wide SecOC simulation stack used by the FastAPI backend.

Wires together the same sim/ modules used by the test suite into one
long-lived stack so REST/WebSocket clients observe consistent ECU state,
DEM events, and CAN bus traffic across requests.
"""
from pathlib import Path

from sim import config, performance_profiler
from sim.authenticator import Authenticator
from sim.can_bus import CanBus
from sim.csm import CSM
from sim.cryif import CryIf
from sim.dem import DEM, Severity
from sim.ecu_state import EcuState, EcuStateValue
from sim.event_logger import EventLogger
from sim.fault_manager import FailureCategory, FaultManager
from sim.freshness_manager import FreshnessManager
from sim.hmac_crypto import HmacCrypto
from sim.hsm import HSM
from sim.integrity_checker import IntegrityChecker
from sim.key_manager import KeyManager
from sim.key_storage import KeyStorage
from sim.message_injector import MessageInjector
from sim.nvm import NvM
from sim.pdu_manager import PduManager
from sim.replay_attack import ReplayAttack
from sim.secoc import SecOC
from sim.secure_boot import SecureBoot, _CURRENT_SNAPSHOT
from sim.security_events import SecurityEvents
from sim.security_policy_engine import SecurityPolicyEngine
from sim.security_profile import SecurityProfile

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_PROFILE_CONFIG_PATH = _PROJECT_ROOT / config.DEFAULT_SECURITY_PROFILE_PATH


class AppState:
    """Holds one long-lived SecOC simulation stack for the FastAPI app."""

    def __init__(self) -> None:
        self.nvm = NvM()
        self.dem = DEM()

        self.hsm = HSM()
        self.cryif = CryIf(hsm=self.hsm)
        self.csm = CSM(cryif=self.cryif)
        self.crypto = HmacCrypto(csm=self.csm)

        self.key_storage = KeyStorage(nvm=self.nvm)
        self.key_manager = KeyManager(key_storage=self.key_storage, cryif=self.cryif)

        self.profile_provider = SecurityProfile(config_path=str(_PROFILE_CONFIG_PATH))
        self.freshness_manager = FreshnessManager(
            nvm=self.nvm,
            window_size=16,
            freshness_length=config.DEFAULT_FRESHNESS_LENGTH,
        )
        self.security_events = SecurityEvents()
        self.event_logger = EventLogger(dem=self.dem, security_events=self.security_events)
        self.authenticator = Authenticator(
            key_manager=self.key_manager,
            crypto_interface=self.crypto,
            profiler=performance_profiler,
            event_logger=self.event_logger,
            profile_provider=self.profile_provider,
        )
        self.pdu_manager = PduManager()
        self.ecu_state = EcuState()
        self.secoc = SecOC(
            profile_provider=self.profile_provider,
            freshness_manager=self.freshness_manager,
            authenticator=self.authenticator,
            pdu_manager=self.pdu_manager,
            event_logger=self.event_logger,
            ecu_state=self.ecu_state,
        )
        self.security_policy_engine: SecurityPolicyEngine = self.secoc._security_policy_engine
        self.fault_manager: FaultManager = self.secoc._fault_manager

        self.can_bus = CanBus()
        self.can_bus.start()
        self.injector = MessageInjector(can_bus=self.can_bus)
        self.replay_attack = ReplayAttack(can_bus=self.can_bus, injector=self.injector)

        self.integrity_checker = IntegrityChecker(cryif=self.cryif)
        self.secure_boot = SecureBoot(
            integrity_checker=self.integrity_checker, nvm=self.nvm, event_logger=self.event_logger
        )

        self._provision_keys()
        self._provision_boot_golden_hashes()
        self.secure_boot.verify_boot_integrity()

        self._broadcast_index = 0

    def _provision_keys(self) -> None:
        for pdu_id, profile in self.profile_provider._profiles.items():
            try:
                self.key_manager.resolve_key(pdu_id)
            except KeyError:
                self.key_manager.provision_key(pdu_id, profile.key_id)

    def _provision_boot_golden_hashes(self) -> None:
        golden_hash = self.integrity_checker.compute_hash(_CURRENT_SNAPSHOT)
        for nvm_key in ("boot_golden_hash_code", "boot_golden_hash_config", "boot_golden_hash_keys"):
            if self.nvm.read(nvm_key) is None:
                self.nvm.write(nvm_key, golden_hash)

    def reset_ecu(self) -> None:
        """Reset ECU state, security policy, and fault counters to a clean baseline."""
        self.ecu_state.transition(EcuStateValue.NORMAL_OPERATION)
        self.security_policy_engine._locked_out = False
        self.fault_manager._counts.clear()
        self.event_logger.log(Severity.INFO, "ECU_RESET", swr_ref="SecOC-RESET")

    def get_status(self) -> dict:
        """Return combined ECU/SecOC status."""
        return {
            "ecu_state": self.ecu_state.current_state.value,
            "locked_out": self.security_policy_engine.is_locked_out(),
            "boot_status": self.secure_boot.get_status(),
        }

    def new_dem_events(self) -> list[DEM]:
        """Return DEM events recorded since the last call, advancing the cursor."""
        events = self.dem.get_events()
        new_events = events[self._broadcast_index:]
        self._broadcast_index = len(events)
        return new_events


state = AppState()
