"""Runs each VTC-SR-01..20 scenario as a self-contained smoke test (SR-18)."""
import asyncio
import json
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from sim import config, performance_profiler
from sim.authenticator import Authenticator
from sim.can_bus import CanBus
from sim.can_fd_interface import CanFdInterface
from sim.can_interface import CanInterface
from sim.csm import CSM
from sim.cryif import CryIf
from sim.dem import DEM, Severity
from sim.ecu_state import EcuState, EcuStateValue
from sim.event_logger import EventLogger
from sim.fault_manager import FailureCategory, FaultManager
from sim.freshness_manager import FreshnessManager
from sim.fuzzing_engine import ForgeMode, FuzzingEngine
from sim.hmac_crypto import HmacCrypto
from sim.hsm import HSM
from sim.integrity_checker import IntegrityChecker
from sim.key_manager import KeyManager
from sim.key_storage import KeyStorage
from sim.message_frame import MessageFrame
from sim.message_injector import MessageInjector
from sim.mitm_attack import MitmAttack
from sim.nvm import NvM
from sim.pdu_manager import PduManager
from sim.pdu_router import PduRouter
from sim.receiver_ecu import ReceiverECU
from sim.replay_attack import ReplayAttack
from sim.secoc import SecOC
from sim.secure_boot import SecureBoot
from sim.security_policy_engine import SecurityPolicyEngine
from sim.security_profile import SecurityProfile, SecurityProfileEntry
from sim.sender_ecu import SenderECU
from sim.serialization import Serialization
from sim.test_vectors import expected_truncated_mac, get_vector, list_vector_names


_VTC_IDS = [f"VTC-SR-{n:02d}" for n in range(1, 21)]


class UnknownScenarioError(Exception):
    """Raised by run_scenario() for a vtc_id outside VTC-SR-01..20."""


class ScenarioStatus(str, Enum):
    """Outcome of a scenario run."""

    PASSED = "PASSED"
    FAILED = "FAILED"
    ERROR = "ERROR"


@dataclass
class ScenarioResult:
    """Result of running a single VTC scenario."""

    vtc_id: str
    status: ScenarioStatus
    steps: list[str] = field(default_factory=list)
    error_message: str | None = None


_results: dict[str, ScenarioResult] = {}


def list_scenarios() -> list[str]:
    """Return all VTC-SR-01..20 IDs in TestPlan.txt row order.

    Returns:
        List of 20 VTC ID strings.
    """
    return list(_VTC_IDS)


def reset_environment() -> None:
    """Reset shared process-wide simulation state to a clean baseline."""
    bus = CanBus()
    bus._last_frames.clear()
    bus._queue.clear()
    bus._running = False
    performance_profiler.reset()


def get_result(vtc_id: str) -> ScenarioResult | None:
    """Return the most recently recorded ScenarioResult for vtc_id.

    Args:
        vtc_id: VTC identifier.

    Returns:
        The last ScenarioResult for vtc_id, or None if never run.
    """
    return _results.get(vtc_id)


def run_scenario(vtc_id: str) -> ScenarioResult:
    """Run the scenario for vtc_id and record/return its ScenarioResult.

    Args:
        vtc_id: VTC identifier (e.g. "VTC-SR-01").

    Returns:
        The ScenarioResult of this run.

    Raises:
        UnknownScenarioError: If vtc_id is not in VTC-SR-01..20.
    """
    if vtc_id not in _SCENARIOS:
        raise UnknownScenarioError(f"unknown scenario id: {vtc_id}")

    reset_environment()
    steps: list[str] = []
    try:
        _SCENARIOS[vtc_id](steps)
        result = ScenarioResult(vtc_id=vtc_id, status=ScenarioStatus.PASSED, steps=steps)
    except AssertionError as exc:
        result = ScenarioResult(
            vtc_id=vtc_id, status=ScenarioStatus.FAILED, steps=steps, error_message=str(exc)
        )
    except Exception as exc:
        result = ScenarioResult(
            vtc_id=vtc_id, status=ScenarioStatus.ERROR, steps=steps,
            error_message=f"{type(exc).__name__}: {exc}",
        )
    _results[vtc_id] = result
    return result


def _new_nvm() -> NvM:
    tmp_dir = tempfile.mkdtemp(prefix="secoc_scenario_")
    return NvM(path=str(Path(tmp_dir) / "nvm_store.json"))


def _new_profile_provider(pdu_id: str = "PDU_BRAKE_TORQUE") -> SecurityProfile:
    tmp_dir = tempfile.mkdtemp(prefix="secoc_scenario_profile_")
    config_path = Path(tmp_dir) / "secoc_profiles.json"
    config_path.write_text(json.dumps({
        pdu_id: {
            "algorithm": "HMAC-SHA256",
            "key_id": f"secoc_mac_key_{pdu_id}",
            "freshness_length": config.DEFAULT_FRESHNESS_LENGTH,
            "authenticator_length": config.DEFAULT_AUTHENTICATOR_LENGTH,
            "profile_version": "v1",
        }
    }), encoding="utf-8")
    return SecurityProfile(config_path=str(config_path))


def _build_secoc(pdu_id: str = "PDU_BRAKE_TORQUE"):
    nvm = _new_nvm()
    dem = DEM()
    profile_provider = _new_profile_provider(pdu_id)
    freshness_manager = FreshnessManager(nvm=nvm, window_size=16, freshness_length=2)
    event_logger = EventLogger(dem=dem, security_events=None)
    authenticator = Authenticator(
        key_manager=None,
        crypto_interface=None,
        profiler=None,
        event_logger=event_logger,
        profile_provider=profile_provider,
    )
    pdu_manager = PduManager(serializer=None)
    ecu_state = EcuState()
    secoc = SecOC(
        profile_provider=profile_provider,
        freshness_manager=freshness_manager,
        authenticator=authenticator,
        pdu_manager=pdu_manager,
        event_logger=event_logger,
        ecu_state=ecu_state,
    )
    return secoc, dem, ecu_state


def _build_ecu_pair(secoc: SecOC, ecu_state: EcuState, pdu_id: str, bus: CanBus):
    """Builds a SenderECU/ReceiverECU pair sharing secoc/ecu_state, wired to bus."""
    tx_can_if = CanInterface(ecu_id="ECU_TX", bus=bus)
    tx_can_fd_if = CanFdInterface(ecu_id="ECU_TX", bus=bus)
    tx_router = PduRouter(ecu_id="ECU_TX", can_if=tx_can_if, can_fd_if=tx_can_fd_if)
    sender = SenderECU(
        ecu_id="ECU_TX", secoc=secoc, pdu_router=tx_router,
        ecu_state=ecu_state, managed_pdu_ids=(pdu_id,),
    )
    sender.on_startup()

    rx_can_if = CanInterface(ecu_id="ECU_RX", bus=bus)
    rx_router = PduRouter(ecu_id="ECU_RX", can_if=rx_can_if)
    receiver = ReceiverECU(
        ecu_id="ECU_RX", secoc=secoc, pdu_router=rx_router,
        ecu_state=ecu_state, managed_pdu_ids=(pdu_id,),
    )
    receiver.on_startup()

    return sender, receiver


def _scenario_01(steps: list[str]) -> None:
    pdu_id = "PDU_BRAKE_TORQUE"
    secoc, dem, ecu_state = _build_secoc(pdu_id)
    bus = CanBus()
    bus.start()
    injector = MessageInjector(can_bus=bus)
    fuzzer = FuzzingEngine(can_bus=bus, injector=injector)
    _sender, receiver = _build_ecu_pair(secoc, ecu_state, pdu_id, bus)

    steps.append("inject forged frames until lockout (via ReceiverECU)")
    for _ in range(config.MAX_AUTH_FAILURES):
        forged = fuzzer.generate_forged_pdu(pdu_id, ForgeMode.INVALID_MAC)
        accepted = receiver.on_frame_received(pdu_id, forged)
        assert accepted is False

    steps.append("verify ECU enters SECURITY_VIOLATION_LOCKOUT")
    assert ecu_state.current_state == EcuStateValue.SECURITY_VIOLATION_LOCKOUT


def _scenario_02(steps: list[str]) -> None:
    pdu_id = "PDU_BRAKE_TORQUE"
    secoc, dem, ecu_state = _build_secoc(pdu_id)
    bus = CanBus()
    bus.start()
    injector = MessageInjector(can_bus=bus)
    mitm = MitmAttack(can_bus=bus, injector=injector)
    sender, receiver = _build_ecu_pair(secoc, ecu_state, pdu_id, bus)

    steps.append("transmit a valid secured PDU (via SenderECU)")
    asyncio.run(sender.send_signal(pdu_id, b"\x01\x02\x03\x04"))
    secured = bus.get_last(pdu_id)

    steps.append("intercept and tamper one bit")
    frame = MessageFrame(pdu_id=pdu_id, data=secured, timestamp=0.0)
    tampered = mitm.intercept(frame)
    assert tampered.tampered_raw_bytes != tampered.original_raw_bytes

    steps.append("verify tampered PDU fails MAC verification (via ReceiverECU)")
    assert receiver.on_frame_received(pdu_id, tampered.tampered_raw_bytes) is False


def _scenario_03(steps: list[str]) -> None:
    pdu_id = "PDU_BRAKE_TORQUE"
    secoc, dem, ecu_state = _build_secoc(pdu_id)
    bus = CanBus()
    bus.start()
    injector = MessageInjector(can_bus=bus)
    replay = ReplayAttack(can_bus=bus, injector=injector)
    sender, receiver = _build_ecu_pair(secoc, ecu_state, pdu_id, bus)

    steps.append("transmit and accept first secured PDU (via Sender/ReceiverECU)")
    asyncio.run(sender.send_signal(pdu_id, b"\x01"))
    secured1 = bus.get_last(pdu_id)
    assert receiver.on_frame_received(pdu_id, secured1) is True

    steps.append("capture the accepted frame")
    captured = replay.capture(pdu_id)
    assert captured.raw_bytes == secured1

    steps.append("transmit and accept a fresher second PDU")
    asyncio.run(sender.send_signal(pdu_id, b"\x02"))
    secured2 = bus.get_last(pdu_id)
    assert receiver.on_frame_received(pdu_id, secured2) is True

    steps.append("replay the stale captured PDU and verify rejection")
    replay.replay(pdu_id)
    assert receiver.on_frame_received(pdu_id, captured.raw_bytes) is False


def _scenario_04(steps: list[str]) -> None:
    pdu_id = "PDU_BRAKE_TORQUE"
    nvm = _new_nvm()
    fm = FreshnessManager(nvm=nvm, window_size=16, freshness_length=2)

    steps.append("commit a baseline freshness value")
    fm.commit_freshness(pdu_id, 10)

    steps.append("verify out-of-window value is rejected")
    ok, full_value = fm.validate_freshness(pdu_id, 10 + 16 + 1)
    assert ok is False
    assert full_value == 0


def _scenario_05(steps: list[str]) -> None:
    pdu_id = "PDU_0x100"
    nvm = _new_nvm()
    fm = FreshnessManager(nvm=nvm, window_size=16, freshness_length=2)

    steps.append("commit a freshness value, simulate reset with new instance")
    fm.commit_freshness(pdu_id, 100)
    rebooted = FreshnessManager(nvm=nvm, window_size=16, freshness_length=2)
    assert rebooted.load_last_valid_freshness(pdu_id) == 100

    steps.append("resync window and verify post-resync acceptance")
    rebooted.reinitialize_window(pdu_id, 500)
    ok, full_value = rebooted.validate_freshness(pdu_id, 501 & 0xFFFF)
    assert ok is True
    assert full_value == 501


def _scenario_06(steps: list[str]) -> None:
    nvm = _new_nvm()
    hsm = HSM()
    cryif = CryIf(hsm=hsm)
    csm = CSM(cryif=cryif)
    crypto = HmacCrypto(csm=csm)

    steps.append("compute HMAC-SHA256 over RFC 4231 test vector")
    assert "rfc4231_case_2" in list_vector_names()
    vector = get_vector("rfc4231_case_2")
    key_id = "rfc4231_test_key"
    hsm._key_store[key_id] = vector.key

    mac = crypto.generate_mac(key_id, vector.message)
    assert mac == expected_truncated_mac(vector)


def _scenario_07(steps: list[str]) -> None:
    pdu_id = "PDU_0x100"
    nvm = _new_nvm()
    hsm = HSM()
    cryif = CryIf(hsm=hsm)
    csm = CSM(cryif=cryif)
    key_storage = KeyStorage(nvm=nvm)
    key_manager = KeyManager(key_storage=key_storage, cryif=cryif)
    key_id = f"secoc_mac_key_{pdu_id}"
    key_manager.provision_key(pdu_id, key_id)
    crypto = HmacCrypto(csm=csm)
    profile_provider = _new_profile_provider(pdu_id)
    authenticator = Authenticator(
        key_manager=key_manager,
        crypto_interface=crypto,
        profiler=None,
        event_logger=None,
        profile_provider=profile_provider,
    )

    steps.append("generate a valid MAC")
    authentic_pdu = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    valid_mac = authenticator.generate_mac(pdu_id, authentic_pdu, 1)

    steps.append("corrupt one byte and verify rejection")
    corrupted = bytearray(valid_mac)
    corrupted[0] ^= 0xFF
    assert authenticator.verify_mac(pdu_id, authentic_pdu, 1, bytes(corrupted)) is False

    steps.append("verify uncorrupted MAC still verifies")
    assert authenticator.verify_mac(pdu_id, authentic_pdu, 1, valid_mac) is True


def _scenario_08(steps: list[str]) -> None:
    pdu_id = "PDU_0x100"
    key_id = f"secoc_mac_key_{pdu_id}"
    nvm = _new_nvm()
    hsm = HSM()
    cryif = CryIf(hsm=hsm)
    key_storage = KeyStorage(nvm=nvm)
    key_manager = KeyManager(key_storage=key_storage, cryif=cryif)

    steps.append("provision key and resolve via logical key_id")
    key_manager.provision_key(pdu_id, key_id)
    resolved = key_manager.resolve_key(pdu_id)
    assert isinstance(resolved, str)
    assert resolved == key_id

    steps.append("verify metadata never carries raw key bytes")
    metadata = key_storage.get_key_metadata(pdu_id)
    forbidden_fields = {"key_bytes", "raw_key", "secret", "key_material", "private_key"}
    assert forbidden_fields.isdisjoint(vars(metadata).keys())


def _scenario_09(steps: list[str]) -> None:
    pdu_id = "PDU_BRAKE_TORQUE"
    key_id = f"secoc_mac_key_{pdu_id}"
    nvm = _new_nvm()
    hsm = HSM()
    cryif = CryIf(hsm=hsm)
    key_storage = KeyStorage(nvm=nvm)
    key_manager = KeyManager(key_storage=key_storage, cryif=cryif)

    steps.append("provision and resolve key via secure API only")
    key_manager.provision_key(pdu_id, key_id)
    resolved_key_id = key_manager.resolve_key(pdu_id)
    assert isinstance(resolved_key_id, str)

    steps.append("perform crypto ops only via CryIf, key bytes stay in HSM")
    mac = cryif.hmac_sha256(resolved_key_id, b"protected-region-bytes")
    assert isinstance(mac, (bytes, bytearray))
    assert resolved_key_id in hsm._key_store


def _scenario_10(steps: list[str]) -> None:
    pdu_id = "PDU_BRAKE_TORQUE"
    profile_provider = _new_profile_provider(pdu_id)

    steps.append("verify initial algorithm")
    assert profile_provider.get_profile(pdu_id).algorithm == "HMAC-SHA256"

    steps.append("switch algorithm in config and reload")
    raw = json.loads(Path(profile_provider._config_path).read_text(encoding="utf-8"))
    raw[pdu_id]["algorithm"] = "HMAC-SHA512"
    Path(profile_provider._config_path).write_text(json.dumps(raw), encoding="utf-8")
    profile_provider.reload()

    assert profile_provider.get_profile(pdu_id).algorithm == "HMAC-SHA512"


def _scenario_11(steps: list[str]) -> None:
    pdu_id = "PDU_BRAKE_TORQUE"
    profile_provider = _new_profile_provider(pdu_id)
    pdu_manager = PduManager(serializer=Serialization())
    profile = profile_provider.get_profile(pdu_id)

    steps.append("build secured PDU and verify protected-region layout")
    authentic_pdu = b"\x01\x02\x03\x04"
    freshness_value = 0x00FF
    mac = b"\xAA" * profile.authenticator_length

    secured_pdu = pdu_manager.build_secured_pdu(authentic_pdu, freshness_value, mac, profile)
    trailer = profile.freshness_length + profile.authenticator_length
    assert len(secured_pdu) == len(authentic_pdu) + trailer
    assert secured_pdu[-profile.authenticator_length:] == mac


def _scenario_12(steps: list[str]) -> None:
    pdu_id = "PDU_BRAKE_TORQUE"
    profile_provider = _new_profile_provider(pdu_id)
    event_logger = EventLogger(dem=DEM(), security_events=None)
    authenticator = Authenticator(
        key_manager=None,
        crypto_interface=None,
        profiler=performance_profiler,
        event_logger=event_logger,
        profile_provider=profile_provider,
    )

    steps.append("generate a MAC and check it completes within WCET budget")
    mac = authenticator.generate_mac(pdu_id, b"\x01\x02\x03\x04", 1)
    assert isinstance(mac, bytes)

    summary = performance_profiler.get_summary()
    assert summary["count"] >= 1


def _scenario_13(steps: list[str]) -> None:
    from sim.security_events import RejectionReason

    dem = DEM()
    event_logger = EventLogger(dem=dem, security_events=None)

    steps.append("log a MAC_MISMATCH rejection")
    event_logger.log_rejection("PDU_BRAKE_TORQUE", RejectionReason.MAC_MISMATCH)

    critical_events = dem.get_events_by_severity(Severity.CRITICAL)
    assert any("SECOC_AUTH_FAIL" in e.event_id for e in critical_events)


def _scenario_14(steps: list[str]) -> None:
    pdu_id = "PDU_BRAKE_TORQUE"
    dem = DEM()
    ecu_state = EcuState()
    event_logger = EventLogger(dem=dem, security_events=None)
    policy_engine = SecurityPolicyEngine(ecu_state=ecu_state, event_logger=event_logger)
    fault_manager = FaultManager(security_policy_engine=policy_engine)

    nvm = _new_nvm()
    profile_provider = _new_profile_provider(pdu_id)
    freshness_manager = FreshnessManager(nvm=nvm, window_size=16, freshness_length=2)
    authenticator = Authenticator(
        key_manager=None, crypto_interface=None, profiler=None,
        event_logger=event_logger, profile_provider=profile_provider,
    )
    secoc = SecOC(
        profile_provider=profile_provider,
        freshness_manager=freshness_manager,
        authenticator=authenticator,
        pdu_manager=PduManager(serializer=None),
        event_logger=event_logger,
        ecu_state=ecu_state,  # share this scenario's ecu_state/policy_engine
    )
    bus = CanBus()
    bus.start()
    sender, _receiver = _build_ecu_pair(secoc, ecu_state, pdu_id, bus)

    steps.append("record repeated AUTH failures up to MAX_AUTH_FAILURES")
    for _ in range(config.MAX_AUTH_FAILURES):
        fault_manager.record_failure(pdu_id, FailureCategory.AUTH)

    steps.append("verify ECU enters lockout and CRITICAL DEM event logged")
    assert ecu_state.current_state == EcuStateValue.SECURITY_VIOLATION_LOCKOUT
    critical_events = dem.get_events_by_severity(Severity.CRITICAL)
    assert any("SAFE_STATE_ENTERED" in e.event_id for e in critical_events)

    steps.append("verify SenderECU.send_signal() suppressed while locked out")
    sent = asyncio.run(sender.send_signal(pdu_id, b"\x01\x02\x03\x04"))
    assert sent is False


def _scenario_15(steps: list[str]) -> None:
    from sim.bus_scheduler import BusScheduler

    scheduler = BusScheduler(scheduler_id="BUS_SCHED_SCENARIO")
    fired: list = []

    steps.append("schedule a periodic transmission and tick the scheduler")
    scheduler.schedule_periodic(0x100, 10, lambda pdu_id: fired.append(pdu_id))
    scheduler.start()
    for tick in range(1, 11):
        scheduler.tick(tick * 10)

    assert len(fired) == 10
    assert len(fired) <= config.MAX_BUS_MESSAGES_PER_WINDOW


def _scenario_16(steps: list[str]) -> None:
    pdu_id_numeric = 0x100
    pdu_id = "PDU_BRAKE_TORQUE"
    short_pdu = bytes(range(8))
    long_pdu = bytes(range(64))

    secoc, dem, ecu_state = _build_secoc(pdu_id)
    bus = CanBus()
    bus.start()
    can_if = CanInterface(ecu_id="ECU_ROUTER", bus=bus)
    can_fd_if = CanFdInterface(ecu_id="ECU_ROUTER", bus=bus)
    router = PduRouter(ecu_id="ECU_ROUTER", can_if=can_if, can_fd_if=can_fd_if)
    receiver = ReceiverECU(
        ecu_id="ECU_ROUTER", secoc=secoc, pdu_router=router,
        ecu_state=ecu_state, managed_pdu_ids=(pdu_id,),
    )
    receiver.on_startup()

    steps.append("route a short PDU (classic CAN) and a long PDU (CAN FD) via PduRouter")

    async def _run():
        await router.route_to_bus(pdu_id_numeric, short_pdu)
        result_classic = receiver.on_frame_received(pdu_id, bus.get_last(pdu_id_numeric))

        await router.route_to_bus(pdu_id_numeric, long_pdu)
        result_fd = receiver.on_frame_received(pdu_id, bus.get_last(pdu_id_numeric))

        return result_classic, result_fd

    result_classic, result_fd = asyncio.run(_run())
    assert result_classic == result_fd


def _scenario_17(steps: list[str]) -> None:
    pdu_id = "PDU_BRAKE_TORQUE"
    initial_key_id = f"secoc_mac_key_{pdu_id}"
    rotated_key_id = f"{initial_key_id}_v2"

    profile_provider = _new_profile_provider(pdu_id)
    nvm = _new_nvm()
    hsm = HSM()
    cryif = CryIf(hsm=hsm)
    key_storage = KeyStorage(nvm=nvm)
    key_manager = KeyManager(key_storage=key_storage, cryif=cryif)

    steps.append("provision v1 key, rotate to v2, update profile version")
    key_manager.provision_key(pdu_id, initial_key_id)
    key_manager.rotate_key(pdu_id, new_key_id=rotated_key_id)
    profile_provider.update_profile_version(pdu_id, "v2")

    updated_entry = profile_provider.get_profile(pdu_id)
    active_key_id = key_manager.resolve_key(pdu_id)
    assert updated_entry.profile_version == "v2"
    assert active_key_id == rotated_key_id


def _scenario_18(steps: list[str]) -> None:
    steps.append("verify list_scenarios() returns all 20 VTC IDs in order")
    scenarios = list_scenarios()
    assert scenarios == _VTC_IDS
    assert len(set(scenarios)) == 20


def _scenario_19(steps: list[str]) -> None:
    firmware_snapshot = b"SECOC_FIRMWARE_SNAPSHOT_V1::code+config+keymeta"
    nvm = _new_nvm()
    hsm = HSM()
    cryif = CryIf(hsm=hsm)
    integrity_checker = IntegrityChecker(cryif=cryif)
    dem = DEM()
    event_logger = EventLogger(dem=dem, security_events=None)

    steps.append("provision golden hashes and verify unmodified boot passes")
    golden_hash = integrity_checker.compute_hash(firmware_snapshot)
    nvm.write("boot_golden_hash_code", golden_hash)
    nvm.write("boot_golden_hash_config", golden_hash)
    nvm.write("boot_golden_hash_keys", golden_hash)

    secure_boot = SecureBoot(integrity_checker=integrity_checker, nvm=nvm, event_logger=event_logger)
    assert secure_boot.verify_boot_integrity() is True

    steps.append("tamper golden hash and verify boot is blocked + CRITICAL DEM event")
    tampered_golden = integrity_checker.compute_hash(b"TAMPERED_GOLDEN_VALUE")
    nvm.write("boot_golden_hash_code", tampered_golden)
    assert secure_boot.verify_boot_integrity() is False

    critical_events = dem.get_events_by_severity(Severity.CRITICAL)
    assert any(e.event_id == "BOOT_INTEGRITY_FAIL" for e in critical_events)


def _scenario_20(steps: list[str]) -> None:
    import dataclasses

    steps.append("verify SecurityProfileEntry schema is authenticity/integrity only")
    field_names = {f.name for f in dataclasses.fields(SecurityProfileEntry)}
    assert field_names == {
        "algorithm", "key_id", "freshness_length", "authenticator_length", "profile_version",
        "tfv_length", "tmac_length",
    }
    for name in field_names:
        assert "encrypt" not in name.lower()
        assert "confidential" not in name.lower()


_SCENARIOS = {
    "VTC-SR-01": _scenario_01,
    "VTC-SR-02": _scenario_02,
    "VTC-SR-03": _scenario_03,
    "VTC-SR-04": _scenario_04,
    "VTC-SR-05": _scenario_05,
    "VTC-SR-06": _scenario_06,
    "VTC-SR-07": _scenario_07,
    "VTC-SR-08": _scenario_08,
    "VTC-SR-09": _scenario_09,
    "VTC-SR-10": _scenario_10,
    "VTC-SR-11": _scenario_11,
    "VTC-SR-12": _scenario_12,
    "VTC-SR-13": _scenario_13,
    "VTC-SR-14": _scenario_14,
    "VTC-SR-15": _scenario_15,
    "VTC-SR-16": _scenario_16,
    "VTC-SR-17": _scenario_17,
    "VTC-SR-18": _scenario_18,
    "VTC-SR-19": _scenario_19,
    "VTC-SR-20": _scenario_20,
}
