# ASPICE SWE.2 — Software Architectural Design

**Document ID:** ASPICE-SWE2-SecOC-001
**Version:** 1.0
**Date:** 2026-06-11
**Author:** TBD
**ASPICE Process:** SWE.2 (Software Architectural Design)
**Project:** SecOC — AUTOSAR Classic Secure Onboard Communication Simulation, Phase 1

| Version | Date | Author | Change |
|---|---|---|---|
| 1.0 | 2026-06-11 | TBD | Initial release — Phase 1, Step 7 (post-qualification) |

---

## 1. Purpose & Scope

This document is the SWE.2 evidence record for the SecOC simulation architecture. It
summarizes and references the authoritative architecture artifacts produced in
Step 2:

| Artifact | Location |
|---|---|
| High-Level Design | `design/hld/HLD_SecOC.md` (HLD-SecOC-001) |
| Static architecture | `design/architecture/static_architecture.md` |
| Dynamic architecture | `design/architecture/dynamic_architecture.md` |
| Sequence diagrams | `design/diagrams/seq_*.md` |
| Low-Level Designs (one per `sim/` module) | `design/lld/LLD_*.md` |

Implements requirements: SR-01..SR-20 (system level), SW-SecOC-01..SW-SecOC-10
(software level), per `requirements/traceability_matrix.md`.

---

## 2. Architecture Overview

The simulation is organized into AUTOSAR-Classic-inspired layers, all running
in-process as Python modules:

```
Application Layer:    sender_ecu.py, receiver_ecu.py, ecu_base.py
COM Layer:            pdu_router.py, signal_packager.py
SecOC Layer:          secoc.py, pdu_manager.py, authenticator.py,
                       freshness_manager.py, security_profile.py
Crypto Stack:         crypto_interface.py -> hmac_crypto.py -> csm.py -> cryif.py -> hsm.py
Key Management:       key_manager.py, key_storage.py
Diagnostics:          event_logger.py, security_events.py, dem.py,
                       fault_manager.py, security_policy_engine.py, ecu_state.py
Boot:                  secure_boot.py, integrity_checker.py
Transport (CAN/FD):   can_interface.py, can_fd_interface.py, can_bus.py,
                       message_frame.py, bus_scheduler.py
Persistence:          nvm.py
Attack/Test Harness:  replay_attack.py, mitm_attack.py, fuzzing_engine.py,
                       message_injector.py, scenario_runner.py, test_vectors.py
Cross-cutting:        config.py, logger.py, time_utils.py, serialization.py,
                       performance_profiler.py
API/Dashboard:        api/* (FastAPI), dashboard/index.html (PoC),
                       dashboard/SecOC_Monitor.html (live monitor)
```

The full module inventory with one-line role descriptions is in
`design/hld/HLD_SecOC.md` §3 (Component Overview), and the dependency graph is in
`design/architecture/static_architecture.md`.

---

## 3. Component Interfaces

The primary inter-component call chains are documented in `design/hld/HLD_SecOC.md`
§4 (Inter-Component Interfaces). Key interfaces:

| Caller | Callee | Key Operations |
|---|---|---|
| `secoc.py` | `pdu_manager.py` | `build_secured_pdu()`, `parse_secured_pdu()` |
| `secoc.py` | `freshness_manager.py` | `get_freshness()`, `validate_freshness()`, `commit_freshness()` |
| `secoc.py` | `authenticator.py` | `generate_mac()`, `verify_mac()` |
| `secoc.py` | `security_profile.py` | `get_profile(pdu_id)` |
| `authenticator.py` | `crypto_interface.py` → `hmac_crypto.py` → `csm.py` → `cryif.py` → `hsm.py` | MAC compute/verify chain |
| `authenticator.py` | `key_manager.py` | `resolve_key(pdu_id)` |
| `key_manager.py` | `key_storage.py` | `get_key_metadata()`, `rotate_key()` |
| `freshness_manager.py` | `nvm.py` | `read()`, `write()`, `increment_counter()` |
| All security-relevant modules | `event_logger.py` → `dem.py` / `security_events.py` | `log_event()`, `log_rejection()`, `classify()` |
| `security_events.py` | `fault_manager.py` → `security_policy_engine.py` → `ecu_state.py` | `record_failure()`, `evaluate()`, `transition()` |
| `secure_boot.py` | `integrity_checker.py` | `verify_code_integrity()`, `verify_config_integrity()`, `verify_key_metadata_integrity()` |

The end-to-end primary flow (Tester/OEM Tool → API → SecOC → HSM → Response) is
visualized in `design/architecture/dynamic_architecture.md` and
`design/diagrams/seq_primary_happy_path_SecOC.md`. The error/rejection flow is in
`design/diagrams/seq_failure_abort_SecOC.md`, and the recovery (resync) flow is in
`design/diagrams/seq_recovery_SecOC.md`.

---

## 4. Architectural Rationale

### 4.1 Layered crypto abstraction (SW-SecOC-04, SW-SecOC-10, SR-08, SR-09)

`authenticator.py` never calls a crypto primitive directly. It calls
`crypto_interface.py` (algorithm-agnostic abstract MAC API), implemented by
`hmac_crypto.py`, which dispatches a CSM job (`csm.py`) routed through `cryif.py` to
`hsm.py`. Raw key bytes exist only inside `hsm._key_store`; `key_manager.py` and
`key_storage.py` operate exclusively on logical key IDs and metadata. This satisfies
SR-08/SR-09 ("keys never exposed in plaintext outside secure storage") and is verified
by VTC-SR-08 and VTC-SR-09.

### 4.2 Algorithm agility via JSON security profiles (SW-SecOC-07, SR-10, SR-17)

`security_profile.py` loads `config/secoc_profiles.json`, which defines per-PDU
`{algorithm, key_id, freshness_length, authenticator_length, profile_version}`. Switching
`PDU_0x100` from HMAC-SHA256 to HMAC-SHA512 requires only a config edit and reload — no
code change — verified by VTC-SR-10. Profile version changes (key rotation) are tracked
the same way, verified by VTC-SR-17.

### 4.3 Single shared `EcuState` and fault-escalation chain (SR-13, SR-14)

Every rejection path (`MAC_MISMATCH`, `FRESHNESS_OUT_OF_WINDOW`, `MALFORMED_STRUCTURE`)
converges on `event_logger.log_rejection()` → `security_events.classify()` (always
`CRITICAL`/`SECOC_AUTH_FAIL`) → `fault_manager.record_failure(pdu_id, AUTH)` →
`security_policy_engine.evaluate()`. At `failure_count >= MAX_AUTH_FAILURES` (5,
`config.py`), `ecu_state` transitions to `SECURITY_VIOLATION_LOCKOUT` and a `CRITICAL`
`SAFE_STATE_ENTERED` DEM event is logged exactly once (idempotent via `_locked_out`
flag). This single convergent path keeps SR-13/SR-14 enforcement centralized rather
than duplicated per rejection reason.

### 4.4 CanBus singleton (SR-16, multi-ECU bus simulation)

`CanBus()` always returns the same process-wide instance (`__new__` override), so all
ECUs/attack-harness components observe one shared bus — matching CR-08's "multiple ECUs
share the same bus" requirement. `scenario_runner.run_scenario()` calls
`reset_environment()` to give each VTC scenario a clean bus state; the FastAPI layer
(`api/state.py`) restores `_running = True` after a scenario run so the live API/
dashboard bus stays usable (see §4.5).

### 4.5 FastAPI process-wide `AppState` vs. per-scenario isolation

`api/state.py`'s `AppState` wires one persistent instance of the full sim/ module graph
(NvM, DEM, HSM/CryIf/CSM, KeyManager, SecurityProfile, FreshnessManager, EventLogger,
Authenticator, PduManager, EcuState, SecOC, CanBus, ReplayAttack, IntegrityChecker/
SecureBoot) so that REST/WebSocket clients see one consistent, evolving ECU state across
requests — appropriate for a "live monitor". `scenario_runner.py`, by contrast, builds
fresh isolated instances per VTC so that test scenarios are independent and
order-insensitive (appropriate for `pytest`/CI). Both paths exercise the same
`sim/` module implementations.

### 4.6 Dashboard split: PoC (no backend) vs. Live Monitor (FastAPI + WebSocket)

`dashboard/index.html` is a standalone HTML/JS PoC with its own JS state machine that
mirrors `freshness_manager.py`/`pdu_manager.py`/`security_events.py`/
`security_policy_engine.py` logic (window=16, modulus arithmetic, MAX_AUTH_FAILURES=5,
rejection→lockout), so it can be opened with no server for demos.
`dashboard/SecOC_Monitor.html` is a thin client over the FastAPI REST API and
`/ws/events` WebSocket — it contains no simulation logic of its own and always reflects
the real `sim/` module state in `api/state.py`.

---

## 5. Constraints & Assumptions

Per `design/hld/HLD_SecOC.md` §7:

- Simulation only — no real hardware, CAN transceivers, or HSM hardware.
- `cryptography` library provides ECDSA P-256 / AES-256-GCM / HMAC-SHA256 primitives;
  `hashlib`/`hmac` are not used directly for security operations.
- NvM is a JSON file (`sim/nvm_store.json`) with atomic write-then-rename (gitignored,
  regenerated at runtime).
- The CAN bus is an in-process pub/sub simulation; `bus_scheduler.py` models timing for
  WCET/load measurement only.
- Per SR-20: authenticity/integrity only — no confidentiality mechanism is part of the
  SecOC path (AES-GCM in `hsm.py` exists but is unused by `secoc.py`).
- Ethernet transport is out of scope for Phase 1 (CAN and CAN FD only).
