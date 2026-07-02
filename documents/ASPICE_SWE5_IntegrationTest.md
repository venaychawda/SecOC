# ASPICE SWE.5 — Software Integration Test

**Document ID:** ASPICE-SWE5-SecOC-001
**Version:** 1.0
**Date:** 2026-06-11
**Author:** TBD
**ASPICE Process:** SWE.5 (Software Integration Test)
**Project:** SecOC — AUTOSAR Classic Secure Onboard Communication Simulation, Phase 1

| Version | Date | Author | Change |
|---|---|---|---|
| 1.0 | 2026-06-11 | TBD | Initial release — Phase 1, Step 7 (post-qualification) |

---

## 1. Purpose & Scope

This document is the SWE.5 evidence record. While SWE.4 (`docs/ASPICE_SWE4_UnitVerification.md`)
verifies each `sim/` module in isolation via `tests/test_vtc_NN_*.py`, this document
covers **integration** of those modules through the FastAPI layer (`api/`), the
WebSocket event bus (`api/websocket.py`), and the live dashboard
(`dashboard/SecOC_Monitor.html`) — i.e., the integrated system as exercised end-to-end
in Step 5 and Step 6b.

---

## 2. Integration Levels

| Level | Scope | Evidence |
|---|---|---|
| L1 — Module-to-module | `secoc.py` ↔ `pdu_manager.py`/`freshness_manager.py`/`authenticator.py`/`security_profile.py`, crypto chain `authenticator → crypto_interface → hmac_crypto → csm → cryif → hsm`, fault chain `security_events → fault_manager → security_policy_engine → ecu_state` | Exercised implicitly by every `tests/test_vtc_NN_*.py` (SWE.4) — these are multi-module tests by construction since `secoc.receive_secured()` calls all of the above. |
| L2 — API-to-sim | FastAPI routers (`api/routers/*.py`) ↔ `api/state.py` `AppState` ↔ `sim/` module graph | §3 (TestClient-based REST tests) |
| L3 — WebSocket event bus | `sim/event_logger.py`/`dem.py` → `api/websocket.py` `ConnectionManager` → connected clients | §4 |
| L4 — Dashboard-to-API | `dashboard/SecOC_Monitor.html` (browser JS) ↔ FastAPI REST + WebSocket | §5 |

---

## 3. L2 — API Integration Test Evidence (Step 5)

The following scenarios were exercised against the FastAPI app via `httpx`/`TestClient`
and/or a live `uvicorn` instance, confirming that REST endpoints correctly drive the
underlying `sim/` module graph and that DEM/ECU-state side effects are observable
through the API:

| Scenario | Endpoint(s) | Result |
|---|---|---|
| Forged-frame rejection | `POST /attack/forge` (mode=`MALFORMED_STRUCTURE`/`INVALID_MAC`/`WRONG_FRESHNESS`) → `POST /secoc/receive` | Forged PDU rejected (`accepted: false`), DEM `SECOC_AUTH_FAIL` event recorded, visible via `GET /events` |
| MITM tamper rejection | `POST /attack/mitm` → `POST /secoc/receive` | Tampered authentic-PDU bytes invalidate MAC; `accepted: false` |
| Replay capture + rejection | `POST /attack/replay/capture` then `POST /attack/replay/replay` | Replayed (stale-freshness) PDU rejected with `FRESHNESS_OUT_OF_WINDOW` |
| Key rotation | `POST /test/VTC-SR-17/run` (security profile version change scenario) | Scenario `status: PASSED`, profile version change traceable via `GET /profiles` |
| Repeated AUTH-failure → lockout | 5× `POST /attack/forge` + `POST /secoc/receive` for same `pdu_id` | `GET /ecu/state` → `ecu_state: SECURITY_VIOLATION_LOCKOUT`, `locked_out: true`; single `SAFE_STATE_ENTERED` CRITICAL event (idempotent) |
| ECU reset / resync | `POST /ecu/reset` after lockout | `GET /ecu/state` → `ecu_state: NORMAL_OPERATION`, `locked_out: false`; freshness counters resynchronized (VTC-SR-05 logic) |

---

## 4. L3 — WebSocket Event Bus Integration (Step 5/6b)

`api/websocket.py`'s `ConnectionManager` is wired into `event_logger`/`dem` (via
`broadcast_dem_event`) and `ecu_state` (via `broadcast_ecu_state`). Verified message
shapes received on `/ws/events`:

```json
{"type": "dem_event", "event_id": "...", "severity": "CRITICAL",
 "description": "...", "swr_ref": "SR-13", "timestamp": ..., "data": {...}}
```

```json
{"type": "ecu_state", "ecu_state": "SECURITY_VIOLATION_LOCKOUT", "locked_out": true,
 "boot_status": {"boot_integrity_ok": true, "failed_component": null}}
```

Live verification (Step 6b): `dashboard/SecOC_Monitor.html` connected to
`ws://localhost:8000/ws/events`, with `connectWs()` auto-reconnect (2s interval) and
connection-status indicator (`conn-status`). Triggering `POST /attack/forge` +
`POST /secoc/receive` via the dashboard's Panel 2 produced an immediate `dem_event`
message that appeared in Panel 4 (Event Log) and flashed Panel 1 (ECU State Monitor)
without a page reload.

---

## 5. L4 — Live Dashboard Integration Evidence (Step 6b)

End-to-end verification was performed with `python -m uvicorn api.main:app --port 8000`
running and `dashboard/SecOC_Monitor.html` open against it:

| Test | Command / Action | Result |
|---|---|---|
| ECU state read | `curl http://localhost:8000/ecu/state` | `{"ecu_state":"NORMAL_OPERATION","locked_out":false,"boot_status":{"boot_integrity_ok":true,"failed_component":null}}` |
| Profile listing | `curl http://localhost:8000/profiles` | All 3 PDU profiles (`PDU_BRAKE_TORQUE`, `PDU_0x100`, `PDU_0x200`) returned with correct `freshness_length`/`authenticator_length`/`algorithm` |
| Transmit | `POST /secoc/transmit {"pdu_id":"PDU_0x100","payload_hex":"01020304"}` | `{"pdu_id":"PDU_0x100","secured_pdu_hex":"010203040001b9d536a61b042268"}` — 4-byte payload + 2-byte freshness + 8-byte MAC = 14 bytes ✅ |
| Receive (round trip) | `POST /secoc/receive` with the above hex | `{"pdu_id":"PDU_0x100","accepted":true,"authentic_pdu_hex":"01020304","ecu_state":"NORMAL_OPERATION","locked_out":false}` |
| Telemetry | `GET /telemetry` | `{ecu_state, dem:{total_events, by_severity}, can_bus:{running:true, queue_depth:1, last_frames}, performance:{count:1,...}}` — shape matches dashboard `refreshTelemetry()` expectations |
| Scenario runner | `GET /test/scenarios` then `POST /test/VTC-SR-06/run` | All 20 `VTC-SR-01..20` listed; VTC-SR-06 → `{"status":"PASSED","steps":["compute HMAC-SHA256 over RFC 4231 test vector"],"error_message":null}` |
| Event log | `GET /events?limit=5` | `[]` on a clean ECU (no prior failures) |
| CORS | `curl -i -X OPTIONS http://localhost:8000/secoc/transmit -H "Origin: http://localhost:3000" ...` | `access-control-allow-origin: http://localhost:3000` confirmed, satisfying dashboard-on-3000 / API-on-8000 split |

Byte-segment rendering in Panel 2 (`renderPduBytes()`) was confirmed to correctly split
`010203040001b9d536a61b042268` into authentic PDU (`01020304`), freshness
(`0001`), and MAC (`b9d536a61b042268`) using the profile's `freshness_length=2`/
`authenticator_length=8`.

---

## 6. Regression Confirmation

After Step 6b changes (dashboard-only, no `sim/`/`api/` code changes), the full test
suite was re-run to confirm no regressions:

```bash
pytest tests/ --runslow --tb=short -p no:cacheprovider -q
```

**Result: 112 passed, 10875 warnings in 2.47s.**

---

## 7. Conclusion

All four integration levels (module-to-module, API-to-sim, WebSocket event bus,
dashboard-to-API) have been exercised with passing results and no regressions. SWE.5
evidence is satisfied for Phase 1.
