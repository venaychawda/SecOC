# ASPICE SWE.4 — Software Unit Verification

**Document ID:** ASPICE-SWE4-SecOC-001
**Version:** 1.0
**Date:** 2026-06-11
**Author:** TBD
**ASPICE Process:** SWE.4 (Software Unit Verification)
**Project:** SecOC — AUTOSAR Classic Secure Onboard Communication Simulation, Phase 1

| Version | Date | Author | Change |
|---|---|---|---|
| 1.0 | 2026-06-11 | TBD | Initial release — Phase 1, Step 7 (post-qualification) |

---

## 1. Purpose & Scope

This document records unit-level test execution evidence for all `sim/` modules,
satisfying ASPICE SWE.4. Verification is performed exclusively via `pytest`
(`tests/test_vtc_NN_*.py`), per CLAUDE.md's mandatory TDD workflow ("Never mark a
requirement VERIFIED without a passing test").

---

## 2. Test Execution Command and Result

```bash
pytest tests/ -v --tb=short --runslow -p no:cacheprovider
```

**Result: 112 passed, 0 skipped, 0 failed, 0 errors** (last run: 2026-06-11, against
the full Step 4-6b implementation, no regressions from Step 5/6a/6b additions).

---

## 3. Per-VTC Unit Test Results

| VTC-ID | Test File | Tests | Result |
|---|---|---|---|
| VTC-SR-01 | `test_vtc_01_forged_frame_rejection.py` | 5 | ✅ PASSED |
| VTC-SR-02 | `test_vtc_02_integrity_tamper_detection.py` | 4 | ✅ PASSED |
| VTC-SR-03 | `test_vtc_03_freshness_replay_rejection.py` | 5 | ✅ PASSED |
| VTC-SR-04 | `test_vtc_04_freshness_window_policy.py` | 6 | ✅ PASSED |
| VTC-SR-05 | `test_vtc_05_resync_after_reset.py` | 6 | ✅ PASSED |
| VTC-SR-06 | `test_vtc_06_mac_generation_known_vector.py` | 5 | ✅ PASSED |
| VTC-SR-07 | `test_vtc_07_mac_corruption_rejection.py` | 5 | ✅ PASSED |
| VTC-SR-08 | `test_vtc_08_key_extraction_denied.py` | 5 | ✅ PASSED |
| VTC-SR-09 | `test_vtc_09_key_access_via_hsm_only.py` | 5 | ✅ PASSED |
| VTC-SR-10 | `test_vtc_10_algorithm_agility.py` | 5 | ✅ PASSED |
| VTC-SR-11 | `test_vtc_11_protected_region_config.py` | 5 | ✅ PASSED |
| VTC-SR-12 | `test_vtc_12_mac_wcet.py` | 5 | ✅ PASSED |
| VTC-SR-13 | `test_vtc_13_dem_event_on_auth_failure.py` | 6 | ✅ PASSED |
| VTC-SR-14 | `test_vtc_14_repeated_failure_safe_state.py` | 7 | ✅ PASSED |
| VTC-SR-15 | `test_vtc_15_resource_overhead.py` | 5 | ✅ PASSED |
| VTC-SR-16 | `test_vtc_16_can_canfd_consistency.py` | 7 | ✅ PASSED |
| VTC-SR-17 | `test_vtc_17_security_profile_versioning.py` | 7 | ✅ PASSED |
| VTC-SR-18 | `test_vtc_18_ci_test_suite.py` | 7 | ✅ PASSED |
| VTC-SR-19 | `test_vtc_19_secure_boot_block.py` | 6 | ✅ PASSED |
| VTC-SR-20 | `test_vtc_20_confidentiality_scope.py` | 6 | ✅ PASSED |
| **Total** | 20 files | **112** | **✅ 112/112 PASSED** |

Each test file follows the mandated structure: `test_precondition_*`,
one test per logical step (`@pytest.mark.vtc("VTC-SR-NN")`), and
`test_expected_result_*` assertions verbatim against `requirements/TestPlan.txt`.

---

## 4. VTC → SWR Coverage Mapping

| VTC-ID | Title (per `requirements/TestPlan.txt`) | SWR Refs |
|---|---|---|
| VTC-SR-01 | Forged frame injection → rejection + violation state | (SR-01; see SWE1 §5.1) |
| VTC-SR-02 | Payload tamper → integrity failure detection | (SR-02; see SWE1 §5.1) |
| VTC-SR-03 | Replay with old counter → freshness rejection | SW-SecOC-01, SW-SecOC-03 |
| VTC-SR-04 | Out-of-window message → rejection per policy | SW-SecOC-02, SW-SecOC-03, SW-SecOC-05 |
| VTC-SR-05 | ECU reset → resynchronization restores comms | SW-SecOC-05, SW-SecOC-09 |
| VTC-SR-06 | Sender MAC matches known-good vector | SW-SecOC-01, SW-SecOC-04 |
| VTC-SR-07 | Corrupted MAC → rejection + DEM log | SW-SecOC-02, SW-SecOC-04 |
| VTC-SR-08 | Key extraction from application layer denied | SW-SecOC-10 |
| VTC-SR-09 | Keys accessible only via secure API/HSM abstraction | SW-SecOC-10 |
| VTC-SR-10 | Algorithm config switch without code change | SW-SecOC-07 |
| VTC-SR-11 | Protected region config matches MAC input bytes | (SR-11; see SWE1 §5.1) |
| VTC-SR-12 | MAC compute/verify time within WCET budget | SW-SecOC-08 |
| VTC-SR-13 | Auth failure → DEM event logged | SW-SecOC-06 |
| VTC-SR-14 | Repeated crypto failure → safe state transition | (SR-14; see SWE1 §5.1) |
| VTC-SR-15 | CPU/memory/CAN load under max traffic | (SR-15; SIMULATION ONLY) |
| VTC-SR-16 | Same SecOC message on CAN/CAN FD validates consistently | (SR-16; see SWE1 §5.1) |
| VTC-SR-17 | Security profile version change → traceable, consistent | SW-SecOC-07 |
| VTC-SR-18 | CI suite executes all SecOC scenarios | (SR-18; process requirement) |
| VTC-SR-19 | Corrupted firmware at boot → comms blocked | (SR-19; SIMULATION ONLY) |
| VTC-SR-20 | Disabled confidentiality flag → declared scope enforced | (SR-20; design constraint) |

Source: `requirements/traceability_matrix.md` §3 (VTC → SWR Reverse Map).

---

## 5. Coverage

`requirements.txt` (pinned) does not include `pytest-cov`; line-coverage percentages
are therefore not machine-generated for Phase 1. Coverage is instead demonstrated by
**requirement-based traceability**: `requirements/traceability_matrix.md` §8
(Implementation Coverage by Module) lists every `sim/` module, its implemented
REQ-IDs, and the VTC(s) that exercise it — every module in `requirements/sim.txt`
has at least one covering VTC and is marked `✅ VERIFIED (GREEN, Step 4)`.

**Recommendation for Phase 2**: add `pytest-cov` to `requirements.txt` and run
`pytest tests/ --cov=sim --cov-report=term-missing` to produce line/branch coverage
percentages as supplementary evidence; this is not required for Phase 1 closure
since the 100% requirement-to-test mapping is already complete.

---

## 6. Conclusion

All 112 unit tests across all 20 VTC modules pass with `--runslow` enabled, with zero
failures, errors, or skips. Every `sim/` module listed in `requirements/sim.txt` is
mapped to at least one passing VTC. SWE.4 evidence is satisfied for Phase 1.
