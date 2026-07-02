"""Shared pytest fixtures for SecOC VTC test suites.

Markers:
  sim  — Phase 1 simulation test (no hardware required)
  slow — Test involves real timer delays; skipped unless --runslow is passed
  vtc  — Verification test case marker, e.g. @pytest.mark.vtc("VTC-SR-01")
"""
import pytest

from sim.csm import CSM
from sim.cryif import CryIf
from sim.dem import DEM
from sim.hsm import HSM
from sim.nvm import NvM


def pytest_addoption(parser):
    parser.addoption(
        "--runslow",
        action="store_true",
        default=False,
        help="Run slow tests (timer/delay-dependent)",
    )


def pytest_configure(config):
    config.addinivalue_line("markers", "sim: Phase 1 simulation test (no hardware required)")
    config.addinivalue_line("markers", "slow: Test involves real timer delays")
    config.addinivalue_line(
        "markers",
        "vtc: Verification test case marker — pass VTC id as argument, "
        "e.g. @pytest.mark.vtc('VTC-SR-01')",
    )


def pytest_collection_modifyitems(config, items):
    if not config.getoption("--runslow"):
        skip_slow = pytest.mark.skip(reason="Pass --runslow to run timer-dependent tests")
        for item in items:
            if "slow" in item.keywords:
                item.add_marker(skip_slow)


@pytest.fixture
def tmp_nvm_path(tmp_path):
    return str(tmp_path / "nvm_store.json")


@pytest.fixture
def nvm_stub(tmp_nvm_path):
    return NvM(path=tmp_nvm_path)


@pytest.fixture
def dem_stub():
    return DEM()


@pytest.fixture
def hsm_stub():
    return HSM()


@pytest.fixture
def cryif_stub(hsm_stub):
    return CryIf(hsm=hsm_stub)


@pytest.fixture
def csm_stub(cryif_stub):
    return CSM(cryif=cryif_stub)
