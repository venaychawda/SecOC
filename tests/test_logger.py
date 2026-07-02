"""
Unit tests for sim/logger.py (shared infrastructure, no dedicated VTC).
Generic non-security trace/debug logging, explicitly separate from sim/dem.py
per design/lld/LLD_logger.md.
"""
import logging

import pytest

from sim import logger as secoc_logger


@pytest.fixture(autouse=True)
def _restore_level():
    yield
    secoc_logger.configure()


class TestLogger:
    def test_get_logger_returns_logging_logger(self):
        """get_logger() returns a standard library Logger instance."""
        log = secoc_logger.get_logger("sim.freshness_manager")
        assert isinstance(log, logging.Logger)

    def test_get_logger_name_is_namespaced_under_secoc(self):
        """The returned logger's name is prefixed under the 'secoc' hierarchy."""
        log = secoc_logger.get_logger("sim.freshness_manager")
        assert log.name == "secoc.sim.freshness_manager"

    def test_get_logger_is_idempotent_no_duplicate_handlers(self):
        """Calling get_logger() repeatedly does not attach duplicate handlers."""
        secoc_logger.get_logger("sim.a")
        secoc_logger.get_logger("sim.b")
        root = logging.getLogger("secoc")
        assert len(root.handlers) == 1

    def test_set_level_overrides_root_logger_level(self):
        """set_level() changes the effective level of the 'secoc' hierarchy."""
        secoc_logger.set_level(logging.DEBUG)
        assert logging.getLogger("secoc").level == logging.DEBUG

    def test_configure_overrides_level(self):
        """configure(level=...) re-applies a level override."""
        secoc_logger.configure(level=logging.WARNING)
        assert logging.getLogger("secoc").level == logging.WARNING

    def test_configure_does_not_duplicate_handlers(self):
        """configure() clears and re-attaches exactly one handler."""
        secoc_logger.configure()
        secoc_logger.configure()
        root = logging.getLogger("secoc")
        assert len(root.handlers) == 1

    def test_security_events_are_not_logged_via_this_module(self):
        """logger.py has no security-event API surface (DEM-only, per CLAUDE.md)."""
        assert not hasattr(secoc_logger, "log_rejection")
        assert not hasattr(secoc_logger, "log_critical")
