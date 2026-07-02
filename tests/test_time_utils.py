"""
Unit tests for sim/time_utils.py (shared infrastructure, no dedicated VTC).
Requirements: supports SR-04, SR-15 timing needs per design/lld/LLD_time_utils.md
"""
import re

import pytest

from sim import time_utils


class TestTimeUtils:
    def test_now_ms_returns_int(self):
        """now_ms() returns a non-negative int."""
        value = time_utils.now_ms()
        assert isinstance(value, int)
        assert value >= 0

    def test_now_ms_is_monotonic_non_decreasing(self):
        """Successive now_ms() calls never go backwards."""
        first = time_utils.now_ms()
        second = time_utils.now_ms()
        assert second >= first

    def test_elapsed_ms_since_earlier_now_ms_is_non_negative(self):
        """elapsed_ms(start_ms) == now_ms() - start_ms, always >= 0."""
        start = time_utils.now_ms()
        elapsed = time_utils.elapsed_ms(start)
        assert elapsed >= 0

    def test_elapsed_ms_reflects_sleep_ms_duration(self):
        """A sleep_ms(duration) call increases elapsed_ms() by roughly duration."""
        start = time_utils.now_ms()
        time_utils.sleep_ms(20)
        elapsed = time_utils.elapsed_ms(start)
        assert elapsed >= 15

    def test_sleep_ms_rejects_negative_duration(self):
        """sleep_ms() with a negative duration raises ValueError."""
        with pytest.raises(ValueError):
            time_utils.sleep_ms(-1)

    def test_sleep_ms_zero_is_a_no_op(self):
        """sleep_ms(0) is valid and returns immediately."""
        time_utils.sleep_ms(0)

    def test_to_iso8601_returns_iso_formatted_string(self):
        """to_iso8601() renders a now_ms()-style timestamp as ISO-8601."""
        formatted = time_utils.to_iso8601(time_utils.now_ms())
        assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", formatted)

    def test_to_iso8601_is_monotonically_increasing_with_ms(self):
        """A later ms value renders to a later (or equal) ISO-8601 string."""
        earlier = time_utils.to_iso8601(1000)
        later = time_utils.to_iso8601(2000)
        assert later >= earlier
