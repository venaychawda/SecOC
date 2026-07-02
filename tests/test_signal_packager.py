"""
Unit tests for sim/signal_packager.py -- AUTOSAR COM signal<->I-PDU mapping
layer (SR-11). Standalone module, no dedicated VTC of its own; supports
VTC-SR-11's protected-region-config requirement (see
design/lld/LLD_signal_packager.md).
"""
import pytest

from sim.signal_packager import (
    SignalLayout,
    SignalPackager,
    SignalValueOutOfRangeError,
    UnknownSignalError,
)

PDU_ID = 0x100


@pytest.fixture
def signal_table():
    return {
        "VehicleSpeed": SignalLayout(
            signal_name="VehicleSpeed",
            pdu_id=PDU_ID,
            pdu_length_bytes=2,
            offset_bits=0,
            width_bits=16,
            factor=0.01,
            offset=0.0,
        ),
        "BrakePressed": SignalLayout(
            signal_name="BrakePressed",
            pdu_id=0x101,
            pdu_length_bytes=1,
            offset_bits=0,
            width_bits=1,
            factor=1.0,
            offset=0.0,
        ),
    }


@pytest.fixture
def packager(signal_table):
    return SignalPackager(ecu_id="ECU_A", signal_table=signal_table)


class TestSignalPackager:
    def test_pack_signal_returns_full_pdu_buffer(self, packager):
        """pack_signal() returns the full Authentic I-PDU buffer for the
        signal's pdu_id, with this signal's bits set."""
        buf = packager.pack_signal("VehicleSpeed", 100.0)
        assert isinstance(buf, bytes)
        assert len(buf) == 2

    def test_pack_unpack_round_trip_recovers_original_value(self, packager):
        """pack_signal()/unpack_signal() round-trip recovers the physical value."""
        buf = packager.pack_signal("VehicleSpeed", 100.0)
        value = packager.unpack_signal(buf, "VehicleSpeed")
        assert value == pytest.approx(100.0, abs=0.01)

    def test_pack_unknown_signal_raises(self, packager):
        with pytest.raises(UnknownSignalError):
            packager.pack_signal("NotASignal", 1)

    def test_unpack_unknown_signal_raises(self, packager):
        with pytest.raises(UnknownSignalError):
            packager.unpack_signal(b"\x00\x00", "NotASignal")

    def test_unpack_wrong_length_pdu_bytes_raises(self, packager):
        with pytest.raises(UnknownSignalError):
            packager.unpack_signal(b"\x00\x00\x00", "VehicleSpeed")

    def test_pack_value_out_of_range_raises(self, packager):
        """A value scaling to a raw > 2**width_bits - 1 raises SignalValueOutOfRangeError."""
        with pytest.raises(SignalValueOutOfRangeError):
            packager.pack_signal("VehicleSpeed", 1_000_000.0)

    def test_send_signal_returns_packed_authentic_pdu(self, packager):
        """send_signal() packs and returns the Authentic I-PDU bytes for signal_name."""
        buf = packager.send_signal("VehicleSpeed", 50.0)
        assert len(buf) == 2
        assert packager.unpack_signal(buf, "VehicleSpeed") == pytest.approx(50.0, abs=0.01)

    def test_two_signals_in_same_pdu_do_not_clobber_each_other(self):
        table = {
            "A": SignalLayout("A", PDU_ID, 2, offset_bits=0, width_bits=8, factor=1.0, offset=0.0),
            "B": SignalLayout("B", PDU_ID, 2, offset_bits=8, width_bits=8, factor=1.0, offset=0.0),
        }
        packager = SignalPackager(ecu_id="ECU_A", signal_table=table)

        packager.pack_signal("A", 5)
        buf = packager.pack_signal("B", 200)

        assert packager.unpack_signal(buf, "A") == 5
        assert packager.unpack_signal(buf, "B") == 200

    def test_unpack_signal_from_pdu_fans_out_to_registered_handler(self, packager):
        """unpack_signal_from_pdu() decodes every signal mapped to pdu_id and
        forwards (signal_name, value) pairs to the registered handler."""
        decoded = []
        packager.register_signal_handler(lambda name, value: decoded.append((name, value)))

        buf = packager.pack_signal("VehicleSpeed", 75.0)
        packager.unpack_signal_from_pdu(PDU_ID, buf)

        assert len(decoded) == 1
        name, value = decoded[0]
        assert name == "VehicleSpeed"
        assert value == pytest.approx(75.0, abs=0.01)

    def test_unpack_signal_from_pdu_without_handler_does_not_raise(self, packager):
        buf = packager.pack_signal("VehicleSpeed", 10.0)
        packager.unpack_signal_from_pdu(PDU_ID, buf)  # no handler registered

    def test_get_status_lists_configured_signals(self, packager):
        status = packager.get_status()
        assert status["ecu_id"] == "ECU_A"
        names = {s["signal_name"] for s in status["signals"]}
        assert names == {"VehicleSpeed", "BrakePressed"}
