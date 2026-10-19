"""Tests for the ArduPilot .BIN reader and the code tables behind it."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.analysis import ardupilot
from app.analysis.dataflash import read_dataflash
from app.analysis.errors import UnreadableLogError
from app.models import LogLevel
from tests.builders import DataflashBuilder

SEC = 1_000_000


def test_records_are_decoded_with_boot_relative_time(tmp_path: Path) -> None:
    path = (DataflashBuilder().msg(1 * SEC, "ArduCopter V4.5.2 (test)").mode(2 * SEC, 4)
            .ev(3 * SEC, 10).ev(4 * SEC, 11).write(tmp_path / "a.BIN"))
    a = read_dataflash(path)
    assert [e.message for e in a.result.events] == [
        "ArduCopter V4.5.2 (test)", "Mode: GUIDED", "Armed", "Disarmed"]
    assert all(e.timestamp is None for e in a.result.events)  # never invent wall-clock time
    assert [e.elapsed_s for e in a.result.events] == [1.0, 2.0, 3.0, 4.0]
    assert a.stats["firmware"] == "ArduCopter V4.5.2 (test)"
    assert a.stats["duration_s"] == 3.0 and "boot-relative" in a.stats["time_base"]
    assert a.source_type == "bin" and a.findings == ()


def test_crash_check_error_is_critical_and_decoded(tmp_path: Path) -> None:
    path = DataflashBuilder().msg(SEC, "ArduCopter").err(2 * SEC, 12, 1).write(tmp_path / "c.BIN")
    a = read_dataflash(path)
    [f] = a.findings
    assert f.kind == "ardupilot_error" and f.severity is LogLevel.CRITICAL
    assert f.title == "CRASH_CHECK: crash detected"
    ev = next(e for e in a.result.events if e.line_number == f.event_number)
    assert ev.level is LogLevel.CRITICAL and "subsys 12, code 1" in ev.message


def test_resolved_error_is_info_and_not_a_finding(tmp_path: Path) -> None:
    path = DataflashBuilder().msg(SEC, "x").err(2 * SEC, 6, 0).write(tmp_path / "r.BIN")
    a = read_dataflash(path)
    assert a.findings == ()
    assert any(e.level is LogLevel.INFO and "failsafe resolved" in e.message
               for e in a.result.events)


def test_failsafe_and_unknown_codes(tmp_path: Path) -> None:
    path = (DataflashBuilder().msg(SEC, "x").err(2 * SEC, 6, 1).err(3 * SEC, 99, 7)
            .write(tmp_path / "f.BIN"))
    titles = [f.title for f in read_dataflash(path).findings]
    assert titles == ["FAILSAFE_BATT: failsafe occurred", "subsystem 99: code 7"]


def test_lost_gps_event_is_warning_and_unknown_events_are_skipped(tmp_path: Path) -> None:
    path = (DataflashBuilder().msg(SEC, "x").ev(2 * SEC, 19).ev(3 * SEC, 200)
            .write(tmp_path / "e.BIN"))
    events = read_dataflash(path).result.events
    assert [(e.level, e.message) for e in events[1:]] == [(LogLevel.WARNING, "Lost GPS")]


def test_msg_keywords_flag_but_never_invent_severity(tmp_path: Path) -> None:
    path = (DataflashBuilder().msg(SEC, "Crash: Disarming").msg(2 * SEC, "RC Protocol: SITL")
            .write(tmp_path / "k.BIN"))
    a = read_dataflash(path)
    assert all(e.level is LogLevel.INFO for e in a.result.events)  # MSG has no severity
    [f] = a.findings
    assert f.kind == "notable_message" and "keyword" in f.detail.lower()
    assert f.event_number == 1


@pytest.mark.parametrize("content", [b"", b"\x00" * 600, b"not a dataflash log" * 50])
def test_unreadable_bin_raises(tmp_path: Path, content: bytes) -> None:
    path = tmp_path / "bad.BIN"
    path.write_bytes(content)
    with pytest.raises(UnreadableLogError):
        read_dataflash(path)


def test_reader_noise_does_not_leak_to_stdout(
    tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    path = DataflashBuilder().msg(SEC, "x").write(tmp_path / "n.BIN")
    path.write_bytes(b"\x01\x02\x03" * 400 + path.read_bytes())  # leading garbage -> warnings
    a = read_dataflash(path)
    out = capfd.readouterr()
    assert "bad header" not in out.out + out.err
    assert a.stats["reader_warnings"]


# ---- tables copied from AP_Logger.h ----

@pytest.mark.parametrize("sub, code, text", [
    (12, 1, "crash detected"), (12, 2, "loss of control"), (16, 2, "bad variance"),
    (16, 0, "variance cleared"), (6, 1, "failsafe occurred"), (5, 0, "failsafe resolved"),
    (11, 2, "glitch"), (30, 1, "internal errors detected"), (2, 2, "late frame"),
    (3, 4, "unhealthy"), (3, 1, "failed to initialise / occurred"), (3, 77, "code 77"),
])
def test_error_descriptions(sub: int, code: int, text: str) -> None:
    assert ardupilot.error_description(sub, code) == text


def test_subsystem_names_and_crash_predicate() -> None:
    assert ardupilot.subsystem_name(12) == "CRASH_CHECK"
    assert ardupilot.subsystem_name(250) == "subsystem 250"
    assert ardupilot.is_crash_error(12, 1) and ardupilot.is_crash_error(12, 2)
    assert not ardupilot.is_crash_error(12, 0) and not ardupilot.is_crash_error(16, 1)
