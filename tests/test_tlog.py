"""Tests for the .tlog reader and mission-transfer analysis (synthetic packets only)."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.analysis.errors import UnreadableLogError
from app.analysis.tlog import read_tlog
from app.models import LogLevel
from tests.builders import (
    T0,
    TlogBuilder,
    command_ack,
    mission_ack,
    mission_count,
    mission_item,
    mission_request,
    mission_request_list,
)

INVALID_SEQUENCE = 13  # MAV_MISSION_INVALID_SEQUENCE
MAV_RESULT_FAILED = 4
MAV_CMD_GET_HOME_POSITION = 410


def messages(analysis_events: object) -> list[str]:
    return [e.message for e in analysis_events]  # type: ignore[attr-defined]


def upload(b: TlogBuilder, t: float, items: int, twice: bool = False) -> float:
    """GCS uploads ``items`` items cleanly; returns the time after the ACK."""
    b.gcs(t, mission_count(items), twice)
    for seq in range(items):
        t += 0.1
        b.vehicle(t, mission_request(seq), twice)
        t += 0.1
        b.gcs(t, mission_item(seq), twice)
    t += 0.1
    b.vehicle(t, mission_ack(0), twice)
    return t


def test_status_text_severity_arm_and_mode(tmp_path: Path) -> None:
    b = TlogBuilder()
    b.heartbeat(T0).heartbeat(T0 + 1, armed=True)
    b.status(T0 + 1.5, 4, "Battery low").status(T0 + 2, 3, "Bad AHRS").status(T0 + 2.2, 2, "Fire")
    b.status(T0 + 2.4, 6, "all good").status(T0 + 2.6, 7, "debug text")
    b.heartbeat(T0 + 3, armed=True, mode=3).heartbeat(T0 + 4, armed=False, mode=3)
    a = read_tlog(b.write(tmp_path / "a.tlog"))
    by_text = {e.message: e.level for e in a.result.events}
    assert by_text["Battery low"] is LogLevel.WARNING
    assert by_text["Bad AHRS"] is LogLevel.ERROR
    assert by_text["Fire"] is LogLevel.CRITICAL
    assert by_text["all good"] is LogLevel.INFO and by_text["debug text"] is LogLevel.DEBUG
    assert "Armed" in by_text and "Disarmed" in by_text
    assert "Mode changed: GUIDED -> AUTO" in by_text
    assert a.stats["armed_s"] == 3.0 and a.stats["duration_s"] == 4.0
    assert a.stats["vehicles"]["sys1"]["vehicle_type"] == "MAV_TYPE_QUADROTOR"
    assert a.source_type == "tlog" and a.findings == ()


def test_event_timestamps_are_utc_from_the_file(tmp_path: Path) -> None:
    b = TlogBuilder().heartbeat(T0).status(T0 + 1, 6, "hello")
    a = read_tlog(b.write(tmp_path / "t.tlog"))
    ev = a.result.events[0]
    assert ev.timestamp is not None and ev.timestamp.utcoffset().total_seconds() == 0  # type: ignore[union-attr]
    assert ev.timestamp.timestamp() == pytest.approx(T0 + 1, abs=1e-3)


def test_failed_upload_is_pinned_to_the_item(tmp_path: Path) -> None:
    b = TlogBuilder().heartbeat(T0)
    b.gcs(T0 + 1, mission_count(5))
    b.vehicle(T0 + 1.1, mission_request(0)).gcs(T0 + 1.2, mission_item(0))
    b.vehicle(T0 + 1.3, mission_request(1)).gcs(T0 + 1.4, mission_item(1))
    b.vehicle(T0 + 1.5, mission_request(2))
    b.vehicle(T0 + 3.5, mission_request(2))  # item 2 never arrived: asked again
    b.vehicle(T0 + 5, mission_ack(INVALID_SEQUENCE))
    a = read_tlog(b.write(tmp_path / "up.tlog"))
    failed = [f for f in a.findings if f.kind == "mission_transfer_failed"]
    assert len(failed) == 1
    f = failed[0]
    assert f.severity is LogLevel.ERROR and f.mission_item == 2
    assert "MAV_MISSION_INVALID_SEQUENCE" in f.title
    assert "2/5 items delivered" in f.detail and "1 retries" in f.detail
    event = next(e for e in a.result.events if e.line_number == f.event_number)
    assert event.mission_item == 2 and event.level is LogLevel.ERROR
    assert any("requested again" in m for m in messages(a.result.events))


def test_item_zero_failure_keeps_zero_not_none(tmp_path: Path) -> None:
    b = TlogBuilder().heartbeat(T0)
    b.gcs(T0 + 1, mission_count(3)).vehicle(T0 + 1.1, mission_request(0))
    b.vehicle(T0 + 2, mission_ack(INVALID_SEQUENCE))
    a = read_tlog(b.write(tmp_path / "z.tlog"))
    assert a.findings[0].mission_item == 0


def test_upload_that_never_finishes_is_flagged(tmp_path: Path) -> None:
    b = TlogBuilder().heartbeat(T0)
    b.gcs(T0 + 1, mission_count(3)).vehicle(T0 + 1.1, mission_request(0))
    b.gcs(T0 + 1.2, mission_item(0)).vehicle(T0 + 1.3, mission_request(1))
    b.heartbeat(T0 + 30)
    a = read_tlog(b.write(tmp_path / "inc.tlog"))
    [f] = [f for f in a.findings if f.kind == "mission_transfer_incomplete"]
    assert f.severity is LogLevel.WARNING and f.mission_item == 1
    assert "stalled after item 1" in f.title


def test_success_after_retries_is_a_warning(tmp_path: Path) -> None:
    b = TlogBuilder().heartbeat(T0)
    b.gcs(T0 + 1, mission_count(2)).vehicle(T0 + 1.1, mission_request(0))
    b.vehicle(T0 + 2.5, mission_request(0)).gcs(T0 + 2.6, mission_item(0))
    b.vehicle(T0 + 2.7, mission_request(1)).gcs(T0 + 2.8, mission_item(1))
    b.vehicle(T0 + 2.9, mission_ack(0))
    a = read_tlog(b.write(tmp_path / "retry.tlog"))
    assert [f.kind for f in a.findings] == ["mission_transfer_retries"]
    assert a.findings[0].severity is LogLevel.WARNING


def test_clean_upload_has_no_findings(tmp_path: Path) -> None:
    b = TlogBuilder().heartbeat(T0)
    upload(b, T0 + 1, 3)
    a = read_tlog(b.write(tmp_path / "ok.tlog"))
    assert a.findings == ()
    assert a.stats["mission_transfers"][0]["result"] == "MAV_MISSION_ACCEPTED"
    assert a.stats["mission_transfers"][0]["delivered"] == 3


def test_mission_fence_and_rally_transfers_do_not_interfere(tmp_path: Path) -> None:
    b = TlogBuilder().heartbeat(T0)
    b.gcs(T0 + 1, mission_request_list(0)).gcs(T0 + 1.01, mission_request_list(1))
    b.vehicle(T0 + 1.1, mission_count(0, 0)).vehicle(T0 + 1.11, mission_count(0, 1))
    b.gcs(T0 + 1.2, mission_ack(0, 0)).gcs(T0 + 1.21, mission_ack(0, 1))
    a = read_tlog(b.write(tmp_path / "multi.tlog"))
    assert a.findings == ()
    kinds = sorted(t["kind"] for t in a.stats["mission_transfers"])
    assert kinds == ["fence", "mission"]


def test_duplicate_packets_from_two_links_are_merged(tmp_path: Path) -> None:
    def build(twice: bool, name: str) -> list[str]:
        b = TlogBuilder().heartbeat(T0, twice=twice).status(T0 + 0.5, 4, "warn", twice=twice)
        upload(b, T0 + 1, 2, twice=twice)
        b.vehicle(T0 + 9, command_ack(MAV_CMD_GET_HOME_POSITION, MAV_RESULT_FAILED), twice)
        return messages(read_tlog(b.write(tmp_path / name)).result.events)

    assert build(True, "dup.tlog") == build(False, "single.tlog")


def test_heartbeat_gap_is_reported(tmp_path: Path) -> None:
    b = TlogBuilder().heartbeat(T0).heartbeat(T0 + 1).heartbeat(T0 + 2).heartbeat(T0 + 20)
    path = b.write(tmp_path / "gap.tlog")
    a = read_tlog(path)
    [f] = a.findings
    assert f.kind == "heartbeat_gap" and "18.0s" in f.title
    assert a.stats["heartbeat_gaps"] == 1
    assert read_tlog(path, max_gap_s=30).findings == ()  # threshold is configurable


def test_gcs_heartbeats_are_not_vehicle_heartbeats(tmp_path: Path) -> None:
    b = TlogBuilder().heartbeat(T0).gcs_heartbeat(T0 + 1).gcs_heartbeat(T0 + 40)
    b.heartbeat(T0 + 41)
    a = read_tlog(b.write(tmp_path / "g.tlog"))
    assert [f.kind for f in a.findings] == ["heartbeat_gap"]  # only the vehicle's own gap
    assert list(a.stats["vehicles"]) == ["sys1"]


def test_rejected_commands_are_aggregated_into_one_finding(tmp_path: Path) -> None:
    b = TlogBuilder().heartbeat(T0)
    for i in range(3):
        b.vehicle(T0 + 1 + 5 * i, command_ack(MAV_CMD_GET_HOME_POSITION, MAV_RESULT_FAILED))
    b.vehicle(T0 + 30, command_ack(MAV_CMD_GET_HOME_POSITION, 0))  # accepted: ignored
    a = read_tlog(b.write(tmp_path / "cmd.tlog"))
    [f] = a.findings
    assert f.kind == "command_rejected" and "3x" in f.title
    assert "MAV_CMD_GET_HOME_POSITION" in f.title
    assert sum(1 for e in a.result.events if e.mav_cmd == MAV_CMD_GET_HOME_POSITION) == 3


def test_chunked_status_text_is_reassembled_once(tmp_path: Path) -> None:
    head = "A" * 50
    b = TlogBuilder().heartbeat(T0)
    b.status(T0 + 1, 6, head, msg_id=7, chunk=0, twice=True)
    b.status(T0 + 1.001, 6, "tail", msg_id=7, chunk=1, twice=True)
    a = read_tlog(b.write(tmp_path / "chunk.tlog"))
    texts = [e.message for e in a.result.events]
    assert texts == [head + "tail"]


@pytest.mark.parametrize("content", [b"", b"this is definitely not a tlog" * 20])
def test_unreadable_files_raise_clear_error(tmp_path: Path, content: bytes) -> None:
    path = tmp_path / "bad.tlog"
    path.write_bytes(content)
    with pytest.raises(UnreadableLogError, match="no MAVLink packets"):
        read_tlog(path)


def test_truncated_file_still_yields_what_it_can(tmp_path: Path) -> None:
    b = TlogBuilder().heartbeat(T0).status(T0 + 1, 4, "kept")
    path = b.write(tmp_path / "t.tlog")
    path.write_bytes(path.read_bytes() + b"\x00\x01\x02garbage-tail")
    a = read_tlog(path)
    assert "kept" in messages(a.result.events)
