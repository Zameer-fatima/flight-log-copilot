"""Tests for the parser, serialization and CLI. All offline and deterministic."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from app.cli import EXIT_INPUT_ERROR, EXIT_OK, main
from app.log_parser import parse_logs
from app.models import LogLevel
from app.serialization import result_to_dict, result_to_json

SAMPLE = Path(__file__).resolve().parent.parent / "sample_data" / "flight.log"
TS = "2024-03-14 10:15:02"


def test_basic_parsing() -> None:
    result = parse_logs(f"{TS}.250 [INFO] Mission upload started\n")
    assert result.total_events == 1
    event = result.events[0]
    assert event.line_number == 1
    assert event.level is LogLevel.INFO
    assert event.message == "Mission upload started"
    assert event.timestamp is not None
    assert event.timestamp.year == 2024 and event.timestamp.microsecond == 250000


def test_severity_counts() -> None:
    text = "\n".join(f"{TS} {lvl} msg" for lvl in
                     ["DEBUG", "INFO", "INFO", "WARNING", "ERROR", "ERROR", "CRITICAL"])
    counts = parse_logs(text).counts_by_level
    assert counts == {LogLevel.DEBUG: 1, LogLevel.INFO: 2, LogLevel.WARNING: 1,
                      LogLevel.ERROR: 2, LogLevel.CRITICAL: 1}


def test_counts_include_zero_levels() -> None:
    assert all(n == 0 for n in parse_logs("").counts_by_level.values())


@pytest.mark.parametrize("message, item", [
    ("Sending mission item 19", 19),
    ("Mission transfer failed at item 7", 7),
    ("Item #19 Command MAV_CMD(94)", 19),
    ("item#5 ok", 5),
])
def test_mission_item_extraction(message: str, item: int) -> None:
    assert parse_logs(f"{TS} [ERROR] {message}").events[0].mission_item == item


def test_item_and_mav_cmd_recognised() -> None:
    event = parse_logs(f"{TS} [DEBUG] Item #19 Command MAV_CMD(94)").events[0]
    assert (event.mission_item, event.mav_cmd) == (19, 94)


def test_missing_mission_item_is_none() -> None:
    event = parse_logs(f"{TS} [ERROR] Telemetry heartbeat timeout").events[0]
    assert event.mission_item is None
    assert event.mav_cmd is None


def test_mission_item_zero_is_distinct_from_missing() -> None:
    zero = parse_logs(f"{TS} [DEBUG] Sending mission item 0").events[0]
    missing = parse_logs(f"{TS} [DEBUG] Sending mission").events[0]
    assert zero.mission_item == 0 and zero.mission_item is not None
    assert missing.mission_item is None


@pytest.mark.parametrize("message", ["subitem 3 done", "items 3 queued", "item 7abc", "item"])
def test_item_regex_does_not_overmatch(message: str) -> None:
    assert parse_logs(f"{TS} [INFO] {message}").events[0].mission_item is None


@pytest.mark.parametrize("text", ["", "\n\n", "   \n\t\n"])
def test_empty_and_blank_input(text: str) -> None:
    result = parse_logs(text)
    assert result.total_events == 0 and not result.malformed_lines


def test_blank_lines_skipped_but_line_numbers_kept() -> None:
    result = parse_logs(f"\n{TS} [INFO] a\n\n   \n{TS} [INFO] b\n")
    assert [e.line_number for e in result.events] == [2, 5]
    assert not result.malformed_lines


def test_malformed_lines_preserve_number_and_text() -> None:
    text = f"{TS} [INFO] ok\ngarbage here\n\n  not a log  \n{TS} [INFO] ok2"
    result = parse_logs(text)
    assert result.total_events == 2
    assert [(m.line_number, m.text) for m in result.malformed_lines] == [
        (2, "garbage here"), (4, "  not a log  ")]


def test_missing_timestamp_is_malformed_not_invented() -> None:
    result = parse_logs("[ERROR] no timestamp here")
    assert result.total_events == 0
    assert result.malformed_lines[0].line_number == 1


def test_missing_level_is_malformed() -> None:
    assert len(parse_logs(f"{TS} something happened").malformed_lines) == 1


def test_invalid_calendar_date_is_malformed() -> None:
    result = parse_logs("2024-13-45 10:15:02 [INFO] bad date")
    assert result.total_events == 0
    assert "timestamp" in result.malformed_lines[0].reason


def test_level_prefix_word_is_not_a_level() -> None:
    # Regression guard: "INFORMATION" must not parse as INFO + "RMATION".
    assert len(parse_logs(f"{TS} INFORMATION blah").malformed_lines) == 1


@pytest.mark.parametrize("line", [
    f"{TS} [ERROR] boom",
    f"{TS} error: boom",
    f"{TS}   ErRoR   boom   ",
    f"   {TS}\t[error]\tboom",
    "2024-03-14T10:15:02Z ERROR - boom",
    "2024-03-14T10:15:02,250+0000 [Error]boom",
])
def test_case_and_whitespace_variations(line: str) -> None:
    event = parse_logs(line).events[0]
    assert event.level is LogLevel.ERROR
    assert event.message == "boom"


def test_mixed_levels_and_error_events() -> None:
    text = (f"{TS} [INFO] a\n{TS} [WARNING] b\n{TS} [ERROR] c\n"
            f"{TS} [CRITICAL] d\n{TS} [DEBUG] e")
    result = parse_logs(text)
    assert [e.message for e in result.error_events] == ["c", "d"]


def test_crlf_line_endings() -> None:
    result = parse_logs(f"{TS} [INFO] a\r\n{TS} [ERROR] b\r\n")
    assert result.total_events == 2 and result.events[1].message == "b"


@pytest.mark.parametrize("bad", [None, 42, b"bytes", ["a"]])
def test_non_string_input_raises_type_error(bad: object) -> None:
    with pytest.raises(TypeError, match="log_text must be str"):
        parse_logs(bad)  # type: ignore[arg-type]


def test_json_serialization_round_trip() -> None:
    result = parse_logs(f"{TS} [ERROR] Item #0 failed\nbad line\n")
    data = json.loads(result_to_json(result))
    assert data == result_to_dict(result)
    assert data["total_events"] == 1
    assert data["counts_by_level"]["ERROR"] == 1
    assert data["events"][0]["mission_item"] == 0
    assert data["events"][0]["level"] == "ERROR"
    assert data["error_events"] == data["events"]
    assert data["malformed_lines"][0]["line_number"] == 2


def test_sample_log_expectations() -> None:
    result = parse_logs(SAMPLE.read_text(encoding="utf-8"))
    assert len(result.malformed_lines) == 1
    assert result.counts_by_level[LogLevel.WARNING] == 1
    assert len(result.error_events) == 2
    assert any(e.mission_item == 0 for e in result.events)
    assert any(e.is_error and e.mission_item is None for e in result.events)


# ---- CLI ----

def test_cli_summary(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([str(SAMPLE)]) == EXIT_OK
    out = capsys.readouterr().out
    assert "Parsed events:" in out and "Malformed lines:  1" in out


def test_cli_json_is_valid(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([str(SAMPLE), "--json"]) == EXIT_OK
    data = json.loads(capsys.readouterr().out)
    assert data["total_events"] == len(data["events"])


def test_cli_errors_only(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([str(SAMPLE), "--errors-only"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "Mission transfer failed" in out and "Sending mission item" not in out


def test_cli_errors_only_json(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([str(SAMPLE), "--json", "--errors-only"]) == EXIT_OK
    data = json.loads(capsys.readouterr().out)
    assert {e["level"] for e in data["events"]} <= {"ERROR", "CRITICAL"}


def test_cli_missing_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main([str(tmp_path / "nope.log")]) == EXIT_INPUT_ERROR
    assert "file not found" in capsys.readouterr().err


def test_cli_directory_is_input_error(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main([str(tmp_path)]) == EXIT_INPUT_ERROR
    assert "cannot read" in capsys.readouterr().err


@pytest.mark.skipif(os.name == "nt" or os.geteuid() == 0, reason="needs POSIX non-root")
def test_cli_unreadable_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "locked.log"
    path.write_text(f"{TS} [INFO] x\n", encoding="utf-8")
    path.chmod(0)
    try:
        assert main([str(path)]) == EXIT_INPUT_ERROR
    finally:
        path.chmod(0o600)
    assert "cannot read" in capsys.readouterr().err


def test_cli_non_utf8_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "bin.log"
    path.write_bytes(b"\xff\xfe\x00bad")
    assert main([str(path)]) == EXIT_INPUT_ERROR
    assert "UTF-8" in capsys.readouterr().err


def test_cli_missing_argument_exits_2() -> None:
    with pytest.raises(SystemExit) as exc:
        main([])
    assert exc.value.code == 2
