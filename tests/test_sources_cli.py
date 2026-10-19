"""Format detection, the loader, the CLI on binary/crash inputs, and AI integration."""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

import pytest

from app.ai.prompt import build_prompt
from app.ai.validation import parse_diagnosis
from app.analysis.detect import detect_format
from app.analysis.errors import MissingDependencyError, UnsupportedFormatError
from app.analysis.loader import analyze_path
from app.cli import EXIT_INPUT_ERROR, EXIT_OK, main
from tests.builders import (
    T0,
    DataflashBuilder,
    TlogBuilder,
    mission_ack,
    mission_count,
    mission_request,
)
from tests.test_crash import ABRT_FRAMES, SEGV_FRAMES, block

SEC = 1_000_000


@pytest.fixture
def tlog(tmp_path: Path) -> Path:
    b = TlogBuilder().heartbeat(T0).status(T0 + 1, 3, "Bad AHRS")
    b.gcs(T0 + 2, mission_count(4)).vehicle(T0 + 2.1, mission_request(0))
    b.vehicle(T0 + 3, mission_ack(13)).heartbeat(T0 + 4)
    return b.write(tmp_path / "flight.tlog")


@pytest.fixture
def bin_file(tmp_path: Path) -> Path:
    return (DataflashBuilder().msg(SEC, "ArduCopter V4.5.2 (test)").err(2 * SEC, 12, 1)
            .write(tmp_path / "00000001.BIN"))


@pytest.fixture
def crash_file(tmp_path: Path) -> Path:
    path = tmp_path / "crashes.txt"
    path.write_text(block(7, "11 (SEGV)", "Fri 2026-08-21 11:48:10", SEGV_FRAMES)
                    + block(8, "6 (ABRT)", "Fri 2026-08-22 11:48:10", ABRT_FRAMES),
                    encoding="utf-8")
    return path


# ---------------- detection ----------------

def test_detects_by_extension_and_by_content(tlog: Path, bin_file: Path, tmp_path: Path) -> None:
    assert detect_format(tlog) == "tlog" and detect_format(bin_file) == "bin"
    bare_tlog = tmp_path / "recording"
    bare_tlog.write_bytes(tlog.read_bytes())
    bare_bin = tmp_path / "dataflash"
    bare_bin.write_bytes(bin_file.read_bytes())
    assert detect_format(bare_tlog) == "tlog" and detect_format(bare_bin) == "bin"


def test_detects_crash_text_and_plain_logs(crash_file: Path, tmp_path: Path) -> None:
    assert detect_format(crash_file) == "crash"
    plain = tmp_path / "a.log"
    plain.write_text("2024-03-14 10:15:04 [INFO] hello\n", encoding="utf-8")
    assert detect_format(plain) == "text"
    other = tmp_path / "notes.txt"
    other.write_text("nothing special here\n", encoding="utf-8")
    assert detect_format(other) == "text"


def test_log_line_that_mentions_segfault_stays_a_text_log(tmp_path: Path) -> None:
    path = tmp_path / "gcs.log"
    path.write_text("\n".join(f"2024-03-14 10:15:0{i} [INFO] step {i}" for i in range(5))
                    + "\n2024-03-14 10:15:09 [ERROR] helper reported Segmentation fault\n",
                    encoding="utf-8")
    assert detect_format(path) == "text"


def test_unknown_binary_is_unsupported(tmp_path: Path) -> None:
    path = tmp_path / "blob"
    path.write_bytes(b"\xff\xfe\x00\x01" * 100)
    with pytest.raises(UnsupportedFormatError, match="UTF-8"):
        detect_format(path)


def test_loader_respects_forced_format_and_rejects_unknown(crash_file: Path) -> None:
    assert analyze_path(crash_file, "crash").source_type == "crash"
    assert analyze_path(crash_file, "text").source_type == "text"
    with pytest.raises(UnsupportedFormatError, match="unknown format"):
        analyze_path(crash_file, "zip")


# ---------------- CLI on each source ----------------

def test_cli_tlog_text_output(tlog: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main([str(tlog)]) == EXIT_OK
    out = capsys.readouterr().out
    assert "Source: tlog" in out and "Findings (1):" in out
    assert "Mission upload failed: MAV_MISSION_INVALID_SEQUENCE" in out
    assert "Lines read" not in out  # text-only counters are not shown for binary logs


def test_cli_tlog_json(tlog: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main([str(tlog), "--json"]) == EXIT_OK
    data = json.loads(capsys.readouterr().out)
    assert data["source_type"] == "tlog" and data["stats"]["duration_s"] == 4.0
    assert data["findings"][0]["kind"] == "mission_transfer_failed"
    assert data["findings"][0]["mission_item"] == 0
    assert {"total_events", "events", "error_events", "counts_by_level"} <= set(data)


def test_cli_max_gap_option(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = TlogBuilder().heartbeat(T0).heartbeat(T0 + 8).write(tmp_path / "g.tlog")
    main([str(path), "--json"])
    assert json.loads(capsys.readouterr().out)["stats"]["heartbeat_gaps"] == 1
    main([str(path), "--json", "--max-gap", "10"])
    assert json.loads(capsys.readouterr().out)["stats"]["heartbeat_gaps"] == 0


def test_cli_bin_output_shows_boot_relative_time(
    bin_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main([str(bin_file)]) == EXIT_OK
    out = capsys.readouterr().out
    assert "Source: bin" in out and "t+2.00s" in out and "CRASH_CHECK: crash detected" in out


def test_cli_crash_file_without_addr2line(crash_file: Path,
                                           capsys: pytest.CaptureFixture[str]) -> None:
    assert main([str(crash_file), "--no-symbols"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "Source: crash" in out and "Crashes: 2" in out and "core_missing" not in out
    assert "Core dump file missing for 2 of 2" in out


def fake_coredumpctl(text: str):  # type: ignore[no-untyped-def]
    def runner(argv: Sequence[str]) -> tuple[int, str]:
        assert argv[0] == "coredumpctl"
        return 0, text
    return runner


def test_cli_system_crashes_uses_injected_runner(capsys: pytest.CaptureFixture[str]) -> None:
    text = block(7, "11 (SEGV)", "Fri 2026-08-21 11:48:10", SEGV_FRAMES)
    code = main(["--system-crashes", "MYAPP", "--no-symbols"],
                crash_runner=fake_coredumpctl(text))
    assert code == EXIT_OK and "Crashes: 1" in capsys.readouterr().out


def test_cli_system_crashes_when_nothing_recorded(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["--system-crashes", "--no-symbols"], crash_runner=lambda argv: (1, ""))
    assert code == EXIT_INPUT_ERROR
    assert "no coredump records" in capsys.readouterr().err


def test_cli_argument_combinations(tlog: Path) -> None:
    for argv in ([], [str(tlog), "--system-crashes"]):
        with pytest.raises(SystemExit) as exc:
            main(argv)
        assert exc.value.code == 2


def test_cli_unknown_binary_and_missing_dependency(
    tmp_path: Path, tlog: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    blob = tmp_path / "blob"
    blob.write_bytes(b"\xff\x00" * 50)
    assert main([str(blob)]) == EXIT_INPUT_ERROR
    assert "unrecognised binary file" in capsys.readouterr().err

    def no_pymavlink() -> None:
        raise MissingDependencyError("reading .tlog/.bin needs pymavlink; run: pip install pymavlink")

    monkeypatch.setattr("app.analysis.tlog.import_pymavlink", no_pymavlink)
    assert main([str(tlog)]) == EXIT_INPUT_ERROR
    assert "pip install pymavlink" in capsys.readouterr().err


def test_cli_corrupt_tlog_is_a_clean_error(tmp_path: Path,
                                           capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "bad.tlog"
    path.write_bytes(b"garbage" * 40)
    assert main([str(path)]) == EXIT_INPUT_ERROR
    assert "error:" in capsys.readouterr().err


# ---------------- AI integration ----------------

class RecordingProvider:
    name, model = "fake", "fake-model"

    def __init__(self, reply: str) -> None:
        self.reply = reply
        self.user = ""

    def complete(self, system: str, user: str) -> str:
        self.user = user
        return self.reply


def _payload(user: str) -> dict[str, object]:
    return json.loads(user.split("<log_data>")[1].split("</log_data>")[0])  # type: ignore[no-any-return]


def test_prompt_contains_findings_and_pulls_in_their_events(bin_file: Path) -> None:
    a = analyze_path(bin_file)
    prompt = build_prompt(a.result, findings=a.findings, source_type="bin")
    assert prompt is not None
    payload = _payload(prompt.user)
    assert payload["source_type"] == "bin"
    titles = [f["title"] for f in payload["deterministic_findings"]]  # type: ignore[attr-defined]
    assert "CRASH_CHECK: crash detected" in titles


def test_keyword_finding_on_info_event_is_still_sent(tmp_path: Path) -> None:
    path = DataflashBuilder().msg(SEC, "ok").msg(2 * SEC, "Crash: Disarming").write(tmp_path / "k.BIN")
    a = analyze_path(path)
    assert build_prompt(a.result) is None  # no WARNING+ events on their own...
    prompt = build_prompt(a.result, findings=a.findings, source_type="bin")  # ...but a finding
    assert prompt is not None and "Crash: Disarming" in prompt.user


def test_home_directories_are_scrubbed_from_the_prompt(crash_file: Path, tmp_path: Path) -> None:
    a = analyze_path(crash_file, symbolize=None)
    crash_prompt = build_prompt(a.result, findings=a.findings, source_type="crash")
    assert crash_prompt is not None and "/home/dev" not in crash_prompt.user

    log = tmp_path / "gcs.log"
    log.write_text("2024-03-14 10:15:04 [ERROR] cannot open /home/alice/missions/plan.waypoints\n",
                   encoding="utf-8")
    text = analyze_path(log)
    prompt = build_prompt(text.result)
    assert prompt is not None
    assert "alice" not in prompt.user and "~/missions/plan.waypoints" in prompt.user


def test_cli_show_prompt_for_a_crash_file(crash_file: Path,
                                           capsys: pytest.CaptureFixture[str]) -> None:
    assert main([str(crash_file), "--no-symbols", "--diagnose", "--show-prompt"],
                environ={}) == EXIT_OK
    out = capsys.readouterr().out
    assert "deterministic_findings" in out and "/home/dev" not in out


def test_cli_diagnose_a_tlog_end_to_end(tlog: Path, capsys: pytest.CaptureFixture[str]) -> None:
    reply = json.dumps({
        "summary": "Upload failed early.",
        "evidence": [{"line_number": 3, "observation": "rejected"}],
        "hypotheses": [{"description": "Vehicle rejected item 0", "confidence": "low",
                        "supporting_lines": [3], "reasoning": "ack came right after request 0"}],
        "recommended_checks": ["Inspect item 0 parameters"],
        "confidence": "low", "confidence_explanation": "one transfer only"})
    provider = RecordingProvider(reply)
    assert main([str(tlog), "--diagnose"], provider=provider) == EXIT_OK
    out = capsys.readouterr().out
    assert "Hypotheses (unconfirmed)" in out and "MAV_MISSION_INVALID_SEQUENCE" in provider.user


def test_item_numbers_named_only_by_findings_are_not_flagged(tlog: Path) -> None:
    a = analyze_path(tlog)
    prompt = build_prompt(a.result, findings=a.findings, source_type="tlog")
    assert prompt is not None and 0 in prompt.allowed_items
    reply = json.dumps({
        "summary": "Failed after item 0.", "evidence": [], "hypotheses": [],
        "recommended_checks": ["recheck item 0"], "confidence": "low",
        "confidence_explanation": "x"})
    d = parse_diagnosis(reply, prompt.events, provider="p", model="m",
                        extra_items=prompt.allowed_items)
    assert not any("mission item" in w for w in d.warnings)
