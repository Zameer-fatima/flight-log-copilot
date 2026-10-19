"""Tests for application-crash analysis (coredumpctl / gdb / console text)."""

from __future__ import annotations

import subprocess
from collections.abc import Sequence

import pytest

from app.analysis.crash import (
    SIGNAL_MEANING,
    analyze_crash_text,
    collect_system_crashes,
    looks_like_crash,
    parse_crash_text,
)
from app.analysis.errors import AnalysisError
from app.models import LogLevel

QT = "/opt/qt/lib/libQt6Core.so.6.6.3"
LIBC = "/lib/x86_64-linux-gnu/libc.so.6"


def block(pid: int, sig: str, ts: str, frames: list[str], core: bool = False,
          exe: str = "/home/dev/app/build/MYAPP") -> str:
    storage = "/var/lib/systemd/coredump/core.MYAPP" + ("" if core else " (missing)")
    body = "\n".join(f"                {f}" for f in frames)
    return f"""           PID: {pid} (MYAPP)
           UID: 1000 (dev)
        Signal: {sig}
     Timestamp: {ts} IST (1 week ago)
  Command Line: {exe}
    Executable: {exe}
       Storage: {storage}
       Message: Process {pid} (MYAPP) of user 1000 dumped core.

                Stack trace of thread {pid}:
{body}

"""


SEGV_FRAMES = [f"#0  0x00007f0000b2845 n/a ({QT} + 0x1b2845)",
               "#1  0x0000000101000014 n/a (n/a + 0x0)"]
ABRT_FRAMES = [
    f"#0  0x00007f00969fc __pthread_kill_implementation ({LIBC} + 0x969fc)",
    f"#1  0x00007f0042476 raise ({LIBC} + 0x42476)",
    f"#2  0x00007f00287f3 abort ({LIBC} + 0x287f3)",
    f"#3  0x00007f0089637 __libc_message ({LIBC} + 0x89637)",
    f"#4  0x00007f00a0cbc malloc_printerr ({LIBC} + 0xa0cbc)",
    f"#5  0x00007f00a2a14 _int_free ({LIBC} + 0xa2a14)",
    f"#6  0x00007f00a5413 free ({LIBC} + 0xa5413)",
    f"#7  0x00007f001cd1f0 n/a ({QT} + 0x1cd1f0)",
]
TABLE = {(QT, 0x1b2845): "QObject::property(char const*) const",
         (QT, 0x1cd1f0): "QVariant::~QVariant()"}


def fake_symbolizer(module: str, offset: int) -> str | None:
    return TABLE.get((module, offset))


def kinds(a: object) -> list[str]:
    return [f.kind for f in a.findings]  # type: ignore[attr-defined]


def test_parses_coredumpctl_fields_and_first_thread_frames() -> None:
    [r] = parse_crash_text(block(11201, "11 (SEGV)", "Fri 2026-08-21 11:48:10", SEGV_FRAMES))
    assert (r.signal, r.pid, r.name, r.core_available) == ("SIGSEGV", 11201, "MYAPP", False)
    assert r.timestamp is not None and r.timestamp.year == 2026
    assert [f.index for f in r.frames] == [0, 1]
    assert r.frames[0].module == QT and r.frames[0].offset == 0x1b2845
    assert not r.frames[0].known


def test_core_available_true_when_storage_not_missing() -> None:
    [r] = parse_crash_text(block(1, "11 (SEGV)", "Fri 2026-08-21 11:48:10", SEGV_FRAMES, core=True))
    assert r.core_available is True


def test_symbolization_fills_unknown_frames_and_event_is_critical() -> None:
    text = block(1, "11 (SEGV)", "Fri 2026-08-21 11:48:10", SEGV_FRAMES)
    a = analyze_crash_text(text, "x", fake_symbolizer)
    [e] = a.result.events
    assert e.level is LogLevel.CRITICAL and e.line_number == 1
    assert "QObject::property(char const*) const" in e.message and "SIGSEGV" in e.message
    assert a.stats["symbolized_with"] == "addr2line"


def test_without_symbolizer_frames_stay_unknown() -> None:
    a = analyze_crash_text(block(1, "11 (SEGV)", "Fri 2026-08-21 11:48:10", SEGV_FRAMES), "x")
    assert "(unknown)" in a.result.events[0].message
    assert a.stats["symbolized_with"] is None


def test_signal_meaning_is_stated_as_fact() -> None:
    a = analyze_crash_text(block(1, "11 (SEGV)", "Fri 2026-08-21 11:48:10", SEGV_FRAMES),
                           "x", fake_symbolizer)
    crash = next(f for f in a.findings if f.kind == "app_crash")
    assert crash.severity is LogLevel.CRITICAL
    assert SIGNAL_MEANING["SIGSEGV"] in crash.detail
    assert "QObject::property" in crash.detail


def test_inferences_are_labelled_hypotheses() -> None:
    a = analyze_crash_text(block(1, "11 (SEGV)", "Fri 2026-08-21 11:48:10", SEGV_FRAMES),
                           "x", fake_symbolizer)
    h = next(f for f in a.findings if f.kind == "heuristic")
    assert h.title.startswith("Hypothesis") and "HEURISTIC, not proven" in h.detail


def test_repeated_crash_site_is_detected_across_crashes() -> None:
    text = "".join(block(100 + i, "11 (SEGV)", f"Fri 2026-08-2{i} 11:48:10", SEGV_FRAMES)
                    for i in range(3))
    a = analyze_crash_text(text, "x", fake_symbolizer)
    assert a.stats["crash_count"] == 3 and a.stats["distinct_crash_sites"] == 1
    [rep] = [f for f in a.findings if f.kind == "repeated_crash"]
    assert "3 times" in rep.title and rep.severity is LogLevel.CRITICAL


def test_different_sites_are_not_grouped() -> None:
    text = (block(1, "11 (SEGV)", "Fri 2026-08-21 11:48:10", SEGV_FRAMES)
            + block(2, "6 (ABRT)", "Fri 2026-08-22 11:48:10", ABRT_FRAMES))
    a = analyze_crash_text(text, "x", fake_symbolizer)
    assert a.stats["distinct_crash_sites"] == 2 and "repeated_crash" not in kinds(a)


def test_abort_machinery_is_skipped_to_find_the_real_site() -> None:
    a = analyze_crash_text(block(1, "6 (ABRT)", "Fri 2026-08-22 11:48:10", ABRT_FRAMES),
                           "x", fake_symbolizer)
    msg = a.result.events[0].message
    assert "QVariant::~QVariant()" in msg and "heap corruption" in msg
    assert "__pthread_kill_implementation" not in msg
    heap = next(f for f in a.findings if f.kind == "heap_corruption")
    assert "QVariant::~QVariant()" in heap.title and "not proven" in heap.detail


def test_missing_core_finding_counts_and_advises() -> None:
    text = (block(1, "11 (SEGV)", "Fri 2026-08-21 11:48:10", SEGV_FRAMES)
            + block(2, "11 (SEGV)", "Fri 2026-08-22 11:48:10", SEGV_FRAMES, core=True))
    a = analyze_crash_text(text, "x", fake_symbolizer)
    [f] = [f for f in a.findings if f.kind == "core_missing"]
    assert "1 of 2" in f.title and "coredumpctl gdb" in f.detail


def test_broken_unwinding_is_reported() -> None:
    a = analyze_crash_text(block(1, "11 (SEGV)", "Fri 2026-08-21 11:48:10", SEGV_FRAMES),
                           "x", fake_symbolizer)
    assert "unwind_incomplete" in kinds(a)


def test_unresolved_app_frame_gives_actionable_command_and_rebuild_warning() -> None:
    frames = [f"#0  0x1 __pthread_kill_implementation ({LIBC} + 0x969fc)",
              "#1  0x2 abort (" + LIBC + " + 0x287f3)",
              "#2  0x3 n/a (/home/dev/app/build/MYAPP (deleted) + 0x4cfcbd)"]
    a = analyze_crash_text(block(1, "6 (ABRT)", "Fri 2026-08-22 11:48:10", frames), "x",
                           fake_symbolizer)
    f = next(f for f in a.findings if f.kind == "unresolved_frame")
    assert "0x4cfcbd" in f.title and "addr2line -f -C -e" in f.detail and "rebuilt" in f.detail


GDB = """Program received signal SIGSEGV, Segmentation fault.
0x0000555555555131 in crash_here (p=0x0) at main.cpp:12
12	    *p = 1;
#0  0x0000555555555131 in crash_here (p=0x0) at main.cpp:12
#1  0x0000555555555150 in main () at main.cpp:20
"""


def test_gdb_backtrace_is_parsed_with_source_locations() -> None:
    [r] = parse_crash_text(GDB)
    assert r.source == "gdb" and r.signal == "SIGSEGV"
    assert [f.symbol for f in r.frames] == ["crash_here", "main"]
    assert r.frames[0].location == "main.cpp:12"
    a = analyze_crash_text(GDB, "gdb.txt")
    assert "crash_here" in a.result.events[0].message and "main.cpp:12" in a.result.events[0].message


def test_console_terminate_is_one_crash_with_reason() -> None:
    text = ("starting\nterminate called after throwing an instance of 'std::bad_alloc'\n"
            "  what():  std::bad_alloc\nAborted (core dumped)\n")
    reports = parse_crash_text(text)
    assert len(reports) == 1
    assert reports[0].signal == "SIGABRT" and "std::bad_alloc" in (reports[0].reason or "")
    assert reports[0].line == 2


def test_console_segfault_line_number_is_preserved() -> None:
    a = analyze_crash_text("ok\nok\nSegmentation fault (core dumped)\n", "console.txt")
    assert a.result.events[0].line_number == 3 and "SIGSEGV" in a.result.events[0].message


def test_no_crash_information_raises() -> None:
    with pytest.raises(AnalysisError, match="no crash information"):
        analyze_crash_text("just some ordinary text\nnothing wrong\n")


def test_looks_like_crash() -> None:
    assert looks_like_crash(GDB) and looks_like_crash("Segmentation fault")
    assert not looks_like_crash("2024-03-14 10:15:04 [INFO] all fine")


# ---- collect_system_crashes (fixed argv, injectable runner) ----

def test_collect_runs_fixed_argv_without_shell() -> None:
    seen: list[Sequence[str]] = []

    def runner(argv: Sequence[str]) -> tuple[int, str]:
        seen.append(argv)
        return 0, "PID: 1 (X)"

    assert collect_system_crashes("MYAPP", runner) == "PID: 1 (X)"
    assert seen == [["coredumpctl", "info", "--no-pager", "MYAPP"]]


def test_collect_errors_are_clear() -> None:
    def missing(argv: Sequence[str]) -> tuple[int, str]:
        raise FileNotFoundError

    def empty(argv: Sequence[str]) -> tuple[int, str]:
        return 1, ""

    def slow(argv: Sequence[str]) -> tuple[int, str]:
        raise subprocess.TimeoutExpired(argv, 1)

    with pytest.raises(AnalysisError, match="coredumpctl not found"):
        collect_system_crashes("", missing)
    with pytest.raises(AnalysisError, match="no coredump records found for 'X'"):
        collect_system_crashes("X", empty)
    with pytest.raises(AnalysisError, match="timed out"):
        collect_system_crashes("", slow)


def test_most_explanatory_findings_come_first() -> None:
    text = "".join(block(100 + i, "11 (SEGV)", f"Fri 2026-08-2{i} 11:48:10", SEGV_FRAMES)
                    for i in range(3))
    text += block(9, "6 (ABRT)", "Fri 2026-08-25 11:48:10", ABRT_FRAMES)
    a = analyze_crash_text(text, "x", fake_symbolizer)
    assert a.findings[0].kind == "repeated_crash"
    ranks = [f.severity for f in a.findings]
    order = [LogLevel.CRITICAL, LogLevel.ERROR, LogLevel.WARNING, LogLevel.INFO]
    assert ranks == sorted(ranks, key=order.index)  # never a milder finding before a worse one
