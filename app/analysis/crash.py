"""Application crash analysis: coredumpctl records, gdb backtraces, crash console text.

Everything here is deterministic. Conclusions about *why* a crash happened are
only stated as facts when they follow from the data (signal, location, repeat
count); anything inferred is explicitly labelled as a heuristic hypothesis.
"""

from __future__ import annotations

import dataclasses
import re
import shutil
import subprocess
from collections import defaultdict
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from app.analysis.errors import AnalysisError
from app.analysis.models import Analysis, AnalysisBuilder
from app.models import LogLevel

#: Maps a (module path, offset) to a function name, or None if unknown.
Symbolizer = Callable[[str, int], "str | None"]
#: Runs an argv list and returns (exit code, stdout). Injectable for tests.
Runner = Callable[[Sequence[str]], "tuple[int, str]"]

SIGNAL_MEANING: dict[str, str] = {
    "SIGSEGV": "invalid memory access (typically a null, dangling or corrupted pointer)",
    "SIGABRT": "the program called abort(): uncaught C++ exception, failed assertion "
               "(Q_ASSERT/assert), or heap corruption detected by glibc (double free etc.)",
    "SIGBUS": "bus error: bad memory alignment or access to a truncated mapped file",
    "SIGFPE": "arithmetic fault (e.g. integer division by zero)",
    "SIGILL": "illegal instruction (corrupted code, or a binary built for a newer CPU)",
    "SIGKILL": "killed externally, commonly by the out-of-memory killer",
    "SIGTERM": "asked to terminate by another process",
}
_SIGNAL_NAMES = {"SEGV": "SIGSEGV", "ABRT": "SIGABRT", "BUS": "SIGBUS", "FPE": "SIGFPE",
                 "ILL": "SIGILL", "KILL": "SIGKILL", "TERM": "SIGTERM", "TRAP": "SIGTRAP"}

_PID_RE = re.compile(r"^\s*PID:\s*(\d+)\s*\((.*?)\)")
_FIELD_RE = re.compile(r"^\s*(Signal|Timestamp|Executable|Command Line|Storage):\s*(.*)$")
_FRAME_CORE_RE = re.compile(
    r"^\s*#(\d+)\s+(0x[0-9a-fA-F]+)\s+(.+?)\s+\((.*?)(?:\s\+\s(0x[0-9a-fA-F]+))?\)\s*$")
_FRAME_GDB_RE = re.compile(
    r"^#(\d+)\s+(?:(0x[0-9a-fA-F]+)\s+in\s+)?(.+?) \(.*?\)(?:\s+(?:at|from)\s+(\S+))?\s*$")
_STACK_HEADER_RE = re.compile(r"Stack trace of thread (\d+)")
_GDB_SIGNAL_RE = re.compile(r"Program (?:received|terminated with) signal (SIG\w+)")
_TERMINATE_RE = re.compile(r"terminate called after throwing an instance of '([^']+)'")
_WHAT_RE = re.compile(r"^\s*what\(\):\s*(.*)$")
_CONSOLE_SIGNALS = (
    (re.compile(r"Segmentation fault"), "SIGSEGV"),
    (re.compile(r"\bAborted\b.*core dumped|\bAborted \(core dumped\)"), "SIGABRT"),
    (re.compile(r"Bus error"), "SIGBUS"),
    (re.compile(r"Floating point exception"), "SIGFPE"),
)
_TS_RE = re.compile(r"(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})")
_MARKERS = re.compile(
    r"Stack trace of thread|Program (?:received|terminated with) signal|Segmentation fault|"
    r"\bSIGSEGV\b|\bSIGABRT\b|terminate called after|dumped core|core dumped|"
    r"AddressSanitizer|^#0\s+(?:0x)?[0-9a-f]+", re.MULTILINE)
_QT_TOP = re.compile(r"^(?:Q[A-Z]\w*)::")
#: libc frames that only implement abort()/free(); the real site is the first frame below them.
_RUNTIME_FRAME = re.compile(
    r"^(?:__pthread_kill_implementation|pthread_kill|__GI_raise|raise|gsignal|__GI_abort|abort|"
    r"__libc_message|malloc_printerr|_int_free|__GI___libc_free|__libc_free|free|cfree|"
    r"__assert_fail|__GI___assert_fail|__GI___libc_malloc|_int_malloc)$")
_HEAP_ABORT = ("malloc_printerr", "__libc_message")


@dataclass(frozen=True)
class StackFrame:
    index: int
    address: str | None
    symbol: str | None
    module: str | None
    offset: int | None = None
    location: str | None = None  # "file:line" when debug info is available
    resolved_by: str | None = None  # "addr2line" when we filled in the symbol

    @property
    def known(self) -> bool:
        return self.symbol not in (None, "n/a")

    def describe(self) -> str:
        name: str = self.symbol if self.known and self.symbol else "(unknown)"
        where = Path(self.module).name if self.module and self.module != "n/a" else None
        if where and self.offset is not None:
            name += f" [{where}+{hex(self.offset)}]"
        elif where:
            name += f" [{where}]"
        if self.location and not self.location.startswith("??"):
            name += f" at {self.location}"
        return name


@dataclass(frozen=True)
class CrashReport:
    source: str  # "coredumpctl" | "gdb" | "console"
    line: int  # 1-based line in the input where this crash starts
    signal: str | None = None
    process: str | None = None
    executable: str | None = None
    pid: int | None = None
    timestamp: datetime | None = None
    core_available: bool | None = None
    frames: tuple[StackFrame, ...] = ()
    reason: str | None = None  # e.g. C++ exception type / what()

    @property
    def top_frame(self) -> StackFrame | None:
        return self.frames[0] if self.frames else None

    @property
    def site_frame(self) -> StackFrame | None:
        """First frame that is not abort()/free() machinery (the real crash site)."""
        for frame in self.frames:
            if not (frame.known and frame.symbol and _RUNTIME_FRAME.match(frame.symbol)):
                return frame
        return self.top_frame

    @property
    def heap_corruption(self) -> bool:
        return any(f.symbol in _HEAP_ABORT for f in self.frames)

    @property
    def name(self) -> str:
        return Path(self.executable).name if self.executable else (self.process or "application")

    @property
    def site_key(self) -> tuple[str, str, str]:
        """Identity of the crash location, for spotting repeated crashes."""
        top = self.site_frame
        where = "unknown"
        if top is not None:
            where = top.symbol if top.known and top.symbol else f"{top.module}+{top.offset}"
            if top.known and top.module:
                where = f"{where}@{Path(top.module).name}"
        return (self.name, self.signal or "?", where)


class Addr2Line:
    """Symbolizer backed by the ``addr2line`` tool (fixed argv, no shell)."""

    def __init__(self, timeout_s: float = 5.0) -> None:
        self._exe = shutil.which("addr2line")
        self._timeout = timeout_s
        self._cache: dict[tuple[str, int], str | None] = {}

    def __call__(self, module: str, offset: int) -> str | None:
        key = (module, offset)
        if key in self._cache:
            return self._cache[key]
        result: str | None = None
        if self._exe and Path(module).is_file():
            try:
                out = subprocess.run(
                    [self._exe, "-f", "-C", "-e", module, hex(offset)],
                    capture_output=True, text=True, timeout=self._timeout, check=False,
                ).stdout.splitlines()
            except (OSError, subprocess.SubprocessError):
                out = []
            if out and not out[0].startswith("??"):
                result = out[0].strip()
        self._cache[key] = result
        return result


def _signal_from_field(value: str) -> str | None:
    match = re.search(r"\((\w+)\)", value)
    if match:
        return _SIGNAL_NAMES.get(match.group(1).upper(), f"SIG{match.group(1).upper()}")
    return None


def _parse_coredumpctl(lines: Sequence[str]) -> list[CrashReport]:
    reports: list[CrashReport] = []
    starts = [i for i, ln in enumerate(lines) if _PID_RE.match(ln)]
    for n, start in enumerate(starts):
        end = starts[n + 1] if n + 1 < len(starts) else len(lines)
        block = lines[start:end]
        pid_match = _PID_RE.match(block[0])
        assert pid_match is not None
        fields: dict[str, str] = {}
        frames: list[StackFrame] = []
        in_first_thread = False
        seen_thread = False
        for ln in block[1:]:
            fm = _FIELD_RE.match(ln)
            if fm and fm.group(1) not in fields:
                fields[fm.group(1)] = fm.group(2).strip()
            if _STACK_HEADER_RE.search(ln):
                in_first_thread = not seen_thread  # the first listed thread crashed
                seen_thread = True
                continue
            if in_first_thread:
                frame = _FRAME_CORE_RE.match(ln)
                if frame:
                    idx, addr, sym, module, off = frame.groups()
                    frames.append(StackFrame(int(idx), addr, sym, module,
                                             int(off, 16) if off else None))
                elif ln.strip() == "":
                    in_first_thread = False
        ts = None
        tm = _TS_RE.search(fields.get("Timestamp", ""))
        if tm:
            ts = datetime.strptime(f"{tm.group(1)} {tm.group(2)}", "%Y-%m-%d %H:%M:%S")
        storage = fields.get("Storage", "")
        reports.append(CrashReport(
            "coredumpctl", start + 1, _signal_from_field(fields.get("Signal", "")),
            pid_match.group(2), fields.get("Executable"), int(pid_match.group(1)), ts,
            None if not storage else "(missing)" not in storage, tuple(frames)))
    return reports


def _parse_gdb(lines: Sequence[str]) -> list[CrashReport]:
    signal: str | None = None
    first_line = 0
    frames: list[StackFrame] = []
    for i, ln in enumerate(lines, 1):
        sm = _GDB_SIGNAL_RE.search(ln)
        if sm and signal is None:
            signal, first_line = sm.group(1), i
        fm = _FRAME_GDB_RE.match(ln.strip())
        if fm and not (frames and int(fm.group(1)) == 0):
            idx, addr, sym, loc = fm.groups()
            module = loc if loc and ".so" in loc else None
            location = loc if loc and ":" in loc else None
            frames.append(StackFrame(int(idx), addr, sym.strip(), module, None, location))
    if signal is None and not frames:
        return []
    return [CrashReport("gdb", first_line or 1, signal, frames=tuple(frames))]


def _parse_console(lines: Sequence[str]) -> list[CrashReport]:
    reports: list[CrashReport] = []
    for i, ln in enumerate(lines, 1):
        term = _TERMINATE_RE.search(ln)
        if term:
            what = next((m.group(1) for m in (_WHAT_RE.match(x) for x in lines[i:i + 3]) if m), None)
            reason = f"uncaught C++ exception {term.group(1)}" + (f": {what}" if what else "")
            reports.append(CrashReport("console", i, "SIGABRT", reason=reason))
            continue
        for pattern, sig in _CONSOLE_SIGNALS:
            if pattern.search(ln):
                # "Aborted (core dumped)" right after "terminate called..." is the same crash
                if reports and reports[-1].reason and i - reports[-1].line <= 5:
                    break
                reports.append(CrashReport("console", i, sig))
                break
    return reports


def looks_like_crash(text: str) -> bool:
    """Cheap content sniff used by format detection."""
    return _MARKERS.search(text) is not None


def parse_crash_text(text: str) -> list[CrashReport]:
    """Extract crash reports from coredumpctl output, gdb output or console text."""
    lines = text.splitlines()
    reports = _parse_coredumpctl(lines)
    if reports:
        return reports
    reports = _parse_gdb(lines)
    if reports:
        return reports
    return _parse_console(lines)


def resolve_frames(report: CrashReport, symbolize: Symbolizer | None) -> CrashReport:
    """Fill in unknown symbols using ``symbolize`` (module + offset -> name)."""
    if symbolize is None:
        return report
    resolved: list[StackFrame] = []
    for frame in report.frames:
        if not frame.known and frame.module and frame.module != "n/a" and frame.offset is not None:
            name = symbolize(frame.module, frame.offset)
            if name:
                frame = dataclasses.replace(frame, symbol=name, resolved_by="addr2line")
        resolved.append(frame)
    return dataclasses.replace(report, frames=tuple(resolved))


def _describe_crash(r: CrashReport) -> str:
    site = r.site_frame.describe() if r.site_frame else "location unknown"
    sig = r.signal or "unknown signal"
    note = " (glibc detected heap corruption)" if r.heap_corruption else ""
    return r.reason or f"{r.name} crashed with {sig} in {site}{note}"


def analyze_crash_text(
    text: str, source_name: str = "crash", symbolize: Symbolizer | None = None,
    other_events: Sequence[tuple[int, str]] = (),
) -> Analysis:
    """Analyze crash text. ``symbolize=None`` disables addr2line resolution.

    Raises:
        AnalysisError: no crash information recognised in the text.
    """
    reports = [resolve_frames(r, symbolize) for r in parse_crash_text(text)]
    if not reports:
        raise AnalysisError(
            "no crash information found (looked for coredumpctl output, gdb backtraces, "
            "'Segmentation fault', 'terminate called ...' and similar)")
    b = AnalysisBuilder()
    event_no: dict[int, int] = {}
    for r in reports:
        event_no[id(r)] = b.event(
            LogLevel.CRITICAL, _describe_crash(r), timestamp=r.timestamp, number=r.line)

    groups: dict[tuple[str, str, str], list[CrashReport]] = defaultdict(list)
    for r in reports:
        groups[r.site_key].append(r)

    for members in groups.values():
        first = members[0]
        sig = first.signal or "unknown signal"
        meaning = SIGNAL_MEANING.get(sig, "")
        frames = "\n".join(f"  #{f.index} {f.describe()}" for f in first.frames[:12])
        detail = (f"Signal {sig}" + (f" = {meaning}." if meaning else ".") +
                  (f"\nCrashing thread, top frames:\n{frames}" if frames else
                   "\nNo stack frames were available."))
        b.finding("app_crash", LogLevel.CRITICAL,
                  f"{first.name} crashed: {sig} at {_site_label(first)}",
                  detail, event_number=event_no[id(first)], timestamp=first.timestamp)
        if len(members) > 1:
            stamps = [m.timestamp.strftime("%Y-%m-%d %H:%M") for m in members if m.timestamp]
            if len(stamps) > 6:
                stamps = stamps[:3] + [f"... ({len(stamps) - 6} more) ..."] + stamps[-3:]
            when = ", ".join(stamps)
            b.finding("repeated_crash", LogLevel.CRITICAL,
                      f"Same crash location hit {len(members)} times ({sig} at {_site_label(first)})",
                      "Identical signal and top frame every time points to one deterministic "
                      "bug rather than random corruption." + (f" Occurrences: {when}." if when else ""),
                      event_number=event_no[id(first)])
        site = first.site_frame
        if (site is not None and not site.known and site.module not in (None, "n/a")
                and site.offset is not None):
            rebuilt = "(deleted)" in (site.module or "")
            b.finding("unresolved_frame", LogLevel.WARNING,
                      f"Crash site inside {Path(site.module or '').name} could not be symbolised "
                      f"(offset {hex(site.offset)})",
                      ("The binary was replaced (rebuilt) after the crash, so the original is gone "
                       "and offsets cannot be trusted against the new build. " if rebuilt else "")
                      + f"With the exact matching build run: addr2line -f -C -e <that binary> "
                      f"{hex(site.offset)}. Keep debug symbols (-g / RelWithDebInfo) and archive "
                      "the binary of every release you ship or test.",
                      event_number=event_no[id(first)])
        top = first.top_frame
        if first.heap_corruption:
            b.finding("heap_corruption", LogLevel.ERROR,
                      f"glibc aborted on a corrupted heap while freeing memory in {_site_label(first)}",
                      "FACT: the abort came from malloc_printerr, i.e. free() found an invalid "
                      "chunk. Typical causes in general (not proven for this log): double free, "
                      "use-after-free, or an earlier buffer overflow. The corruption usually "
                      "happened before the crash, so the reported function is where it was "
                      "noticed, not necessarily where it was caused. Reproduce under "
                      "AddressSanitizer (-fsanitize=address) or valgrind.",
                      event_number=event_no[id(first)])
        elif top is not None and top.known and top.symbol and _QT_TOP.match(top.symbol):
            b.finding("heuristic", LogLevel.WARNING,
                      f"Hypothesis: invalid object passed to Qt ({top.symbol})",
                      "HEURISTIC, not proven: a crash directly inside a Qt method usually means "
                      "the application passed it a null/deleted object (or QML accessed a "
                      "destroyed object). The calling application frame was not captured, so "
                      "the faulty call site must be found with a debugger or a symbolised core.",
                      event_number=event_no[id(first)])
        if len(first.frames) > 1 and not first.frames[1].known and first.frames[1].module in (None, "n/a"):
            b.finding("unwind_incomplete", LogLevel.WARNING,
                      "Stack unwinding stopped after the top frame",
                      f"Frame #{first.frames[1].index} ({first.frames[1].address}) belongs to no "
                      "known module, so the application's own call chain is missing. Build the "
                      "app with frame pointers/debug info (-g, -fno-omit-frame-pointer) to get "
                      "a usable caller chain.", event_number=event_no[id(first)])

    missing = [r for r in reports if r.core_available is False]
    if missing:
        b.finding("core_missing", LogLevel.WARNING,
                  f"Core dump file missing for {len(missing)} of {len(reports)} crash(es)",
                  "Only the journal's summary survived, so full variable/thread inspection "
                  "(gdb) is impossible for these. Keep cores next time: "
                  "`ulimit -c unlimited`, check `coredumpctl` storage limits in "
                  "/etc/systemd/coredump.conf (MaxUse/KeepFree), and avoid cleaning "
                  "/var/lib/systemd/coredump. Then use `coredumpctl gdb <pid>`.",
                  event_number=event_no[id(missing[0])])

    stats = {
        "crash_count": len(reports),
        "distinct_crash_sites": len(groups),
        "executables": sorted({r.name for r in reports}),
        "signals": sorted({r.signal or "?" for r in reports}),
        "symbolized_with": "addr2line" if symbolize is not None else None,
        "input_format": reports[0].source,
        "crashes": [{
            "signal": r.signal, "executable": r.executable, "pid": r.pid,
            "timestamp": r.timestamp.isoformat() if r.timestamp else None,
            "core_available": r.core_available,
            "top_frame": r.top_frame.describe() if r.top_frame else None,
            "site": r.site_frame.describe() if r.site_frame else None,
        } for r in reports],
    }
    return b.build("crash", source_name, stats)


def _site_label(r: CrashReport) -> str:
    return r.site_frame.describe() if r.site_frame else "unknown location"


def _subprocess_runner(argv: Sequence[str]) -> tuple[int, str]:
    proc = subprocess.run(list(argv), capture_output=True, text=True, timeout=60, check=False)
    return proc.returncode, proc.stdout


def collect_system_crashes(name: str = "", runner: Runner | None = None) -> str:
    """Return ``coredumpctl info`` text (optionally for one program name).

    Runs a fixed argv (no shell). Raises ``AnalysisError`` with a clear message
    if coredumpctl is missing or no crash records exist.
    """
    run = runner or _subprocess_runner
    argv = ["coredumpctl", "info", "--no-pager"] + ([name] if name else [])
    try:
        code, out = run(argv)
    except FileNotFoundError:
        raise AnalysisError("coredumpctl not found: systemd-coredump is not available") from None
    except subprocess.TimeoutExpired:
        raise AnalysisError("coredumpctl timed out") from None
    if not out.strip():
        raise AnalysisError(
            "no coredump records found" + (f" for {name!r}" if name else "")
            + (f" (coredumpctl exit code {code})" if code else ""))
    return out
