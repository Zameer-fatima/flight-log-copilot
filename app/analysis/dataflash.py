"""ArduPilot dataflash (.BIN) reader and analyzer (needs ``pymavlink``)."""

from __future__ import annotations

import re
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.analysis import ardupilot
from app.analysis.errors import UnreadableLogError
from app.analysis.models import Analysis, AnalysisBuilder
from app.analysis.tlog import captured_output, import_pymavlink, reader_warnings
from app.models import LogLevel

_RECORDS = ["MSG", "ERR", "EV", "MODE"]
_WALL_CLOCK_MIN = 946684800  # 2000-01-01; smaller values are boot-relative
#: MSG records carry no severity, so these keywords only *flag* a message.
_KEYWORDS = re.compile(
    r"\b(crash\w*|failsafe|lost|fail(?:ed|ure)?|error|bad|unhealthy|timeout|emergency)\b",
    re.IGNORECASE)


def read_dataflash(path: Path) -> Analysis:
    """Analyze a .BIN: MSG text, decoded ERR records, EV events and MODE changes.

    Raises:
        MissingDependencyError: pymavlink is not installed.
        UnreadableLogError: no readable records.
    """
    import_pymavlink()
    with captured_output() as captured:
        try:
            analysis = _read_dataflash(path)
        except (ValueError, struct.error, IndexError, OverflowError) as exc:
            raise UnreadableLogError(f"corrupt or empty ArduPilot .bin ({exc})") from exc
    analysis.stats["reader_warnings"] = reader_warnings(captured)
    return analysis


def _read_dataflash(path: Path) -> Analysis:
    from pymavlink import DFReader

    log = DFReader.DFReader_binary(str(path), zero_time_base=False)
    b = AnalysisBuilder()
    counts: dict[str, int] = {}
    firmware: str | None = None
    first_us: int | None = None
    last_us: int | None = None
    wall_clock = False

    while True:
        msg = log.recv_match(type=_RECORDS)
        if msg is None:
            break
        kind = msg.get_type()
        counts[kind] = counts.get(kind, 0) + 1
        us = getattr(msg, "TimeUS", None)
        if us is not None:
            first_us = us if first_us is None else first_us
            last_us = us
        ts = getattr(msg, "_timestamp", None)
        stamp: dict[str, Any] = {}
        if ts is not None and ts > _WALL_CLOCK_MIN:
            wall_clock = True
            stamp["timestamp"] = datetime.fromtimestamp(ts, tz=timezone.utc)
        elif us is not None:
            stamp["elapsed_s"] = round(us / 1e6, 3)

        if kind == "MSG":
            text = str(msg.Message)
            if firmware is None and text.startswith("Ardu"):
                firmware = text
            n = b.event(LogLevel.INFO, text, **stamp)
            hit = _KEYWORDS.search(text)
            if hit:
                b.finding("notable_message", LogLevel.WARNING,
                          f"Message mentions '{hit.group(0)}': {text}",
                          "Keyword match only: dataflash MSG records have no severity.",
                          event_number=n, **stamp)
        elif kind == "ERR":
            sub, code = int(msg.Subsys), int(msg.ECode)
            desc = f"{ardupilot.subsystem_name(sub)}: {ardupilot.error_description(sub, code)}"
            if code == 0:
                level = LogLevel.INFO
            elif ardupilot.is_crash_error(sub, code):
                level = LogLevel.CRITICAL
            else:
                level = LogLevel.ERROR
            n = b.event(level, f"ERR {desc} (subsys {sub}, code {code})", **stamp)
            if level is not LogLevel.INFO:
                b.finding("ardupilot_error", level, desc,
                          f"ERR record, subsystem {sub}, error code {code}.",
                          event_number=n, **stamp)
        elif kind == "EV":
            ev_id = int(msg.Id)
            if ev_id in ardupilot.EVENTS:
                level = LogLevel.WARNING if ev_id in ardupilot.WARNING_EVENTS else LogLevel.INFO
                b.event(level, ardupilot.EVENTS[ev_id], **stamp)
        elif kind == "MODE":
            b.event(LogLevel.INFO, f"Mode: {getattr(log, 'flightmode', msg.Mode)}", **stamp)

    if not counts:
        raise UnreadableLogError(
            "no MSG/ERR/EV/MODE records found; the file may be corrupt or not an ArduPilot .BIN")
    duration = None if first_us is None or last_us is None else round((last_us - first_us) / 1e6, 3)
    stats: dict[str, Any] = {
        "firmware": firmware,
        "duration_s": duration,
        "time_base": "wall-clock (GPS)" if wall_clock else "boot-relative (no GPS time in log)",
        "record_counts": counts,
    }
    return b.build("bin", path.name, stats)
