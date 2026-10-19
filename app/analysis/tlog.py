"""MAVLink telemetry log (.tlog) reader and analyzer (needs ``pymavlink``)."""

from __future__ import annotations

import contextlib
import io
import os
import struct
import sys
import tempfile
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.analysis.errors import MissingDependencyError, UnreadableLogError
from app.analysis.mission import MissionTracker
from app.analysis.models import Analysis, AnalysisBuilder
from app.models import LogLevel

#: MAV_SEVERITY (0..7) -> our levels. 0-2 are EMERGENCY/ALERT/CRITICAL.
_SEVERITY = {0: LogLevel.CRITICAL, 1: LogLevel.CRITICAL, 2: LogLevel.CRITICAL,
             3: LogLevel.ERROR, 4: LogLevel.WARNING, 5: LogLevel.INFO,
             6: LogLevel.INFO, 7: LogLevel.DEBUG}
_TYPES = ["HEARTBEAT", "STATUSTEXT", "MISSION_REQUEST_LIST", "MISSION_COUNT",
          "MISSION_REQUEST", "MISSION_REQUEST_INT", "MISSION_ITEM",
          "MISSION_ITEM_INT", "MISSION_ACK", "COMMAND_ACK"]
_MAV_TYPE_GCS = 6
_AUTOPILOT_INVALID = 8
_ARMED_FLAG = 128
_STATUSTEXT_CHUNK = 50  # a chunk shorter than this ends a multi-part STATUSTEXT
_DEDUP_WINDOW_S = 1.0
DEFAULT_MAX_GAP_S = 5.0


def import_pymavlink() -> Any:
    """Import pymavlink's ``mavutil`` or raise a friendly error."""
    try:
        from pymavlink import mavutil
    except ImportError as exc:
        raise MissingDependencyError(
            "reading .tlog/.bin needs pymavlink; run: pip install pymavlink"
        ) from exc
    return mavutil


@contextlib.contextmanager
def captured_output() -> Iterator[io.StringIO]:
    """Capture everything the reader library prints, at file-descriptor level.

    pymavlink prints warnings ('bad header...') that bypass ``sys.stderr``; left
    alone they would corrupt ``--json`` output. The captured text is returned in
    the yielded buffer once the block exits.
    """
    buf = io.StringIO()
    sys.stdout.flush()
    sys.stderr.flush()
    saved = {fd: os.dup(fd) for fd in (1, 2)}
    with tempfile.TemporaryFile("w+b") as tmp:
        try:
            for fd in saved:
                os.dup2(tmp.fileno(), fd)
            with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                yield buf
        finally:
            for fd, old in saved.items():
                os.dup2(old, fd)
                os.close(old)
        tmp.seek(0)
        buf.write(tmp.read().decode("utf-8", errors="replace"))


def reader_warnings(buf: io.StringIO, limit: int = 5) -> list[str]:
    """Distinct, trimmed warning lines the library printed."""
    seen: list[str] = []
    bad_headers = 0
    for line in buf.getvalue().splitlines():
        line = line.strip()
        if line.startswith("bad header"):
            bad_headers += 1
        elif line and line not in seen:
            seen.append(line)
    if bad_headers:
        seen.insert(0, f"{bad_headers} byte(s) skipped because of bad record headers")
    return seen[:limit]


def _enum_name(mavutil: Any, enum: str, value: int) -> str:
    entry = mavutil.mavlink.enums.get(enum, {}).get(value)
    return entry.name if entry is not None else f"{enum}({value})"


def read_tlog(path: Path, max_gap_s: float = DEFAULT_MAX_GAP_S) -> Analysis:
    """Analyze a .tlog: status messages, arm/mode changes, link gaps, mission transfers.

    Raises:
        MissingDependencyError: pymavlink is not installed.
        UnreadableLogError: no MAVLink packets could be decoded.
    """
    mavutil = import_pymavlink()
    with captured_output() as captured:
        try:
            analysis = _read_tlog(path, mavutil, max_gap_s)
        except (ValueError, struct.error, IndexError, OverflowError) as exc:
            raise UnreadableLogError(f"corrupt or unsupported .tlog ({exc})") from exc
    analysis.stats["reader_warnings"] = reader_warnings(captured)
    return analysis


def _read_tlog(path: Path, mavutil: Any, max_gap_s: float) -> Analysis:
    link = mavutil.mavlink_connection(str(path), dialect="ardupilotmega", robust_parsing=True)

    def to_dt(ts: float) -> datetime:
        return datetime.fromtimestamp(ts, tz=timezone.utc)

    b = AnalysisBuilder()
    tracker = MissionTracker(b, to_dt)
    gcs_ids = {255}
    last_hb: dict[tuple[int, int], float] = {}
    armed: dict[tuple[int, int], bool] = {}
    mode: dict[tuple[int, int], str] = {}
    vehicles: dict[str, dict[str, str]] = {}
    pending_text: dict[tuple[int, int, int], dict[int, str]] = {}
    recent_text: dict[str, float] = {}
    seen_chunks: dict[tuple[int, int, int, int, str], float] = {}
    counts: dict[str, int] = {}
    gaps = 0
    rejected: dict[tuple[str, str], list[Any]] = {}
    armed_since: dict[tuple[int, int], float] = {}
    armed_total = 0.0
    first_ts: float | None = None
    last_ts: float | None = None

    def status_text(ts: float, severity: int, text: str) -> None:
        if recent_text.get(text, -1e9) >= ts - _DEDUP_WINDOW_S:
            return  # same text seen on a second link within a second
        recent_text[text] = ts
        b.event(_SEVERITY.get(severity, LogLevel.INFO), text, timestamp=to_dt(ts))

    while True:
        msg = link.recv_match(type=_TYPES)
        if msg is None:
            break
        kind = msg.get_type()
        counts[kind] = counts.get(kind, 0) + 1
        ts = getattr(msg, "_timestamp", None)
        if ts is None:
            continue
        first_ts = ts if first_ts is None else first_ts
        last_ts = ts
        sysid, comp = msg.get_srcSystem(), msg.get_srcComponent()
        key = (sysid, comp)

        if kind == "HEARTBEAT":
            if msg.type == _MAV_TYPE_GCS:
                gcs_ids.add(sysid)
                continue
            if msg.autopilot == _AUTOPILOT_INVALID:
                continue
            vehicles.setdefault(f"sys{sysid}", {
                "vehicle_type": _enum_name(mavutil, "MAV_TYPE", msg.type),
                "autopilot": _enum_name(mavutil, "MAV_AUTOPILOT", msg.autopilot)})
            prev = last_hb.get(key)
            if prev is not None and ts - prev > max_gap_s:
                gaps += 1
                n = b.event(LogLevel.WARNING,
                            f"No heartbeat from system {sysid} for {ts - prev:.1f}s",
                            timestamp=to_dt(ts))
                b.finding("heartbeat_gap", LogLevel.WARNING,
                          f"Link/heartbeat gap of {ts - prev:.1f}s from system {sysid}",
                          f"Last heartbeat at {to_dt(prev).isoformat()}, next at "
                          f"{to_dt(ts).isoformat()}.", event_number=n, timestamp=to_dt(ts))
            last_hb[key] = ts
            is_armed = bool(msg.base_mode & _ARMED_FLAG)
            if key in armed and armed[key] != is_armed:
                b.event(LogLevel.INFO, "Armed" if is_armed else "Disarmed", timestamp=to_dt(ts))
            if is_armed and key not in armed_since:
                armed_since[key] = ts
            elif not is_armed and key in armed_since:
                armed_total += ts - armed_since.pop(key)
            armed[key] = is_armed
            name = mavutil.mode_string_v10(msg)
            if mode.get(key, name) != name:
                b.event(LogLevel.INFO, f"Mode changed: {mode[key]} -> {name}", timestamp=to_dt(ts))
            mode[key] = name

        elif kind == "STATUSTEXT":
            msg_id = getattr(msg, "id", 0)
            if msg_id:
                seq = getattr(msg, "chunk_seq", 0)
                ckey = (sysid, comp, msg_id, seq, msg.text)
                if ts - seen_chunks.get(ckey, -1e9) < _DEDUP_WINDOW_S:
                    continue  # the same chunk again from a second link
                seen_chunks[ckey] = ts
                parts = pending_text.setdefault((sysid, comp, msg_id), {})
                parts[seq] = msg.text
                if len(msg.text) >= _STATUSTEXT_CHUNK:
                    continue
                done = pending_text.pop((sysid, comp, msg_id))
                text = "".join(done[k] for k in sorted(done))
            else:
                text = msg.text
            status_text(ts, msg.severity, text)

        elif kind == "COMMAND_ACK":
            if msg.result != 0:
                result = _enum_name(mavutil, "MAV_RESULT", msg.result)
                cmd = _enum_name(mavutil, "MAV_CMD", msg.command)
                entry = rejected.get((cmd, result))
                if entry is not None and ts - entry[2] < _DEDUP_WINDOW_S / 2:
                    continue  # duplicate packet from a second link
                n = b.event(LogLevel.WARNING, f"Command {cmd} not accepted: {result}",
                            timestamp=to_dt(ts), mav_cmd=msg.command)
                if entry is None:
                    rejected[(cmd, result)] = [1, n, ts, ts]
                else:
                    entry[0] += 1
                    entry[2] = ts

        else:  # mission protocol
            from_gcs = sysid in gcs_ids
            mtype = getattr(msg, "mission_type", 0)
            if kind == "MISSION_REQUEST_LIST":
                tracker.on_request_list(ts, from_gcs, mtype)
            elif kind == "MISSION_COUNT":
                tracker.on_count(ts, from_gcs, msg.count, mtype)
            elif kind in ("MISSION_REQUEST", "MISSION_REQUEST_INT"):
                tracker.on_request(ts, from_gcs, msg.seq, mtype)
            elif kind in ("MISSION_ITEM", "MISSION_ITEM_INT"):
                tracker.on_item(ts, from_gcs, msg.seq, mtype)
            elif kind == "MISSION_ACK":
                tracker.on_ack(ts, from_gcs, msg.type,
                               _enum_name(mavutil, "MAV_MISSION_RESULT", msg.type), mtype)

    for parts in pending_text.values():  # unterminated chunks
        if last_ts is not None:
            status_text(last_ts, 6, "".join(parts[k] for k in sorted(parts)))
    packets = (getattr(link.mav, "total_packets_received", 0)
               - getattr(link.mav, "total_receive_errors", 0))  # valid packets only
    if last_ts is None or first_ts is None:
        if not packets:
            raise UnreadableLogError(
                "no MAVLink packets found; the file may be corrupt or not a .tlog")
        raise UnreadableLogError(
            "MAVLink packets found but none of the supported message types "
            "(heartbeat, status text, mission, command ack)")
    tracker.finish(last_ts)
    for (cmd, result), (count, n, last, first) in rejected.items():
        span = f"between {to_dt(first).isoformat()} and {to_dt(last).isoformat()}"
        times = f"{count}x" if count == 1 else f"{count}x {span}"
        b.finding("command_rejected", LogLevel.WARNING,
                  f"{cmd} not accepted by the vehicle: {result} ({times})",
                  "Usually the GCS probing for optional capabilities or data not available yet; "
                  "check whether it matters for the problem you are chasing.",
                  event_number=n, timestamp=to_dt(first))
    for start in armed_since.values():  # still armed at end of log
        armed_total += last_ts - start

    stats: dict[str, Any] = {
        "first_timestamp": to_dt(first_ts).isoformat(),
        "last_timestamp": to_dt(last_ts).isoformat(),
        "duration_s": round(last_ts - first_ts, 3),
        "armed_s": round(armed_total, 3),
        "packets_decoded": packets,
        "message_counts": counts,
        "vehicles": vehicles,
        "heartbeat_gaps": gaps,
        "max_gap_threshold_s": max_gap_s,
        "mission_transfers": tracker.summary(),
    }
    return b.build("tlog", path.name, stats)
