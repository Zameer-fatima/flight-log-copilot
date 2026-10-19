"""Mission upload/download tracker built from MAVLink mission-protocol messages.

Reconstructs each transfer (start, items requested/delivered, retries, final ACK)
so a failure can be pinned to a specific item, deterministically.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.analysis.models import AnalysisBuilder
from app.models import LogLevel

_KIND_NAMES = {0: "mission", 1: "fence", 2: "rally"}
_DUP_WINDOW_S = 0.5


@dataclass
class _Transfer:
    direction: str  # "upload" (GCS -> vehicle) or "download"
    start: float
    kind: int = 0  # MAV_MISSION_TYPE: 0 mission, 1 fence, 2 rally
    count: int | None = None
    requested: list[int] = field(default_factory=list)
    delivered: set[int] = field(default_factory=set)
    retries: dict[int, int] = field(default_factory=dict)
    last_request_ts: dict[int, float] = field(default_factory=dict)
    done: bool = False
    result: str | None = None
    end: float | None = None
    start_known: bool = True

    @property
    def progressed(self) -> bool:
        return bool(self.requested or self.delivered)

    @property
    def label(self) -> str:
        return f"{_KIND_NAMES.get(self.kind, f'type-{self.kind}')} {self.direction}"

    @property
    def total_retries(self) -> int:
        return sum(self.retries.values())

    @property
    def last_requested(self) -> int | None:
        return self.requested[-1] if self.requested else None


class MissionTracker:
    """Feed mission messages in file order; call :meth:`finish` at the end."""

    def __init__(self, builder: AnalysisBuilder, to_dt: Callable[[float], datetime]) -> None:
        self._b = builder
        self._dt = to_dt
        self._active: dict[tuple[str, int], _Transfer | None] = {}
        self._all: list[_Transfer] = []
        self._recent: dict[tuple[LogLevel, str], tuple[float, int]] = {}

    # -- helpers ---------------------------------------------------------
    def _emit(self, level: LogLevel, msg: str, ts: float, item: int | None = None) -> int:
        """Emit an event; an identical one within 0.5s (duplicate packet) is merged."""
        seen = self._recent.get((level, msg))
        if seen is not None and ts - seen[0] < _DUP_WINDOW_S:
            return seen[1]
        number = self._b.event(level, msg, timestamp=self._dt(ts), mission_item=item)
        self._recent[(level, msg)] = (ts, number)
        return number

    def _begin(self, direction: str, ts: float, kind: int, count: int | None = None) -> _Transfer:
        """Start a transfer. A repeated start that made no progress (a retried
        request or a duplicate packet from a second link) reuses the open one."""
        previous = self._active.get((direction, kind))
        if previous is not None and not previous.done:
            if not previous.progressed:
                if count is not None:
                    previous.count = count
                return previous
            self._close_incomplete(previous, ts, "superseded by a new transfer")
        transfer = _Transfer(direction, ts, kind, count)
        self._active[(direction, kind)] = transfer
        self._all.append(transfer)
        return transfer

    def _close_incomplete(self, t: _Transfer, ts: float, why: str) -> None:
        t.done, t.result, t.end = True, "incomplete", ts
        last = t.last_requested
        where = f"stalled after item {last}" if last is not None else "no items transferred"
        n = self._emit(LogLevel.WARNING, f"{t.label.capitalize()} never acknowledged ({where}; {why})",
                       ts, last)
        self._b.finding(
            "mission_transfer_incomplete", LogLevel.WARNING,
            f"{t.label.capitalize()} never completed: {where}",
            f"{len(t.delivered)}/{t.count if t.count is not None else '?'} items delivered, "
            f"{t.total_retries} retries, no final MISSION_ACK ({why}).",
            event_number=n, mission_item=last, timestamp=self._dt(ts),
        )

    # -- message handlers --------------------------------------------------
    def on_request_list(self, ts: float, from_gcs: bool, kind: int = 0) -> None:
        if from_gcs:
            t = self._begin("download", ts, kind)
            if t.start == ts:  # a genuinely new transfer, not a repeat of an open one
                self._emit(LogLevel.INFO, f"{t.label.capitalize()} requested", ts)

    def on_count(self, ts: float, from_gcs: bool, count: int, kind: int = 0) -> None:
        if from_gcs:
            t = self._begin("upload", ts, kind, count)
            if t.start == ts:
                self._emit(LogLevel.INFO, f"{t.label.capitalize()} started: {count} items", ts)
        else:
            current = self._active.get(("download", kind))
            if current is None or current.done:
                current = self._begin("download", ts, kind, count)
                current.start_known = False
            current.count = count
            self._emit(LogLevel.INFO,
                       f"Vehicle reports {count} {current.label.split()[0]} items", ts)

    def on_request(self, ts: float, from_gcs: bool, seq: int, kind: int = 0) -> None:
        t = self._active.get(("download" if from_gcs else "upload", kind))
        if t is None or t.done:
            return
        if ts - t.last_request_ts.get(seq, -1e9) < _DUP_WINDOW_S:
            return  # the same request again from a second link, not a retry
        t.last_request_ts[seq] = ts
        if seq in t.requested:
            t.retries[seq] = t.retries.get(seq, 0) + 1
            self._emit(LogLevel.WARNING, f"Item {seq} requested again (retry {t.retries[seq]})",
                       ts, seq)
        t.requested.append(seq)

    def on_item(self, ts: float, from_gcs: bool, seq: int, kind: int = 0) -> None:
        t = self._active.get(("upload" if from_gcs else "download", kind))
        if t is not None and not t.done:
            t.delivered.add(seq)

    def on_ack(self, ts: float, from_gcs: bool, result: int, name: str, kind: int = 0) -> None:
        direction = "download" if from_gcs else "upload"
        t = self._active.get((direction, kind))
        if t is not None and t.done and t.end is not None and ts - t.end < _DUP_WINDOW_S:
            return  # duplicate of the ACK we just processed
        if t is None or t.done:
            t = _Transfer(direction, ts, kind, start_known=False)
            self._all.append(t)
            self._active[(direction, kind)] = t
        t.done, t.result, t.end = True, name, ts
        last = t.last_requested
        if result == 0:
            n = self._emit(LogLevel.INFO, f"{t.label.capitalize()} accepted", ts)
            if t.total_retries:
                self._b.finding(
                    "mission_transfer_retries", LogLevel.WARNING,
                    f"{t.label.capitalize()} succeeded only after {t.total_retries} retries",
                    f"Retried items: {sorted(t.retries)}.", event_number=n,
                    timestamp=self._dt(ts))
            return
        where = f" (last requested item {last})" if last is not None else ""
        n = self._emit(LogLevel.ERROR, f"{t.label.capitalize()} rejected: {name}{where}", ts, last)
        dur = ts - t.start if t.start_known else None
        self._b.finding(
            "mission_transfer_failed", LogLevel.ERROR,
            f"{t.label.capitalize()} failed: {name}{where}",
            f"{len(t.delivered)}/{t.count if t.count is not None else '?'} items delivered, "
            f"{t.total_retries} retries"
            + (f", {dur:.1f}s after start" if dur is not None else "") + ".",
            event_number=n, mission_item=last, timestamp=self._dt(ts))

    def finish(self, ts_end: float) -> None:
        """Flag transfers still open at end of file."""
        for t in list(self._active.values()):
            if t is not None and not t.done and (t.requested or t.delivered or t.count):
                self._close_incomplete(t, ts_end, "log ended or link lost")

    def summary(self) -> list[dict[str, Any]]:
        out = []
        for t in self._all:
            duration = None if t.end is None or not t.start_known else round(t.end - t.start, 3)
            out.append({
                "kind": _KIND_NAMES.get(t.kind, str(t.kind)),
                "direction": t.direction,
                "count": t.count,
                "delivered": len(t.delivered),
                "retries": t.total_retries,
                "result": t.result or "no ACK seen",
                "start": self._dt(t.start).isoformat(),
                "duration_s": duration,
            })
        return out
