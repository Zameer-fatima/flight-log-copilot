"""Shared result types for all source readers."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.models import LogEvent, LogLevel, ParseResult


@dataclass(frozen=True)
class Finding:
    """A fact (or clearly marked heuristic) computed by code, not by an LLM.

    ``event_number`` links to the supporting ``LogEvent.line_number``.
    """

    kind: str
    severity: LogLevel
    title: str
    detail: str = ""
    event_number: int | None = None
    mission_item: int | None = None
    timestamp: datetime | None = None
    elapsed_s: float | None = None


@dataclass(frozen=True)
class Analysis:
    """Everything known about one source."""

    source_type: str  # "text" | "tlog" | "bin" | "crash"
    source_name: str
    result: ParseResult
    findings: tuple[Finding, ...] = ()
    stats: dict[str, Any] = field(default_factory=dict)


_SEVERITY_ORDER = {LogLevel.CRITICAL: 0, LogLevel.ERROR: 1, LogLevel.WARNING: 2,
                   LogLevel.INFO: 3, LogLevel.DEBUG: 4}
#: Within one severity, the most explanatory findings come first.
_KIND_ORDER = ["repeated_crash", "heap_corruption", "mission_transfer_failed", "app_crash",
               "ardupilot_error", "mission_transfer_incomplete", "heartbeat_gap",
               "mission_transfer_retries", "unresolved_frame", "heuristic", "core_missing"]


def _finding_order(f: Finding) -> tuple[int, int]:
    kind = _KIND_ORDER.index(f.kind) if f.kind in _KIND_ORDER else len(_KIND_ORDER)
    return (_SEVERITY_ORDER[f.severity], kind)


class AnalysisBuilder:
    """Collects events and findings while a reader walks a source."""

    def __init__(self) -> None:
        self._events: list[LogEvent] = []
        self._findings: list[Finding] = []

    @property
    def event_count(self) -> int:
        return len(self._events)

    def event(
        self,
        level: LogLevel,
        message: str,
        *,
        timestamp: datetime | None = None,
        elapsed_s: float | None = None,
        mission_item: int | None = None,
        mav_cmd: int | None = None,
        number: int | None = None,
    ) -> int:
        """Add an event and return its number (sequence index unless given)."""
        number = len(self._events) + 1 if number is None else number
        self._events.append(
            LogEvent(number, timestamp, level, message, mission_item, mav_cmd, elapsed_s)
        )
        return number

    def finding(
        self,
        kind: str,
        severity: LogLevel,
        title: str,
        detail: str = "",
        *,
        event_number: int | None = None,
        mission_item: int | None = None,
        timestamp: datetime | None = None,
        elapsed_s: float | None = None,
    ) -> None:
        self._findings.append(
            Finding(kind, severity, title, detail, event_number, mission_item,
                    timestamp, elapsed_s)
        )

    def build(
        self, source_type: str, source_name: str, stats: dict[str, Any],
        events: tuple[LogEvent, ...] | None = None, total_records: int | None = None,
    ) -> Analysis:
        evs = tuple(self._events) if events is None else events
        result = ParseResult(evs, (), total_lines=len(evs) if total_records is None else total_records)
        findings = tuple(sorted(self._findings, key=_finding_order))  # stable within a rank
        return Analysis(source_type, source_name, result, findings, stats)
