"""Data models for parsed flight/GCS logs.

These are plain, immutable containers. They know nothing about regexes,
JSON or the command line, so each of those can change independently.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class LogLevel(str, Enum):
    """Supported log severities. Subclassing ``str`` lets members compare
    equal to their names and serialize to JSON as plain strings."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


#: Severities treated as errors by ``ParseResult.error_events``.
ERROR_LEVELS: frozenset[LogLevel] = frozenset({LogLevel.ERROR, LogLevel.CRITICAL})


@dataclass(frozen=True)
class LogEvent:
    """One successfully parsed log line.

    ``mission_item`` is ``None`` when the message names no item. ``0`` is a
    valid item number, so always test with ``is None``, never truthiness.
    ``mav_cmd`` follows the same rule. ``timestamp`` is ``None`` when the source
    has no wall-clock time (e.g. ArduPilot .BIN without GPS lock); ``elapsed_s``
    then carries seconds since vehicle boot when known. For binary sources,
    ``line_number`` is the event's sequence number, not a text line.
    """

    line_number: int
    timestamp: datetime | None
    level: LogLevel
    message: str
    mission_item: int | None = None
    mav_cmd: int | None = None
    elapsed_s: float | None = None

    @property
    def is_error(self) -> bool:
        """True for ERROR and CRITICAL events."""
        return self.level in ERROR_LEVELS


@dataclass(frozen=True)
class MalformedLine:
    """A non-blank line that could not be parsed, kept verbatim."""

    line_number: int
    text: str
    reason: str


@dataclass(frozen=True)
class ParseResult:
    """Everything produced by one parse run."""

    events: tuple[LogEvent, ...] = field(default_factory=tuple)
    malformed_lines: tuple[MalformedLine, ...] = field(default_factory=tuple)
    total_lines: int = 0

    @property
    def total_events(self) -> int:
        """Number of successfully parsed events."""
        return len(self.events)

    @property
    def counts_by_level(self) -> dict[LogLevel, int]:
        """Event count per level; levels with no events appear as 0."""
        counts = {level: 0 for level in LogLevel}
        for event in self.events:
            counts[event.level] += 1
        return counts

    @property
    def error_events(self) -> tuple[LogEvent, ...]:
        """Events with ERROR or CRITICAL severity, in log order."""
        return tuple(e for e in self.events if e.is_error)
