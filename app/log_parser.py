"""Deterministic parser for GCS / drone mission logs.

Expected line shape (the level may be bracketed, followed by ``:`` or ``-``)::

    2024-03-14 10:15:02.123 [ERROR] Mission transfer failed at item 7
    2024-03-14T10:15:02Z WARNING: Link quality degraded
"""

from __future__ import annotations

import re
from datetime import datetime

from app.models import LogEvent, LogLevel, MalformedLine, ParseResult

_LINE_RE = re.compile(
    r"""^\s*
    (?P<ts>\d{4}-\d{2}-\d{2}[T\ ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)
    \s*[-\s]?\s*
    \[?\s*(?P<level>DEBUG|INFO|WARNING|ERROR|CRITICAL)\b\s*\]?
    \s*[:\-]?\s*
    (?P<msg>.*?)\s*$""",
    re.IGNORECASE | re.VERBOSE,
)

# Matches "mission item 19", "Item #19", "failed at item 7". The (?!\w) guard
# keeps "item 7abc" from yielding 7; \b before "item" rejects "subitem 3".
_ITEM_RE = re.compile(r"\bitem\s*#?\s*(?P<n>\d+)(?!\w)", re.IGNORECASE)
_MAV_CMD_RE = re.compile(r"\bMAV_CMD\s*\(\s*(?P<n>\d+)\s*\)", re.IGNORECASE)


def _extract_int(pattern: re.Pattern[str], message: str) -> int | None:
    """Return the first captured integer, or ``None`` if there is no match."""
    match = pattern.search(message)
    return int(match.group("n")) if match else None


def _parse_timestamp(raw: str) -> datetime:
    """Parse the timestamp text; raises ``ValueError`` if it is not a real date.

    Python 3.10's ``fromisoformat`` is strict, so normalise the few variants
    we accept (comma decimal, trailing ``Z``, ``+0000`` offsets).
    """
    text = raw.replace(",", ".")
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    text = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", text)
    # 3.10 also only accepts 3 or 6 fractional digits.
    text = re.sub(
        r"\.(\d+)", lambda m: "." + m.group(1)[:6].ljust(6, "0"), text, count=1
    )
    return datetime.fromisoformat(text)


def parse_line(line_number: int, line: str) -> LogEvent | MalformedLine:
    """Parse one non-blank line into an event, or describe why it failed."""
    match = _LINE_RE.match(line)
    if match is None:
        return MalformedLine(line_number, line, "does not match '<timestamp> <LEVEL> <message>'")
    try:
        timestamp = _parse_timestamp(match.group("ts"))
    except ValueError:
        return MalformedLine(line_number, line, f"invalid timestamp {match.group('ts')!r}")
    message = match.group("msg")
    return LogEvent(
        line_number=line_number,
        timestamp=timestamp,
        level=LogLevel(match.group("level").upper()),
        message=message,
        mission_item=_extract_int(_ITEM_RE, message),
        mav_cmd=_extract_int(_MAV_CMD_RE, message),
    )


def parse_logs(log_text: str) -> ParseResult:
    """Parse a whole log into a :class:`ParseResult`.

    Blank lines are skipped. Unparseable lines are recorded as malformed with
    their 1-based line number and original text; parsing never aborts on them.

    Raises:
        TypeError: if ``log_text`` is not a ``str`` (e.g. ``bytes`` or ``None``).
    """
    if not isinstance(log_text, str):
        raise TypeError(
            f"log_text must be str, got {type(log_text).__name__}; "
            "decode bytes first (e.g. data.decode('utf-8'))"
        )
    lines = log_text.splitlines()
    events: list[LogEvent] = []
    malformed: list[MalformedLine] = []
    for number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        parsed = parse_line(number, line)
        if isinstance(parsed, LogEvent):
            events.append(parsed)
        else:
            malformed.append(parsed)
    return ParseResult(tuple(events), tuple(malformed), total_lines=len(lines))
