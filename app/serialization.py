"""JSON-friendly conversion of parse results (kept apart from parsing)."""

from __future__ import annotations

import json
from typing import Any

from app.models import LogEvent, MalformedLine, ParseResult


def event_to_dict(event: LogEvent) -> dict[str, Any]:
    """Convert one event to JSON-compatible primitives."""
    return {
        "line_number": event.line_number,
        "timestamp": event.timestamp.isoformat() if event.timestamp else None,
        "level": event.level.value,
        "message": event.message,
        "mission_item": event.mission_item,
        "mav_cmd": event.mav_cmd,
        "elapsed_s": event.elapsed_s,
    }


def malformed_to_dict(entry: MalformedLine) -> dict[str, Any]:
    """Convert one malformed line to JSON-compatible primitives."""
    return {"line_number": entry.line_number, "text": entry.text, "reason": entry.reason}


def result_to_dict(result: ParseResult) -> dict[str, Any]:
    """Convert a full result to a JSON-serializable dict."""
    return {
        "total_lines": result.total_lines,
        "total_events": result.total_events,
        "counts_by_level": {lvl.value: n for lvl, n in result.counts_by_level.items()},
        "events": [event_to_dict(e) for e in result.events],
        "error_events": [event_to_dict(e) for e in result.error_events],
        "malformed_lines": [malformed_to_dict(m) for m in result.malformed_lines],
    }


def result_to_json(result: ParseResult, indent: int | None = 2) -> str:
    """Serialize a full result to a JSON string."""
    return json.dumps(result_to_dict(result), indent=indent)
