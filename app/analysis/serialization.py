"""JSON-compatible conversion of an :class:`Analysis`."""

from __future__ import annotations

from typing import Any

from app.analysis.models import Analysis, Finding
from app.serialization import result_to_dict


def finding_to_dict(f: Finding) -> dict[str, Any]:
    return {
        "kind": f.kind,
        "severity": f.severity.value,
        "title": f.title,
        "detail": f.detail,
        "event_number": f.event_number,
        "mission_item": f.mission_item,
        "timestamp": f.timestamp.isoformat() if f.timestamp else None,
        "elapsed_s": f.elapsed_s,
    }


def analysis_to_dict(analysis: Analysis) -> dict[str, Any]:
    """Superset of ``result_to_dict`` (existing keys unchanged)."""
    data = result_to_dict(analysis.result)
    data["source_type"] = analysis.source_type
    data["source_name"] = analysis.source_name
    data["stats"] = analysis.stats
    data["findings"] = [finding_to_dict(f) for f in analysis.findings]
    return data
