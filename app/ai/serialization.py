"""JSON-compatible conversion of a :class:`Diagnosis`."""

from __future__ import annotations

from typing import Any

from app.ai.models import Diagnosis


def diagnosis_to_dict(diagnosis: Diagnosis) -> dict[str, Any]:
    """Convert a diagnosis to JSON-serializable primitives."""
    return {
        "ai_generated": True,
        "provider": diagnosis.provider,
        "model": diagnosis.model,
        "summary": diagnosis.summary,
        "evidence": [
            {"line_number": e.line_number, "log_message": e.log_message,
             "observation": e.observation}
            for e in diagnosis.evidence
        ],
        "hypotheses": [
            {"description": h.description, "confidence": h.confidence,
             "supporting_lines": list(h.supporting_lines), "reasoning": h.reasoning}
            for h in diagnosis.hypotheses
        ],
        "recommended_checks": list(diagnosis.recommended_checks),
        "confidence": diagnosis.confidence,
        "confidence_explanation": diagnosis.confidence_explanation,
        "warnings": list(diagnosis.warnings),
    }
