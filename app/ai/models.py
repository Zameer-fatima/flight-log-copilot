"""Structured diagnosis returned by the AI layer."""

from __future__ import annotations

from dataclasses import dataclass

CONFIDENCE_LEVELS: tuple[str, ...] = ("low", "medium", "high")


@dataclass(frozen=True)
class Evidence:
    """A cited log line. ``log_message`` comes from the parsed log, not the model."""

    line_number: int
    log_message: str
    observation: str


@dataclass(frozen=True)
class Hypothesis:
    """A possible cause. Always a hypothesis, never a confirmed finding."""

    description: str
    confidence: str
    supporting_lines: tuple[int, ...]
    reasoning: str


@dataclass(frozen=True)
class Diagnosis:
    """Validated model output plus any safeguard warnings raised against it."""

    summary: str
    evidence: tuple[Evidence, ...]
    hypotheses: tuple[Hypothesis, ...]
    recommended_checks: tuple[str, ...]
    confidence: str
    confidence_explanation: str
    warnings: tuple[str, ...]
    provider: str
    model: str
