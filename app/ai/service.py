"""Orchestrates prompt building, the provider call and response validation."""

from __future__ import annotations

from collections.abc import Sequence

from app.ai.models import Diagnosis
from app.ai.prompt import DEFAULT_CONTEXT, DEFAULT_MAX_EVENTS, build_prompt
from app.ai.provider import LLMProvider
from app.ai.validation import parse_diagnosis
from app.analysis.models import Finding
from app.models import ParseResult


def diagnose(
    result: ParseResult,
    provider: LLMProvider,
    *,
    context: int = DEFAULT_CONTEXT,
    max_events: int = DEFAULT_MAX_EVENTS,
    findings: Sequence[Finding] = (),
    source_type: str = "text",
) -> Diagnosis | None:
    """Diagnose a parse result.

    Returns ``None`` (without calling the provider) when the log has no
    WARNING/ERROR/CRITICAL events.

    Raises:
        DiagnosticsError: provider failure or an invalid model response.
    """
    prompt = build_prompt(result, context, max_events, findings, source_type)
    if prompt is None:
        return None
    raw = provider.complete(prompt.system, prompt.user)
    return parse_diagnosis(raw, prompt.events, provider=provider.name, model=provider.model,
                           extra_items=prompt.allowed_items)
