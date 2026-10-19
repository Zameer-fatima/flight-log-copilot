"""Turn raw model text into a validated, grounded :class:`Diagnosis`.

The model is treated as an untrusted producer: structure is checked strictly
(raises ``InvalidResponseError``) and factual grounding is checked against the
events we actually sent (problems become ``warnings`` and lower confidence).
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Sequence
from typing import Any

from app.ai.errors import InvalidResponseError
from app.ai.models import CONFIDENCE_LEVELS, Diagnosis, Evidence, Hypothesis
from app.models import LogEvent

_ITEM_REF_RE = re.compile(r"\bitem\s*#?\s*(\d+)(?!\w)", re.IGNORECASE)
_CERTAINTY_RE = re.compile(
    r"(?<!not )\b(?:confirmed|definitely|certainly|proven|conclusively)\b"
    r"|\broot cause (?:is|was)\b",
    re.IGNORECASE,
)


def extract_json_object(text: str) -> dict[str, Any]:
    """Parse the model reply as a JSON object, tolerating ``` fences / chatter."""
    candidates = [text.strip()]
    start, end = text.find("{"), text.rfind("}")
    if 0 <= start < end:
        candidates.append(text[start : end + 1])
    for candidate in candidates:
        try:
            data = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict):
            return data
    raise InvalidResponseError("the model's reply was not a valid JSON object")


def _str(data: dict[str, Any], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise InvalidResponseError(f"field {key!r} must be a non-empty string")
    return value.strip()


def _list(data: dict[str, Any], key: str) -> list[Any]:
    value = data.get(key)
    if not isinstance(value, list):
        raise InvalidResponseError(f"field {key!r} must be a list")
    return value


def _level(value: Any, where: str) -> str:
    level = value.strip().lower() if isinstance(value, str) else ""
    if level not in CONFIDENCE_LEVELS:
        raise InvalidResponseError(f"{where} must be one of {CONFIDENCE_LEVELS}")
    return level


def _line(value: Any, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidResponseError(f"{where} must be an integer line number")
    return value


def _cap(level: str, ceiling: str) -> str:
    return min(level, ceiling, key=CONFIDENCE_LEVELS.index)


def parse_diagnosis(
    raw_text: str,
    sent_events: Sequence[LogEvent],
    *,
    provider: str,
    model: str,
    extra_items: Iterable[int] = (),
) -> Diagnosis:
    """Validate ``raw_text`` against the events that were sent to the model.

    Raises:
        InvalidResponseError: the reply is not JSON or violates the schema.
    """
    data = extract_json_object(raw_text)
    by_line = {e.line_number: e for e in sent_events}
    allowed_items = {e.mission_item for e in sent_events if e.mission_item is not None}
    allowed_items.update(extra_items)
    warnings: list[str] = []

    summary = _str(data, "summary")
    explanation = _str(data, "confidence_explanation")
    confidence = _level(data.get("confidence"), "field 'confidence'")

    evidence: list[Evidence] = []
    for i, raw in enumerate(_list(data, "evidence")):
        if not isinstance(raw, dict):
            raise InvalidResponseError(f"evidence[{i}] must be an object")
        number = _line(raw.get("line_number"), f"evidence[{i}].line_number")
        event = by_line.get(number)
        if event is None:
            warnings.append(
                f"dropped evidence citing line {number}: not in the supplied log events"
            )
            continue
        evidence.append(Evidence(number, event.message, _str(raw, "observation")))

    hypotheses: list[Hypothesis] = []
    for i, raw in enumerate(_list(data, "hypotheses")):
        if not isinstance(raw, dict):
            raise InvalidResponseError(f"hypotheses[{i}] must be an object")
        h_conf = _level(raw.get("confidence"), f"hypotheses[{i}].confidence")
        claimed = [
            _line(n, f"hypotheses[{i}].supporting_lines")
            for n in _list(raw, "supporting_lines")
        ]
        valid = tuple(n for n in claimed if n in by_line)
        if len(valid) != len(claimed):
            warnings.append(
                f"hypothesis {i + 1}: removed supporting line(s) not in the supplied events"
            )
        if not valid:
            warnings.append(
                f"hypothesis {i + 1} has no verifiable supporting log lines; "
                "confidence set to low"
            )
            h_conf = "low"
        hypotheses.append(
            Hypothesis(_str(raw, "description"), h_conf, valid, _str(raw, "reasoning"))
        )

    checks = tuple(_str({"c": c}, "c") for c in _list(data, "recommended_checks"))

    texts = [summary, explanation, *checks]
    texts += [e.observation for e in evidence]
    texts += [t for h in hypotheses for t in (h.description, h.reasoning)]
    joined = "\n".join(texts)

    invented = sorted({int(n) for n in _ITEM_REF_RE.findall(joined)} - allowed_items)
    if invented:
        nums = ", ".join(str(n) for n in invented)
        warnings.append(
            f"the model mentioned mission item(s) {nums} that do not appear in the supplied "
            "events; treat as unsupported; overall confidence capped at low"
        )
        confidence = _cap(confidence, "low")
    if _CERTAINTY_RE.search(joined):
        warnings.append(
            "the response uses language of certainty (e.g. 'confirmed'); "
            "all causes here are unverified hypotheses"
        )
    if not evidence:
        warnings.append("no verifiable evidence was cited; treat this diagnosis with caution")
        confidence = _cap(confidence, "low")

    return Diagnosis(
        summary=summary, evidence=tuple(evidence), hypotheses=tuple(hypotheses),
        recommended_checks=checks, confidence=confidence,
        confidence_explanation=explanation, warnings=tuple(warnings),
        provider=provider, model=model,
    )
