"""Single entry point: turn any supported file into an :class:`Analysis`."""

from __future__ import annotations

from pathlib import Path

from app.analysis.crash import Addr2Line, Symbolizer, analyze_crash_text
from app.analysis.dataflash import read_dataflash
from app.analysis.detect import FORMATS, detect_format
from app.analysis.errors import UnsupportedFormatError
from app.analysis.models import Analysis
from app.analysis.tlog import DEFAULT_MAX_GAP_S, read_tlog
from app.log_parser import parse_logs


def analyze_text(text: str, source_name: str = "text") -> Analysis:
    """Analyze plain ``timestamp [LEVEL] message`` log text (original Phase 1 behaviour)."""
    return Analysis("text", source_name, parse_logs(text))


def analyze_path(
    path: Path,
    fmt: str = "auto",
    *,
    symbolize: Symbolizer | None = None,
    max_gap_s: float = DEFAULT_MAX_GAP_S,
) -> Analysis:
    """Detect the format of ``path`` (or use ``fmt``) and analyze it.

    Raises:
        OSError, UnicodeDecodeError: file/text decoding problems.
        AnalysisError: unsupported/corrupt content or a missing optional dependency.
    """
    kind = detect_format(path) if fmt == "auto" else fmt
    if kind not in FORMATS:
        raise UnsupportedFormatError(f"unknown format {kind!r}; choose from {', '.join(FORMATS)}")
    if kind == "tlog":
        return read_tlog(path, max_gap_s)
    if kind == "bin":
        return read_dataflash(path)
    text = path.read_text(encoding="utf-8")
    if kind == "crash":
        return analyze_crash_text(text, path.name, symbolize)
    return analyze_text(text, path.name)


def default_symbolizer() -> Symbolizer:
    """addr2line-backed symbolizer for crash frames."""
    return Addr2Line()
