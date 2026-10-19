"""Decide which reader a file needs, from its bytes (extension is only a hint)."""

from __future__ import annotations

from pathlib import Path

from app.analysis.crash import looks_like_crash
from app.analysis.errors import UnsupportedFormatError
from app.log_parser import parse_line
from app.models import LogEvent

FORMATS = ("tlog", "bin", "crash", "text")
_HEAD_BYTES = 8192
_SNIFF_BYTES = 256 * 1024
_DATAFLASH_MAGIC = b"\xa3\x95\x80"  # header bytes + FMT message type


def _looks_like_tlog(head: bytes) -> bool:
    """A .tlog record is an 8-byte big-endian microsecond timestamp, then a MAVLink packet."""
    return len(head) > 8 and head[8] in (0xFD, 0xFE) and b"\x00" in head[:8]


def _mostly_log_lines(text: str) -> bool:
    lines = [ln for ln in text.splitlines()[:200] if ln.strip()][:50]
    if not lines:
        return False
    ok = sum(isinstance(parse_line(i, ln), LogEvent) for i, ln in enumerate(lines, 1))
    return ok * 2 >= len(lines)


def detect_format(path: Path) -> str:
    """Return one of ``FORMATS``.

    Raises:
        OSError: the file cannot be opened/read.
        UnsupportedFormatError: unrecognised binary content.
    """
    with path.open("rb") as handle:
        head = handle.read(_SNIFF_BYTES)
    suffix = path.suffix.lower()
    if suffix == ".tlog" or _looks_like_tlog(head[:_HEAD_BYTES]):
        return "tlog"
    if suffix == ".bin" or head[:3] == _DATAFLASH_MAGIC:
        return "bin"
    if b"\x00" in head[:_HEAD_BYTES]:
        raise UnsupportedFormatError(
            "unrecognised binary file (not UTF-8 text, not a MAVLink .tlog, not an "
            "ArduPilot .bin); use --format to force a reader")
    text = head.decode("utf-8", errors="replace")
    if looks_like_crash(text) and not _mostly_log_lines(text):
        return "crash"
    return "text"
