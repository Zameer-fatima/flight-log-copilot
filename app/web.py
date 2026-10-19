"""Local web UI: ``python -m app.web`` then open http://127.0.0.1:8000.

Standard library only. Reuses the same analyzers and AI service as the CLI.
It binds to localhost; log data leaves the machine only if you press
"Diagnose with AI" (same provider/env config as ``--diagnose``).

Hardening (the server can read local files): requests must carry a loopback
``Host`` header (DNS-rebinding guard) and a JSON / octet-stream content type
(browsers cannot send those cross-site without a CORS preflight we never answer).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import shutil
import tempfile
from collections import OrderedDict
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from app.analysis.crash import Runner, analyze_crash_text, collect_system_crashes
from app.analysis.errors import AnalysisError
from app.analysis.loader import analyze_path, analyze_text, default_symbolizer
from app.analysis.models import Analysis
from app.analysis.serialization import analysis_to_dict

MAX_BODY_BYTES = 2 * 1024 * 1024  # JSON / pasted-text requests
MAX_UPLOAD_BYTES = 512 * 1024 * 1024  # raw file uploads (binary logs are large)
STORE_CAPACITY = 4  # analyses kept in memory for the "diagnose" step
DEMO_MAX_UPLOAD_BYTES = 5 * 1024 * 1024  # public demo: small uploads only
DEMO_DISABLED = "disabled in the public demo (it only analyses samples and small uploads)"
#: Demo sample kinds -> file in ``sample_data/`` (all synthetic; see tools/make_demo_samples.py).
_SAMPLE_FILES = {"text": "flight.log", "tlog": "demo.tlog", "bin": "demo.BIN",
                 "crash": "demo_crash.txt"}
_ROOT = Path(__file__).resolve().parent
_SAMPLE_DIR = _ROOT.parent / "sample_data"
_SAMPLE = _SAMPLE_DIR / "flight.log"
_LOOPBACK = frozenset({"127.0.0.1", "localhost", "[::1]"})
_SUFFIX_RE = re.compile(r"^\.[a-z0-9]{1,8}$")
#: URL path -> (file, content type). A whitelist: no arbitrary file serving.
_STATIC = {
    "/": (_ROOT / "static" / "index.html", "text/html; charset=utf-8"),
    "/app.js": (_ROOT / "static" / "app.js", "text/javascript; charset=utf-8"),
    "/style.css": (_ROOT / "static" / "style.css", "text/css; charset=utf-8"),
}
_CSP = "default-src 'self'; frame-ancestors 'none'"


class ApiError(Exception):
    """A client error that maps to an HTTP status and a JSON message."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


def _json_body(body: bytes) -> dict[str, Any]:
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise ApiError(400, "request body must be JSON") from None
    if not isinstance(data, dict):
        raise ApiError(400, "JSON body must be an object")
    return data


def _text_from_body(body: bytes) -> str:
    text = _json_body(body).get("text")
    if not isinstance(text, str):
        raise ApiError(400, "JSON body must be an object with a string field 'text'")
    return text


def _iso_from_epoch_ms(raw: object) -> str | None:
    """File modification time (epoch milliseconds from the browser) -> ISO UTC, or None."""
    try:
        return datetime.fromtimestamp(int(str(raw)) / 1000, tz=timezone.utc).isoformat()
    except (ValueError, OverflowError, OSError):
        return None


class _Store:
    """Small LRU of recent analyses (per server instance, not module state)."""

    def __init__(self, capacity: int = STORE_CAPACITY) -> None:
        self._items: OrderedDict[str, Analysis] = OrderedDict()
        self._capacity = capacity

    def put(self, analysis: Analysis) -> str:
        token = secrets.token_urlsafe(16)
        self._items[token] = analysis
        while len(self._items) > self._capacity:
            self._items.popitem(last=False)
        return token

    def get(self, token: object) -> Analysis:
        analysis = self._items.get(token) if isinstance(token, str) else None
        if analysis is None:
            raise ApiError(404, "analysis expired or unknown; analyze the log again")
        return analysis


def _guard_analysis(call: Any) -> Analysis:
    """Run an analysis, translating failures into API errors."""
    try:
        result: Analysis = call()
        return result
    except FileNotFoundError:
        raise ApiError(404, "file not found") from None
    except UnicodeDecodeError as exc:
        raise ApiError(422, f"file is not valid UTF-8 text ({exc.reason})") from None
    except OSError as exc:
        raise ApiError(400, f"cannot read file: {exc.strerror or exc}") from None
    except AnalysisError as exc:
        raise ApiError(422, str(exc)) from None


def _diagnose(
    analysis: Analysis, provider: Any | None, environ: Mapping[str, str] | None
) -> dict[str, Any]:
    from app.ai.config import LLMConfig
    from app.ai.errors import DiagnosticsError
    from app.ai.provider import create_provider
    from app.ai.serialization import diagnosis_to_dict
    from app.ai.service import diagnose

    diagnosis = None
    error: str | None = None
    try:
        if provider is None:
            env = os.environ if environ is None else environ
            provider = create_provider(LLMConfig.from_env(env))
        found = diagnose(analysis.result, provider, findings=analysis.findings,
                         source_type=analysis.source_type)
        diagnosis = diagnosis_to_dict(found) if found else None
        if found is None:
            error = "No WARNING/ERROR/CRITICAL events or findings: nothing to diagnose."
    except DiagnosticsError as exc:
        error = str(exc)
    return {"diagnosis": diagnosis, "diagnosis_error": error}


def make_handler(
    provider: Any | None = None,
    environ: Mapping[str, str] | None = None,
    crash_runner: Runner | None = None,
    use_addr2line: bool = True,
    allowed_hosts: frozenset[str] = _LOOPBACK,
    demo: bool = False,
) -> type[BaseHTTPRequestHandler]:
    """Build a request-handler class bound to injectable dependencies.

    ``demo=True`` is the public-showcase mode: no server-side file/crash access, no AI,
    small uploads, and no loopback Host check (it is served on a public hostname).
    """
    store = _Store()

    def symbolizer() -> Any:
        return default_symbolizer() if use_addr2line else None

    def remember(analysis: Analysis, file_info: dict[str, Any] | None = None) -> dict[str, Any]:
        """Serialise an analysis; ``file_info`` (name, size, file date) is for the UI header."""
        data = analysis_to_dict(analysis)
        data["token"] = store.put(analysis)
        data["file_info"] = file_info
        return data

    class Handler(BaseHTTPRequestHandler):
        def _send(self, status: int, payload: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Content-Security-Policy", _CSP)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(payload)

        def _json(self, status: int, data: dict[str, Any]) -> None:
            self._send(status, json.dumps(data).encode(), "application/json")

        def _check_host(self) -> None:
            if demo:  # public hostname; nothing local is reachable in demo mode
                return
            host = self.headers.get("Host", "").rsplit(":", 1)[0] if ":" in self.headers.get(
                "Host", "") else self.headers.get("Host", "")
            if host not in allowed_hosts:
                raise ApiError(403, "forbidden host header")

        def _require_type(self, expected: str) -> None:
            if not self.headers.get("Content-Type", "").lower().startswith(expected):
                raise ApiError(415, f"Content-Type must be {expected}")

        def _read_body(self, limit: int) -> bytes:
            length = int(self.headers.get("Content-Length", "0"))
            if length > limit:
                self.close_connection = True
                raise ApiError(413, f"too large (max {limit // 1024} KiB)")
            return self.rfile.read(length)

        def _receive_upload(self, name: str) -> Analysis:
            length = int(self.headers.get("Content-Length", "0"))
            limit = min(MAX_UPLOAD_BYTES, DEMO_MAX_UPLOAD_BYTES) if demo else MAX_UPLOAD_BYTES
            if length > limit:
                self.close_connection = True
                raise ApiError(413, f"file too large (max {limit / 1024 / 1024:g} MiB)")
            suffix = Path(name).suffix.lower()
            suffix = suffix if _SUFFIX_RE.match(suffix) else ""
            tmpdir = tempfile.mkdtemp(prefix="flc-upload-")
            try:
                target = Path(tmpdir) / f"upload{suffix}"
                remaining = length
                with target.open("wb") as out:
                    while remaining > 0:
                        chunk = self.rfile.read(min(1024 * 1024, remaining))
                        if not chunk:
                            raise ApiError(400, "upload ended early")
                        out.write(chunk)
                        remaining -= len(chunk)
                analysis = _guard_analysis(lambda: analyze_path(target, symbolize=symbolizer()))
                # report the user's file name, not our temp name
                return Analysis(analysis.source_type, Path(name).name or analysis.source_name,
                                analysis.result, analysis.findings, analysis.stats)
            finally:
                shutil.rmtree(tmpdir, ignore_errors=True)

        def do_GET(self) -> None:  # noqa: N802 (name fixed by http.server)
            try:
                self._check_host()
                path = urlsplit(self.path).path
                if path == "/api/config":
                    limit = min(MAX_UPLOAD_BYTES, DEMO_MAX_UPLOAD_BYTES) if demo else MAX_UPLOAD_BYTES
                    self._json(200, {"demo": demo, "max_upload_mb": limit // 1024 // 1024})
                elif path == "/api/sample":
                    try:
                        self._json(200, {"text": _SAMPLE.read_text(encoding="utf-8")})
                    except OSError:
                        self._json(404, {"error": "sample log not found"})
                elif path in _STATIC:
                    file, ctype = _STATIC[path]
                    self._send(200, file.read_bytes(), ctype)
                else:
                    self._json(404, {"error": "not found"})
            except ApiError as exc:
                self._json(exc.status, {"error": str(exc)})

        def do_POST(self) -> None:  # noqa: N802
            try:
                self._check_host()
                url = urlsplit(self.path)
                if url.path == "/api/analyze":
                    self._require_type("application/octet-stream")
                    query = parse_qs(url.query)
                    name = query.get("name", ["upload"])[0]
                    info = {
                        "name": Path(name).name or "upload",
                        "size_bytes": int(self.headers.get("Content-Length", "0")),
                        "modified": _iso_from_epoch_ms(query.get("modified", [None])[0]),
                    }
                    self._json(200, remember(self._receive_upload(name), info))
                    return
                self._require_type("application/json")
                body = self._read_body(MAX_BODY_BYTES)
                if url.path == "/api/parse":
                    analysis = analyze_text(_text_from_body(body))
                    self._json(200, remember(analysis))
                elif url.path == "/api/demo-sample":
                    kind = _json_body(body).get("kind")
                    sample_name = _SAMPLE_FILES.get(kind) if isinstance(kind, str) else None
                    if sample_name is None:
                        raise ApiError(400, f"'kind' must be one of {', '.join(_SAMPLE_FILES)}")
                    sample = _SAMPLE_DIR / sample_name
                    analysis = _guard_analysis(lambda: analyze_path(sample, symbolize=None))
                    info = {"name": sample_name, "size_bytes": sample.stat().st_size, "modified": None,
                            "sample": True}
                    self._json(200, remember(analysis, info))
                elif url.path == "/api/analyze-path":
                    if demo:
                        raise ApiError(403, f"analysing server paths is {DEMO_DISABLED}")
                    raw = _json_body(body).get("path")
                    if not isinstance(raw, str) or not raw.strip():
                        raise ApiError(400, "JSON body must contain a string field 'path'")
                    target = Path(raw).expanduser()
                    analysis = _guard_analysis(
                        lambda: analyze_path(target, symbolize=symbolizer()))
                    stat = target.stat()
                    info = {
                        "name": target.name,
                        "size_bytes": stat.st_size,
                        "modified": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                    }
                    self._json(200, remember(analysis, info))
                elif url.path == "/api/system-crashes":
                    if demo:
                        raise ApiError(403, f"reading system crash records is {DEMO_DISABLED}")
                    name = _json_body(body).get("name", "")
                    if not isinstance(name, str) or not re.fullmatch(r"[\w.+-]{0,64}", name):
                        raise ApiError(400, "'name' must be a program name (letters, digits, . _ + -)")
                    analysis = _guard_analysis(lambda: analyze_crash_text(
                        collect_system_crashes(name, crash_runner), "coredumpctl", symbolizer()))
                    self._json(200, remember(analysis))
                elif url.path == "/api/diagnose":
                    if demo:  # never call the provider on a public instance
                        self._json(200, {"diagnosis": None, "diagnosis_error":
                                         "AI diagnosis is disabled in the public demo."})
                        return
                    data = _json_body(body)
                    if "token" in data:
                        analysis = store.get(data["token"])
                    else:  # legacy: diagnose pasted text directly
                        analysis = analyze_text(_text_from_body(body))
                    self._json(200, _diagnose(analysis, provider, environ))
                else:
                    raise ApiError(404, "not found")
            except ValueError:
                self._json(400, {"error": "invalid Content-Length"})
            except ApiError as exc:
                self._json(exc.status, {"error": str(exc)})

    return Handler


def parse_cli(argv: Sequence[str] | None, environ: Mapping[str, str]) -> argparse.Namespace:
    """Parse command-line options, applying ``PORT`` / ``FLC_DEMO`` from the environment.

    Exits with status 2 if asked to listen on a non-local address outside demo mode:
    the full server can read local files and must not be exposed.
    """
    parser = argparse.ArgumentParser(prog="python -m app.web", description=__doc__)
    parser.add_argument("--port", type=int, default=int(environ.get("PORT", "8000")),
                        help="port (default: $PORT or 8000)")
    parser.add_argument("--host", default="127.0.0.1",
                        help="bind address (default: localhost only)")
    parser.add_argument("--demo", action="store_true", default=environ.get("FLC_DEMO") == "1",
                        help="public showcase mode (or set FLC_DEMO=1): samples and small "
                             "uploads only; no server paths, system crashes or AI")
    args = parser.parse_args(argv)
    if not args.demo and args.host not in _LOOPBACK:
        parser.error("refusing to listen on a non-local address without --demo: the full "
                     "server can read local files. Use --demo for a public showcase.")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    """Start the server (Ctrl+C to stop)."""
    args = parse_cli(argv, os.environ)
    handler = make_handler(allowed_hosts=_LOOPBACK | {args.host}, demo=args.demo)
    server = ThreadingHTTPServer((args.host, args.port), handler)
    mode = "PUBLIC DEMO mode" if args.demo else "full mode"
    print(f"Flight Log Copilot UI ({mode}): http://{args.host}:{args.port}  (Ctrl+C to stop)",
          flush=True)  # hosts capture logs through a pipe; don't buffer the startup line
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
