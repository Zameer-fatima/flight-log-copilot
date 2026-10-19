"""Tests for the public-showcase (demo) mode, the sample files, and the CLI safety rules."""

from __future__ import annotations

import http.client
import json
import threading
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from app.web import make_handler, parse_cli

SAMPLES = Path(__file__).resolve().parent.parent / "sample_data"
TLOG = SAMPLES / "demo.tlog"


class ExplodingProvider:
    """A provider that fails the test if it is ever called."""

    name, model = "boom", "boom"

    def complete(self, system: str, user: str) -> str:
        raise AssertionError("the demo must never call the AI provider")


def _serve(**kwargs: Any) -> tuple[ThreadingHTTPServer, str, int]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(**kwargs))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    return srv, f"http://127.0.0.1:{port}", port


@pytest.fixture
def demo() -> Iterator[tuple[str, int]]:
    srv, base, port = _serve(demo=True, provider=ExplodingProvider(), environ={})
    yield base, port
    srv.shutdown()
    srv.server_close()


@pytest.fixture
def full() -> Iterator[str]:
    srv, base, _ = _serve(provider=ExplodingProvider(), environ={})
    yield base
    srv.shutdown()
    srv.server_close()


def call(url: str, data: bytes | None = None, ctype: str = "application/json") -> tuple[int, Any]:
    req = urllib.request.Request(url, data=data, method="POST" if data is not None else "GET")
    if data is not None:
        req.add_header("Content-Type", ctype)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as err:
        return err.code, json.loads(err.read())


def post(base: str, path: str, payload: Any) -> tuple[int, Any]:
    return call(base + path, json.dumps(payload).encode())


# ---------------- demo restrictions ----------------

def test_config_reports_the_mode(demo: tuple[str, int], full: str) -> None:
    status, cfg = call(demo[0] + "/api/config")
    assert status == 200 and cfg == {"demo": True, "max_upload_mb": 5}
    assert call(full + "/api/config")[1]["demo"] is False


def test_demo_blocks_server_side_file_and_crash_access(demo: tuple[str, int]) -> None:
    base, _ = demo
    status, body = post(base, "/api/analyze-path", {"path": str(TLOG)})
    assert status == 403 and "public demo" in body["error"]
    status, body = post(base, "/api/system-crashes", {"name": ""})
    assert status == 403 and "public demo" in body["error"]


def test_demo_never_calls_the_ai_provider(demo: tuple[str, int]) -> None:
    base, _ = demo
    token = post(base, "/api/demo-sample", {"kind": "tlog"})[1]["token"]
    status, body = post(base, "/api/diagnose", {"token": token})
    assert status == 200 and body["diagnosis"] is None
    assert "disabled in the public demo" in body["diagnosis_error"]
    # also for pasted text, and with an unknown token: still no provider call
    assert post(base, "/api/diagnose", {"text": "2024-03-14 10:15:04 [ERROR] x"})[0] == 200
    assert post(base, "/api/diagnose", {"token": "nope"})[0] == 200


def test_demo_upload_limit_is_5_mib_but_full_mode_is_larger(
    demo: tuple[str, int], full: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    base, _ = demo
    big = b"x" * (5 * 1024 * 1024 + 1)
    try:
        status, body = call(f"{base}/api/analyze?name=a.tlog", big, "application/octet-stream")
    except (urllib.error.URLError, ConnectionError):
        pass  # connection closed during the oversized upload: also a rejection
    else:
        assert status == 413 and "max 5 MiB" in body["error"]
    # the same size is not rejected for size in full mode (it fails later as unparseable)
    try:
        status, _ = call(f"{full}/api/analyze?name=a.tlog", big, "application/octet-stream")
        assert status != 413
    except (urllib.error.URLError, ConnectionError):
        pytest.fail("full mode should accept uploads above the demo limit")


def test_demo_accepts_a_small_real_upload(demo: tuple[str, int]) -> None:
    base, _ = demo
    status, body = call(f"{base}/api/analyze?name=demo.tlog", TLOG.read_bytes(),
                        "application/octet-stream")
    assert status == 200 and body["source_type"] == "tlog"


def test_demo_serves_on_any_public_hostname_but_still_requires_content_types(
    demo: tuple[str, int],
) -> None:
    base, port = demo
    conn = http.client.HTTPConnection("127.0.0.1", port)
    conn.request("GET", "/api/config", headers={"Host": "my-demo.onrender.com"})
    assert conn.getresponse().status == 200
    conn.close()
    assert call(base + "/api/parse", b"{}", "text/plain")[0] == 415


def test_full_mode_still_rejects_foreign_hosts(full: str) -> None:
    host_port = full.split("//")[1]
    conn = http.client.HTTPConnection(host_port)
    conn.request("GET", "/api/config", headers={"Host": "evil.example"})
    assert conn.getresponse().status == 403
    conn.close()


# ---------------- samples ----------------

@pytest.mark.parametrize("kind, source, finding_kinds", [
    ("tlog", "tlog", {"mission_transfer_failed", "heartbeat_gap", "command_rejected"}),
    ("bin", "bin", {"ardupilot_error", "notable_message"}),
    ("crash", "crash", {"repeated_crash", "heap_corruption", "core_missing"}),
    ("text", "text", set()),
])
def test_each_sample_shows_its_headline_findings(
    demo: tuple[str, int], kind: str, source: str, finding_kinds: set[str]
) -> None:
    status, body = post(demo[0], "/api/demo-sample", {"kind": kind})
    assert status == 200 and body["source_type"] == source
    assert body["file_info"]["sample"] is True and body["token"]
    assert finding_kinds <= {f["kind"] for f in body["findings"]}


def test_samples_headline_numbers(demo: tuple[str, int]) -> None:
    tlog = post(demo[0], "/api/demo-sample", {"kind": "tlog"})[1]
    failed = next(f for f in tlog["findings"] if f["kind"] == "mission_transfer_failed")
    assert failed["mission_item"] == 3 and "2 retries" in failed["detail"]
    assert tlog["stats"]["duration_s"] == 75.0
    crash = post(demo[0], "/api/demo-sample", {"kind": "crash"})[1]
    assert crash["stats"]["crash_count"] == 6 and crash["findings"][0]["kind"] == "repeated_crash"


def test_unknown_sample_kind_is_400(demo: tuple[str, int]) -> None:
    for payload in ({"kind": "zip"}, {"kind": 5}, {}):
        assert post(demo[0], "/api/demo-sample", payload)[0] == 400


def test_sample_files_are_synthetic_and_contain_nothing_private() -> None:
    forbidden = (b"zameer", b"suind", b"/home/", b"@gmail")
    for path in SAMPLES.iterdir():
        data = path.read_bytes().lower()
        for needle in forbidden:
            assert needle not in data, f"{path.name} contains {needle!r}"
    assert (SAMPLES / "demo_crash.txt").read_text().count("demo-gcs") >= 6


def test_sample_generator_is_deterministic(tmp_path: Path) -> None:
    import runpy

    ns = runpy.run_path(str(SAMPLES.parent / "tools" / "make_demo_samples.py"))
    before = {p.name: p.read_bytes() for p in SAMPLES.iterdir()}
    ns["make_tlog"](), ns["make_bin"](), ns["make_crash"]()
    assert {p.name: p.read_bytes() for p in SAMPLES.iterdir()} == before


# ---------------- CLI safety ----------------

def test_server_refuses_public_binding_without_demo() -> None:
    with pytest.raises(SystemExit) as exc:
        parse_cli(["--host", "0.0.0.0"], {})
    assert exc.value.code == 2


def test_demo_may_bind_publicly_and_reads_env_settings() -> None:
    args = parse_cli(["--host", "0.0.0.0"], {"FLC_DEMO": "1", "PORT": "10000"})
    assert args.demo is True and args.port == 10000 and args.host == "0.0.0.0"
    assert parse_cli(["--demo", "--host", "0.0.0.0", "--port", "9"], {}).port == 9


def test_default_is_local_full_mode() -> None:
    args = parse_cli([], {})
    assert (args.host, args.port, args.demo) == ("127.0.0.1", 8000, False)
