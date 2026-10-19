"""Tests for the local web UI backend (real server on an ephemeral localhost port)."""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator
from http.server import ThreadingHTTPServer
from typing import Any

import pytest

from app.web import MAX_BODY_BYTES, make_handler

LOG = "2024-03-14 10:15:04 [ERROR] Mission transfer failed at item 0\nbad line\n"
GOOD_REPLY = json.dumps({
    "summary": "Transfer failed.", "evidence": [{"line_number": 1, "observation": "failed"}],
    "hypotheses": [], "recommended_checks": ["check link"],
    "confidence": "low", "confidence_explanation": "single line",
})


class FakeProvider:
    name, model = "fake", "fake-model"

    def complete(self, system: str, user: str) -> str:
        return GOOD_REPLY


@pytest.fixture
def base_url() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(FakeProvider(), {}))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


def call(
    url: str, data: bytes | None = None, content_type: str = "application/json"
) -> tuple[int, dict[str, Any], Any]:
    req = urllib.request.Request(url, data=data, method="POST" if data is not None else "GET")
    if data is not None:
        req.add_header("Content-Type", content_type)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read()), resp.headers
    except urllib.error.HTTPError as err:
        return err.code, json.loads(err.read()), err.headers


def post(base: str, path: str, payload: Any) -> tuple[int, dict[str, Any], Any]:
    return call(base + path, json.dumps(payload).encode())


def test_index_and_static_files_served(base_url: str) -> None:
    for path, marker in [("/", b"Flight Log Copilot"), ("/app.js", b"textContent"),
                         ("/style.css", b"--bg")]:
        with urllib.request.urlopen(base_url + path) as resp:
            assert marker in resp.read()
            assert "default-src 'self'" in resp.headers["Content-Security-Policy"]


def test_parse_endpoint_matches_cli_json(base_url: str) -> None:
    status, data, _ = post(base_url, "/api/parse", {"text": LOG})
    assert status == 200 and data["total_events"] == 1
    assert data["events"][0]["mission_item"] == 0          # zero preserved, not null
    assert data["malformed_lines"][0]["line_number"] == 2


def test_diagnose_endpoint_with_mock_provider(base_url: str) -> None:
    status, data, _ = post(base_url, "/api/diagnose", {"text": LOG})
    assert status == 200 and data["diagnosis_error"] is None
    assert data["diagnosis"]["evidence"][0]["log_message"].startswith("Mission transfer")


def test_diagnose_nothing_to_diagnose(base_url: str) -> None:
    _, data, _ = post(base_url, "/api/diagnose", {"text": "2024-03-14 10:15:04 [INFO] ok"})
    assert data["diagnosis"] is None and "nothing to diagnose" in data["diagnosis_error"]


def test_diagnose_missing_credentials_reported_not_crashed() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(None, {}))  # no provider, empty env
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}"
        status, data, _ = post(url, "/api/diagnose", {"text": LOG})
        assert status == 200 and data["diagnosis"] is None
        assert "ANTHROPIC_API_KEY" in data["diagnosis_error"]
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize("payload", [[1], {"text": 5}, {"nope": "x"}])
def test_bad_payloads_get_400(base_url: str, payload: Any) -> None:
    assert post(base_url, "/api/parse", payload)[0] == 400


def test_non_json_body_400(base_url: str) -> None:
    assert call(base_url + "/api/parse", b"not json")[0] == 400


def test_oversized_body_413(base_url: str) -> None:
    big = json.dumps({"text": "x" * (MAX_BODY_BYTES + 1)}).encode()
    try:
        status = call(base_url + "/api/parse", big)[0]
    except (urllib.error.URLError, ConnectionError):
        return  # server closed the connection mid-upload: also a rejection
    assert status == 413


def test_unknown_paths_404_and_no_file_traversal(base_url: str) -> None:
    assert call(base_url + "/nope")[0] == 404
    assert call(base_url + "/../app/web.py")[0] == 404
    assert call(base_url + "/api/unknown", b"{}")[0] == 404


def test_sample_endpoint(base_url: str) -> None:
    status, data, _ = call(base_url + "/api/sample")
    assert status == 200 and "Mission upload started" in data["text"]


# ===================== v2: binary uploads, local paths, crashes, hardening =====================

import http.client  # noqa: E402
import tempfile  # noqa: E402
from pathlib import Path  # noqa: E402

from tests.builders import (  # noqa: E402
    T0,
    DataflashBuilder,
    TlogBuilder,
    mission_ack,
    mission_count,
    mission_request,
)
from tests.test_crash import SEGV_FRAMES, block  # noqa: E402

CRASH_TEXT = block(7, "11 (SEGV)", "Fri 2026-08-21 11:48:10", SEGV_FRAMES)
OCTET = "application/octet-stream"


def _crash_runner(argv: Any) -> tuple[int, str]:
    return 0, CRASH_TEXT


@pytest.fixture
def server() -> Iterator[tuple[str, int]]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(
        FakeProvider(), {}, crash_runner=_crash_runner, use_addr2line=False))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    yield f"http://127.0.0.1:{port}", port
    srv.shutdown()
    srv.server_close()


def tlog_bytes(tmp_path: Path) -> bytes:
    b = TlogBuilder().heartbeat(T0).status(T0 + 1, 3, "Bad AHRS")
    b.gcs(T0 + 2, mission_count(4)).vehicle(T0 + 2.1, mission_request(0))
    b.vehicle(T0 + 3, mission_ack(13)).heartbeat(T0 + 4)
    return b.write(tmp_path / "x.tlog").read_bytes()


def upload(base: str, name: str, data: bytes) -> tuple[int, dict[str, Any], Any]:
    return call(f"{base}/api/analyze?name={urllib.parse.quote(name)}", data, OCTET)


def test_upload_tlog_returns_findings_and_keeps_the_filename(
    server: tuple[str, int], tmp_path: Path
) -> None:
    base, _ = server
    status, data, _ = upload(base, "my flight.tlog", tlog_bytes(tmp_path))
    assert status == 200 and data["source_type"] == "tlog"
    assert data["source_name"] == "my flight.tlog" and data["token"]
    assert data["findings"][0]["kind"] == "mission_transfer_failed"


def test_upload_bin_and_crash_text(server: tuple[str, int], tmp_path: Path) -> None:
    base, _ = server
    bin_data = DataflashBuilder().msg(1_000_000, "ArduCopter").err(2_000_000, 12, 1)
    path = bin_data.write(tmp_path / "a.BIN")
    status, data, _ = upload(base, "00000001.BIN", path.read_bytes())
    assert status == 200 and data["source_type"] == "bin"
    status, data, _ = upload(base, "crash.txt", CRASH_TEXT.encode())
    assert status == 200 and data["source_type"] == "crash"


def test_upload_garbage_is_a_422_not_a_crash(server: tuple[str, int]) -> None:
    status, data, _ = upload(server[0], "bad.tlog", b"garbage" * 30)
    assert status == 422 and "error" in data
    status, data, _ = upload(server[0], "blob.bin2", b"\xff\x00" * 40)
    assert status == 422 and "unrecognised binary" in data["error"]


def test_upload_leaves_no_temp_files_behind(server: tuple[str, int], tmp_path: Path) -> None:
    before = set(Path(tempfile.gettempdir()).glob("flc-upload-*"))
    upload(server[0], "a.tlog", tlog_bytes(tmp_path))
    upload(server[0], "bad.tlog", b"garbage" * 30)
    assert set(Path(tempfile.gettempdir()).glob("flc-upload-*")) == before


def test_upload_size_limit(server: tuple[str, int], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("app.web.MAX_UPLOAD_BYTES", 100)
    try:
        status = upload(server[0], "a.tlog", b"x" * 500)[0]
    except (urllib.error.URLError, ConnectionError):
        return
    assert status == 413


def test_analyze_path(server: tuple[str, int], tmp_path: Path) -> None:
    base, _ = server
    log = tmp_path / "f.tlog"
    log.write_bytes(tlog_bytes(tmp_path))
    status, data, _ = post(base, "/api/analyze-path", {"path": str(log)})
    assert status == 200 and data["source_name"] == "f.tlog" and data["source_type"] == "tlog"
    assert post(base, "/api/analyze-path", {"path": str(tmp_path / "nope")})[0] == 404
    assert post(base, "/api/analyze-path", {"path": str(tmp_path)})[0] == 400
    assert post(base, "/api/analyze-path", {"path": 5})[0] == 400
    assert post(base, "/api/analyze-path", {"path": "  "})[0] == 400


def test_system_crashes_endpoint(server: tuple[str, int]) -> None:
    base, _ = server
    status, data, _ = post(base, "/api/system-crashes", {"name": "MYAPP"})
    assert status == 200 and data["source_type"] == "crash" and data["stats"]["crash_count"] == 1
    assert post(base, "/api/system-crashes", {"name": "x; rm -rf /"})[0] == 400
    assert post(base, "/api/system-crashes", {"name": 5})[0] == 400


def test_diagnose_by_token_and_unknown_token(server: tuple[str, int], tmp_path: Path) -> None:
    base, _ = server
    _, data, _ = upload(base, "a.tlog", tlog_bytes(tmp_path))
    status, diag, _ = post(base, "/api/diagnose", {"token": data["token"]})
    assert status == 200 and diag["diagnosis"]["provider"] == "fake"
    assert post(base, "/api/diagnose", {"token": "nope"})[0] == 404


def test_token_store_is_bounded(server: tuple[str, int]) -> None:
    base, _ = server
    first = post(base, "/api/parse", {"text": "2024-03-14 10:15:04 [ERROR] boom"})[1]["token"]
    for _ in range(5):
        post(base, "/api/parse", {"text": "2024-03-14 10:15:04 [ERROR] boom"})
    assert post(base, "/api/diagnose", {"token": first})[0] == 404


def test_parse_endpoint_now_also_returns_findings_and_token(server: tuple[str, int]) -> None:
    _, data, _ = post(server[0], "/api/parse", {"text": LOG})
    assert data["source_type"] == "text" and data["findings"] == [] and data["token"]


def test_foreign_host_header_is_rejected(server: tuple[str, int]) -> None:
    _, port = server
    for method, path in (("GET", "/"), ("POST", "/api/parse")):
        conn = http.client.HTTPConnection("127.0.0.1", port)
        conn.request(method, path, body=b"{}" if method == "POST" else None,
                     headers={"Host": "evil.example", "Content-Type": "application/json"})
        assert conn.getresponse().status == 403
        conn.close()


def test_wrong_content_types_are_rejected(server: tuple[str, int]) -> None:
    base, _ = server
    body = json.dumps({"text": LOG}).encode()
    assert call(base + "/api/parse", body, "text/plain")[0] == 415
    assert call(base + "/api/parse", body, "application/x-www-form-urlencoded")[0] == 415
    assert call(base + "/api/analyze?name=a.tlog", body, "application/json")[0] == 415
    assert call(base + "/api/system-crashes", b"{}", "text/plain")[0] == 415


def test_upload_returns_file_info_with_the_browsers_file_date(
    server: tuple[str, int], tmp_path: Path
) -> None:
    base, _ = server
    data = tlog_bytes(tmp_path)
    ms = 1_700_000_000_000  # file's lastModified from the browser (epoch ms)
    status, body, _ = call(
        f"{base}/api/analyze?name={urllib.parse.quote('my flight.tlog')}&modified={ms}", data, OCTET)
    assert status == 200
    assert body["file_info"] == {
        "name": "my flight.tlog", "size_bytes": len(data),
        "modified": "2023-11-14T22:13:20+00:00"}


@pytest.mark.parametrize("modified", ["", "abc", "99999999999999999999999"])
def test_upload_with_bad_or_missing_file_date_still_works(
    server: tuple[str, int], tmp_path: Path, modified: str
) -> None:
    base, _ = server
    status, body, _ = call(f"{base}/api/analyze?name=a.tlog&modified={modified}",
                           tlog_bytes(tmp_path), OCTET)
    assert status == 200 and body["file_info"]["modified"] is None


def test_upload_filename_cannot_smuggle_a_path(server: tuple[str, int], tmp_path: Path) -> None:
    base, _ = server
    name = urllib.parse.quote("../../etc/evil.tlog")
    _, body, _ = call(f"{base}/api/analyze?name={name}", tlog_bytes(tmp_path), OCTET)
    assert body["file_info"]["name"] == "evil.tlog"


def test_analyze_path_returns_file_info_from_disk(
    server: tuple[str, int], tmp_path: Path
) -> None:
    base, _ = server
    log = tmp_path / "f.tlog"
    log.write_bytes(tlog_bytes(tmp_path))
    _, body, _ = post(base, "/api/analyze-path", {"path": str(log)})
    info = body["file_info"]
    assert info["name"] == "f.tlog" and info["size_bytes"] == log.stat().st_size
    assert info["modified"].endswith("+00:00")


def test_pasted_text_and_crashes_have_no_file_info(server: tuple[str, int]) -> None:
    base, _ = server
    assert post(base, "/api/parse", {"text": LOG})[1]["file_info"] is None
    assert post(base, "/api/system-crashes", {"name": "MYAPP"})[1]["file_info"] is None
