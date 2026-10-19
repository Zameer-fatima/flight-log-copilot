# Flight Log Copilot

Analyzes drone / GCS debugging data and tells you **what went wrong and where to look**:

| Input | What it extracts |
|---|---|
| **`.tlog`** (MAVLink telemetry, e.g. from QGroundControl) | status messages with real severities, arm/disarm, mode changes, heartbeat gaps, rejected commands, and a **mission upload/download reconstruction** (which item stalled, retries, final ACK result) |
| **`.BIN`** (ArduPilot dataflash) | `MSG` text, decoded `ERR` records (subsystem + code, e.g. `CRASH_CHECK: crash detected`), `EV` events, mode changes, firmware |
| **Application crashes** (`coredumpctl`, gdb output, console crash text) | signal and its meaning, crash location with function names (via `addr2line`), repeated crash sites, glibc heap-corruption detection, missing-core diagnosis |
| **Plain text logs** (`timestamp [LEVEL] message`) | the original Phase 1 parser |

Everything above is **deterministic** (no AI). An optional `--diagnose` step then asks an LLM to *explain* the
findings, with safeguards (see [AI diagnostics](#ai-diagnostics)). Sample text data is synthetic.

## Setup

Python 3.10+ (developed on 3.10.12).

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt          # pymavlink + anthropic + dev tools
# or as a package:  pip install -e '.[all]'   (extras: binary = pymavlink, ai = anthropic)
```

Plain text logs need nothing beyond the standard library. `.tlog`/`.bin` need `pymavlink`; `--diagnose` needs `anthropic`.
Crash analysis uses the system tools `coredumpctl` (systemd) and `addr2line` (binutils) when present.

## Usage

```bash
python -m app.cli flight.tlog                  # format is auto-detected from the bytes
python -m app.cli 00000012.BIN
python -m app.cli crash_output.txt             # gdb / console crash text
python -m app.cli --system-crashes my-gcs-app    # systemd-coredump records for one program (blank = all)
python -m app.cli flight.tlog --json           # full structured result (stable keys)
python -m app.cli flight.tlog --errors-only    # events limited to ERROR/CRITICAL (findings always shown)
python -m app.cli flight.tlog --max-gap 10     # tlog: heartbeat-gap threshold in seconds (default 5)
python -m app.cli crash.txt --no-symbols       # skip addr2line
python -m app.cli sample_data/flight.log       # plain text log
python -m app.cli --help
```

`--format {auto,text,tlog,bin,crash}` forces a reader. Exit codes: `0` ok, `1` input/analysis error
(missing file, unsupported or corrupt file, missing dependency), `2` bad arguments, `3` AI step failed
(analysis output is still printed).

### Web UI

```bash
python -m app.web        # open http://127.0.0.1:8000    (--port N; local only)
```

Open/upload a `.tlog`/`.BIN`/crash file, give a **local path** (best for big logs, no upload), or press
**Analyze app crashes** (reads `coredumpctl`). You get source stats, a prioritised **findings** list, a filterable
events table and the optional AI diagnosis. Deep links: `/?sample=1`, `/?crashes=PROGRAM`, `/?path=/some/file.tlog`.

The server is a local tool: it binds to localhost, requires a loopback `Host` header and a JSON/octet-stream
content type (blocks DNS-rebinding and cross-site POSTs), caps uploads (512 MiB) and pasted text (2 MiB),
serves only three static files, renders log text with `textContent` only, and deletes upload temp files.
It is not a hardened multi-user service. Because it can read paths you type, don't expose it on a network.

## Deploy a public showcase

The full server can read local files, local crash records and use your API key, so it **refuses to listen on a public
address**. For a showcase, run it in **demo mode** (`--demo` or `FLC_DEMO=1`): visitors get the built-in synthetic samples
(telemetry, ArduPilot log, app crash, text log) and can upload small files (max 5 MB, analysed in memory, deleted
straight away). Server paths, system crash records and AI diagnosis are switched off, the AI provider is never called,
and no API key is needed. The samples in `sample_data/` are invented (`tools/make_demo_samples.py` regenerates them);
no real flight or machine data is included.

Try it locally first:

```bash
python -m app.web --demo --host 0.0.0.0 --port 8001      # http://127.0.0.1:8001
docker build -t flight-log-copilot . && docker run --rm -p 8000:8000 flight-log-copilot   # same, in Docker
```

**Render (no Docker needed, free plan):** push the project to a GitHub repository, then in Render choose
*New + > Blueprint* and select the repo. `render.yaml` sets the build (`pip install -r requirements-demo.txt`), the start
command (`python -m app.web --demo --host 0.0.0.0`, the port comes from `$PORT`) and `FLC_DEMO=1`. You get an
`https://<name>.onrender.com` URL. Free plans sleep when idle, so the first visit after a pause takes about a minute.

**Other hosts:** anything that runs a Dockerfile works (Hugging Face Spaces with the Docker SDK, Railway, Fly.io, a small
VM): the image listens on `$PORT` (default 8000) in demo mode. Netlify/GitHub Pages cannot host it (static hosting only;
the analysis is a Python backend).

Before publishing, check `git status` for anything private (keep `.env` out of git; nothing here needs one in demo mode).

## How findings work (and what they are not)

Findings are computed by code, from the data, and say which kind of statement they are:

- **Facts** follow directly from the log: a mission upload ended with `MAV_MISSION_INVALID_SEQUENCE` after item 2;
  signal `SIGSEGV` at `QObject::property` in `libQt6Core + 0x1b2845`; the same crash site hit 60 times; `malloc_printerr`
  in the stack (glibc detected heap corruption); the core file is missing.
- **Heuristics** are labelled `Hypothesis` / `HEURISTIC, not proven` (e.g. "a crash directly inside a Qt method usually
  means an invalid object was passed"), and keyword flags on dataflash `MSG` text (those records carry no severity,
  so their level is never invented).
- **Tables** (ERR subsystems/codes, event ids) are copied from ArduPilot's `AP_Logger.h`; unknown values are shown as
  numbers, never guessed.

Heartbeat gaps are measured on the vehicle autopilot's heartbeats only. Duplicate packets from a second link are
merged (otherwise every request would look like a retry). A binary event's `line` number is its sequence number in
the analysis; `timestamp` is `null` when the source has no wall clock (`.BIN` without GPS), with `elapsed_s` instead.

### Reading a crash report

1. Check **repeated_crash**: identical signal + location every time means one deterministic bug, not random corruption.
2. Read the **signal meaning** and the **site** (first frame that is not abort()/free() machinery).
3. `heap_corruption` means the damage happened *before* the crash; run under AddressSanitizer/valgrind.
4. `unwind_incomplete` / `unresolved_frame`: the app's own frames are missing; build with `-g` and
   `-fno-omit-frame-pointer`, and archive the exact binary of each build (a rebuilt binary makes old offsets
   meaningless, shown as `(deleted)`).
5. `core_missing`: without the core you can't inspect variables; keep cores (`ulimit -c unlimited`, systemd-coredump
   storage limits) and use `coredumpctl gdb <pid>`.

## AI diagnostics

`--diagnose` sends a *selected extract* (WARNING+ events and findings, with context) to an LLM and prints a structured
diagnosis: summary, evidence, hypotheses, recommended checks, confidence. The deterministic findings go in too, so the
model explains them rather than rediscovering them. Without `--diagnose` nothing changes and no AI code is imported.

| Variable | Default | Meaning |
|---|---|---|
| `ANTHROPIC_API_KEY` | (required) | API key; read only from the environment, never printed |
| `FLC_LLM_PROVIDER` | `anthropic` | provider name (only `anthropic` ships) |
| `FLC_LLM_MODEL` | `claude-opus-5-5` | model id (e.g. `claude-sonnet-5-5` for lower cost) |
| `FLC_LLM_TIMEOUT` | `120` | request timeout, seconds |
| `FLC_LLM_MAX_TOKENS` | `16000` | max response tokens (includes model reasoning) |
| `FLC_LLM_MAX_RETRIES` | `2` | SDK retries on 429/5xx/connection errors |

```bash
export ANTHROPIC_API_KEY=...             # never commit it
python -m app.cli --system-crashes my-gcs-app --diagnose
python -m app.cli flight.tlog --diagnose --show-prompt   # preview exactly what would be sent; no network or key
```

**Safeguards** (`app/ai/validation.py`; the model is treated as an untrusted producer): facts are separated from
hypotheses; evidence cites only event numbers and the shown text comes from the analysed file, not the model's quote;
cited events that were not sent are dropped; a hypothesis with no valid supporting event is forced to low confidence;
mission items not present in the events or findings are flagged and cap confidence at low; "confirmed / definitely /
root cause is" wording is flagged; non-JSON or off-schema replies are rejected. These are heuristics: a lead for an
engineer, never a verdict.

**Privacy.** `--diagnose` transmits text to the provider. Only WARNING+ events/findings plus 2 neighbours each side are
sent (max 150 events, 40 findings, messages truncated), malformed-line text is never sent, and home-directory names
(`/home/<user>`) are replaced by `~`. Crash frames still reveal program and library names. Log content is fenced and
escaped as untrusted data (prompt-injection mitigation, not a guarantee). Use `--show-prompt` to inspect the payload;
check your provider's data-retention terms.

## Architecture

| Path | Responsibility |
|---|---|
| `app/models.py`, `log_parser.py`, `serialization.py` | Phase 1: `LogEvent` (optional `timestamp`/`elapsed_s`), text parser, JSON |
| `app/analysis/detect.py`, `loader.py` | byte-level format detection; one `analyze_path()` entry point |
| `app/analysis/tlog.py`, `mission.py` | MAVLink reader; mission-transfer state machine (per mission type) |
| `app/analysis/dataflash.py`, `ardupilot.py` | `.BIN` reader; code tables from `AP_Logger.h` |
| `app/analysis/crash.py` | coredumpctl/gdb/console parsing, `addr2line`, crash findings, `collect_system_crashes()` |
| `app/analysis/models.py`, `serialization.py` | `Analysis` = `ParseResult` + `Finding`s + stats (+ ordering) |
| `app/ai/` | optional LLM diagnosis: config, provider (Anthropic SDK), prompt/scrubbing, validation, service |
| `app/cli.py`, `app/web.py`, `app/static/` | command line and web UI (full local mode + public `--demo` mode) |
| `tools/make_demo_samples.py`, `sample_data/demo.*` | generator and output of the synthetic demo samples |
| `Dockerfile`, `render.yaml`, `requirements-demo.txt` | deployment of the demo |
| `tests/` | `test_log_parser`, `test_diagnostics`, `test_tlog`, `test_dataflash`, `test_crash`, `test_sources_cli`, `test_web`; `builders.py` generates synthetic `.tlog`/`.BIN` |

Flow: file → `detect_format` → reader → `Analysis(events, findings, stats)` → text / JSON / UI →
(optional) `build_prompt` → `LLMProvider` → `parse_diagnosis` → `Diagnosis`. The Phase 1 parser never imports the
analysis or AI packages.

## Tests and checks

```bash
pytest                       # 231 tests; no API key, network, or real flight data needed
ruff check .
mypy app tests
```

External tools (`coredumpctl`, `addr2line`) are injected/faked in tests. Synthetic `.tlog`/`.BIN` files are built on
the fly with pymavlink's encoder, so no flight data is stored in the repo.

## Known limitations

- Mission analysis covers the mission protocol messages (count/request/item/ack); it does not model every vendor extension.
- `.tlog` reads only the message types listed above (no telemetry plots, battery/GPS/EKF trends yet), and `.BIN` reads
  `MSG/ERR/EV/MODE` only. Both are deliberate first steps; vibration, battery, GPS and EKF analysis are the natural next
  deterministic additions.
- Crash analysis needs the data to exist: if the journal kept no stack trace and the core file is gone, only the signal
  and executable are known. Frames in the application itself need a matching, unstripped binary to resolve.
- Crash frames are read from the first listed thread of each coredumpctl record (the crashing thread in practice).
- Python/Java tracebacks and Windows/macOS crash dumps are not parsed.
- Timestamps in coredumpctl output are local time without a zone.
- Text logs: one line = one event; only the `timestamp [LEVEL] message` layout.
- The AI step has only been exercised against mocks in the test suite, not a live model.
