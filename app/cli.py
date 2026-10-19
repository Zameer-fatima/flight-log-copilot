"""Command-line interface: ``python -m app.cli <logfile> [--json] [--errors-only]``."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any

from app.analysis.errors import AnalysisError
from app.analysis.loader import analyze_path, default_symbolizer
from app.analysis.models import Analysis, Finding
from app.analysis.serialization import analysis_to_dict
from app.models import LogEvent, LogLevel, ParseResult

if TYPE_CHECKING:  # AI layer is imported lazily so parser-only use needs no extras
    from app.ai.models import Diagnosis
    from app.ai.provider import LLMProvider
    from app.analysis.crash import Runner

EXIT_OK = 0
EXIT_INPUT_ERROR = 1
EXIT_DIAGNOSIS_ERROR = 3


def build_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    parser = argparse.ArgumentParser(
        prog="python -m app.cli",
        description="Analyze flight/GCS logs (.tlog, .bin, crash logs, text logs) and print findings.",
        epilog="Exit codes: 0 success, 1 file/input error, 2 bad arguments, "
               "3 AI diagnosis failed (parser output is still printed).",
    )
    parser.add_argument("logfile", type=Path, nargs="?",
                        help="log file: .tlog, ArduPilot .bin, crash text, or plain text log "
                             "(format is auto-detected)")
    parser.add_argument("--format", choices=["auto", "text", "tlog", "bin", "crash"],
                        default="auto", help="force a reader instead of auto-detecting")
    parser.add_argument("--system-crashes", nargs="?", const="", default=None, metavar="NAME",
                        help="analyze application crashes recorded by systemd-coredump "
                             "(coredumpctl); optionally only for program NAME, e.g. my-gcs-app")
    parser.add_argument("--no-symbols", action="store_true",
                        help="do not resolve crash frames with addr2line")
    parser.add_argument("--max-gap", type=float, default=5.0, metavar="SECONDS",
                        help="tlog: report heartbeat gaps longer than this (default 5)")
    parser.add_argument("--json", action="store_true", dest="as_json",
                        help="print the full structured result as JSON")
    parser.add_argument("--errors-only", action="store_true",
                        help="show only ERROR and CRITICAL events "
                             "(with --json, 'events' is limited to those)")
    parser.add_argument("--diagnose", action="store_true",
                        help="also ask an LLM for a diagnosis of the problem events "
                             "(sends selected log lines to the provider; needs "
                             "ANTHROPIC_API_KEY)")
    parser.add_argument("--show-prompt", action="store_true",
                        help="with --diagnose: print exactly what would be sent and "
                             "exit, without any network call or API key")
    return parser


def format_diagnosis(diagnosis: Diagnosis) -> str:
    """Render an AI diagnosis as text, clearly labelled as AI-generated."""
    out = [
        "",
        f"AI diagnosis ({diagnosis.provider}/{diagnosis.model}) -- AI-generated, "
        "NOT verified. Causes below are hypotheses.",
        "",
        f"Summary: {diagnosis.summary}",
        "",
        "Evidence (log text is from the parsed file):",
    ]
    out += [f"  line {e.line_number:>4}: {e.log_message}\n             -> {e.observation}"
            for e in diagnosis.evidence] or ["  (none verified)"]
    out += ["", "Hypotheses (unconfirmed):"]
    for n, h in enumerate(diagnosis.hypotheses, 1):
        lines = ", ".join(map(str, h.supporting_lines)) or "none"
        out += [f"  {n}. [{h.confidence}] {h.description}",
                f"     supporting lines: {lines}", f"     why: {h.reasoning}"]
    if not diagnosis.hypotheses:
        out.append("  (none)")
    out += ["", "Recommended checks:"]
    out += [f"  - {c}" for c in diagnosis.recommended_checks] or ["  (none)"]
    out += ["", f"Confidence: {diagnosis.confidence} -- {diagnosis.confidence_explanation}"]
    if diagnosis.warnings:
        out += ["", "Safeguard warnings:"] + [f"  ! {w}" for w in diagnosis.warnings]
    return "\n".join(out)


def _run_diagnosis(
    analysis: Analysis, provider: LLMProvider | None, environ: Mapping[str, str]
) -> Diagnosis | None:
    """Run the AI layer; may raise ``DiagnosticsError``."""
    from app.ai.config import LLMConfig
    from app.ai.provider import create_provider
    from app.ai.service import diagnose

    if provider is None:
        provider = create_provider(LLMConfig.from_env(environ))
    return diagnose(analysis.result, provider, findings=analysis.findings,
                    source_type=analysis.source_type)


def _format_event(event: LogEvent) -> str:
    item = "" if event.mission_item is None else f" [item {event.mission_item}]"
    if event.timestamp is not None:
        when = event.timestamp.isoformat()
    elif event.elapsed_s is not None:
        when = f"t+{event.elapsed_s:.2f}s"
    else:
        when = "-"
    return (f"  line {event.line_number:>4}  {when}  "
            f"{event.level.value:<8} {event.message}{item}")


_RANK = {LogLevel.CRITICAL: 0, LogLevel.ERROR: 1, LogLevel.WARNING: 2,
         LogLevel.INFO: 3, LogLevel.DEBUG: 4}


def format_stats(analysis: Analysis) -> str:
    """Header lines describing a non-text source."""
    st = analysis.stats
    out = [f"Source: {analysis.source_type}  ({analysis.source_name})"]
    if analysis.source_type == "tlog":
        out.append(f"Duration: {st['duration_s']}s, armed {st['armed_s']}s, "
                   f"{st['packets_decoded']} MAVLink packets")
        for name, info in st["vehicles"].items():
            out.append(f"Vehicle {name}: {info['vehicle_type']} / {info['autopilot']}")
        out.append(f"Mission transfers: {len(st['mission_transfers'])}, "
                   f"heartbeat gaps >{st['max_gap_threshold_s']}s: {st['heartbeat_gaps']}")
    elif analysis.source_type == "bin":
        out.append(f"Firmware: {st.get('firmware') or 'unknown'}; duration {st['duration_s']}s; "
                   f"time base: {st['time_base']}")
    elif analysis.source_type == "crash":
        out.append(f"Crashes: {st['crash_count']} ({st['distinct_crash_sites']} distinct "
                   f"location(s)); programs: {', '.join(st['executables'])}; "
                   f"signals: {', '.join(st['signals'])}")
    for warning in st.get("reader_warnings", []):
        out.append(f"Reader note: {warning}")
    return "\n".join(out)


def format_findings(findings: Sequence[Finding]) -> str:
    """Findings, most severe first, each with its explanation."""
    if not findings:
        return "Findings: none"
    out = [f"Findings ({len(findings)}):"]
    for f in sorted(findings, key=lambda f: _RANK[f.severity]):
        out.append(f"  [{f.severity.value}] {f.title}")
        out += [f"      {ln}" for ln in f.detail.splitlines()]
    return "\n".join(out)


def format_summary(
    result: ParseResult, errors_only: bool = False, text_source: bool = True
) -> str:
    """Render a human-readable summary (line/malformed counters only for text logs)."""
    lines = [f"Lines read:       {result.total_lines}"] if text_source else []
    lines += [
        f"Parsed events:    {result.total_events}",
        "By level:         " + ", ".join(
            f"{lvl.value}={n}" for lvl, n in result.counts_by_level.items()),
    ]
    if text_source:
        lines.append(f"Malformed lines:  {len(result.malformed_lines)}")
    lines.append("")
    shown = result.error_events if errors_only else result.events
    lines.append("Errors (ERROR/CRITICAL):" if errors_only else "Events:")
    if shown:
        lines.extend(_format_event(e) for e in shown)
    else:
        lines.append("  (none)")
    if result.malformed_lines:
        lines += ["", "Malformed lines:"]
        lines += [f"  line {m.line_number:>4}  {m.text!r}  ({m.reason})"
                  for m in result.malformed_lines]
    return "\n".join(lines)


def main(
    argv: Sequence[str] | None = None,
    *,
    provider: LLMProvider | None = None,
    environ: Mapping[str, str] | None = None,
    crash_runner: Runner | None = None,
) -> int:
    """Run the CLI and return the process exit code.

    ``provider``, ``environ`` and ``crash_runner`` exist so tests can inject a
    fake LLM, a fake environment and a fake ``coredumpctl``.
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.show_prompt and not args.diagnose:
        parser.error("--show-prompt requires --diagnose")
    if args.system_crashes is None and args.logfile is None:
        parser.error("a log file is required (or use --system-crashes)")
    if args.system_crashes is not None and args.logfile is not None:
        parser.error("use either a log file or --system-crashes, not both")
    symbolize = None if args.no_symbols else default_symbolizer()

    path = args.logfile
    try:
        if args.system_crashes is not None:
            from app.analysis.crash import analyze_crash_text, collect_system_crashes

            text = collect_system_crashes(args.system_crashes, crash_runner)
            analysis = analyze_crash_text(text, "coredumpctl", symbolize)
        else:
            analysis = analyze_path(path, args.format, symbolize=symbolize,
                                    max_gap_s=args.max_gap)
    except FileNotFoundError:
        print(f"error: file not found: {path}", file=sys.stderr)
        return EXIT_INPUT_ERROR
    except UnicodeDecodeError as exc:
        print(f"error: {path} is not valid UTF-8 text ({exc.reason})", file=sys.stderr)
        return EXIT_INPUT_ERROR
    except OSError as exc:  # directory, permission denied, I/O failure
        print(f"error: cannot read {path}: {exc.strerror or exc}", file=sys.stderr)
        return EXIT_INPUT_ERROR
    except AnalysisError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INPUT_ERROR

    result = analysis.result
    is_text = analysis.source_type == "text"

    if args.show_prompt:
        from app.ai.prompt import build_prompt

        prompt = build_prompt(result, findings=analysis.findings,
                              source_type=analysis.source_type)
        if prompt is None:
            print("No WARNING/ERROR/CRITICAL events or findings: nothing would be sent.")
        else:
            print(f"--- SYSTEM ---\n{prompt.system}\n--- USER ---\n{prompt.user}")
        return EXIT_OK

    diagnosis: Diagnosis | None = None
    diagnosis_error: str | None = None
    if args.diagnose:
        from app.ai.errors import DiagnosticsError

        try:
            env = os.environ if environ is None else environ
            diagnosis = _run_diagnosis(analysis, provider, env)
        except DiagnosticsError as exc:
            diagnosis_error = str(exc)

    if args.as_json:
        data: dict[str, Any] = analysis_to_dict(analysis)
        if args.errors_only:
            data["events"] = data["error_events"]
        if args.diagnose:
            from app.ai.serialization import diagnosis_to_dict

            data["diagnosis"] = diagnosis_to_dict(diagnosis) if diagnosis else None
            data["diagnosis_error"] = diagnosis_error
        print(json.dumps(data, indent=2))
    else:
        if not is_text:
            print(format_stats(analysis))
            print()
            print(format_findings(analysis.findings))
            print()
        print(format_summary(result, errors_only=args.errors_only, text_source=is_text))
        if diagnosis is not None:
            print(format_diagnosis(diagnosis))
        elif args.diagnose and diagnosis_error is None:
            print("\nAI diagnosis skipped: no WARNING/ERROR/CRITICAL events to diagnose.")

    if diagnosis_error is not None:
        print(f"error: AI diagnosis failed: {diagnosis_error}", file=sys.stderr)
        return EXIT_DIAGNOSIS_ERROR
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
