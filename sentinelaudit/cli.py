"""Command-line entrypoint.

    python main.py --target local
    python main.py --target audit@10.0.0.5 --key ~/.ssh/audit_ed25519
    python main.py --target docker://vulnerable-ubuntu
    python main.py --target local --reaudit

Exit codes are meaningful, because Requirement 9 says a connector failure must
fail loudly rather than producing an empty report:

    0  audit completed (findings may include FAILs -- that is a successful audit)
    1  unexpected internal error
    2  the connector could not establish a session against the target
    3  the target's operating system could not be identified
    4  usage or configuration error
"""

from __future__ import annotations

import argparse
import sys
from typing import Any

from . import allowlist, engine, prioritizer, reporter, scoring
from .connectors.base import Connector, ConnectorError
from .connectors.docker import DockerConnector
from .connectors.local import LocalConnector
from .connectors.ssh import SSHConnector
from .diff import diff_reports, render as render_diff, render_terminal
from .models import CRITICAL, FAIL, HIGH, LOW, MEDIUM, PASS, UNKNOWN
from .platforms.detector import DetectionError, detect
from .rules import load_rules

EXIT_OK = 0
EXIT_INTERNAL = 1
EXIT_CONNECTOR = 2
EXIT_DETECTION = 3
EXIT_USAGE = 4

_MARK = {PASS: "PASS", FAIL: "FAIL", UNKNOWN: "UNKN"}


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sentinelaudit",
        description=(
            "Read-only, evidence-first security auditor. Runs a fixed allowlist "
            "of read-only commands against a target, evaluates CIS-style rules "
            "deterministically, and emits a prioritized remediation plan where "
            "every item traces to real captured output."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "--target", default="local",
        help="local | user@host | host | docker://container  (default: local)",
    )
    p.add_argument(
        "--transport", choices=("auto", "local", "ssh", "docker"), default="auto",
        help="override transport detection (default: auto, inferred from --target)",
    )
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("--user", default=None,
                   help="remote username; also read from SENTINEL_SSH_USER")
    p.add_argument("--key", default=None,
                   help="path to an SSH private key; also read from SENTINEL_SSH_KEY. "
                        "A path only -- key material is never read by this tool")
    p.add_argument("--insecure-host-key", action="store_true",
                   help="disable SSH host-key verification (throwaway targets only; "
                        "recorded loudly in the report)")
    p.add_argument("--platform", choices=("linux", "macos", "windows"), default=None,
                   help="skip OS detection and force a rule set")

    p.add_argument("--out", default="reports", help="report directory (default: reports)")
    p.add_argument("--reaudit", action="store_true",
                   help="diff this run against the most recent prior report")
    p.add_argument("--compare", nargs=2, metavar=("PREV", "CURR"),
                   help="diff two stored reports and exit (no target contacted)")

    p.add_argument("--llm", action="store_true",
                   help="use an LLM to write the 'why it matters' prose. Verdicts, "
                        "severities, ordering and fix commands stay deterministic")
    p.add_argument("--model", default=None, help="model id for --llm")

    p.add_argument("--list-rules", action="store_true",
                   help="print the rule set for --platform (or every platform) and exit")
    p.add_argument("--list-commands", action="store_true",
                   help="print the full command allowlist and exit")
    p.add_argument("--quiet", action="store_true", help="suppress progress output")
    return p


# ---------------------------------------------------------------------------
# Connector selection
# ---------------------------------------------------------------------------


def make_connector(args: argparse.Namespace) -> Connector:
    target = args.target.strip()
    transport = args.transport

    if transport == "auto":
        if target in ("local", "localhost", "127.0.0.1", ""):
            transport = "local"
        elif target.startswith("docker://"):
            transport = "docker"
        else:
            transport = "ssh"

    if transport == "local":
        return LocalConnector()

    if transport == "docker":
        container = target[len("docker://"):] if target.startswith("docker://") else target
        if not container:
            raise ValueError("--target docker:// requires a container name")
        return DockerConnector(container, user=args.user)

    host = target
    user = args.user
    if "@" in host:
        user, _, host = host.partition("@")
    if not host:
        raise ValueError("--target must name a host for the ssh transport")
    return SSHConnector(
        host=host, user=user, port=args.port, key_path=args.key,
        insecure_host_key=args.insecure_host_key,
    )


# ---------------------------------------------------------------------------
# Offline modes
# ---------------------------------------------------------------------------


def cmd_list_commands() -> int:
    print(f"Command allowlist version {allowlist.ALLOWLIST_VERSION} "
          f"({len(allowlist.ALL_COMMANDS)} entries, all validated read-only)\n")
    current = None
    for spec in allowlist.ALL_COMMANDS:
        if spec.platform != current:
            current = spec.platform
            print(f"\n[{current}]")
        print(f"  {spec.command_id:<32} {spec.display}")
        print(f"  {'':<32} {spec.description}")
    return EXIT_OK


def cmd_list_rules(platform: str | None) -> int:
    platforms = [platform] if platform else ["linux", "macos", "windows"]
    for name in platforms:
        rules = load_rules(name)
        print(f"\n[{name}] {len(rules)} rules")
        for rule in rules:
            print(f"  {rule.rule_id:<22} {rule.severity:<9} {rule.control_id:<12} "
                  f"{rule.title}")
            print(f"  {'':<22} reads: {', '.join(rule.commands)}")
    return EXIT_OK


def cmd_compare(prev: str, curr: str) -> int:
    from .diff import compare, load
    diff = compare(load(prev), load(curr))
    print(render_terminal(diff))
    return EXIT_OK


# ---------------------------------------------------------------------------
# Main audit flow
# ---------------------------------------------------------------------------


def _print_summary(report, out_paths: tuple[str, str]) -> None:
    summary = report.summary
    score = report.score
    by_sev = summary["failed_by_severity"]

    print("\n" + "=" * 62)
    print(f"  SECURITY SCORE: {score['value']}/100   (grade {score['grade']})")
    if not score.get("sufficient_coverage", True):
        print(f"  !! Only {score['coverage_percent']}% of the rule set was")
        print("     observable on this target. The score reflects what could")
        print("     be read, not the security of the host. Treat it as void.")
    print("=" * 62)
    print(f"  Critical : {by_sev[CRITICAL]}")
    print(f"  High     : {by_sev[HIGH]}")
    print(f"  Medium   : {by_sev[MEDIUM]}")
    print(f"  Low      : {by_sev[LOW]}")
    print(f"  Passed   : {summary['passed']}")
    print(f"  Unknown  : {summary['unknown']}")
    print("=" * 62)

    if report.fix_list:
        print("\nPRIORITIZED FIX LIST")
        for item in report.fix_list:
            print(f"  {item.priority}. [{item.severity}] {item.rule_id}  {item.finding}")
    else:
        print("\nNo failing checks on this target.")

    unknowns = [f for f in report.findings if f.status == UNKNOWN]
    if unknowns:
        print("\nUNKNOWN (not guessed at)")
        for f in unknowns:
            reason = (f.reason or "").split(";")[0]
            print(f"  {f.rule_id:<22} {reason[:70]}")

    print(f"\n  fingerprint : {report.fingerprint}")
    print(f"  json        : {out_paths[0]}")
    print(f"  markdown    : {out_paths[1]}\n")


def run(args: argparse.Namespace) -> int:
    quiet = args.quiet

    def say(msg: str = "") -> None:
        if not quiet:
            print(msg)

    try:
        connector = make_connector(args)
    except ValueError as exc:
        print(f"usage error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    notes: list[str] = []
    if getattr(connector, "insecure_host_key", False):
        warning = ("SSH host-key verification was DISABLED for this run "
                   "(--insecure-host-key). The session was not authenticated "
                   "against a known host key and is vulnerable to interception. "
                   "Never use this against a target you care about.")
        print(f"\n  !! {warning}\n", file=sys.stderr)
        notes.append(warning)

    say(f"Opening read-only session to {args.target} ...")
    try:
        connector.open()
    except ConnectorError as exc:
        print(f"\nconnector error: {exc}", file=sys.stderr)
        print("The run produced no report. Fix the connection and re-run.",
              file=sys.stderr)
        return EXIT_CONNECTOR

    try:
        info = connector.describe()
        say(f"  session open  ({info.transport} -> {info.label})")

        # -- detect ------------------------------------------------------
        if args.platform:
            platform, evidence = args.platform, "forced with --platform"
        else:
            say("\nDetecting operating system ...")
            try:
                platform, evidence = detect(connector)
            except DetectionError as exc:
                print(f"\ndetection error: {exc}", file=sys.stderr)
                return EXIT_DETECTION
        say(f"  {platform} detected  ({evidence})")

        rules = load_rules(platform)
        say(f"\nLoading {platform} security controls ...")
        say(f"  {len(rules)} rules loaded from the fixed rule set")

        # -- collect + evaluate -----------------------------------------
        say("\nCollecting evidence (read-only, allowlisted commands only) ...")

        def progress(index: int, total: int, description: str) -> None:
            if not quiet:
                print(f"  [{index:>2}/{total}] {description}")

        findings, results, feeds, collect_notes = engine.audit(
            connector, platform, progress
        )
        notes.extend(collect_notes)

        say("\nEvaluating rules ...")
        for f in findings:
            say(f"  {f.rule_id:<22} -> {_MARK[f.status]}")

        # -- prioritize --------------------------------------------------
        explanations: dict[str, str] = {}
        if args.llm:
            say("\nGenerating explanations ...")
            from .llm import LLMUnavailable, explain
            try:
                kwargs: dict[str, Any] = {}
                if args.model:
                    kwargs["model"] = args.model
                explanations, note = explain(findings, **kwargs)
                notes.append(note)
                say(f"  {note}")
            except LLMUnavailable as exc:
                note = (f"LLM explanations unavailable ({exc}); "
                        "fell back to the static rationale table")
                notes.append(note)
                say(f"  {note}")

        fix_list = prioritizer.build_fix_list(findings, explanations)
        summary = scoring.summarize(findings)
        score = scoring.score(findings)

        target_dict: dict[str, Any] = {
            "transport": info.transport,
            "label": info.label,
            **info.detail,
        }

        notes.append(
            f"Command allowlist version {allowlist.ALLOWLIST_VERSION}; "
            f"{len(results)} commands executed, all read-only and validated at "
            "both import time and execution time."
        )

        report = reporter.build_report(
            platform=platform,
            target=target_dict,
            findings=findings,
            fix_list=fix_list,
            commands=[results[cid] for cid in sorted(results)],
            summary=summary,
            score=score,
            notes=notes,
        )

        # -- reaudit -----------------------------------------------------
        previous = reporter.latest_report(args.out) if args.reaudit else None

        paths = reporter.save(report, feeds, args.out)
        # --quiet suppresses per-command progress, never the result: an audit
        # that prints nothing is indistinguishable from one that did not run.
        _print_summary(report, paths)

        if args.reaudit:
            if previous is None:
                print("  --reaudit: no prior report found in "
                      f"{args.out}/ -- this run is the new baseline.\n")
            else:
                diff = diff_reports(previous, report)
                print(render_terminal(diff))
                diff_path = paths[0].replace(".json", "_diff.md")
                with open(diff_path, "w", encoding="utf-8") as handle:
                    handle.write(render_diff(diff))
                print(f"  compared against : {previous}")
                print(f"  diff             : {diff_path}\n")

        return EXIT_OK
    finally:
        connector.close()


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_commands:
        return cmd_list_commands()
    if args.list_rules:
        return cmd_list_rules(args.platform)
    if args.compare:
        return cmd_compare(*args.compare)

    try:
        return run(args)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return EXIT_INTERNAL
    except Exception as exc:  # noqa: BLE001 - report cleanly instead of a traceback
        print(f"\ninternal error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_INTERNAL
