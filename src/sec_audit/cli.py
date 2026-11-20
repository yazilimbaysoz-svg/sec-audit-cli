from __future__ import annotations

import argparse
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from sec_audit import __version__
from sec_audit.models import Finding, Severity
from sec_audit.report import build_report, render_terminal, to_json, write_report
from sec_audit.scanners.dependencies import scan_dependencies
from sec_audit.scanners.owasp import scan_text as scan_owasp_text
from sec_audit.scanners.secrets import scan_text as scan_secrets_text
from sec_audit.utils import CODE_EXTENSIONS, iter_files, read_text

SEVERITY_CHOICES = ("info", "low", "medium", "high", "critical")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sec-audit",
        description="Scan a project for leaked secrets, vulnerable packages and OWASP risks.",
        epilog="Example: sec-audit . --fail-on high --output sec-audit-report.json",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("path", nargs="?", default=".", help="project directory (default: .)")
    parser.add_argument("--json", action="store_true", help="print the JSON report to stdout")
    parser.add_argument("-o", "--output", metavar="FILE", help="write the JSON report to a file")
    parser.add_argument(
        "--fail-on",
        choices=(*SEVERITY_CHOICES, "none"),
        default="high",
        help="exit with status 1 when a finding of this severity or higher exists",
    )
    parser.add_argument(
        "--min-severity",
        choices=SEVERITY_CHOICES,
        default="info",
        help="hide findings below this severity",
    )
    parser.add_argument(
        "--exclude", action="append", default=[], metavar="GLOB", help="exclude paths"
    )
    parser.add_argument(
        "--include", action="append", default=[], metavar="GLOB", help="include only paths"
    )
    parser.add_argument(
        "--max-file-size",
        type=int,
        default=5,
        metavar="MB",
        help="skip files larger than this size (default: 5)",
    )
    parser.add_argument(
        "--online", action="store_true", help="query the OSV vulnerability database"
    )
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    parser.add_argument("-q", "--quiet", action="store_true", help="print only the summary")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _analyze(item: tuple[Path, str]) -> tuple[str, str, list[Finding]]:
    path, relative_path = item
    text = read_text(path)
    if text is None:
        return relative_path, "", []
    findings = scan_secrets_text(text, relative_path)
    if Path(relative_path).suffix.lower() in CODE_EXTENSIONS:
        findings.extend(scan_owasp_text(text, relative_path))
    return relative_path, text, findings


def run_scan(args: argparse.Namespace) -> tuple[dict[str, object], float]:
    root = Path(args.path).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"not a directory: {root}")

    started = time.perf_counter()
    files = list(
        iter_files(
            root,
            tuple(args.include),
            tuple(args.exclude),
            args.max_file_size * 1024 * 1024,
        )
    )
    findings: list[Finding] = []
    manifests: list[tuple[str, str]] = []
    workers = min(8, max(1, len(files)))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        for relative_path, text, group in executor.map(_analyze, files):
            findings.extend(group)
            if text:
                manifests.append((relative_path, text))

    findings.extend(scan_dependencies(manifests, online=args.online))
    minimum = Severity[args.min_severity.upper()]
    findings = [finding for finding in findings if finding.severity >= minimum]
    findings.sort(key=lambda item: (-item.severity, item.file, item.line, item.rule_id))
    duration_ms = (time.perf_counter() - started) * 1000

    config: dict[str, object] = {
        "include": list(args.include),
        "exclude": list(args.exclude),
        "min_severity": args.min_severity,
        "fail_on": args.fail_on,
        "online": args.online,
        "max_file_size_mb": args.max_file_size,
    }
    return build_report(str(root), findings, duration_ms, config), duration_ms


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report, _ = run_scan(args)
        if args.json:
            sys.stdout.write(to_json(report) + "\n")
        elif args.quiet:
            sys.stdout.write(f"{report['summary']['total']} finding(s)\n")
        else:
            use_color = not args.no_color and sys.stdout.isatty() and "NO_COLOR" not in os.environ
            sys.stdout.write(render_terminal(report, color=use_color))
        if args.output:
            write_report(report, args.output)
    except (OSError, ValueError) as error:
        sys.stderr.write(f"sec-audit: {error}\n")
        return 2
    except KeyboardInterrupt:
        sys.stderr.write("sec-audit: interrupted\n")
        return 130

    threshold = Severity[args.fail_on.upper()] if args.fail_on != "none" else None
    if threshold is not None and any(
        Severity[finding["severity"]] >= threshold for finding in report["findings"]
    ):
        return 1
    return 0
