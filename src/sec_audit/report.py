from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from sec_audit import __version__
from sec_audit.models import SEVERITY_ORDER, Finding, Severity
from sec_audit.utils import Color, paint

SCHEMA_VERSION = "1.0"

SEVERITY_COLOR = {
    Severity.CRITICAL: Color.RED + Color.BOLD,
    Severity.HIGH: Color.RED,
    Severity.MEDIUM: Color.YELLOW,
    Severity.LOW: Color.BLUE,
    Severity.INFO: Color.DIM,
}

SEVERITY_SYMBOL = {
    Severity.CRITICAL: "X",
    Severity.HIGH: "!",
    Severity.MEDIUM: "~",
    Severity.LOW: ".",
    Severity.INFO: "i",
}


def build_report(
    scan_path: str,
    findings: list[Finding],
    duration_ms: float,
    config: dict[str, object],
) -> dict[str, object]:
    counts = {severity.name: 0 for severity in Severity}
    for finding in findings:
        counts[finding.severity.name] += 1
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": "sec-audit-cli",
        "version": __version__,
        "timestamp": datetime.now(UTC).isoformat(timespec="seconds"),
        "scan_path": scan_path,
        "duration_ms": round(duration_ms, 2),
        "summary": {
            "total": len(findings),
            "by_severity": counts,
            "clean": len(findings) == 0,
        },
        "config": config,
        "findings": [finding.to_dict() for finding in findings],
    }


def to_json(report: dict[str, object]) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False)


def write_report(report: dict[str, object], output: str | Path) -> None:
    Path(output).write_text(to_json(report) + "\n", encoding="utf-8")


def render_terminal(report: dict[str, object], color: bool = True) -> str:
    summary = report["summary"]
    counts = summary["by_severity"]
    total = summary["total"]
    lines = [
        paint("=" * 72, Color.DIM, color),
        paint(
            f"  sec-audit-cli v{__version__}  |  {report['scan_path']}",
            Color.BOLD + Color.CYAN,
            color,
        ),
        paint(f"  {report['duration_ms']} ms  |  {total} finding(s)", Color.DIM, color),
        paint("=" * 72, Color.DIM, color),
        "",
    ]
    if not total:
        lines.append(paint("  No issues found. Clean scan.", Color.GREEN + Color.BOLD, color))
        return "\n".join(lines) + "\n"

    parts = []
    for severity in SEVERITY_ORDER:
        count = counts[severity.name]
        if count:
            parts.append(paint(f"{severity.name}: {count}", SEVERITY_COLOR[severity], color))
    lines.append("  " + "   ".join(parts))
    lines.append("")

    for severity in SEVERITY_ORDER:
        findings: list[dict[str, object]] = [
            item for item in report["findings"] if item["severity"] == severity.name
        ]
        if not findings:
            continue
        header = f"  {SEVERITY_SYMBOL[severity]} {severity.name} ({len(findings)})"
        lines.append(paint(header, SEVERITY_COLOR[severity], color))
        for finding in findings:
            lines.append(
                f"    {paint(str(finding['rule_id']), Color.BOLD, color)}  {finding['title']}"
            )
            lines.append(
                paint(
                    f"    {finding['file']}:{finding['line']}:{finding['column']}",
                    Color.DIM,
                    color,
                )
            )
            lines.append(f"    {paint('fix:', Color.MAGENTA, color)} {finding['remediation']}")
        lines.append("")
    return "\n".join(lines) + "\n"
