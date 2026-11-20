from __future__ import annotations

import json
from pathlib import Path

from sec_audit.models import Finding, Severity
from sec_audit.report import build_report, render_terminal, to_json, write_report


def make_finding(severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        rule_id="SEC-TEST-001",
        title="Example finding",
        severity=severity,
        category="secret",
        file="app.py",
        line=7,
        column=3,
        evidence="masked [sha256:abcdef12]",
        remediation="Rotate the key.",
        cwe="CWE-798",
        owasp="A07:2021",
    )


def test_build_report_counts() -> None:
    report = build_report("/tmp/demo", [make_finding(), make_finding(Severity.LOW)], 12.3456, {})
    assert report["summary"]["total"] == 2
    assert report["summary"]["by_severity"]["HIGH"] == 1
    assert report["summary"]["by_severity"]["LOW"] == 1
    assert report["summary"]["clean"] is False
    assert report["duration_ms"] == 12.35


def test_json_round_trip() -> None:
    report = build_report("/tmp/demo", [make_finding()], 1.0, {"online": False})
    parsed = json.loads(to_json(report))
    assert parsed["tool"] == "sec-audit-cli"
    assert parsed["findings"][0]["severity"] == "HIGH"
    assert parsed["config"] == {"online": False}


def test_write_report(tmp_path: Path) -> None:
    report = build_report("/tmp/demo", [], 1.0, {})
    output = tmp_path / "report.json"
    write_report(report, output)
    assert json.loads(output.read_text())["summary"]["clean"] is True


def test_terminal_render_includes_finding() -> None:
    report = build_report("/tmp/demo", [make_finding()], 1.0, {})
    rendered = render_terminal(report, color=False)
    assert "HIGH" in rendered
    assert "app.py:7:3" in rendered
    assert "\033[" not in rendered


def test_terminal_render_clean() -> None:
    report = build_report("/tmp/demo", [], 1.0, {})
    assert "No issues found" in render_terminal(report, color=False)
