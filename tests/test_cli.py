from __future__ import annotations

import json
from pathlib import Path

import pytest

from sec_audit.cli import main

AWS_KEY = "AKIA" + "AB3DE5GH7JK9MN2P"


@pytest.fixture
def sample_project(tmp_path: Path) -> Path:
    (tmp_path / "requirements.txt").write_text("requests==2.30.0\n", encoding="utf-8")
    (tmp_path / "app.py").write_text(f"api_key = '{AWS_KEY}'\neval(user_input)\n", encoding="utf-8")
    return tmp_path


def read_report(capsys: pytest.CaptureFixture[str]) -> dict[str, object]:
    return json.loads(capsys.readouterr().out)


def test_json_report_and_exit_code(
    sample_project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(["--json", str(sample_project)])
    report = read_report(capsys)
    assert code == 1
    assert report["summary"]["total"] >= 3
    assert report["schema_version"] == "1.0"


def test_fail_on_none_returns_zero(
    sample_project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    capsys.readouterr()
    assert main(["--json", "--fail-on", "none", str(sample_project)]) == 0
    capsys.readouterr()


def test_min_severity_filters(sample_project: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["--json", "--min-severity", "critical", str(sample_project)])
    report = read_report(capsys)
    assert code == 1
    assert report["summary"]["total"] == 2
    assert all(item["severity"] == "CRITICAL" for item in report["findings"])


def test_exclude_pattern(sample_project: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["--json", "--exclude", "app.py", str(sample_project)])
    report = read_report(capsys)
    assert code == 1
    assert all(finding["file"] != "app.py" for finding in report["findings"])


def test_include_pattern(sample_project: Path, capsys: pytest.CaptureFixture[str]) -> None:
    main(["--json", "--include", "*.py", str(sample_project)])
    report = read_report(capsys)
    assert report["summary"]["total"] == 2


def test_output_file(
    sample_project: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "audit.json"
    main(["--quiet", "--output", str(output), str(sample_project)])
    capsys.readouterr()
    assert json.loads(output.read_text())["summary"]["total"] >= 3


def test_invalid_path(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--json", "/definitely/missing/path"]) == 2
    assert "not a directory" in capsys.readouterr().err


def test_clean_project(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (tmp_path / "clean.py").write_text("value = 42\n", encoding="utf-8")
    assert main(["--json", str(tmp_path)]) == 0
    report = read_report(capsys)
    assert report["summary"]["clean"] is True


def test_version_flag() -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])
    assert exc_info.value.code == 0


def test_quiet_output(sample_project: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--quiet", "--fail-on", "none", str(sample_project)]) == 0
    assert "finding(s)" in capsys.readouterr().out
