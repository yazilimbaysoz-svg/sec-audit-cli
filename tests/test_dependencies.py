from __future__ import annotations

import pytest

from sec_audit.scanners import dependencies as deps


def test_vulnerable_requirement_detected() -> None:
    findings = deps.scan_dependencies([("requirements.txt", "requests==2.30.0\n")])
    assert any(finding.rule_id == "DEP-CVE-2023-32681" for finding in findings)
    assert findings[0].category == "vulnerability"
    assert findings[0].source == "bundled-advisory-db"


def test_safe_requirement_is_clean() -> None:
    assert deps.scan_dependencies([("requirements.txt", "requests==2.32.3\n")]) == []


def test_unpinned_dependency_is_reported() -> None:
    findings = deps.scan_dependencies([("requirements.txt", "requests>=2.0\n")])
    assert any(finding.rule_id == "DEP-UNPINNED" for finding in findings)
    assert findings[0].severity == 1


def test_pyproject_dependencies() -> None:
    text = '[project]\nname = "demo"\ndependencies = ["pyyaml==5.3.1"]\n'
    findings = deps.scan_dependencies([("pyproject.toml", text)])
    assert any(finding.rule_id == "DEP-CVE-2020-14343" for finding in findings)


def test_package_json_dependencies() -> None:
    text = '{"dependencies": {"lodash": "4.17.20", "axios": "1.6.0"}}'
    findings = deps.scan_dependencies([("package.json", text)])
    assert any(finding.rule_id == "DEP-CVE-2021-23337" for finding in findings)
    assert not any("axios" in finding.rule_id for finding in findings)


def test_package_lock_dependencies() -> None:
    text = '{"packages": {"node_modules/minimist": {"version": "1.2.5"}}}'
    findings = deps.scan_dependencies([("package-lock.json", text)])
    assert any(finding.rule_id == "DEP-CVE-2021-44906" for finding in findings)


def test_yarn_lock_dependencies() -> None:
    text = 'semver@^7.0.0:\n  version "7.5.1"\n  resolved "https://registry.test/semver"\n'
    findings = deps.scan_dependencies([("yarn.lock", text)])
    assert any(finding.rule_id == "DEP-CVE-2022-25883" for finding in findings)


def test_cargo_and_go_parsers() -> None:
    cargo = '[[package]]\nname = "serde"\nversion = "1.0.0"\n'
    go_mod = "module demo\n\nrequire github.com/gin-gonic/gin v1.9.0\n"
    cargo_deps = list(deps.dependencies_for("Cargo.lock", cargo))
    go_deps = list(deps.dependencies_for("go.mod", go_mod))
    assert cargo_deps[0].name == "serde"
    assert cargo_deps[0].ecosystem == "crates.io"
    assert go_deps[0].version == "1.9.0"
    assert go_deps[0].ecosystem == "Go"


def test_online_osv_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_query(dependency: object, timeout: float = 3.0) -> list[dict[str, object]]:
        return [
            {
                "id": "GHSA-test-0000",
                "summary": "Example advisory",
                "aliases": ["CVE-2099-0001"],
                "database_specific": {"severity": "HIGH"},
            }
        ]

    monkeypatch.setattr(deps, "query_osv", fake_query)
    findings = deps.scan_dependencies([("requirements.txt", "flask==2.2.5\n")], online=True)
    assert any(finding.rule_id == "OSV-GHSA-test-0000" for finding in findings)
    assert findings[0].source == "osv-api"


def test_online_deduplicates_bundled_ids(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_query(dependency: object, timeout: float = 3.0) -> list[dict[str, object]]:
        return [{"id": "CVE-2023-32681", "summary": "Duplicate advisory"}]

    monkeypatch.setattr(deps, "query_osv", fake_query)
    findings = deps.scan_dependencies([("requirements.txt", "requests==2.30.0\n")], online=True)
    assert [finding.rule_id for finding in findings] == ["DEP-CVE-2023-32681"]
