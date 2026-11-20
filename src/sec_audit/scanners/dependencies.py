from __future__ import annotations

import json
import re
import tomllib
import urllib.request
from collections.abc import Iterable, Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import PurePosixPath

from sec_audit.models import Finding, Severity
from sec_audit.utils import parse_version, version_in_range

OSV_URL = "https://api.osv.dev/v1/query"
OSV_ECOSYSTEMS = {"PyPI": "PyPI", "npm": "npm", "crates.io": "Crates.io", "Go": "Go"}

PIN_REMEDIATION = "Pin this dependency to an exact, reviewed version and enable automated updates."


@dataclass(frozen=True, slots=True)
class Advisory:
    advisory_id: str
    ecosystem: str
    package: str
    vulnerable_range: str
    severity: Severity
    title: str
    remediation: str
    cwe: str


BUNDLED_ADVISORIES: tuple[Advisory, ...] = (
    Advisory(
        "CVE-2023-32681",
        "PyPI",
        "requests",
        "<2.31.0",
        Severity.HIGH,
        "Proxy-Authorization header leaked to an unrelated host on redirect",
        "Upgrade requests to 2.31.0 or newer.",
        "CWE-200",
    ),
    Advisory(
        "CVE-2023-45803",
        "PyPI",
        "urllib3",
        "<1.26.18|>=2.0.0,<2.0.7",
        Severity.MEDIUM,
        "Request body leaked after a cross-origin redirect",
        "Upgrade urllib3 to 1.26.18 or 2.0.7 or newer.",
        "CWE-200",
    ),
    Advisory(
        "CVE-2020-14343",
        "PyPI",
        "pyyaml",
        "<5.4",
        Severity.CRITICAL,
        "PyYAML full loader allows arbitrary code execution",
        "Upgrade PyYAML to 5.4 or newer and use yaml.safe_load.",
        "CWE-502",
    ),
    Advisory(
        "CVE-2023-30861",
        "PyPI",
        "flask",
        "<2.2.5",
        Severity.MEDIUM,
        "Flask session cookies may be cached by a proxy",
        "Upgrade Flask to 2.2.5 or newer.",
        "CWE-524",
    ),
    Advisory(
        "CVE-2024-33663",
        "PyPI",
        "python-jose",
        "<3.3.0",
        Severity.HIGH,
        "Algorithm confusion in JWT verification",
        "Upgrade python-jose to 3.3.0 or newer.",
        "CWE-347",
    ),
    Advisory(
        "CVE-2021-23337",
        "npm",
        "lodash",
        "<4.17.21",
        Severity.HIGH,
        "Lodash template command injection",
        "Upgrade lodash to 4.17.21 or newer.",
        "CWE-77",
    ),
    Advisory(
        "CVE-2023-45857",
        "npm",
        "axios",
        "<1.6.0",
        Severity.MEDIUM,
        "Axial X-XSRF-TOKEN header leaked to a third-party host",
        "Upgrade axios to 1.6.0 or newer.",
        "CWE-200",
    ),
    Advisory(
        "CVE-2021-44906",
        "npm",
        "minimist",
        "<1.2.6",
        Severity.CRITICAL,
        "Minimist prototype pollution",
        "Upgrade minimist to 1.2.6 or newer.",
        "CWE-1321",
    ),
    Advisory(
        "CVE-2022-25883",
        "npm",
        "semver",
        "<7.5.2",
        Severity.MEDIUM,
        "Semver regular expression denial of service",
        "Upgrade semver to 7.5.2 or newer.",
        "CWE-1333",
    ),
    Advisory(
        "CVE-2021-37701",
        "npm",
        "tar",
        "<6.1.11",
        Severity.HIGH,
        "Tar path traversal on extraction",
        "Upgrade tar to 6.1.11 or newer.",
        "CWE-22",
    ),
    Advisory(
        "CVE-2021-44228",
        "Maven",
        "org.apache.logging.log4j:log4j-core",
        ">=2.0.0,<2.15.0",
        Severity.CRITICAL,
        "Log4j JNDI remote code execution",
        "Upgrade log4j-core to 2.15.0 or newer and disable JNDI lookups.",
        "CWE-94",
    ),
)


@dataclass(frozen=True, slots=True)
class Dependency:
    name: str
    version: str
    ecosystem: str
    line: int
    pinned: bool


def _clean_name(name: str) -> str:
    return re.sub(r"[^a-z0-9._-]+", "-", name.strip().lower()).strip("-")


def _line_of(text: str, needle: str) -> int:
    for number, line in enumerate(text.splitlines(), 1):
        if needle in line:
            return number
    return 1


def _pep508_dependency(spec: str, line: int) -> Dependency:
    match = re.match(r"^([A-Za-z0-9_.-]+)\s*(?:\[[^\]]+\])?\s*(.*)$", spec.strip())
    if match is None:
        return Dependency("", "", "PyPI", line, False)
    name, raw_spec = match.groups()
    version = ""
    if raw_spec.startswith("=="):
        candidate = re.split(r"[,;\s]", raw_spec[2:].lstrip("v"), maxsplit=1)[0]
        if parse_version(candidate):
            version = candidate
    return Dependency(_clean_name(name), version, "PyPI", line, bool(version))


def parse_requirements(text: str) -> Iterator[Dependency]:
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].split(";", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http://", "https://")):
            continue
        dependency = _pep508_dependency(line, number)
        if dependency.name:
            yield dependency


def parse_pyproject(text: str) -> Iterator[Dependency]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return
    project = data.get("project", {})
    groups = [project.get("dependencies", [])]
    groups.extend(project.get("optional-dependencies", {}).values())
    for group in groups:
        if not isinstance(group, list):
            continue
        for spec in group:
            if isinstance(spec, str):
                dependency = _pep508_dependency(spec, _line_of(text, spec))
                if dependency.name:
                    yield dependency
    poetry = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    for name, spec in poetry.items():
        version = ""
        if isinstance(spec, str) and spec.startswith(("^", "~", "==")):
            candidate = spec.lstrip("^~=")
            if parse_version(candidate):
                version = candidate
        yield Dependency(_clean_name(name), version, "PyPI", _line_of(text, name), bool(version))


def parse_package_json(text: str) -> Iterator[Dependency]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, spec in data.get(section, {}).items():
            version = ""
            if isinstance(spec, str):
                candidate = spec.strip().lstrip("v=")
                if re.fullmatch(r"\d+(?:\.\d+){0,4}", candidate):
                    version = candidate
            yield Dependency(_clean_name(name), version, "npm", _line_of(text, name), bool(version))


def parse_package_lock(text: str) -> Iterator[Dependency]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return
    for key, info in data.get("packages", {}).items():
        if not key.startswith("node_modules/"):
            continue
        name = key.split("node_modules/")[-1]
        version = str(info.get("version", ""))
        yield Dependency(
            _clean_name(name), version, "npm", _line_of(text, key), bool(parse_version(version))
        )


def parse_yarn_lock(text: str) -> Iterator[Dependency]:
    name = ""
    for number, raw in enumerate(text.splitlines(), 1):
        if raw and not raw.startswith((" ", "#", "\n")) and raw.rstrip().endswith(":"):
            raw_name = raw.rstrip()[:-1].split(",")[0].strip().strip('"')
            name = (
                raw_name[1:].split("@")[0] if raw_name.startswith("@") else raw_name.split("@")[0]
            )
        match = re.match(r'\s+version\s+"?(\d+(?:\.\d+){0,4})"?', raw)
        if match and name:
            yield Dependency(_clean_name(name), match.group(1), "npm", number, True)
            name = ""


def parse_cargo_lock(text: str) -> Iterator[Dependency]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return
    for package in data.get("package", []):
        name = str(package.get("name", ""))
        version = str(package.get("version", ""))
        if name:
            yield Dependency(_clean_name(name), version, "crates.io", _line_of(text, name), True)


def parse_go_mod(text: str) -> Iterator[Dependency]:
    seen: set[str] = set()
    pattern = re.compile(
        r"(?m)^\s*(?:require\s+)?([a-z0-9.-]+\.[a-z]{2,}/[^\s]+)\s+v(\d+(?:\.\d+){0,4})"
    )
    for match in pattern.finditer(text):
        name = _clean_name(match.group(1))
        if name in seen:
            continue
        seen.add(name)
        line = _line_of(text, match.group(1))
        yield Dependency(name, match.group(2), "Go", line, True)


def parse_pipfile_lock(text: str) -> Iterator[Dependency]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return
    for section in ("default", "develop"):
        for name, info in data.get(section, {}).items():
            raw_version = str(info.get("version", ""))
            version = re.sub(r"^==\s*v?", "", raw_version)
            yield Dependency(
                _clean_name(name),
                version if parse_version(version) else "",
                "PyPI",
                _line_of(text, name),
                bool(parse_version(version)),
            )


def dependencies_for(relative_path: str, text: str) -> Iterator[Dependency]:
    name = PurePosixPath(relative_path).name
    if name == "pyproject.toml":
        yield from parse_pyproject(text)
    elif name.startswith("requirements") and name.endswith(".txt"):
        yield from parse_requirements(text)
    elif name == "package.json":
        yield from parse_package_json(text)
    elif name == "package-lock.json":
        yield from parse_package_lock(text)
    elif name == "yarn.lock":
        yield from parse_yarn_lock(text)
    elif name == "Cargo.lock":
        yield from parse_cargo_lock(text)
    elif name == "go.mod":
        yield from parse_go_mod(text)
    elif name == "Pipfile.lock":
        yield from parse_pipfile_lock(text)


def advisory_finding(advisory: Advisory, dependency: Dependency, relative_path: str) -> Finding:
    return Finding(
        rule_id=f"DEP-{advisory.advisory_id}",
        title=f"{dependency.name} {dependency.version}: {advisory.title}",
        severity=advisory.severity,
        category="vulnerability",
        file=relative_path,
        line=dependency.line,
        column=1,
        evidence=f"{dependency.ecosystem}:{dependency.name}=={dependency.version}",
        remediation=advisory.remediation,
        cwe=advisory.cwe,
        owasp="A06:2021 Vulnerable and Outdated Components",
        source="bundled-advisory-db",
    )


def unpinned_finding(dependency: Dependency, relative_path: str) -> Finding:
    return Finding(
        rule_id="DEP-UNPINNED",
        title=f"Unpinned dependency: {dependency.name}",
        severity=Severity.LOW,
        category="vulnerability",
        file=relative_path,
        line=dependency.line,
        column=1,
        evidence=f"{dependency.ecosystem}:{dependency.name} has no exact version",
        remediation=PIN_REMEDIATION,
        cwe="CWE-1104",
        owasp="A06:2021 Vulnerable and Outdated Components",
        source="manifest-analysis",
    )


def query_osv(dependency: Dependency, timeout: float = 3.0) -> list[dict[str, object]]:
    ecosystem = OSV_ECOSYSTEMS.get(dependency.ecosystem)
    if ecosystem is None or not dependency.version:
        return []
    payload = json.dumps(
        {
            "package": {"name": dependency.name, "ecosystem": ecosystem},
            "version": dependency.version,
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        OSV_URL,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "sec-audit-cli/0.1"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        data = json.load(response)
    vulnerabilities = data.get("vulns", [])
    return vulnerabilities if isinstance(vulnerabilities, list) else []


def osv_findings(
    vulnerabilities: Iterable[dict[str, object]],
    dependency: Dependency,
    relative_path: str,
) -> list[Finding]:
    findings: list[Finding] = []
    for vulnerability in vulnerabilities:
        vulnerability_id = str(vulnerability.get("id", "OSV-UNKNOWN"))
        declared = str(vulnerability.get("database_specific", {}).get("severity", "")).upper()
        try:
            severity = Severity[declared]
        except KeyError:
            severity = Severity.MEDIUM
        aliases = vulnerability.get("aliases") or []
        evidence = f"{dependency.ecosystem}:{dependency.name}=={dependency.version}"
        if aliases:
            evidence += f" ({', '.join(str(alias) for alias in aliases[:3])})"
        findings.append(
            Finding(
                rule_id=f"OSV-{vulnerability_id}",
                title=str(vulnerability.get("summary") or vulnerability_id)[:160],
                severity=severity,
                category="vulnerability",
                file=relative_path,
                line=dependency.line,
                column=1,
                evidence=evidence,
                remediation=(
                    f"Upgrade {dependency.name} to a patched version (see {vulnerability_id})."
                ),
                cwe="",
                owasp="A06:2021 Vulnerable and Outdated Components",
                source="osv-api",
            )
        )
    return findings


def _check_bundled(dependencies: list[tuple[Dependency, str]]) -> list[Finding]:
    findings: list[Finding] = []
    for dependency, relative_path in dependencies:
        if not dependency.name:
            continue
        if not dependency.pinned:
            findings.append(unpinned_finding(dependency, relative_path))
            continue
        version = parse_version(dependency.version)
        for advisory in BUNDLED_ADVISORIES:
            if advisory.ecosystem != dependency.ecosystem:
                continue
            if advisory.package != dependency.name:
                continue
            if version_in_range(version, advisory.vulnerable_range):
                findings.append(advisory_finding(advisory, dependency, relative_path))
    return findings


def _check_online(
    dependencies: list[tuple[Dependency, str]],
    workers: int,
    bundled_ids: set[str],
) -> list[Finding]:
    pinned = [(dep, path) for dep, path in dependencies if dep.pinned and dep.name]
    if not pinned:
        return []

    def query(item: tuple[Dependency, str]) -> list[Finding]:
        dependency, relative_path = item
        try:
            vulnerabilities = query_osv(dependency)
        except Exception:
            return []
        return [
            finding
            for finding in osv_findings(vulnerabilities, dependency, relative_path)
            if finding.rule_id.removeprefix("OSV-") not in bundled_ids
        ]

    findings: list[Finding] = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        for group in executor.map(query, pinned):
            findings.extend(group)
    return findings


def scan_dependencies(
    manifests: Iterable[tuple[str, str]],
    online: bool = False,
    workers: int = 8,
) -> list[Finding]:
    dependencies: list[tuple[Dependency, str]] = []
    for relative_path, text in manifests:
        for dependency in dependencies_for(relative_path, text):
            dependencies.append((dependency, relative_path))

    findings = _check_bundled(dependencies)
    if online:
        bundled_ids = {finding.rule_id.removeprefix("DEP-") for finding in findings}
        findings.extend(_check_online(dependencies, workers, bundled_ids))
    return findings
