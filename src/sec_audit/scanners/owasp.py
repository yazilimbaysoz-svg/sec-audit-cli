from __future__ import annotations

import re
from dataclasses import dataclass

from sec_audit.models import Finding, Severity
from sec_audit.utils import line_column

GENERIC_REMEDIATION = (
    "Validate and sanitize all untrusted input before using it in a sensitive sink."
)


@dataclass(frozen=True, slots=True)
class OwaspRule:
    rule_id: str
    title: str
    pattern: re.Pattern[str]
    severity: Severity
    cwe: str
    owasp: str
    remediation: str = GENERIC_REMEDIATION


RULES: tuple[OwaspRule, ...] = (
    OwaspRule(
        "OWASP-A03-SQLI",
        "Possible SQL injection via string interpolation",
        re.compile(
            r"\.execute\s*\(\s*(?:f[\"']|[\"'][^\"'\n]*[\"']\s*(?:%|\+|\.format\s*\())",
            re.IGNORECASE,
        ),
        Severity.CRITICAL,
        "CWE-89",
        "A03:2021 Injection",
        "Use parameterized queries or an ORM instead of building SQL from strings.",
    ),
    OwaspRule(
        "OWASP-A03-CMDI",
        "Possible operating system command injection",
        re.compile(
            r"\bos\.(?:system|popen)\s*\(|subprocess\.(?:call|run|Popen|check_output)\s*\([^)]*shell\s*=\s*True",
            re.IGNORECASE,
        ),
        Severity.CRITICAL,
        "CWE-78",
        "A03:2021 Injection",
        "Pass argument lists and avoid shell=True; validate any user-controlled input.",
    ),
    OwaspRule(
        "OWASP-A03-XSS",
        "Possible cross-site scripting sink",
        re.compile(
            r"\.innerHTML\s*=|\.outerHTML\s*=|document\.write\s*\(|dangerouslySetInner[H]TML",
            re.IGNORECASE,
        ),
        Severity.HIGH,
        "CWE-79",
        "A03:2021 Injection",
        "Use textContent or a framework-safe renderer and escape untrusted data.",
    ),
    OwaspRule(
        "OWASP-A08-DESER",
        "Unsafe deserialization or dynamic evaluation",
        re.compile(
            r"\bpickle\.(?:load|loads)\s*\(|\byaml\.load\s*\((?![^)]*SafeLoader)|\beval\s*\(|\bexec\s*\(",
            re.IGNORECASE,
        ),
        Severity.CRITICAL,
        "CWE-502",
        "A08:2021 Software and Data Integrity Failures",
        "Use yaml.safe_load/json and avoid eval, exec and pickle on untrusted data.",
    ),
    OwaspRule(
        "OWASP-A02-TLS",
        "TLS certificate verification disabled",
        re.compile(
            r"verify\s*=\s*False|NODE_TLS_REJECT_UNAUTHORIZED\s*[:=]\s*[\"']?0|ssl\._create_unverified_context",
            re.IGNORECASE,
        ),
        Severity.HIGH,
        "CWE-295",
        "A02:2021 Cryptographic Failures",
        "Keep certificate verification enabled and install the correct CA bundle.",
    ),
    OwaspRule(
        "OWASP-A02-HASH",
        "Weak hashing algorithm",
        re.compile(
            r"hashlib\.(?:md5|sha1)\s*\(|createHash\(\s*[\"'](?:md5|sha1)[\"']",
            re.IGNORECASE,
        ),
        Severity.MEDIUM,
        "CWE-327",
        "A02:2021 Cryptographic Failures",
        "Use SHA-256 or Argon2/bcrypt for passwords instead of MD5 or SHA-1.",
    ),
    OwaspRule(
        "OWASP-A10-SSRF",
        "Possible server-side request forgery",
        re.compile(
            r"(?:requests|httpx|fetch)\.(?:get|post|put|delete)\s*\(\s*(?:request\.|req\.|ctx\.query)",
            re.IGNORECASE,
        ),
        Severity.HIGH,
        "CWE-918",
        "A10:2021 Server-Side Request Forgery",
        "Use an allowlist of destinations and block private/link-local addresses.",
    ),
    OwaspRule(
        "OWASP-A01-PATH",
        "Possible path traversal from user input",
        re.compile(
            r"(?:open|send_file|readFile|readFileSync)\s*\(\s*(?:request\.|req\.|os\.path\.join\s*\(\s*request\.)",
            re.IGNORECASE,
        ),
        Severity.HIGH,
        "CWE-22",
        "A01:2021 Broken Access Control",
        "Resolve paths against a fixed base directory and reject traversal sequences.",
    ),
    OwaspRule(
        "OWASP-A05-DEBUG",
        "Debug mode enabled",
        re.compile(
            r"(?:DEBUG|FLASK_DEBUG|DJANGO_DEBUG)\s*[:=]\s*(?:True|[\"']1[\"'])|\bdebug\s*=\s*True",
            re.IGNORECASE,
        ),
        Severity.MEDIUM,
        "CWE-489",
        "A05:2021 Security Misconfiguration",
        "Disable debug mode in production builds and environment configuration.",
    ),
    OwaspRule(
        "OWASP-A04-XXE",
        "XML parser configured to resolve external entities",
        re.compile(r"resolve_entities\s*=\s*True|no_network\s*=\s*False", re.IGNORECASE),
        Severity.HIGH,
        "CWE-611",
        "A04:2021 Insecure Design",
        "Disable entity resolution and network access in XML parsers.",
    ),
    OwaspRule(
        "OWASP-A07-STORE",
        "Sensitive token stored in browser local storage",
        re.compile(
            r"localStorage\.setItem\s*\(\s*[\"'](?:token|jwt|password|secret)[\"']",
            re.IGNORECASE,
        ),
        Severity.MEDIUM,
        "CWE-522",
        "A07:2021 Identification and Authentication Failures",
        "Prefer HttpOnly, Secure cookies with short lifetimes for session tokens.",
    ),
    OwaspRule(
        "OWASP-A08-INTEGRITY",
        "Dependency integrity verification weakened",
        re.compile(
            r"--trusted[-]host|--no-package-lock|integrity\s*=\s*[\"']undefined", re.IGNORECASE
        ),
        Severity.MEDIUM,
        "CWE-494",
        "A08:2021 Software and Data Integrity Failures",
        "Verify package signatures and keep lockfiles and integrity hashes enabled.",
    ),
)


def scan_text(text: str, relative_path: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = text.splitlines()
    for rule in RULES:
        for match in rule.pattern.finditer(text):
            line, column = line_column(text, match.start())
            snippet = lines[line - 1].strip()[:160] if 0 < line <= len(lines) else ""
            findings.append(
                Finding(
                    rule_id=rule.rule_id,
                    title=rule.title,
                    severity=rule.severity,
                    category="owasp",
                    file=relative_path,
                    line=line,
                    column=column,
                    evidence=snippet,
                    remediation=rule.remediation,
                    cwe=rule.cwe,
                    owasp=rule.owasp,
                    source="static-pattern",
                )
            )
    findings.sort(key=lambda item: (-item.severity, item.line, item.rule_id))
    unique: list[Finding] = []
    seen: set[tuple[int, str]] = set()
    for finding in findings:
        key = (finding.line, finding.rule_id)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique
