from __future__ import annotations

import re
from dataclasses import dataclass

from sec_audit.models import Finding, Severity
from sec_audit.utils import line_column, looks_like_placeholder, masked_evidence, shannon_entropy

REMEDIATION = (
    "Move this value to a secret manager or environment variable and rotate it immediately."
)
OWASP = "A07:2021 Identification and Authentication Failures"


@dataclass(frozen=True, slots=True)
class SecretRule:
    rule_id: str
    title: str
    pattern: re.Pattern[str]
    severity: Severity
    cwe: str


GENERIC_ASSIGNMENT = re.compile(
    r"(?im)\b(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token|"
    r"client[_-]?secret|private[_-]?token|password|passwd|pwd)\b\s*[:=]\s*"
    r"([\"'])(?P<value>[^\"'\n]{8,200})\1"
)

ENV_ASSIGNMENT = re.compile(
    r"(?im)^[A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|PWD)[A-Z0-9_]*\s*=\s*"
    r"(?P<value>[^\s#\"']{8,200})\s*$"
)

RULES: tuple[SecretRule, ...] = (
    SecretRule(
        "SEC-AWS-001",
        "AWS Access Key ID",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        Severity.CRITICAL,
        "CWE-798",
    ),
    SecretRule(
        "SEC-GIT-001",
        "GitHub access token",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{36,255}\b"),
        Severity.CRITICAL,
        "CWE-798",
    ),
    SecretRule(
        "SEC-OAI-001",
        "OpenAI API key",
        re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
        Severity.CRITICAL,
        "CWE-798",
    ),
    SecretRule(
        "SEC-STR-001",
        "Stripe live secret key",
        re.compile(r"\bsk_live_[A-Za-z0-9]{16,}\b"),
        Severity.CRITICAL,
        "CWE-798",
    ),
    SecretRule(
        "SEC-SLK-001",
        "Slack API token",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        Severity.HIGH,
        "CWE-798",
    ),
    SecretRule(
        "SEC-GCP-001",
        "Google API key",
        re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        Severity.HIGH,
        "CWE-798",
    ),
    SecretRule(
        "SEC-PEM-001",
        "Private key material",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
        Severity.CRITICAL,
        "CWE-321",
    ),
    SecretRule(
        "SEC-JWT-001",
        "JSON Web Token",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
        Severity.MEDIUM,
        "CWE-798",
    ),
)

ASSIGNMENT_RULES: tuple[SecretRule, ...] = (
    SecretRule(
        "SEC-GEN-001",
        "Hardcoded credential assignment",
        GENERIC_ASSIGNMENT,
        Severity.HIGH,
        "CWE-798",
    ),
    SecretRule(
        "SEC-ENV-001",
        "Credential in environment-style assignment",
        ENV_ASSIGNMENT,
        Severity.MEDIUM,
        "CWE-798",
    ),
)


def _finding(
    rule: SecretRule,
    value: str,
    line: int,
    column: int,
    relative_path: str,
    severity: Severity,
) -> Finding:
    return Finding(
        rule_id=rule.rule_id,
        title=rule.title,
        severity=severity,
        category="secret",
        file=relative_path,
        line=line,
        column=column,
        evidence=masked_evidence(value),
        remediation=REMEDIATION,
        cwe=rule.cwe,
        owasp=OWASP,
        source="regex+entropy",
    )


def scan_text(text: str, relative_path: str, min_entropy: float = 4.0) -> list[Finding]:
    findings: list[Finding] = []
    for rule in RULES + ASSIGNMENT_RULES:
        for match in rule.pattern.finditer(text):
            value = match.groupdict().get("value") or match.group(0)
            if looks_like_placeholder(value):
                continue
            line, column = line_column(text, match.start())
            severity = rule.severity
            if rule in ASSIGNMENT_RULES and shannon_entropy(value) < min_entropy:
                severity = Severity.LOW
            findings.append(_finding(rule, value, line, column, relative_path, severity))

    findings.sort(key=lambda item: (-item.severity, item.line, item.rule_id))
    unique: list[Finding] = []
    seen: set[tuple[int, str]] = set()
    for finding in findings:
        key = (finding.line, finding.evidence.rsplit("sha256:", 1)[-1])
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique
