from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:
        return self.name


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    title: str
    severity: Severity
    category: str
    file: str
    line: int
    column: int
    evidence: str
    remediation: str
    cwe: str = ""
    owasp: str = ""
    source: str = "local"

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["severity"] = str(self.severity)
        return data


SEVERITY_ORDER = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)
