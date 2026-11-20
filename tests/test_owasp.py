from __future__ import annotations

import pytest

from sec_audit.scanners.owasp import scan_text

CASES = [
    ("OWASP-A03-SQLI", 'cursor.execute("SELECT * FROM users WHERE id=" + user_id)'),
    ("OWASP-A03-CMDI", "subprocess.run(command, shell=True)"),
    ("OWASP-A03-XSS", "element.innerHTML = userInput"),
    ("OWASP-A08-DESER", "data = pickle.loads(payload)"),
    ("OWASP-A02-TLS", "requests.get(url, verify=False)"),
    ("OWASP-A02-HASH", "digest = hashlib.md5(value).digest()"),
    ("OWASP-A10-SSRF", "requests.get(request.args['url'])"),
    ("OWASP-A01-PATH", "return send_file(request.args['path'])"),
    ("OWASP-A05-DEBUG", "app.run(debug=True)"),
    ("OWASP-A04-XXE", "parser = etree.XMLParser(resolve_entities=True)"),
]


@pytest.mark.parametrize(("rule_id", "source"), CASES)
def test_owasp_rules_detect_risky_code(rule_id: str, source: str) -> None:
    findings = scan_text(source + "\n", "app.py")
    assert any(finding.rule_id == rule_id for finding in findings)


def test_owasp_finding_contains_remediation() -> None:
    finding = scan_text("eval(user_input)\n", "app.py")[0]
    assert finding.remediation
    assert finding.cwe.startswith("CWE-")
    assert finding.owasp.startswith("A")


def test_clean_code_is_ignored() -> None:
    source = (
        "from hashlib import sha256\n\n"
        "def digest(value: str) -> str:\n"
        "    return sha256(value.encode()).hexdigest()\n"
    )
    assert scan_text(source, "safe.py") == []


def test_duplicate_matches_on_same_line_are_collapsed() -> None:
    findings = scan_text("eval(a); eval(b)\n", "app.py")
    assert len([finding for finding in findings if finding.rule_id == "OWASP-A08-DESER"]) == 1
