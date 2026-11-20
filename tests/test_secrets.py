from __future__ import annotations

from sec_audit.scanners.secrets import scan_text

AWS_KEY = "AKIA" + "AB3DE5GH7JK9MN2P"
GITHUB_TOKEN = "ghp_" + "aB3dE5gH7jK9mN2pQ4rS6tU8vW0xY1zA3bC5"
OPENAI_KEY = "sk-" + "aB3dE5gH7jK9mN2pQ4rS6tU8vW0x"
STRIPE_KEY = "sk_live_" + "aB3dE5gH7jK9mN2pQ4rS6t"
LONG_VALUE = "aB3dE5gH7jK9mN2pQ4rS6t"


def test_detects_aws_key() -> None:
    findings = scan_text(f"aws_key = '{AWS_KEY}'\n", "config.py")
    assert any(finding.rule_id == "SEC-AWS-001" for finding in findings)
    assert all(AWS_KEY not in finding.evidence for finding in findings)
    assert findings[0].severity == 4
    assert findings[0].file == "config.py"


def test_detects_multiple_provider_tokens() -> None:
    text = "\n".join([GITHUB_TOKEN, OPENAI_KEY, STRIPE_KEY])
    rules = {finding.rule_id for finding in scan_text(text, "tokens.txt")}
    assert {"SEC-GIT-001", "SEC-OAI-001", "SEC-STR-001"} <= rules


def test_detects_private_key_header() -> None:
    findings = scan_text("-----BEGIN " + "RSA PRIVATE KEY-----\n", "key.pem")
    assert any(finding.rule_id == "SEC-PEM-001" for finding in findings)


def test_ignores_placeholders() -> None:
    text = "api_key = 'your_api_key_here'\nAWS_KEY = 'aaaaaaaaaaaaaaaa'\n"
    assert scan_text(text, "example.py") == []


def test_detects_generic_credential() -> None:
    findings = scan_text(f'api_key = "{LONG_VALUE}"\n', "settings.py")
    assert any(finding.rule_id == "SEC-GEN-001" for finding in findings)


def test_detects_env_credential() -> None:
    findings = scan_text(f"PROD_API_TOKEN={LONG_VALUE}\n", ".env")
    assert any(finding.rule_id == "SEC-ENV-001" for finding in findings)


def test_reports_line_number() -> None:
    text = f'# comment\nvalue = 1\nsecret_key = "{LONG_VALUE}"\n'
    finding = next(item for item in scan_text(text, "a.py") if item.rule_id == "SEC-GEN-001")
    assert finding.line == 3


def test_deduplicates_overlapping_matches() -> None:
    findings = scan_text(f'auth_token = "{LONG_VALUE}"\n', "a.py")
    assert len(findings) == 1


def test_clean_source_has_no_findings() -> None:
    assert scan_text("def add(a: int, b: int) -> int:\n    return a + b\n", "math.py") == []
