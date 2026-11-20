from __future__ import annotations

import pytest

from sec_audit.utils import (
    is_excluded,
    line_column,
    looks_like_placeholder,
    masked_evidence,
    parse_version,
    shannon_entropy,
    version_in_range,
)


def test_line_column() -> None:
    text = "first\nsecond\nthird"
    assert line_column(text, 0) == (1, 1)
    assert line_column(text, 6) == (2, 1)
    assert line_column(text, 14) == (3, 2)


def test_masked_evidence_hides_value() -> None:
    masked = masked_evidence("superSecretValue123")
    assert "superSecretValue123" not in masked
    assert masked.startswith("supe")
    assert "sha256:" in masked


def test_masked_evidence_short_value() -> None:
    assert masked_evidence("abc").startswith("***")


def test_entropy() -> None:
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("aB3dE5gH7jK9mN2p") > 3.8
    assert shannon_entropy("") == 0.0


def test_placeholders() -> None:
    assert looks_like_placeholder("your_api_key_here")
    assert looks_like_placeholder("aaaaaaaaaaaaaaaa")
    assert looks_like_placeholder("${SECRET_TOKEN}")
    assert not looks_like_placeholder("aB3dE5gH7jK9mN2pQ4rS6")


def test_exclusions() -> None:
    assert is_excluded("node_modules/pkg/index.js", ())
    assert is_excluded("src/secrets.json", ("*.json",))
    assert is_excluded("build/output.py", ())
    assert not is_excluded("src/main.py", ())


def test_version_ranges() -> None:
    assert version_in_range(parse_version("2.30.0"), "<2.31.0")
    assert not version_in_range(parse_version("2.31.0"), "<2.31.0")
    assert version_in_range(parse_version("1.26.17"), "<1.26.18|>=2.0.0,<2.0.7")
    assert version_in_range(parse_version("2.0.5"), "<1.26.18|>=2.0.0,<2.0.7")
    assert not version_in_range(parse_version("2.0.7"), "<1.26.18|>=2.0.0,<2.0.7")
    assert parse_version("no version") == ()


@pytest.mark.parametrize(
    ("version", "expression", "expected"),
    [("1.2.3", ">=1.0.0", True), ("0.9.0", ">=1.0.0", False), ("1.2.3", "==1.2.3", True)],
)
def test_clause_matches(version: str, expression: str, expected: bool) -> None:
    assert version_in_range(parse_version(version), expression) is expected
