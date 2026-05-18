import pytest
from easm_report.exceptions import ValidationError
from easm_report.validator import validate_html, validate_output_path
from pathlib import Path


def test_clean_html_passes() -> None:
    validate_html("<html><body>Asset grade F, proximity 55%</body></html>")


@pytest.mark.parametrize("snippet,expected_reason", [
    ("This is a Critical finding", "Invented severity: Critical"),
    ("High severity issue here", "Invented severity: High"),
    ("Medium risk asset", "Invented severity: Medium"),
    ("Low severity", "Invented severity: Low"),
    ("Compliant with DORA", "Regulatory framing: DORA"),
    ("NIS2 requirements", "Regulatory framing: NIS2"),
    ("GDPR Article 5", "Regulatory framing: GDPR"),
    ("TPRM process", "Regulatory framing: TPRM"),
    ("FCA guidelines", "Regulatory framing: FCA"),
    ("Likely registered domain", "Registration judgement"),
    ("Likely not registered", "Registration judgement"),
    ("blast radius of exposure", "Invented risk narrative"),
    ("domain taken over", "Invented risk narrative"),
    ("Article 28 obligations", "Regulatory reference"),
    ("Article 28 obligations", "Regulatory reference"),
])
def test_forbidden_patterns_raise(snippet: str, expected_reason: str) -> None:
    with pytest.raises(ValidationError, match=expected_reason):
        validate_html(f"<html><body>{snippet}</body></html>")


def test_high_proximity_is_allowed() -> None:
    # "High proximity" must NOT trigger the "High" severity check
    validate_html("<html><body>High proximity supplier</body></html>")


def test_low_profile_is_allowed() -> None:
    validate_html("<html><body>Low profile asset</body></html>")


def test_low_risk_is_allowed() -> None:
    validate_html("<html><body>Low risk</body></html>")


def test_validate_output_path_normal() -> None:
    p = validate_output_path("Acme Corp", Path("/tmp/outputs"))
    assert p == Path("/tmp/outputs/acme-corp-veracode-easm-report.html")


def test_validate_output_path_special_chars() -> None:
    p = validate_output_path("Example Ltd!", Path("/tmp/outputs"))
    assert p.name == "example-ltd--veracode-easm-report.html"


def test_validate_output_path_empty_raises() -> None:
    with pytest.raises(ValueError, match="empty slug"):
        validate_output_path("   ", Path("/tmp/outputs"))
