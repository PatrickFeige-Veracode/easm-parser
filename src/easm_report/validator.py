"""Validate rendered HTML output for forbidden patterns."""

from __future__ import annotations

import re
from pathlib import Path

from easm_report.exceptions import ValidationError

FORBIDDEN_PATTERNS: list[tuple[str, str]] = [
    (r"\bCritical\b",                 "Invented severity: Critical"),
    (r"\bHigh\b(?!\s+proximity)",     "Invented severity: High"),
    (r"\bMedium\b",                   "Invented severity: Medium"),
    (r"\bLow\b(?!\s+(profile|risk))", "Invented severity: Low"),
    (r"\bDORA\b",                     "Regulatory framing: DORA"),
    (r"\bNIS2\b",                     "Regulatory framing: NIS2"),
    (r"\bGDPR\b",                     "Regulatory framing: GDPR"),
    (r"\bTPRM\b",                     "Regulatory framing: TPRM"),
    (r"\bFCA\b",                      "Regulatory framing: FCA"),
    (r"Likely registered",            "Registration judgement"),
    (r"Likely not registered",        "Registration judgement"),
    (r"blast radius",                 "Invented risk narrative"),
    (r"taken over",                   "Invented risk narrative"),
    (r"Article 28",                   "Regulatory reference"),
]


def validate_html(html: str) -> None:
    errors = [
        reason
        for pattern, reason in FORBIDDEN_PATTERNS
        if re.search(pattern, html, re.IGNORECASE)
    ]
    if errors:
        raise ValidationError(
            "Output failed validation:\n" + "\n".join(f"  • {e}" for e in errors)
        )


def validate_output_path(customer: str, output_dir: Path) -> Path:
    safe_name = re.sub(r"[^a-zA-Z0-9\-_]", "-", customer.strip())[:50].lower()
    if not safe_name:
        raise ValueError("Customer name produced empty slug")
    return output_dir / f"{safe_name}-veracode-easm-report.html"
