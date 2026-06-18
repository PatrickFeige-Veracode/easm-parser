"""Validate rendered HTML output for forbidden patterns."""

from __future__ import annotations

import re
from pathlib import Path

from easm_report.exceptions import ValidationError

FORBIDDEN_PATTERNS: list[tuple[str, str]] = [
    (r"\bCritical\b",                 "Invented severity: Critical"),
    (r"\bHigh\b(?!\s+proximity)",     "Invented severity: High"),
    # Only fire when Medium is used as a severity/risk label, not as a data-derived grade value
    (r"\bMedium\b\s+(?:severity|risk|priority|vulnerability|finding)|\b(?:severity|risk|priority)\s+(?:is\s+)?Medium\b", "Invented severity: Medium"),
    (r"\bLow\b(?!\s+(profile|risk))", "Invented severity: Low"),
    # Only fire when DORA/FCA appear in regulatory framing context, not as supplier/tag names
    (r"\bDORA\b\s+(?:regulation|compliance|requirement|mandate|framework|standard|rule|Article)|\b(?:under|per|comply\s+with)\s+(?:the\s+)?\bDORA\b", "Regulatory framing: DORA"),
    (r"\bNIS2\b",                     "Regulatory framing: NIS2"),
    (r"\bGDPR\b",                     "Regulatory framing: GDPR"),
    (r"\bTPRM\b",                     "Regulatory framing: TPRM"),
    (r"\bFCA\b\s+(?:regulation|compliance|requirement|mandate|guidance|framework|standard|rules?|handbook)|\b(?:under|per|comply\s+with)\s+(?:the\s+)?\bFCA\b", "Regulatory framing: FCA"),
    (r"Likely registered",            "Registration judgement"),
    (r"Likely not registered",        "Registration judgement"),
    (r"blast radius",                 "Invented risk narrative"),
    (r"taken over",                   "Invented risk narrative"),
    (r"Article 28",                   "Regulatory reference"),
]


def _strip_data_passthrough(html: str) -> str:
    """Remove elements that contain raw xlsx data (tag badges, supplier names, asset names).

    The forbidden patterns must not fire on verbatim data values from the input files —
    only on generated prose. Badge spans, label divs, table cells, and supplier name
    displays carry values directly from the xlsx, so strip them before validation.
    """
    # <span> with class containing "b" prefix — Veracode tag badges (any attribute order)
    stripped = re.sub(r'<span\b[^>]*\bclass="b[^"]*"[^>]*>[^<]*</span>', "", html)
    # <span> or <div> with class "pr-lab" (any order/suffix) — bar chart labels
    stripped = re.sub(r'<span\b[^>]*\bclass="pr-lab[^"]*"[^>]*>[^<]*</span>', "", stripped)
    stripped = re.sub(r'<div\b[^>]*\bclass="pr-lab[^"]*"[^>]*>[^<]*</div>', "", stripped)
    # <span> with only a style attribute (no class) — inline supplier name badges (ciso)
    stripped = re.sub(r'<span\s+style="[^"]*">[^<]*</span>', "", stripped)
    # <td> cells — data tables with asset names, supplier names, grades, statuses
    stripped = re.sub(r'<td\b[^>]*>.*?</td>', "", stripped, flags=re.DOTALL)
    return stripped


def validate_html(html: str) -> None:
    prose = _strip_data_passthrough(html)
    errors = [
        reason
        for pattern, reason in FORBIDDEN_PATTERNS
        if re.search(pattern, prose, re.IGNORECASE)
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


def validate_teaser_output_path(customer: str, output_dir: Path) -> Path:
    safe_name = re.sub(r"[^a-zA-Z0-9\-_]", "-", customer.strip())[:50].lower()
    if not safe_name:
        raise ValueError("Customer name produced empty slug")
    return output_dir / f"{safe_name}-veracode-easm-teaser.html"
