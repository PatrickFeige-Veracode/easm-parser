"""Jinja2 render → HTML string."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pandas as pd

from easm_report.models import Finding, ReportData
from easm_report.validator import validate_html


def _build_context(
    data: ReportData,
    dataframes: dict[str, Any],
    findings: list[Finding],
) -> dict[str, Any]:
    df: pd.DataFrame = dataframes["application"]
    total = data.total_apps or 1

    grade_pct = {g: round(100 * c / total, 1) for g, c in data.grade_counts.items()}
    tag_pct = {t: round(100 * c / total, 1) for t, c in data.tag_counts.items()}
    top_tags = sorted(data.tag_counts.items(), key=lambda x: -x[1])[:10]

    investigation_count = int(
        (df["application.RecommendedSecurityProgram"].str.lower().str.strip() == "investigation").sum()
    )

    top_suppliers = sorted(data.suppliers, key=lambda s: -s.proximity)[:7]

    cname_findings = [f for f in findings if f.category == "cname"]
    staging_findings = [f for f in findings if f.category == "staging"]
    internal_api_findings = [f for f in findings if f.category == "internal_api"]
    hygiene_findings = [f for f in findings if f.category == "hygiene"]
    supplier_findings = [f for f in findings if f.category == "supplier"]
    auth_findings = [f for f in findings if "hsts-auth" in f.id]

    sev_order = {"crit": 0, "d-lvl": 1, "med": 2, "": 3}
    top_findings = sorted(findings, key=lambda f: sev_order.get(f.fc_class, 3))[:3]

    _staging_re = re.compile(
        r"(?:staging|stage|stg|test|dev|uat|admin|pilot|sandbox)", re.IGNORECASE
    )
    _bare_ip_re = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    seen: set[str] = set()
    priority_assets: list[dict[str, Any]] = []

    for _, row in df.iterrows():
        tags: list[str] = row["_parsed_tags"]
        grade = str(row["application.risk"])
        status = str(row["application.status"])
        name = str(row["application.name"])
        port = int(row["application.port"]) if pd.notna(row["application.port"]) else 0
        raw_cname = str(row["application.cname"]) if pd.notna(row["application.cname"]) else ""
        cname = raw_cname if raw_cname.lower() not in ("no", "none", "nan", "") else "—"

        is_priority = (
            ("internalApi" in tags)
            or ("suspiciousSubdomain" in tags)
            or (grade in ("F", "D"))
            or (
                bool(_staging_re.search(name))
                and status not in ("notFound",)
                and not _bare_ip_re.match(name)
            )
        )
        key = f"{name}:{port}"
        if is_priority and key not in seen:
            seen.add(key)
            priority_assets.append(
                {
                    "name": name,
                    "port": port,
                    "grade": grade,
                    "status": status,
                    "cname": cname,
                    "tags": tags,
                }
            )

    grade_order = {"F": 0, "D": 1, "C": 2, "B": 3, "A": 4}
    priority_assets.sort(key=lambda x: grade_order.get(x["grade"], 5))

    bare_ip_rows: list[dict[str, Any]] = []
    for _, row in df[
        df["application.name"].str.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", na=False)
    ].iterrows():
        bare_ip_rows.append(
            {
                "ip": str(row["application.name"]),
                "port": int(row["application.port"]) if pd.notna(row["application.port"]) else 0,
                "status": str(row["application.status"]),
                "tags": row["_parsed_tags"],
            }
        )

    seed_domain_0 = data.seed_domains[0] if data.seed_domains else data.customer.lower()

    crit_count = sum(1 for f in findings if f.fc_class == "crit")
    high_count = sum(1 for f in findings if f.fc_class == "d-lvl")
    med_count = sum(1 for f in findings if f.fc_class == "med")
    track_count = sum(1 for f in findings if f.fc_class == "")

    return {
        "customer": data.customer,
        "scan_date": data.scan_date,
        "seed_domains": list(data.seed_domains),
        "seed_domain_0": seed_domain_0,
        "seed_domain_count": len(data.seed_domains),
        "total_apps": data.total_apps,
        "unique_fqdns": data.unique_fqdns,
        "bare_ip_count": data.bare_ip_count,
        "total_cnames": data.total_cnames,
        "grade_counts": data.grade_counts,
        "grade_pct": grade_pct,
        "tag_counts": data.tag_counts,
        "tag_pct": tag_pct,
        "top_tags": top_tags,
        "clear_http_count": data.clear_http_count,
        "suppliers": list(data.suppliers),
        "pii_suppliers": list(data.pii_suppliers),
        "pci_suppliers": list(data.pci_suppliers),
        "ai_suppliers": list(data.ai_suppliers),
        "top_suppliers": top_suppliers,
        "findings": findings,
        "cname_findings": cname_findings,
        "staging_findings": staging_findings,
        "internal_api_findings": internal_api_findings,
        "hygiene_findings": hygiene_findings,
        "supplier_findings": supplier_findings,
        "auth_findings": auth_findings,
        "top_findings": top_findings,
        "priority_assets": priority_assets,
        "bare_ip_rows": bare_ip_rows,
        "investigation_count": investigation_count,
        "crit_count": crit_count,
        "high_count": high_count,
        "med_count": med_count,
        "track_count": track_count,
    }


def render_report(
    data: ReportData,
    dataframes: dict[str, Any],
    findings: list[Finding],
    template_dir: Path,
    output_path: Path,
) -> None:
    from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(["html"]),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )

    ctx = _build_context(data, dataframes, findings)
    html = env.get_template("base.html").render(ctx)
    validate_html(html)
    output_path.write_text(html, encoding="utf-8")
