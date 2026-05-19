"""Jinja2 render → HTML string."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pandas as pd

from easm_report.findings import attacker_score
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


def _build_hook(f: Finding) -> str:
    port_str = f" on port {f.port}" if f.port else ""
    if "clearHttp" in f.tags:
        return f"{f.asset} serves unencrypted HTTP{port_str} — traffic is transmitted in cleartext."
    if f.status == "online" and "internalApi" in f.tags:
        cname_note = f", routed via {f.cname}" if f.cname else ""
        return f"{f.asset} is an internalApi-tagged endpoint with status online{port_str}{cname_note}."
    if f.status == "online" and f.category == "staging":
        env = next(
            (w for w in ("sandbox", "dev", "staging", "uat", "test", "admin", "pilot")
             if w in f.asset.lower()), "staging"
        )
        return f"{f.asset} is a resolvable {env} environment with status online{port_str}."
    if f.category == "cname" and f.status == "online":
        return (
            f"{f.asset} resolves via CNAME to {f.cname} "
            f"and is actively serving on port {f.port}."
        )
    if f.category == "cname":
        return f"{f.asset} resolves via CNAME to {f.cname}, an external third-party host."
    if f.category == "hygiene" and "hostnameCertificateMismatch" in f.tags:
        return f"{f.asset} has a hostname/certificate mismatch{port_str}, status {f.status}."
    return f.title


def _build_researcher_note(f: Finding) -> str:
    if "clearHttp" in f.tags:
        return (
            f"{f.asset} transmits over port {f.port} without TLS — "
            f"form submissions and session tokens on this endpoint are visible on the network path."
        )
    if f.status == "online" and "internalApi" in f.tags:
        cname_note = f" via {f.cname}" if f.cname else ""
        return (
            f"{f.asset} returns an active response{cname_note} — "
            f"the confirmed online status means path and header enumeration requires no access bypass."
        )
    if f.status == "online" and f.category == "staging":
        return (
            f"{f.asset} is live and responding on port {f.port} — "
            f"staging environments routinely carry reduced access controls and data that mirrors production."
        )
    if f.category == "cname" and f.status == "online":
        return (
            f"{f.asset} is live and responding through {f.cname} on port {f.port} — "
            f"an external host outside the seed domains is in the serving path for this active endpoint."
        )
    if f.category == "cname":
        return (
            f"The CNAME target {f.cname} is external to the seed domains — "
            f"its configuration and response are not controlled by the scanned organisation."
        )
    if "hostnameCertificateMismatch" in f.tags:
        return (
            f"{f.asset} presents a certificate that does not match its hostname — "
            f"the mismatch indicates a server identity that cannot be verified at the TLS layer."
        )
    return (
        f"{f.title} — score {attacker_score(f)} — is the highest-priority finding in this dataset."
    )


def _researcher_pick(findings: list[Finding]) -> dict[str, str]:
    if not findings:
        return {}
    best = findings[0]  # already sorted by attacker_score() in detect_findings()
    return {
        "finding_title": best.title,
        "hook": _build_hook(best),
        "technical_detail": best.body,
        "researcher_note": _build_researcher_note(best),
    }


def _build_teaser_context(
    data: ReportData,
    findings: list[Finding],
) -> dict[str, Any]:
    total = data.total_apps or 1
    grade_pct = {g: round(100 * c / total, 1) for g, c in data.grade_counts.items()}
    top_suppliers = sorted(data.suppliers, key=lambda s: -s.proximity)[:5]

    sev_order = {"crit": 0, "d-lvl": 1, "med": 2, "": 3}
    top_findings = sorted(findings, key=lambda f: sev_order.get(f.fc_class, 3))[:3]

    seed_domain_0 = data.seed_domains[0] if data.seed_domains else data.customer.lower()

    hsts_count = (
        data.tag_counts.get("headerMissingHsts", 0)
        + data.tag_counts.get("hstsMisconfig", 0)
    )
    internal_api_count = sum(1 for f in findings if f.category == "internal_api")
    live_app_count = data.tag_counts.get("liveApp", 0)

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
        "clear_http_count": data.clear_http_count,
        "hsts_count": hsts_count,
        "internal_api_count": internal_api_count,
        "live_app_count": live_app_count,
        "top_suppliers": top_suppliers,
        "top_findings": top_findings,
        "total_findings": len(findings),
        "total_suppliers": len(data.suppliers),
        "pii_supplier_count": len(data.pii_suppliers),
        "pci_supplier_count": len(data.pci_suppliers),
        "ai_supplier_count": len(data.ai_suppliers),
        "cname_finding_count": sum(1 for f in findings if f.category == "cname"),
        "crit_count": sum(1 for f in findings if f.fc_class == "crit"),
        "high_count": sum(1 for f in findings if f.fc_class == "d-lvl"),
        "med_count": sum(1 for f in findings if f.fc_class == "med"),
        "ai_analysis": _researcher_pick(findings),
    }


def render_teaser(
    data: ReportData,
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

    ctx = _build_teaser_context(data, findings)
    html = env.get_template("teaser.html").render(ctx)
    validate_html(html)
    output_path.write_text(html, encoding="utf-8")


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
