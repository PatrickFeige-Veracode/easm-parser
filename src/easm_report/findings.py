"""Rule-based finding detection from parsed report data."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

import pandas as pd

from easm_report.models import Finding, ReportData

if TYPE_CHECKING:
    pass

_KNOWN_SUPPLIERS = frozenset({
    "amazon", "aws", "akamai", "google", "ibm", "digicert", "f5", "microsoft", "cloudflare",
})
_LETSENCRYPT_NAMES = frozenset({"let's encrypt", "internet security research group", "isrg"})
_COMMERCIAL_CA_NAMES = frozenset({
    "geotrust", "digicert", "comodo", "sectigo", "entrust", "globalsign",
    "godaddy", "thawte", "verisign", "usertrust",
})

FC_CLASS: dict[str, str] = {"F": "crit", "D": "d-lvl", "B": "med", "A": ""}

# Hostnames that indicate high-value targets from an attacker's perspective
_AUTH_ASSET_RE = re.compile(r"(?:auth|login|oauth|sso|token|admin)", re.IGNORECASE)
_DEV_ASSET_RE = re.compile(r"(?:sandbox|developer\.|devlake|netbox|netsuite|fulfil)", re.IGNORECASE)


def fc_class(grade: str) -> str:
    return FC_CLASS.get(str(grade).upper(), "")


def attacker_score(f: "Finding") -> int:
    """Score a finding by how immediately actionable it is for an external attacker.

    Higher = more interesting. Criteria in descending priority:
    - Cleartext HTTP: credentials/sessions in plaintext, no TLS required
    - Online status: the endpoint actually responds (not just 403)
    - Internal API surface: intended to be internal, exposed externally
    - Dev/staging/sandbox: lighter controls, test data, often mirrors production
    - Auth/admin hostnames: session and credential exposure
    - External CNAME chains: potential for hijack or misdirection
    - Non-standard ports on bare IPs: unmanaged / shadow services
    """
    score = 0

    # Status: online = actively responding (2xx), forbidden = gated (403)
    score += {"online": 50, "forbidden": 8, "notFound": 0}.get(f.status, 5)

    # clearHttp tag: highest signal — credentials traverse unencrypted
    if "clearHttp" in f.tags:
        score += 60

    # internalApi tag: service designed for internal use, exposed externally
    if "internalApi" in f.tags:
        score += 25

    # Certificate mismatch: server identity cannot be verified
    if "hostnameCertificateMismatch" in f.tags:
        score += 12

    # Category weights
    score += {"staging": 20, "internal_api": 18, "cname": 15, "hygiene": 8, "supplier": 4}.get(
        f.category, 0
    )

    # Auth/admin hostname: session hijack or privilege escalation surface
    if _AUTH_ASSET_RE.search(f.asset):
        score += 25

    # Developer tooling and network documentation tools: high recon value
    if _DEV_ASSET_RE.search(f.asset):
        score += 20

    # Non-standard ports on bare IPs: shadow/unmanaged services
    if f.port in (8080, 8443, 8000, 8888):
        score += 15

    # fc_class bonus
    score += {"crit": 20, "d-lvl": 12, "med": 5}.get(f.fc_class, 0)

    # Online asset routed through external CDN: confirms public routability
    if f.cname and f.status == "online":
        score += 10

    return score


def _worst_grade(grades: list[str]) -> str:
    order = ["F", "D", "C", "B", "A"]
    for g in order:
        if g in grades:
            return g
    return grades[0] if grades else "A"


_AKAMAI_RE = re.compile(r"akamai(edge|dns|dge)\.net$", re.IGNORECASE)


def _is_third_party_cname(cname_target: str, seed_domains: tuple[str, ...]) -> bool:
    if _AKAMAI_RE.search(cname_target):
        return False
    return not any(cname_target.strip().lower().endswith(d) for d in seed_domains)


def _detect_cname_findings(
    df: pd.DataFrame,
    seed_domains: tuple[str, ...],
    id_counter: list[int],
) -> list[Finding]:
    cname_mask = df["application.cname"].notna() & ~df["application.cname"].str.strip().str.lower().isin(
        ["no", "", "none", "nan"]
    )
    cname_df = df[cname_mask].copy()
    findings: list[Finding] = []

    for cname_target, group in cname_df.groupby("application.cname"):
        cname_str = str(cname_target).strip()
        if not _is_third_party_cname(cname_str, seed_domains):
            continue

        assets = list(group["application.name"].dropna().unique())
        grades = [str(g) for g in group["application.risk"].dropna().tolist()]
        worst = _worst_grade(grades)
        first_status = str(group["application.status"].iloc[0]) if not group.empty else ""
        first_port = int(group["application.port"].iloc[0]) if not group.empty else 0
        tags_set: set[str] = set()
        for tag_list in group["_parsed_tags"]:
            tags_set.update(tag_list)

        asset_list = ", ".join(assets[:5]) + ("…" if len(assets) > 5 else "")
        body = (
            f"{len(assets)} asset{'s' if len(assets) > 1 else ''} "
            f"({asset_list}) resolve{'s' if len(assets) == 1 else ''} "
            f"via CNAME to {cname_str}, an external third-party target. "
            f"Worst observed grade: {worst}."
        )
        fid = f"cname-{id_counter[0]}"
        id_counter[0] += 1
        findings.append(
            Finding(
                id=fid,
                title=f"External CNAME target: {cname_str}",
                body=body,
                tags=tuple(sorted(tags_set)),
                grade=worst,
                status=first_status,
                asset=assets[0],
                port=first_port,
                cname=cname_str,
                category="cname",
                fc_class=fc_class(worst),
            )
        )
    return findings


_STAGING_RE = re.compile(r"(?:staging|stage|stg|test|dev|uat|admin|pilot|sandbox)", re.IGNORECASE)


def _detect_staging_findings(
    df: pd.DataFrame,
    id_counter: list[int],
) -> list[Finding]:
    staging_mask = df["application.name"].str.contains(
        r"(?:staging|stage|stg|test|dev|uat|admin|pilot|sandbox)", na=False, regex=True
    ) & (df["application.status"] != "notFound")
    findings: list[Finding] = []
    groups: dict[str, list[Any]] = {}
    for _, row in df[staging_mask].iterrows():
        groups.setdefault(str(row["application.name"]), []).append(row)
    for asset, rows in groups.items():
        grades = [str(r["application.risk"]) for r in rows]
        worst = _worst_grade(grades)
        ports = sorted({int(r["application.port"]) for r in rows if pd.notna(r["application.port"])})
        ports_str = ", ".join(str(p) for p in ports)
        worst_row = next(r for r in rows if str(r["application.risk"]) == worst)
        status = str(worst_row["application.status"])
        cname = str(worst_row["application.cname"]) if pd.notna(worst_row["application.cname"]) else ""
        tags_set: set[str] = set()
        for r in rows:
            tags_set.update(r["_parsed_tags"])
        tags = tuple(sorted(tags_set))
        body = (
            f"Port{'s' if len(ports) > 1 else ''} {ports_str} · status {status} · grade {worst}. "
            f"Staging/development asset resolvable externally."
        )
        if cname and cname.lower() not in ("no", "none", "nan", ""):
            body += f" CNAME target: {cname}."
        fid = f"staging-{id_counter[0]}"
        id_counter[0] += 1
        findings.append(
            Finding(
                id=fid,
                title=f"Resolvable staging asset: {asset}",
                body=body,
                tags=tags,
                grade=worst,
                status=status,
                asset=asset,
                port=ports[0] if ports else 0,
                cname=cname,
                category="staging",
                fc_class=fc_class(worst),
            )
        )
    return findings


def _detect_internal_api_findings(
    df: pd.DataFrame,
    id_counter: list[int],
) -> list[Finding]:
    internal_mask = df["_parsed_tags"].apply(lambda tags: "internalApi" in tags)
    internal_mask = internal_mask & (df["application.status"] != "notFound")
    findings: list[Finding] = []
    groups: dict[str, list[Any]] = {}
    for _, row in df[internal_mask].iterrows():
        groups.setdefault(str(row["application.name"]), []).append(row)
    for asset, rows in groups.items():
        grades = [str(r["application.risk"]) for r in rows]
        worst = _worst_grade(grades)
        ports = sorted({int(r["application.port"]) for r in rows if pd.notna(r["application.port"])})
        ports_str = ", ".join(str(p) for p in ports)
        worst_row = next(r for r in rows if str(r["application.risk"]) == worst)
        status = str(worst_row["application.status"])
        cname = str(worst_row["application.cname"]) if pd.notna(worst_row["application.cname"]) else ""
        tags_set: set[str] = set()
        for r in rows:
            tags_set.update(r["_parsed_tags"])
        tags = tuple(sorted(tags_set))
        hsts = "headerMissingHsts" in tags or "hstsMisconfig" in tags
        body = (
            f"Port{'s' if len(ports) > 1 else ''} {ports_str} · status {status} · grade {worst}. "
            f"Tagged internalApi — internal API endpoint exposed externally."
        )
        if cname and cname.lower() not in ("no", "none", "nan", ""):
            body += f" CNAME target: {cname}."
        if hsts:
            body += " HSTS header absent or misconfigured."
        findings.append(
            Finding(
                id=f"internal-api-{id_counter[0]}",
                title=f"Externally reachable internal API: {asset}",
                body=body,
                tags=tags,
                grade=worst,
                status=status,
                asset=asset,
                port=ports[0] if ports else 0,
                cname=cname,
                category="internal_api",
                fc_class=fc_class(worst),
            )
        )
        id_counter[0] += 1
    return findings


_AUTH_RE = re.compile(r"(?:token|oauth|federat|auth)", re.IGNORECASE)


def _detect_hsts_auth_findings(
    df: pd.DataFrame,
    id_counter: list[int],
) -> list[Finding]:
    hsts_tag = df["_parsed_tags"].apply(
        lambda tags: "headerMissingHsts" in tags or "hstsMisconfig" in tags
    )
    auth_name = df["application.name"].str.contains(
        r"(?:token|oauth|federat|auth)", na=False, regex=True
    )
    findings: list[Finding] = []

    subset = df[hsts_tag & auth_name].copy()
    if subset.empty:
        return findings

    akamai_cname = subset["application.cname"].apply(
        lambda c: bool(_AKAMAI_RE.search(str(c))) if pd.notna(c) else False
    )
    grouped: dict[str, list[str]] = {}
    for _, row in subset.iterrows():
        key = str(row["application.cname"]) if bool(akamai_cname.at[row.name]) else "__direct__"
        grouped.setdefault(key, []).append(str(row["application.name"]))

    for edge, assets in grouped.items():
        first_row = subset[subset["application.name"] == assets[0]].iloc[0]
        grade = str(first_row["application.risk"])
        status = str(first_row["application.status"])
        port = int(first_row["application.port"]) if pd.notna(first_row["application.port"]) else 0
        tags = tuple(first_row["_parsed_tags"])
        asset_list = ", ".join(assets[:5]) + ("…" if len(assets) > 5 else "")
        edge_note = f" (shared Akamai edge {edge})" if edge != "__direct__" else ""
        body = (
            f"Authentication endpoint{'s' if len(assets) > 1 else ''} {asset_list}{edge_note} "
            f"lack HSTS or have an HSTS misconfiguration. "
            f"Status: {status}, grade: {grade}, port: {port}."
        )
        findings.append(
            Finding(
                id=f"hsts-auth-{id_counter[0]}",
                title=f"Missing HSTS on auth endpoint: {assets[0]}",
                body=body,
                tags=tags,
                grade=grade,
                status=status,
                asset=assets[0],
                port=port,
                cname=edge if edge != "__direct__" else "",
                category="hygiene",
                fc_class=fc_class(grade),
            )
        )
        id_counter[0] += 1
    return findings


def _detect_bare_ip_findings(
    df: pd.DataFrame,
    id_counter: list[int],
) -> list[Finding]:
    bare_ip = df["application.name"].str.match(
        r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", na=False
    )
    nonstandard = df["application.port"].isin([8080, 8443, 8000, 8888])
    findings: list[Finding] = []
    for _, row in df[bare_ip & nonstandard].iterrows():
        asset = str(row["application.name"])
        grade = str(row["application.risk"])
        status = str(row["application.status"])
        port = int(row["application.port"])
        tags = tuple(row["_parsed_tags"])
        body = (
            f"Bare IP {asset} is accessible on port {port} (status {status}, grade {grade}). "
            f"Non-standard ports on bare IPs commonly indicate unintended or unmanaged services."
        )
        findings.append(
            Finding(
                id=f"bare-ip-{id_counter[0]}",
                title=f"Bare IP on non-standard port: {asset}:{port}",
                body=body,
                tags=tags,
                grade=grade,
                status=status,
                asset=asset,
                port=port,
                cname="",
                category="hygiene",
                fc_class=fc_class(grade),
            )
        )
        id_counter[0] += 1
    return findings


def _detect_cert_mismatch_findings(
    df: pd.DataFrame,
    id_counter: list[int],
) -> list[Finding]:
    cert_mask = df["_parsed_tags"].apply(lambda tags: "hostnameCertificateMismatch" in tags)
    findings: list[Finding] = []
    for _, row in df[cert_mask].iterrows():
        asset = str(row["application.name"])
        grade = str(row["application.risk"])
        status = str(row["application.status"])
        port = int(row["application.port"]) if pd.notna(row["application.port"]) else 0
        cname = str(row["application.cname"]) if pd.notna(row["application.cname"]) else ""
        tags = tuple(row["_parsed_tags"])
        body = (
            f"{asset} (port {port}, status {status}, grade {grade}) has a hostname/certificate mismatch. "
        )
        if cname and cname.lower() not in ("no", "none", "nan", ""):
            body += f"CNAME target: {cname}."
        findings.append(
            Finding(
                id=f"cert-mismatch-{id_counter[0]}",
                title=f"Certificate hostname mismatch: {asset}",
                body=body,
                tags=tags,
                grade=grade,
                status=status,
                asset=asset,
                port=port,
                cname=cname,
                category="hygiene",
                fc_class=fc_class(grade),
            )
        )
        id_counter[0] += 1
    return findings


def _detect_unrecognised_supplier_findings(
    data: ReportData,
    id_counter: list[int],
) -> list[Finding]:
    findings: list[Finding] = []
    for supplier in data.suppliers:
        if supplier.proximity <= 30.0:
            continue
        name_lower = supplier.name.lower()
        if any(k in name_lower for k in _KNOWN_SUPPLIERS):
            continue
        vectors_str = ", ".join(f"{k}:{v}" for k, v in supplier.vectors.items())
        body = (
            f"{supplier.name} has a proximity score of {supplier.proximity:.1f}% via vectors: "
            f"{vectors_str or 'unspecified'}. "
            f"This supplier is not in the recognised tier and warrants review."
        )
        findings.append(
            Finding(
                id=f"supplier-{id_counter[0]}",
                title=f"Unrecognised supplier at {supplier.proximity:.1f}%: {supplier.name}",
                body=body,
                tags=(),
                grade="B",
                status="",
                asset="",
                port=0,
                cname="",
                category="supplier",
                fc_class="med",
            )
        )
        id_counter[0] += 1
    return findings


def _detect_mixed_ca_findings(
    data: ReportData,
    id_counter: list[int],
) -> list[Finding]:
    supplier_names_lower = {s.name.lower() for s in data.suppliers}
    has_letsencrypt = any(le in supplier_names_lower for le in _LETSENCRYPT_NAMES)
    has_commercial = any(c in supplier_names_lower for c in _COMMERCIAL_CA_NAMES)

    if not (has_letsencrypt and has_commercial):
        return []

    le_names = [s.name for s in data.suppliers if s.name.lower() in _LETSENCRYPT_NAMES]
    comm_names = [s.name for s in data.suppliers if s.name.lower() in _COMMERCIAL_CA_NAMES]
    body = (
        f"The certificate estate uses both free/automated CAs ({', '.join(le_names)}) "
        f"and commercial CAs ({', '.join(comm_names)}). "
        f"An inconsistent CA mix indicates a fragmented certificate management process, "
        f"which can lead to undetected expirations or policy gaps."
    )
    return [
        Finding(
            id=f"mixed-ca-{id_counter[0]}",
            title="Mixed certificate authority usage detected",
            body=body,
            tags=(),
            grade="B",
            status="",
            asset="",
            port=0,
            cname="",
            category="hygiene",
            fc_class="med",
        )
    ]


def detect_findings(
    data: ReportData,
    dataframes: dict[str, Any],
) -> list[Finding]:
    df: pd.DataFrame = dataframes["application"]
    id_counter = [1]

    findings: list[Finding] = []
    findings.extend(_detect_cname_findings(df, data.seed_domains, id_counter))
    findings.extend(_detect_staging_findings(df, id_counter))
    findings.extend(_detect_internal_api_findings(df, id_counter))
    findings.extend(_detect_hsts_auth_findings(df, id_counter))
    findings.extend(_detect_bare_ip_findings(df, id_counter))
    findings.extend(_detect_cert_mismatch_findings(df, id_counter))
    findings.extend(_detect_unrecognised_supplier_findings(data, id_counter))
    findings.extend(_detect_mixed_ca_findings(data, id_counter))

    # One finding per (asset, port) — keep the highest-scoring where asset is known.
    seen: dict[tuple[str, int], Finding] = {}
    no_asset: list[Finding] = []
    for f in findings:
        if not f.asset:
            no_asset.append(f)
        else:
            key = (f.asset, f.port)
            if key not in seen or attacker_score(f) > attacker_score(seen[key]):
                seen[key] = f

    return sorted(list(seen.values()) + no_asset, key=attacker_score, reverse=True)
