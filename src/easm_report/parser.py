"""Parse xlsx exports into ReportData + raw DataFrames."""

from __future__ import annotations

import json
import logging
import re
from collections import Counter
from pathlib import Path
from typing import Any

import pandas as pd

from easm_report.exceptions import FileTooLargeError, InvalidFileTypeError, PathTraversalError
from easm_report.models import ReportData, Supplier

logger = logging.getLogger(__name__)

_MAX_FILE_BYTES = 50 * 1024 * 1024


def validate_input_path(path: Path, base_dir: Path) -> Path:
    resolved = path.resolve()
    if not resolved.is_relative_to(base_dir.resolve()):
        raise PathTraversalError(f"Path outside allowed directory: {path}")
    if resolved.suffix.lower() != ".xlsx":
        raise InvalidFileTypeError(f"Expected .xlsx, got: {resolved.suffix}")
    if not resolved.exists():
        raise FileNotFoundError(f"File not found: {resolved}")
    if resolved.stat().st_size > _MAX_FILE_BYTES:
        raise FileTooLargeError("File exceeds 50MB limit")
    return resolved


def safe_parse_list(raw: str) -> list[str]:
    if not isinstance(raw, str) or not raw.strip():
        return []
    normalised = re.sub(r"'([^']*)'", r'"\1"', raw.strip())
    try:
        result = json.loads(normalised)
        if not isinstance(result, list):
            return []
        return [str(item)[:100] for item in result if isinstance(item, str)][:50]
    except (json.JSONDecodeError, ValueError):
        return []


def safe_parse_dict(raw: str) -> dict[str, int]:
    if not isinstance(raw, str) or not raw.strip():
        return {}
    normalised = re.sub(r"'([^']*)'", r'"\1"', raw.strip())
    try:
        result = json.loads(normalised)
        if not isinstance(result, dict):
            return {}
        return {
            str(k)[:50]: int(v)
            for k, v in result.items()
            if isinstance(k, str) and isinstance(v, int | float)
        }
    except (json.JSONDecodeError, ValueError, TypeError):
        return {}


def _extract_scan_date(raw: pd.DataFrame) -> str:
    for _, row in raw.iterrows():
        for cell in row:
            if isinstance(cell, str):
                m = re.search(r"Test date:\s*(\d{4}-\d{2}-\d{2})", cell)
                if m:
                    return m.group(1)
    return "unknown"


def _read_suppliers(
    easm_path: Path,
    sheet: str,
    pii_names: set[str],
    pci_names: set[str],
    ai_names: set[str],
) -> tuple[Supplier, ...]:
    try:
        df = pd.read_excel(easm_path, sheet_name=sheet, header=3, engine="openpyxl")
    except Exception as exc:
        logger.warning("Could not read sheet %s: %s", sheet, exc)
        return ()

    if df.empty or "Supplier" not in df.columns:
        return ()

    suppliers: list[Supplier] = []
    for _, row in df.iterrows():
        name = str(row.get("Supplier", "")).strip()
        if not name or name.lower() in ("nan", ""):
            continue
        prox_raw = row.get("Proximity", 0)
        try:
            proximity = float(prox_raw)
        except (ValueError, TypeError):
            proximity = 0.0
        vectors = safe_parse_dict(str(row.get("Vectors", "")))
        suppliers.append(
            Supplier(
                name=name,
                proximity=proximity,
                vectors=vectors,
                is_pii=name in pii_names,
                is_pci=name in pci_names,
                is_ai=name in ai_names,
            )
        )
    logger.info("Parsed %d suppliers from %s", len(suppliers), sheet)
    return tuple(suppliers)


def _read_classified_names(easm_path: Path, sheet: str) -> set[str]:
    try:
        df = pd.read_excel(easm_path, sheet_name=sheet, header=3, engine="openpyxl")
        if df.empty or "Supplier" not in df.columns:
            return set()
        return {str(r).strip() for r in df["Supplier"].dropna() if str(r).strip()}
    except Exception:
        return set()


_DOMAIN_RE = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$"
)


def _parse_seed_domains(seeds_str: str) -> tuple[str, ...]:
    domains = [d.strip().lower() for d in seeds_str.split(",") if d.strip()]
    if not domains:
        raise ValueError("--seeds produced no valid domains after parsing")
    for d in domains:
        if not _DOMAIN_RE.match(d):
            raise ValueError(f"Invalid domain in --seeds: {d!r}")
    return tuple(domains)


def read_easm(
    easm_path: Path,
    domain_path: Path,
    customer: str,
    base_dir: Path,
    seeds: str | None = None,
) -> tuple[ReportData, dict[str, Any]]:
    easm_path = validate_input_path(easm_path, base_dir)
    domain_path = validate_input_path(domain_path, base_dir)

    logger.info("Reading EASM extract: %s", easm_path.name)
    logger.info("Reading domain file: %s", domain_path.name)

    # --- application sheet ---
    raw = pd.read_excel(
        easm_path, sheet_name="application", header=None, nrows=5, engine="openpyxl"
    )
    scan_date = _extract_scan_date(raw)

    df = pd.read_excel(easm_path, sheet_name="application", header=3, engine="openpyxl")
    df = df.assign(
        _parsed_tags=df["autoThingTagNames"].apply(
            lambda x: safe_parse_list(str(x)) if pd.notna(x) else []
        ),
        _parsed_server=df["application.server"].apply(
            lambda x: safe_parse_list(str(x)) if pd.notna(x) else []
        ),
    )

    # --- derived stats ---
    total_apps = len(df)
    unique_fqdns = int(
        df[df["application.name"].str.match(r"^[a-zA-Z]", na=False)]["application.name"].nunique()
    )
    bare_ip_mask = df["application.name"].str.match(
        r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", na=False
    )
    bare_ip_count = int(bare_ip_mask.sum())
    cname_lower = df["application.cname"].fillna("").astype(str).str.strip().str.lower()
    cname_mask = df["application.cname"].notna() & ~cname_lower.isin(["no", "", "none", "nan"])
    total_cnames = int(cname_mask.sum())
    grade_counts: dict[str, int] = {
        str(k): int(v) for k, v in df["application.risk"].value_counts().to_dict().items()
    }
    tag_counts: dict[str, int] = dict(Counter(t for tags in df["_parsed_tags"] for t in tags))
    clear_http_count = int((df["application.clearHttp"] == 1).sum())

    if seeds is not None:
        seed_domains = _parse_seed_domains(seeds)
        logger.info("Using explicit seed domains: %s", ", ".join(seed_domains))
    else:
        # Auto-detect: relatedDomain values with >= 2 unique app names.
        # Auto-discovered related domains appear with exactly 1 unique app and are excluded.
        _rd_unique = (
            df.dropna(subset=["relatedDomain"])
            .groupby("relatedDomain")["application.name"]
            .nunique()
        )
        _seed_candidates = _rd_unique[_rd_unique >= 2].index
        _domain_counts = (
            df[df["relatedDomain"].isin(_seed_candidates)]["relatedDomain"]
            .dropna()
            .str.strip()
            .str.lower()
            .value_counts()
        )
        seed_domains = tuple(str(d) for d in _domain_counts.index if str(d).strip())

    logger.info("Parsed %d applications from %s", total_apps, easm_path.name)

    # --- supply chain sheets ---
    pii_names = _read_classified_names(easm_path, "supplyChainPii")
    pci_names = _read_classified_names(easm_path, "supplyChainPci")
    ai_names = _read_classified_names(easm_path, "supplyChainAi")

    suppliers = _read_suppliers(easm_path, "supplyChain", pii_names, pci_names, ai_names)

    # --- supply chain pii/pci/ai (standalone tuples for template) ---
    pii_only = _read_suppliers(easm_path, "supplyChainPii", pii_names, pci_names, ai_names)
    pci_only = _read_suppliers(easm_path, "supplyChainPci", pii_names, pci_names, ai_names)
    ai_only = _read_suppliers(easm_path, "supplyChainAi", pii_names, pci_names, ai_names)

    # --- domain-things ---
    df_domain = pd.read_excel(domain_path, sheet_name="domain-things", header=0, engine="openpyxl")
    logger.info("Parsed %d domain records from %s", len(df_domain), domain_path.name)

    # --- supplyChain dataframe for findings ---
    try:
        df_sc = pd.read_excel(easm_path, sheet_name="supplyChain", header=3, engine="openpyxl")
    except Exception:
        df_sc = pd.DataFrame()

    report_data = ReportData(
        customer=customer,
        scan_date=scan_date,
        seed_domains=seed_domains,
        seed_count=len(seed_domains),
        total_apps=total_apps,
        unique_fqdns=unique_fqdns,
        bare_ip_count=bare_ip_count,
        total_cnames=total_cnames,
        grade_counts=grade_counts,
        tag_counts=tag_counts,
        clear_http_count=clear_http_count,
        suppliers=suppliers,
        pii_suppliers=pii_only,
        pci_suppliers=pci_only,
        ai_suppliers=ai_only,
    )

    dataframes: dict[str, Any] = {
        "application": df,
        "supply_chain": df_sc,
        "domain": df_domain,
    }

    return report_data, dataframes
