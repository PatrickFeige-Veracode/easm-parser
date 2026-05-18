from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Supplier:
    name: str
    proximity: float
    vectors: dict[str, int]
    is_pii: bool = False
    is_pci: bool = False
    is_ai: bool = False


@dataclass(frozen=True, slots=True)
class Finding:
    id: str
    title: str
    body: str
    tags: tuple[str, ...]
    grade: str
    status: str
    asset: str
    port: int
    cname: str
    category: str    # 'cname'|'staging'|'internal_api'|'hygiene'|'supplier'
    fc_class: str    # ''|'med'|'high'|'crit'


@dataclass(frozen=True, slots=True)
class ReportData:
    customer: str
    scan_date: str
    seed_domains: tuple[str, ...]
    total_apps: int
    unique_fqdns: int
    bare_ip_count: int
    total_cnames: int
    grade_counts: dict[str, int]
    tag_counts: dict[str, int]
    clear_http_count: int
    suppliers: tuple[Supplier, ...]
    pii_suppliers: tuple[Supplier, ...]
    pci_suppliers: tuple[Supplier, ...]
    ai_suppliers: tuple[Supplier, ...]
