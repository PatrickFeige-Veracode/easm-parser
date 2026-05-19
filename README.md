# Veracode EASM Report Generator

> Turn a Veracode EASM xlsx export into a polished report in one command.
> No API keys. No agents. No manual steps.

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://python.org)
[![PDF](https://img.shields.io/badge/PDF-WeasyPrint-brightgreen)](https://weasyprint.org)
[![Jinja2](https://img.shields.io/badge/templates-Jinja2-red)](https://jinja.palletsprojects.com)

---

## What it produces

| Mode | Flag | Description |
|------|------|-------------|
| **Full report** | _(default)_ | Three-view HTML report — CISO executive summary, Security Engineer asset detail, GRC supplier register + remediation plan |
| **Snapshot** | `--teaser` | Single-page preview with headline stats, top findings, and supply chain exposure — designed to share before delivering the full report |
| **PDF** | `--pdf` | Print-ready PDF of either mode, rendered via WeasyPrint |

---

## Screenshots

### Full report — CISO view

![Full report CISO view](docs/screenshots/full-report-ciso.png)

### Snapshot (teaser) report

![Snapshot report](docs/screenshots/teaser.png)

---

## Install

Requires [pipx](https://pipx.pypa.io) — handles the Python environment so you don't need to manage a virtualenv.

**macOS:**
```bash
brew install pipx
git clone <repo>
cd easm-parser
pipx install -e .
```

**Linux / Windows:**
```bash
pip install pipx
git clone <repo>
cd easm-parser
pipx install -e .
```

`easm-report` is now on your PATH.

### PDF support (optional)

PDF output requires WeasyPrint and a system library. Install once:

**macOS:**
```bash
brew install pango
pipx inject easm-report weasyprint
```

**Linux (Debian/Ubuntu):**
```bash
sudo apt-get install -y libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b
pipx inject easm-report weasyprint
```

---

## Usage

Drop your two xlsx exports into `inputs/`, then run:

```bash
easm-report --customer "Acme Corp"
# → outputs/acme-corp-veracode-easm-report.html

easm-report --customer "Acme Corp" --pdf
# → outputs/acme-corp-veracode-easm-report.html
# → outputs/Acme_Corp-veracode-easm-report.pdf

easm-report --customer "Acme Corp" --teaser
# → outputs/acme-corp-veracode-easm-teaser.html

easm-report --customer "Acme Corp" --teaser --pdf
# → outputs/acme-corp-veracode-easm-teaser.html
# → outputs/Acme_Corp-veracode-easm-teaser.pdf
```

The tool auto-detects the xlsx files by filename pattern:
- `*easm-extract*` — the EASM application export
- `*domain-things*` — the domain register

If multiple matches or no match is found, it tells you clearly. It never silently uses the wrong file.

---

## Options

```
--customer     Customer name — used in report header and output filename  [required]
--input-dir    Folder containing xlsx files  [default: inputs]
--output-dir   Folder for output files  [default: outputs]
--teaser       Generate a single-page snapshot instead of the full report
--pdf          Also generate a PDF (requires WeasyPrint — see Install)
--verbose      Debug logging
```

---

## What's in each report

### Full report

Three views rendered into a single self-contained HTML file:

- **CISO** — Attack surface posture, top findings, supply chain risk, discovery methodology
- **Security Engineer** — Full asset inventory, CNAME chain analysis, internal API exposure, bare IP inventory
- **GRC** — PII/PCI/AI supplier classification, governance findings, prioritised remediation action plan

### Snapshot report

A single-page preview designed to share with a prospect or stakeholder before the full report is delivered:

- **Hero stats** — Applications, Unique FQDNs, Suppliers, CNAME records, internalApi-tagged assets
- **Attack surface grid** — All key metrics with red/amber highlights (third-party CNAME targets, bare IPs, HSTS issues, grade F/D/B/A counts)
- **Grade distribution** — Risk grade bar chart across all discovered assets
- **Top 3 findings** — Highest-severity findings in full finding-card format
- **Top 5 suppliers** — Proximity bar chart with PII/PCI/AI classification counts
- **Call to action** — Contact prompt for the full report

All figures come directly from the xlsx data — nothing is invented or estimated.

---

## Input files

Both files are standard Veracode EASM exports:

| File | Sheets used |
|------|-------------|
| `*easm-extract*.xlsx` | `application`, `supplyChain`, `supplyChainPii`, `supplyChainPci`, `supplyChainAi` |
| `*domain-things*.xlsx` | Domain register — NS, DMARC, DKIM, registrar data |

Drop them into `inputs/` before running. Both are gitignored — customer data never lands in version control.

---

## LLM tip

Once the report is generated, load the HTML into an LLM (Claude, ChatGPT, etc.) for a second pass — pattern analysis across findings, remediation prioritisation, or an executive narrative layer that goes beyond what the static report surfaces on its own.
