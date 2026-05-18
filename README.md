# Veracode EASM Report Generator

A local CLI tool that turns a Veracode EASM xlsx export into a polished HTML report.
Drop files in, run one command, get a report. No API keys, no external services, no manual steps.

Two output modes:
- **Full report** — three-view HTML report tailored for CISO, Security Engineer, and GRC audiences
- **Snapshot report** — single-page teaser with top findings and supply chain exposure, designed to share with prospects before delivering the full report

Once the report is generated, it's worth loading the HTML into an LLM (e.g. Claude, ChatGPT) to pull out additional insights — pattern analysis, remediation prioritisation, or executive narrative — that go beyond what the static report surfaces on its own.

---

## Install

Requires [pipx](https://pipx.pypa.io) — it handles the Python environment for you.

**macOS (Homebrew):**
```bash
brew install pipx
git clone <repo>
pipx install -e ./easm-parser
```

**Linux / Windows:**
```bash
pip install pipx
git clone <repo>
pipx install -e ./easm-parser
```

`easm-report` will be on your PATH immediately — no virtual environment to activate.

---

## Usage

```bash
# Drop your two xlsx files into inputs/, then:
easm-report --customer "Acme Corp"

# Output: outputs/acme-corp-veracode-easm-report.html
```

The tool finds the xlsx files automatically by filename pattern:
- `*easm-extract*` — the EASM export
- `*domain-things*` — the domain register

If the wrong files are present it tells you clearly. It never silently uses the wrong file.

### Options

```
--customer     Customer name — used in report header and output filename (required)
--input-dir    Override the inputs folder (default: ./inputs)
--output-dir   Override the outputs folder (default: ./outputs)
--teaser       Generate a single-page snapshot report instead of the full report
--verbose      Debug logging
```

---

## Snapshot report (teaser)

The `--teaser` flag generates a single-page snapshot instead of the full three-view report. Use it to share a high-level preview of findings with a prospect or stakeholder before delivering the full report.

```bash
easm-report --customer "Acme Corp" --teaser

# Output: outputs/acme-corp-veracode-easm-teaser.html
```

The snapshot includes:
- **Hero stats** — Applications, Unique FQDNs, CNAME records, HSTS issues, internalApi tagged
- **Attack surface breakdown** — Bare IPs, Clear HTTP, Live & reachable application count
- **Grade distribution** — Risk grade breakdown across all discovered assets
- **Top 3 findings** — The highest-severity findings from the scan, in full report format
- **Top 5 suppliers** — Third-party supply chain exposure by proximity
- **Call to action** — Directs the recipient to contact Veracode for the full report

All figures are derived directly from the xlsx data — no invented or estimated values.

---

## Input files

Both files come from a Veracode EASM export:

| File | Contents |
|---|---|
| `*easm-extract*.xlsx` | application, supplyChain, supplyChainPii, supplyChainPci, supplyChainAi sheets |
| `*domain-things*.xlsx` | domain register — NS, DMARC, DKIM, registrar |

