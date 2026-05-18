# Veracode EASM Report Generator

Generates a complete three-view HTML report (CISO / Security Engineer / GRC)
from a Veracode EASM xlsx export. Drop files in, run one command, get a report.

No Claude. No API keys. No manual steps after.

---

## Install

```bash
git clone <repo>
cd easm-parser
pip install -e .
```

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
--verbose      Debug logging
```

---

## Input files

Both files come from a Veracode EASM export:

| File | Contents |
|---|---|
| `*easm-extract*.xlsx` | application, supplyChain, supplyChainPii, supplyChainPci, supplyChainAi sheets |
| `*domain-things*.xlsx` | domain register — NS, DMARC, DKIM, registrar |

