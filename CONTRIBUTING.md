# Contributing

Thanks for your interest in improving the Veracode EASM Report Generator.

## How to contribute

1. **Fork** this repo on GitHub
2. **Clone** your fork locally
3. **Create a branch** — one branch per fix or feature
4. **Make your changes** — see the dev setup below
5. **Open a Pull Request** against `master` in this repo

All PRs are reviewed before merging. Please link your PR to the relevant issue using `Closes #<number>` in the commit message or PR description.

---

## Dev setup

```bash
git clone https://github.com/<your-fork>/easm-parser.git
cd easm-parser
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
pip install -e .
pip install -r requirements-dev.txt
```

Drop your Veracode xlsx exports into `inputs/` (gitignored — never commit these).

---

## Before opening a PR

These checks run automatically via GitHub Actions on every push and PR. Run them locally first to catch issues before pushing:

```bash
mypy src/
ruff check src/
pytest
pip-audit --requirement requirements.txt
```

All four must pass cleanly. PRs that fail any of these will not be merged.

---

## Code standards

- **Type hints on every function** — `mypy --strict` must pass
- **No comments explaining what the code does** — only add a comment when the *why* is non-obvious
- **No new dependencies** without discussion — open an issue first
- **No `lxml`** — CVE history; `openpyxl` is the only xlsx engine permitted
- **No `ast.literal_eval()`** — use `safe_parse_list` / `safe_parse_dict` from `parser.py`
- **Jinja2 autoescaping must stay on** — never use `| safe` or `Markup()` on user-derived strings
- **No hardcoded customer names** — all logic must be data-driven

---

## Project structure

```
src/easm_report/
  cli.py         — Click entrypoint (thin wrapper only)
  parser.py      — xlsx parsing → ReportData
  findings.py    — detection rules → list[Finding]
  renderer.py    — Jinja2 render → HTML
  validator.py   — output validation before write
  models.py      — frozen dataclasses
  exceptions.py  — typed exception hierarchy
templates/
  base.html      — CSS, JS, shell layout
  ciso.html / se.html / grc.html — view partials
```

---

## Opening an issue

Before starting work on anything non-trivial, open an issue first so we can agree on the approach. Bug reports should include steps to reproduce and the exact error message.
