"""PDF generation from EASM HTML reports.

Security controls per veracode-easm-pdf-writer skill:
SR-1 Path traversal prevention
SR-2 Shell injection prevention (list-form subprocess only)
SR-3 File size limits
SR-4 File type validation via magic bytes (no python-magic dependency)
SR-5 No eval/exec on data
SR-6 Secure temp directories with guaranteed cleanup
SR-7 Subprocess timeout=120 on all external calls
SR-8 Output filename sanitisation
"""

from __future__ import annotations

import contextlib
import logging
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Generator

from easm_report.exceptions import (
    EasmReportError,
    FileTooLargeError,
    InvalidFileTypeError,
    PathTraversalError,
    ValidationError,
)

logger = logging.getLogger(__name__)

MAX_INPUT_BYTES = 50 * 1024 * 1024    # 50 MB
MAX_OUTPUT_BYTES = 100 * 1024 * 1024  # 100 MB

# SR-2: print CSS injected before </head> — no shell, no exec
#
# WeasyPrint-specific fixes applied here (HTML templates are not touched):
#
#  1. PROGRESS BARS — `.pr-fill { height:100% }` fails when WeasyPrint cannot
#     establish the flex parent height; fix with explicit 7px on the fill.
#     `.pr-lab { width:200px }` overflows narrow 3-col card (~168px each);
#     switch to a percentage that fits.
#
#  2. CARD-ROW GRID — WeasyPrint has partial CSS Grid support; replace with
#     flexbox so the 3-column layout renders correctly.
#
#  3. TABLES — 6-column tables overflow the ~523px usable A4 width (A4 595px
#     minus 2×36px section padding). Shrink font/padding and allow word-wrap.
#
#  4. PII CHIP ROW — The amber alert uses `flex-direction:column` in an inline
#     style; WeasyPrint may not compose class flex + inline flex-direction.
#     Force column direction via the stylesheet. Suppress emoji glyphs that
#     WeasyPrint renders as fallback squares.
#
#  5. GRIDS (stat, pq, bi, steps, pillars) — Repeat the grid definitions from
#     the template's existing @media print so WeasyPrint gets them from the
#     injected block (WeasyPrint processes stylesheets in document order; the
#     template's own @media print block appears later and may lose to defaults).
PRINT_PATCH = """
<style>
@media print {

  /* ══ PAGE ══════════════════════════════════════════════════════════════
     Overrides base template @page{margin:0}. Later in document = wins.   */
  @page { margin:10mm 12mm; size:A4; }

  /* ══ BODY BACKGROUND ════════════════════════════════════════════════════
     body{background:#EEF2F8} (--g100) is the root cause of every grey box:
     WeasyPrint paints the body background wherever section content doesn't
     fill the page. Reset to white so gaps between sections are invisible.  */
  body { background:#fff !important; }

  /* ══ GLOBAL ════════════════════════════════════════════════════════════
     Apply -webkit-print-color-adjust only to elements that actually have
     meaningful background colours. Using * caused the dark cover page to
     overflow onto subsequent pages as a large grey block.                */
  .sec-dark, .sec-mid, .hero, .dots-d,
  .pq-fn, .pq-fs, .pq-mo, .pq-tr,
  .fc, .card, .card-dark, .card-cream, .stat-card, .stat-card.hi,
  .alert-red, .alert-amber, .alert-blue, .alert-green,
  .strip-red, .strip-amber, .strip-blue, .strip-dark,
  .pillar, .step, .bi-cell,
  .tbl-wrap thead, #print-toc,
  .cta-section, thead {
    -webkit-print-color-adjust:exact !important;
  }

  /* ══ CHROME / SIDEBAR ══════════════════════════════════════════════════ */
  .topbar, .sidebar, .foot { display:none !important; }
  .main { margin-left:0 !important; margin-top:0 !important; }
  .view { display:block !important; }
  #view-se  { page-break-before:always; break-before:page; }
  #view-grc { page-break-before:always; break-before:page; }

  /* ══ COVER PAGE ════════════════════════════════════════════════════════
     min-height:100vh is ignored → justify-content:space-between collapses
     everything to the top. Switch to column + gap so sections stack
     neatly. Reduce padding so the stats row (6 items) has room to breathe.
     Stats gap: 36px → 14px so labels don't clip.                         */
  #print-toc {
    display:flex !important;
    flex-direction:column !important;
    justify-content:flex-start !important;
    gap:24px !important;
    padding:36px 40px !important;
    overflow:hidden !important;
  }
  /* Hero orbs: ensure hidden in print even after print-color-adjust changes */
  .hero-orb1, .hero-orb2 { display:none !important; }
  #print-toc div[style*="gap:36px"] {
    gap:14px !important;
    flex-wrap:wrap !important;
  }
  #print-toc div[style*="gap:36px"] > div { min-width:60px; }

  /* ══ SECTION PADDING & OVERFLOW ════════════════════════════════════════
     overflow:hidden prevents section background colours (cream, mid, dark)
     from painting into empty space below content — the root cause of every
     "grey box" artifact. Applied to all .sec variants, not just #ciso-model. */
  .sec, .hero { padding:22px 28px !important; overflow:hidden !important; }

  /* ══ PROGRESS BARS ═════════════════════════════════════════════════════
     height:100% on .pr-fill fails (WeasyPrint can't resolve % of a flex
     child when parent height comes from align-items:center).
     min-width:4px so Grade D/F at <2% of 168 apps aren't invisible.
     7.5px + break-all + overflow:hidden so camelCase tags wrap in card.  */
  .pr-fill { height:7px !important; min-width:4px; }
  .pr-bar  { min-height:7px !important; overflow:hidden; }
  .pr-lab  {
    width:36% !important;
    max-width:36% !important;
    min-width:0 !important;
    white-space:normal !important;
    word-break:break-all !important;
    overflow:hidden;
    font-size:7.5px !important;
    line-height:1.3;
  }
  .pr-val { font-size:8px !important; min-width:44px; }

  /* ══ CARDS & CELLS: no mid-element page breaks ══════════════════════════
     Keeps each pillar/step/pq/stat card on one page and prevents the
     "half a card rendered, then a grey block" artifact.                   */
  .fc, .card, .stat-card, .pillar, .step, .bi-cell, .pq,
  .alert, .strip { page-break-inside:avoid; break-inside:avoid; }
  .pillars, .steps, .bi-grid, .pq-grid { page-break-inside:avoid; break-inside:avoid; }

  /* fc-meta badges: block so they don't render as an empty flex rectangle */
  .fc-body { word-break:break-word; overflow-wrap:anywhere; }
  .fc-meta { display:block !important; overflow:visible; }
  .fc-meta .b { display:inline-block; margin:1px 2px; }
  .code-block { white-space:normal !important; word-break:break-all; overflow:visible; }

  /* ══ CARD GRID → FLEXBOX ═══════════════════════════════════════════════
     WeasyPrint CSS Grid is partial; flexbox is reliable.                  */
  .card-row   { display:flex !important; flex-wrap:nowrap !important; gap:8px !important; }
  .card-row > * { flex:1 1 0 !important; min-width:0 !important; }
  .card-row-2 { display:flex !important; gap:10px !important; }
  .card-row-2 > * { flex:1 1 0 !important; min-width:0 !important; }

  /* ══ OTHER GRIDS ════════════════════════════════════════════════════════ */
  .stat-grid { display:grid !important; grid-template-columns:repeat(5,1fr) !important; }
  .pq-grid   { display:grid !important; grid-template-columns:repeat(4,1fr) !important; }
  .bi-grid   { display:grid !important; grid-template-columns:repeat(5,1fr) !important; }
  .steps     { display:grid !important; grid-template-columns:repeat(4,1fr) !important; }
  /* .pillars: use flexbox (WeasyPrint grid break-inside is unreliable)     */
  .pillars {
    display:flex !important;
    flex-wrap:nowrap !important;
    gap:16px !important;
    align-items:stretch !important;
    page-break-inside:avoid !important;
    break-inside:avoid !important;
  }
  .pillars .pillar {
    flex:1 1 0 !important;
    min-width:0 !important;
    overflow:hidden !important;
  }

  /* ══ PILLAR: ul flex-direction:column → block ══════════════════════════
     The navy VERACODE EASM pillar has a ul with inline display:flex;
     flex-direction:column;gap:7px. WeasyPrint computes extra height for the
     gap and paints the navy+cream section background into empty space below
     the content — this is the persistent "grey box".
     Attribute selectors on [style] are unreliable in WeasyPrint; target all
     ul inside .pillar with a plain class selector instead.
     overflow:hidden on #ciso-model clips any remaining background bleed.   */
  .pillar ul { display:block !important; }
  .pillar ul > li { margin-bottom:6px !important; }
  #ciso-model { overflow:hidden !important; }

  /* ══ ORPHANED HEADINGS: keep eyebrow + h2 glued to following content ═══
     .eyebrow alone (no suffix) was missing page-break-after:avoid.         */
  .eyebrow, .eyebrow-d, .eyebrow-w,
  h2 { page-break-after:avoid !important; break-after:avoid !important; }

  /* ══ TABLES ════════════════════════════════════════════════════════════
     table-layout:fixed + explicit column widths keeps all 6 columns on-page.
     break-all on td so domain names (no natural break point) wrap.        */
  .tbl-wrap { overflow:visible !important; }
  table {
    font-size:8.5px !important;
    table-layout:fixed !important;
    width:100% !important;
  }
  thead th {
    font-size:8px !important;
    padding:4px 5px !important;
    white-space:nowrap !important;
    overflow:hidden;
  }
  tbody td {
    padding:4px 5px !important;
    font-size:8.5px !important;
    word-break:break-all !important;
    overflow:hidden;
  }
  .mn { font-size:8px !important; word-break:break-all !important; }
  thead th:nth-child(1), tbody td:nth-child(1) { width:28%; }
  thead th:nth-child(2), tbody td:nth-child(2) { width:8%;  }
  thead th:nth-child(3), tbody td:nth-child(3) { width:9%;  }
  thead th:nth-child(4), tbody td:nth-child(4) { width:12%; }
  thead th:nth-child(5), tbody td:nth-child(5) { width:22%; }
  thead th:nth-child(6), tbody td:nth-child(6) { width:21%; }

  /* ══ ALERTS ════════════════════════════════════════════════════════════
     Hide emoji icons (render as fallback squares in PDF).                 */
  .al-icon { display:none !important; }
  .alert[style*="flex-direction:column"],
  .alert[style*="flex-direction: column"] {
    flex-direction:column !important;
    gap:6px !important;
  }
  .alert span[style*="border-radius:4px"] { display:inline-block !important; }

  /* ══ ACTION PLAN ════════════════════════════════════════════════════════
     inline display:flex;flex-direction:column on the items wrapper causes
     a large blank region in WeasyPrint. display:block !important wins over
     a non-!important inline style and collapses the gap.
     Inner per-item row divs (display:flex;align-items:flex-start) keep
     their own layout — only the outer column wrapper is changed.          */
  #grc-plan div[style*="flex-direction:column"] {
    display:block !important;
  }
  #grc-plan div[style*="flex-direction:column"] > div {
    margin-bottom:8px !important;
    page-break-inside:avoid;
  }
  #grc-plan h2         { page-break-after:avoid !important; break-after:avoid !important; }
  #grc-plan > p        { page-break-after:avoid !important; break-after:avoid !important; }
  #grc-plan .eyebrow-w { page-break-after:avoid !important; break-after:avoid !important; }

  /* ══ TEASER-SPECIFIC ════════════════════════════════════════════════════
     The teaser is a self-contained HTML file with its own stylesheet.
     The fixes above mostly carry over; these additions are teaser-only.

     1. .cta-section: dark navy CTA block (not in full report) needs exact
        colour printing or it renders as transparent/white.
     2. .cta-orb: decorative radial gradient — hide it (WeasyPrint may
        render it as a large filled circle instead of a soft orb).
     3. .main: the teaser uses max-width:1100px + padding-bottom:80px which
        adds blank space at the bottom of an A4 page.
     4. Grade bars: .grade-fill { height:100% } has the same WeasyPrint
        issue as .pr-fill — replace with an explicit px height.
     5. .stat-card.amber-hi: teaser-only variant, needs colour printing.   */
  .cta-section { overflow:hidden !important; }
  .cta-orb { display:none !important; }
  .main { max-width:none !important; padding:0 !important; }
  .stat-card.amber-hi { -webkit-print-color-adjust:exact !important; }
  .grade-fill { height:10px !important; min-width:2px; }
  .grade-bar  { min-height:10px !important; overflow:hidden !important; }
  .grade-row  { page-break-inside:avoid !important; break-inside:avoid !important; }

}
</style>
"""


# ---------------------------------------------------------------------------
# SR-1  Path traversal
# ---------------------------------------------------------------------------

def safe_path(raw: Path, allowed_dir: Path) -> Path:
    """Resolve path and verify it stays within allowed_dir."""
    resolved = raw.resolve()
    try:
        resolved.relative_to(allowed_dir.resolve())
        return resolved
    except ValueError:
        raise PathTraversalError(f"Path outside allowed directory: {raw!r}")


# ---------------------------------------------------------------------------
# SR-3  Size limits
# ---------------------------------------------------------------------------

def check_size(path: Path, limit: int, label: str) -> None:
    size = path.stat().st_size
    if size == 0:
        raise ValidationError(f"{label} is empty: {path}")
    if size > limit:
        raise FileTooLargeError(f"{label} too large ({size:,} bytes): {path}")


# ---------------------------------------------------------------------------
# SR-4  File type validation (magic bytes — no external lib required)
# ---------------------------------------------------------------------------

def validate_html_file(path: Path) -> None:
    header = path.read_bytes()[:512].lower()
    if b"<!doctype" not in header and b"<html" not in header:
        raise InvalidFileTypeError(
            f"Expected HTML, file does not look like HTML: {path}"
        )


def validate_pdf_output(path: Path) -> None:
    magic = path.read_bytes()[:4]
    if magic != b"%PDF":
        raise ValidationError(
            f"Output is not a valid PDF (bad magic bytes): {path}"
        )


# ---------------------------------------------------------------------------
# SR-6  Secure temp directory
# ---------------------------------------------------------------------------

@contextlib.contextmanager
def secure_tempdir() -> Generator[Path, None, None]:
    with tempfile.TemporaryDirectory(prefix="easm_pdf_") as tmpdir:
        yield Path(tmpdir)


# ---------------------------------------------------------------------------
# SR-8  Output filename sanitisation
# ---------------------------------------------------------------------------

def safe_filename(customer: str, teaser: bool = False) -> str:
    clean = re.sub(r"[^\w.\-]", "_", customer.strip())
    clean = clean.strip("._")
    if not clean:
        clean = "easm-report"
    suffix = "-veracode-easm-teaser" if teaser else "-veracode-easm-report"
    return f"{clean[:80]}{suffix}.pdf"


# ---------------------------------------------------------------------------
# Renderer detection
# ---------------------------------------------------------------------------

def detect_renderer() -> str:
    try:
        import weasyprint as _  # noqa: F401
        return "weasyprint"
    except ImportError:
        pass
    for name in ("chromium", "chromium-browser", "google-chrome"):
        if shutil.which(name):
            return "chromium"
    if shutil.which("wkhtmltopdf"):
        return "wkhtmltopdf"
    raise EasmReportError(
        "No PDF renderer found.\n"
        "Install WeasyPrint:  pipx inject easm-report weasyprint\n"
        "  (macOS: brew install pango cairo libffi first)"
    )


# ---------------------------------------------------------------------------
# HTML patching
# ---------------------------------------------------------------------------

def patch_html_for_print(html_path: Path) -> str:
    """Return patched HTML string with print CSS injected. Does not write to disk."""
    content = html_path.read_text(encoding="utf-8")
    if "</head>" not in content:
        raise ValidationError(
            "Input does not look like a valid HTML document (no </head> found)."
        )
    return content.replace("</head>", PRINT_PATCH + "\n</head>", 1)


# ---------------------------------------------------------------------------
# Renderers (SR-2: always list-form subprocess, SR-7: timeout=120)
# ---------------------------------------------------------------------------

def render_weasyprint(html_string: str, output_path: Path) -> None:
    try:
        from weasyprint import HTML as WeasyprintHTML  # type: ignore[import-untyped]
    except ImportError:
        raise EasmReportError(
            "WeasyPrint not installed. Run: pip install 'easm-report[pdf]'"
        )
    WeasyprintHTML(string=html_string).write_pdf(
        str(output_path),
        presentational_hints=True,
    )


def render_chromium(html_path: Path, output_path: Path) -> None:
    exe = next(
        (x for x in ("chromium", "chromium-browser", "google-chrome") if shutil.which(x)),
        None,
    )
    if exe is None:
        raise EasmReportError("Chromium not found")
    # SR-2: list form, no shell=True
    subprocess.run(
        [
            exe,
            "--headless=new",
            "--no-sandbox",
            "--disable-gpu",
            "--disable-dev-shm-usage",
            f"--print-to-pdf={output_path}",
            "--print-to-pdf-no-header",
            f"file://{html_path}",
        ],
        capture_output=True,
        text=True,
        timeout=120,   # SR-7
        check=True,
    )


def render_wkhtmltopdf(html_path: Path, output_path: Path) -> None:
    # SR-2: list form, no shell=True
    subprocess.run(
        [
            "wkhtmltopdf",
            "--no-stop-slow-scripts",
            "--enable-local-file-access",
            "--quiet",
            str(html_path),
            str(output_path),
        ],
        capture_output=True,
        text=True,
        timeout=120,   # SR-7
        check=True,
    )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def generate_pdf(
    html_path: Path,
    output_dir: Path,
    customer: str,
    teaser: bool = False,
) -> Path:
    """
    Convert an EASM HTML report to PDF.

    html_path must live inside output_dir (SR-1).
    Returns the path to the written PDF.
    """
    # SR-1: path traversal — html_path must be inside output_dir
    src = safe_path(html_path, output_dir)

    # SR-3: size check before reading
    check_size(src, MAX_INPUT_BYTES, "HTML input")

    # SR-4: magic bytes check
    validate_html_file(src)

    # SR-8: sanitised output filename
    out_name = safe_filename(customer, teaser=teaser)
    output_pdf = output_dir.resolve() / out_name

    renderer = detect_renderer()
    logger.debug("PDF renderer: %s → %s", renderer, output_pdf.name)

    patched_html = patch_html_for_print(src)

    if renderer == "weasyprint":
        # WeasyPrint can render from string directly — no temp file needed
        render_weasyprint(patched_html, output_pdf)
    else:
        # Chromium/wkhtmltopdf need a file:// path — SR-6: temp dir for intermediate file
        with secure_tempdir() as tmp:
            tmp_html = tmp / "report.html"
            tmp_html.write_text(patched_html, encoding="utf-8")
            if renderer == "chromium":
                render_chromium(tmp_html, output_pdf)
            else:
                render_wkhtmltopdf(tmp_html, output_pdf)

    # Output validation
    if not output_pdf.exists():
        raise EasmReportError(f"PDF was not created: {output_pdf}")
    check_size(output_pdf, MAX_OUTPUT_BYTES, "PDF output")
    validate_pdf_output(output_pdf)

    return output_pdf
