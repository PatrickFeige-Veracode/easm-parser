"""CLI entrypoint for easm-report."""

from __future__ import annotations

import logging
import re
import sys
from pathlib import Path

import click

from easm_report.exceptions import EasmReportError
from easm_report.findings import detect_findings
from easm_report.parser import read_easm
from easm_report.pdf_writer import generate_pdf
from easm_report.renderer import render_report, render_teaser
from easm_report.validator import validate_output_path, validate_teaser_output_path


def find_file(directory: Path, pattern: str, label: str) -> Path:
    matches = list(directory.glob(pattern))
    if len(matches) == 1:
        return matches[0]
    if len(matches) == 0:
        raise FileNotFoundError(
            f"No {label} file found in {directory}/\n"
            f"Expected a file matching: {pattern}\n"
            f"Drop the xlsx export into {directory}/ and try again."
        )
    names = "\n  ".join(str(m.name) for m in matches)
    raise ValueError(
        f"Multiple {label} files found in {directory}/:\n  {names}\n"
        f"Remove the ones you don't want, or use --input-dir to point at a folder with one file."
    )


@click.command()
@click.option("--customer", required=True, help="Customer name (used in report header and filename)")
@click.option("--input-dir", default="inputs", show_default=True, type=click.Path(), help="Folder containing xlsx files")
@click.option("--output-dir", default="outputs", show_default=True, type=click.Path(), help="Folder for HTML output")
@click.option("--verbose", is_flag=True, default=False)
@click.option("--teaser", is_flag=True, default=False, help="Generate a single-page teaser instead of the full report")
@click.option("--pdf", is_flag=True, default=False, help="Also generate a PDF version of the report (requires weasyprint)")
@click.option("--seeds", default=None, type=str, help="Comma-separated seed domains, e.g. 'example.com,example.co.uk' (overrides auto-detection)")
def main(customer: str, input_dir: str, output_dir: str, verbose: bool, teaser: bool, pdf: bool, seeds: str | None) -> None:
    logging.basicConfig(level=logging.DEBUG if verbose else logging.WARNING)
    try:
        base_dir = Path.cwd()
        in_dir = Path(input_dir)
        safe_slug = re.sub(r"[^a-zA-Z0-9\-_]", "-", customer.strip())[:50].lower()
        out_dir = Path(output_dir) / safe_slug
        out_dir.mkdir(parents=True, exist_ok=True)

        if not in_dir.is_dir():
            raise FileNotFoundError(
                f"Input directory not found: {in_dir.resolve()}\n"
                f"Create it and drop your xlsx files in:\n"
                f"  mkdir -p {in_dir} && cd {in_dir}"
            )

        easm_path = find_file(in_dir, "*easm-extract*", "EASM extract")
        domain_path = find_file(in_dir, "*domain-things*", "domain-things")

        click.echo(f"Using: {easm_path.name}")
        click.echo(f"Using: {domain_path.name}")

        template_dir = Path(__file__).resolve().parent.parent.parent.parent / "templates"
        if not template_dir.exists():
            template_dir = base_dir / "templates"

        report_data, dataframes = read_easm(easm_path, domain_path, customer, base_dir, seeds=seeds)
        findings = detect_findings(report_data, dataframes)

        if teaser:
            output_path = validate_teaser_output_path(customer, out_dir)
            render_teaser(report_data, findings, template_dir, output_path)
            click.echo(f"\n✓  Teaser written: {output_path}")
            click.echo(
                f"   {report_data.total_apps} applications · {len(report_data.suppliers)} suppliers · top {min(3, len(findings))} findings shown"
            )
        else:
            output_path = validate_output_path(customer, out_dir)
            render_report(report_data, dataframes, findings, template_dir, output_path)
            click.echo(f"\n✓  Report written: {output_path}")
            click.echo(
                f"   {report_data.total_apps} applications · {len(findings)} findings · {len(report_data.suppliers)} suppliers"
            )

        if pdf:
            pdf_path = generate_pdf(output_path, out_dir, customer, teaser=teaser)
            click.echo(f"✓  PDF written:    {pdf_path}")

    except EasmReportError as e:
        click.echo(f"\nError: {e}", err=True)
        sys.exit(1)
    except FileNotFoundError as e:
        click.echo(f"\n{e}", err=True)
        sys.exit(1)
    except ValueError as e:
        click.echo(f"\n{e}", err=True)
        sys.exit(1)
