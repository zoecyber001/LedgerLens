"""LedgerLens CLI command line interface."""

from __future__ import annotations

import logging
import sys
import time
from pathlib import Path

import click

from ledgerlens import __version__
from ledgerlens.models import AuditReport, SchemaTarget


def _configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stderr,
    )


@click.group()
@click.version_option(version=__version__, prog_name="LedgerLens")
def main() -> None:
    """LedgerLens — Financial Ledger & DB Integrity Audit Engine."""


@main.command(name="audit-ledger")
@click.argument("target", type=click.Path(exists=True))
@click.option(
    "--output", "-o",
    type=click.Path(),
    default=".",
    help="Output directory for generated compliance reports.",
    show_default=True,
)
@click.option(
    "--format", "-f",
    "output_formats",
    type=click.Choice(["json", "pdf", "html", "sarif", "zk", "all"], case_sensitive=False),
    default="all",
    help="Report output format.",
    show_default=True,
)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose diagnostic output.")
def audit_ledger(target: str, output: str, output_formats: str, verbose: bool) -> None:
    """Audit database schemas and migrations for financial ledger integrity."""
    _configure_logging(verbose)
    log = logging.getLogger("ledgerlens")

    target_path = Path(target).resolve()
    output_dir = Path(output).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    click.echo()
    click.secho("+--------------------------------------------------------------+", fg="cyan", bold=True)
    click.secho("|       LedgerLens v2.0 - Financial Ledger Audit Engine        |", fg="cyan", bold=True)
    click.secho("|     CBN e-Payment Guidelines + NDPA 2023 DB Integrity        |", fg="cyan", bold=True)
    click.secho("+--------------------------------------------------------------+", fg="cyan", bold=True)
    click.echo()

    t_start = time.perf_counter()
    schema_target = SchemaTarget(root_path=target_path)

    click.secho(f"  Target path: {target_path}", fg="yellow")

    report = _run_financial_audit_pipeline(schema_target, output_dir, output_formats, log)

    elapsed = time.perf_counter() - t_start
    _print_summary(report, elapsed)


@main.command(name="scan")
@click.argument("target", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), default=".", help="Output directory.")
@click.option("--format", "-f", "output_formats", type=click.Choice(["json", "pdf", "html", "sarif", "zk", "all"]), default="all")
@click.option("--verbose", "-v", is_flag=True, help="Verbose diagnostic output.")
@click.pass_context
def scan(ctx: click.Context, target: str, output: str, output_formats: str, verbose: bool) -> None:
    """Alias for audit-ledger command."""
    ctx.invoke(audit_ledger, target=target, output=output, output_formats=output_formats, verbose=verbose)


@main.command(name="fix")
@click.argument("target", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), default=".", help="Output directory for remediation.sql.")
@click.option("--verbose", "-v", is_flag=True, help="Verbose diagnostic output.")
def fix(target: str, output: str, verbose: bool) -> None:
    """Generate executable SQL remediation scripts (remediation.sql) for audit findings."""
    _configure_logging(verbose)
    log = logging.getLogger("ledgerlens")

    target_path = Path(target).resolve()
    output_dir = Path(output).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    schema_target = SchemaTarget(root_path=target_path)
    report = _run_financial_audit_pipeline(schema_target, output_dir, "json", log)

    from ledgerlens.remediation.fixer import generate_remediation_sql
    fix_path = generate_remediation_sql(report, output_dir)

    click.echo()
    click.secho(f"  [+] Automated remediation script generated: {fix_path}", fg="green", bold=True)
    click.echo()


def _run_financial_audit_pipeline(
    target: SchemaTarget,
    output_dir: Path,
    output_formats: str,
    log: logging.Logger,
) -> AuditReport:
    from ledgerlens.ingestion.discovery import discover_schema_files
    from ledgerlens.ingestion.sql_parser import parse_schema_file
    from ledgerlens.redaction.engine import redact_schema_files
    from ledgerlens.rules.base import RuleRegistry

    click.secho("\n  [Phase 1] Schema Ingestion & SQL AST Parsing...", fg="white")
    discovered_files = list(discover_schema_files(target.root_path))
    parsed_files = [parse_schema_file(f) for f in discovered_files]

    total_tables = sum(len(f.tables) for f in parsed_files)
    total_ledger_tables = sum(1 for f in parsed_files for t in f.tables if t.is_ledger_table)

    click.secho(f"  [+] Discovered {len(parsed_files)} schema files ({total_tables} tables, {total_ledger_tables} financial ledger tables)", fg="green")

    click.secho("  [Phase 2] Secret & PII Redaction...", fg="white")
    redacted_files = list(redact_schema_files(parsed_files))
    total_secrets = sum(rf.secret_count for rf in redacted_files)
    click.secho(f"  [+] Scrubbed {total_secrets} credentials/PII tokens in memory", fg="green")

    click.secho("  [Phase 3] Financial & DB Integrity Evaluation...", fg="white")
    registry = RuleRegistry()
    from ledgerlens.rules.cbn_financial import get_rules as get_all_financial_rules
    for rule in get_all_financial_rules():
        registry.register(rule)

    rule_results = registry.run_all(redacted_files)
    all_findings = [f for rr in rule_results for f in rr.findings]
    click.secho(f"  [+] Evaluated {len(registry.rules)} financial integrity rules, found {len(all_findings)} findings", fg="green")

    report = AuditReport(
        target=target,
        total_files_scanned=len(parsed_files),
        total_tables_audited=total_tables,
        total_ledger_tables_found=total_ledger_tables,
        total_secrets_redacted=total_secrets,
        findings=all_findings,
        rule_results=rule_results,
    )

    click.secho("  [Phase 4] Report Generation...", fg="white")
    if output_formats in ("json", "all"):
        from ledgerlens.reporting.json_report import generate_json_report
        j_path = generate_json_report(report, output_dir)
        click.secho(f"  [+] JSON audit return:      {j_path}", fg="green")

    if output_formats in ("pdf", "all"):
        from ledgerlens.reporting.pdf_report import generate_pdf_report
        p_path = generate_pdf_report(report, output_dir)
        click.secho(f"  [+] PDF audit return:      {p_path}", fg="green")

    if output_formats in ("html", "all"):
        from ledgerlens.reporting.html_report import generate_html_report
        h_path = generate_html_report(report, output_dir)
        click.secho(f"  [+] HTML Audit Dashboard:  {h_path}", fg="green")

    if output_formats in ("sarif", "all"):
        from ledgerlens.reporting.sarif_report import generate_sarif_report
        s_path = generate_sarif_report(report, output_dir)
        click.secho(f"  [+] SARIF Audit Log:       {s_path}", fg="green")

    if output_formats in ("zk", "all"):
        from ledgerlens.engine.zk_proof import ZKProofGenerator
        zk_path = ZKProofGenerator.generate_proof(report, output_dir)
        click.secho(f"  [+] ZK Compliance Proof:   {zk_path}", fg="green")

    return report


def _print_summary(report: AuditReport, elapsed: float) -> None:
    click.echo()
    click.secho("  --- Financial Audit Summary ---", fg="cyan", bold=True)
    click.echo()

    tier_colors = {
        "CRITICAL": "red",
        "HIGH": "yellow",
        "MEDIUM": "blue",
        "LOW": "white",
    }
    for tier_name, count in report.risk_summary.items():
        color = tier_colors.get(tier_name, "white")
        marker = "[*]" if count > 0 else "[ ]"
        click.secho(f"    {marker} {tier_name:<10} {count}", fg=color, bold=count > 0)

    click.echo()
    click.echo(f"    Files scanned:         {report.total_files_scanned}")
    click.echo(f"    Tables audited:        {report.total_tables_audited}")
    click.echo(f"    Ledger tables found:   {report.total_ledger_tables_found}")
    click.echo(f"    Secrets redacted:      {report.total_secrets_redacted}")
    click.echo(f"    Compliance score:      {report.compliance_score}%")

    overall = report.overall_risk_tier.value
    overall_color = tier_colors.get(overall, "white")
    click.secho(f"    Overall risk tier:     {overall}", fg=overall_color, bold=True)

    click.echo()
    click.secho(f"    Completed in {elapsed:.2f}s", fg="cyan")
    click.echo()


if __name__ == "__main__":
    main()
