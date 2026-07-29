"""Automated SQL Remediation & Schema Rewriter for LedgerLens v2.0."""

import re
from pathlib import Path
from typing import List

from ledgerlens.models import AuditReport, Finding


def generate_remediation_sql(report: AuditReport, output_dir: Path) -> Path:
    """Generates remediation.sql (migration script) and schema.fixed.sql (inline patched schema).

    Args:
        report: The AuditReport containing findings.
        output_dir: Output directory path.

    Returns:
        Path to generated remediation.sql script.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    patch_path = output_dir / "remediation.sql"
    fixed_path = output_dir / "schema.fixed.sql"

    sql_statements: List[str] = [
        "-- ====================================================================",
        "-- LedgerLens v2.0 — Automated SQL Remediation Script",
        f"-- Target: {report.target.root_path}",
        f"-- Fingerprint: {report.target.fingerprint}",
        f"-- Total Findings: {len(report.findings)}",
        "-- ====================================================================\n",
    ]

    for finding in report.findings:
        sql_statements.append(f"-- [{finding.rule_id}] {finding.title}")
        sql_statements.append(f"-- Risk: {finding.risk_tier.value} | Table: {finding.table_name or 'N/A'}")
        table = finding.table_name or "target_table"

        if finding.rule_id == "FIN-DE-001":
            sql_statements.append(f"ALTER TABLE {table} ADD CONSTRAINT chk_{table}_balance_non_negative CHECK (debit >= 0 AND credit >= 0);\n")
        elif finding.rule_id == "FIN-DE-002":
            sql_statements.append(f"-- WARNING: Remove ON DELETE CASCADE from {table} foreign keys.\n")
        elif finding.rule_id == "FIN-PII-001":
            sql_statements.append(f"ALTER TABLE {table} ADD COLUMN bvn_encrypted BYTEA;\n")
        elif finding.rule_id == "FIN-PII-002":
            sql_statements.append(f"-- Replace raw Card PAN/CVV on {table} with gateway tokens.\n")
        elif finding.rule_id == "FIN-IMM-001":
            sql_statements.append(f"CREATE OR REPLACE FUNCTION prevent_{table}_modification()\nRETURNS TRIGGER AS $$\nBEGIN\n    RAISE EXCEPTION 'Financial ledger tables are immutable. UPDATE/DELETE operations prohibited.';\nEND;\n$$ LANGUAGE plpgsql;\n")
            sql_statements.append(f"CREATE TRIGGER trg_prevent_mod_{table}\nBEFORE UPDATE OR DELETE ON {table}\nFOR EACH ROW EXECUTE FUNCTION prevent_{table}_modification();\n")
        elif finding.rule_id == "FIN-IMM-002":
            sql_statements.append(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP;\n")
        elif finding.rule_id == "FIN-CBN-001":
            sql_statements.append(f"CREATE TABLE IF NOT EXISTS audit_log (\n    id BIGSERIAL PRIMARY KEY,\n    table_name VARCHAR(100) NOT NULL,\n    operation VARCHAR(20) NOT NULL,\n    record_id VARCHAR(100),\n    old_data JSONB,\n    new_data JSONB,\n    performed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP\n);\n")

    with open(patch_path, "w", encoding="utf-8") as f:
        f.write("\n".join(sql_statements))

    # Generate inline merged fixed schema file (schema.fixed.sql)
    _generate_inline_fixed_schema(report, fixed_path)

    return patch_path


def _generate_inline_fixed_schema(report: AuditReport, output_path: Path) -> None:
    """Reads target schema files and writes an inline patched schema.fixed.sql for instant diffing."""
    lines: List[str] = [
        "-- ====================================================================",
        "-- LedgerLens v2.0 — Inline Remediated Database Schema (schema.fixed.sql)",
        "-- ====================================================================\n",
    ]

    rules_by_table = {}
    for f in report.findings:
        if f.table_name:
            rules_by_table.setdefault(f.table_name, set()).add(f.rule_id)

    # Read original files and patch table DDLs directly
    schema_files = list(report.target.root_path.glob("**/*.sql"))
    if not schema_files:
        output_path.write_text("\n".join(lines) + "\n-- No .sql files found to rewrite.")
        return

    raw_text = "\n\n".join(f.read_text(encoding="utf-8", errors="ignore") for f in schema_files)

    # Patch table definitions inline
    for table_name, rule_ids in rules_by_table.items():
        pattern = re.compile(rf"(CREATE\s+TABLE\s+{table_name}\s*\((.*?)\);)", re.IGNORECASE | re.DOTALL)
        match = pattern.search(raw_text)
        if match:
            full_create, body = match.group(1), match.group(2)
            new_body = body

            if "FIN-PII-001" in rule_ids:
                new_body = re.sub(r"\bbvn\s+VARCHAR\(\d+\)", "bvn_encrypted BYTEA", new_body, flags=re.IGNORECASE)
                new_body = re.sub(r"\bnin\s+VARCHAR\(\d+\)", "nin_encrypted BYTEA", new_body, flags=re.IGNORECASE)

            if "FIN-IMM-002" in rule_ids and "created_at" not in new_body.lower():
                new_body += ",\n    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP"

            if "FIN-DE-001" in rule_ids and "CHECK" not in new_body.upper():
                new_body += f",\n    CONSTRAINT chk_{table_name}_balance CHECK (debit >= 0 AND credit >= 0)"

            patched_create = f"CREATE TABLE {table_name} ({new_body}\n);"
            raw_text = raw_text.replace(full_create, patched_create)

    lines.append(raw_text)

    # Append immutability triggers and audit tables
    lines.append("\n\n-- Remediation Triggers & Audit Tables")
    for table_name, rule_ids in rules_by_table.items():
        if "FIN-IMM-001" in rule_ids:
            lines.append(f"""
CREATE OR REPLACE FUNCTION prevent_{table_name}_modification()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Financial ledger tables are immutable. UPDATE/DELETE prohibited.';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_prevent_mod_{table_name}
BEFORE UPDATE OR DELETE ON {table_name}
FOR EACH ROW EXECUTE FUNCTION prevent_{table_name}_modification();""")

    lines.append("""
CREATE TABLE IF NOT EXISTS audit_log (
    id BIGSERIAL PRIMARY KEY,
    table_name VARCHAR(100) NOT NULL,
    operation VARCHAR(20) NOT NULL,
    record_id VARCHAR(100),
    old_data JSONB,
    new_data JSONB,
    performed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);""")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
