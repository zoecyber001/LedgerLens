"""Automated SQL Remediation Generator for LedgerLens v2.0."""

from pathlib import Path
from typing import List

from ledgerlens.models import AuditReport, Finding


def generate_remediation_sql(report: AuditReport, output_dir: Path) -> Path:
    """Generates executable remediation.sql script containing SQL DDL fixes for findings.

    Args:
        report: The AuditReport containing findings.
        output_dir: Output directory path.

    Returns:
        Path to generated remediation.sql script.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "remediation.sql"

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
        sql_statements.append(f"-- {finding.description}")

        table = finding.table_name or "target_table"

        if finding.rule_id == "FIN-DE-001":
            sql_statements.append(f"ALTER TABLE {table} ADD CONSTRAINT chk_{table}_balance_non_negative CHECK (debit >= 0 AND credit >= 0);\n")
        elif finding.rule_id == "FIN-DE-002":
            sql_statements.append(f"-- WARNING: Manual migration required. Replace ON DELETE CASCADE on {table} foreign keys with ON DELETE RESTRICT.\n")
        elif finding.rule_id == "FIN-PII-001":
            sql_statements.append(f"-- Encrypt plaintext BVN/NIN columns on table: {table}")
            sql_statements.append(f"ALTER TABLE {table} ADD COLUMN bvn_encrypted BYTEA;")
            sql_statements.append(f"-- UPDATE {table} SET bvn_encrypted = pgcrypto.pgp_sym_encrypt(bvn, 'YOUR-VAULT-KEY');")
            sql_statements.append(f"-- ALTER TABLE {table} DROP COLUMN bvn;\n")
        elif finding.rule_id == "FIN-PII-002":
            sql_statements.append(f"-- WARNING: Remove raw Card PAN/CVV from table: {table}")
            sql_statements.append(f"-- Replace raw card columns with gateway tokenization references.\n")
        elif finding.rule_id == "FIN-IMM-001":
            sql_statements.append(f"CREATE OR REPLACE FUNCTION prevent_{table}_modification()\nRETURNS TRIGGER AS $$\nBEGIN\n    RAISE EXCEPTION 'Financial ledger tables are immutable. UPDATE/DELETE operations prohibited.';\nEND;\n$$ LANGUAGE plpgsql;\n")
            sql_statements.append(f"CREATE TRIGGER trg_prevent_mod_{table}\nBEFORE UPDATE OR DELETE ON {table}\nFOR EACH ROW EXECUTE FUNCTION prevent_{table}_modification();\n")
        elif finding.rule_id == "FIN-IMM-002":
            sql_statements.append(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP;\n")
        elif finding.rule_id == "FIN-CBN-001":
            sql_statements.append(f"CREATE TABLE IF NOT EXISTS audit_log (\n    id BIGSERIAL PRIMARY KEY,\n    table_name VARCHAR(100) NOT NULL,\n    operation VARCHAR(20) NOT NULL,\n    record_id VARCHAR(100),\n    old_data JSONB,\n    new_data JSONB,\n    performed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP\n);\n")
        else:
            sql_statements.append(f"-- Remediation: {finding.remediation}\n")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(sql_statements))

    return output_path
