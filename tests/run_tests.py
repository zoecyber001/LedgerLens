"""Test suite runner for LedgerLens v2.0 — Financial Ledger & DB Integrity Audit Engine."""

import json
import tempfile
import unittest
from pathlib import Path

from ledgerlens.ingestion.discovery import discover_schema_files
from ledgerlens.ingestion.sql_parser import parse_schema_file
from ledgerlens.models import (
    AuditReport,
    DBEngineType,
    FinancialFramework,
    Finding,
    RiskTier,
    RuleResult,
    SchemaTarget,
)
from ledgerlens.redaction.engine import redact_schema_file
from ledgerlens.reporting.json_report import generate_json_report
from ledgerlens.reporting.pdf_report import generate_pdf_report
from ledgerlens.rules.base import RuleRegistry
from ledgerlens.rules.cbn_financial import get_rules as get_all_financial_rules


SAMPLE_SQL_SCHEMA = """\
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    bvn VARCHAR(11), -- Plaintext BVN column risk
    nin VARCHAR(11), -- Plaintext NIN column risk
    card_pan VARCHAR(16) -- Plaintext Card PAN risk
);

CREATE TABLE ledger_entries (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id) ON DELETE CASCADE, -- Unsafe cascade delete risk
    account_id INT NOT NULL,
    debit_amount DECIMAL(15,2),
    credit_amount DECIMAL(15,2),
    balance DECIMAL(15,2)
    -- Missing CHECK constraint for debit/credit balance
    -- Missing BEFORE UPDATE OR DELETE trigger for immutability
);

CREATE TABLE transaction_logs (
    id SERIAL PRIMARY KEY,
    amount DECIMAL(15,2),
    status VARCHAR(50)
    -- Missing created_at timestamp
);
"""

SAMPLE_PRISMA_SCHEMA = """\
datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

model WalletLedger {
  id        String   @id @default(uuid())
  walletId  String
  debit     Float
  credit    Float
  balance   Float
}

model Customer {
  id      String @id
  bvn     String
  cardPan String
}
"""


class TestFinancialLedgerIngestion(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp_dir.name)

        (self.tmp_path / "schema.sql").write_text(SAMPLE_SQL_SCHEMA)
        (self.tmp_path / "schema.prisma").write_text(SAMPLE_PRISMA_SCHEMA)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_schema_discovery_and_parsing(self):
        discovered = list(discover_schema_files(self.tmp_path))
        self.assertEqual(len(discovered), 2)

        parsed_files = [parse_schema_file(f) for f in discovered]
        table_names = {t.name for f in parsed_files for t in f.tables}
        self.assertIn("users", table_names)
        self.assertIn("ledger_entries", table_names)
        self.assertIn("transaction_logs", table_names)
        self.assertIn("WalletLedger", table_names)

        ledger_tables = [t for f in parsed_files for t in f.tables if t.is_ledger_table]
        self.assertTrue(len(ledger_tables) >= 2)


class TestFinancialRedaction(unittest.TestCase):

    def test_pii_redaction(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp_dir.name)
        schema_file = self.tmp_path / "seed.sql"
        content = "INSERT INTO users (bvn, nin) VALUES ('22233344455', '11122233344');"
        schema_file.write_text(content)

        discovered = list(discover_schema_files(self.tmp_path))[0]
        redacted = redact_schema_file(discovered)

        self.assertIn("[REDACTED:", redacted.redacted_text)
        self.assertNotIn("22233344455", redacted.redacted_text)
        self.assertNotIn("11122233344", redacted.redacted_text)
        self.tmp_dir.cleanup()


class TestFinancialComplianceRules(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp_dir.name)
        (self.tmp_path / "schema.sql").write_text(SAMPLE_SQL_SCHEMA)
        discovered = list(discover_schema_files(self.tmp_path))[0]
        parsed = parse_schema_file(discovered)
        self.redacted = redact_schema_file(parsed)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_financial_rules_evaluation(self):
        registry = RuleRegistry()
        from ledgerlens.rules.cbn_financial import get_rules as get_all_financial_rules
        for r in get_all_financial_rules():
            registry.register(r)

        results = registry.run_all([self.redacted])
        all_findings = [f for rr in results for f in rr.findings]
        rule_ids = {f.rule_id for f in all_findings}

        self.assertIn("FIN-DE-001", rule_ids)   # Missing Debit/Credit Balance Constraint
        self.assertIn("FIN-DE-002", rule_ids)   # Unsafe Cascade Delete
        self.assertIn("FIN-PII-001", rule_ids)  # Plaintext BVN/NIN Column
        self.assertIn("FIN-PII-002", rule_ids)  # Plaintext Card PAN Column
        self.assertIn("FIN-IMM-001", rule_ids)  # Missing Immutability Trigger
        self.assertIn("FIN-IMM-002", rule_ids)  # Missing Immutable Timestamp


class TestFinancialReporting(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.out_path = Path(self.tmp_dir.name)

        target = SchemaTarget(root_path=Path("/tmp/sample_fin_db"))
        finding = Finding(
            rule_id="FIN-DE-001",
            title="Missing Debit/Credit Balance Constraint",
            description="Ledger table lacks balance invariant constraint.",
            framework=FinancialFramework.DOUBLE_ENTRY_STANDARD,
            risk_tier=RiskTier.CRITICAL,
            file_path="schema.sql",
            table_name="ledger_entries",
            remediation="Add CHECK constraint enforcing debit/credit non-negative balance invariants.",
            reference="GAAP / IFRS Double-Entry Invariant Standard",
        )
        self.report = AuditReport(
            target=target,
            total_files_scanned=1,
            total_tables_audited=3,
            total_ledger_tables_found=1,
            total_secrets_redacted=2,
            findings=[finding],
            rule_results=[RuleResult(rule_id="FIN-DE-001", rule_name="Debit/Credit", framework=FinancialFramework.DOUBLE_ENTRY_STANDARD, passed=False, findings=[finding])],
        )

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_json_report(self):
        j_file = generate_json_report(self.report, self.out_path)
        self.assertTrue(j_file.exists())
        data = json.loads(j_file.read_text())
        self.assertEqual(data["summary"]["total_tables_audited"], 3)

    def test_pdf_report(self):
        p_file = generate_pdf_report(self.report, self.out_path)
        self.assertTrue(p_file.exists())
        self.assertGreater(p_file.stat().st_size, 1000)

    def test_html_report(self):
        from ledgerlens.reporting.html_report import generate_html_report
        h_file = generate_html_report(self.report, self.out_path)
        self.assertTrue(h_file.exists())
        self.assertIn("LedgerLens Financial Audit Return", h_file.read_text())

    def test_sarif_report(self):
        from ledgerlens.reporting.sarif_report import generate_sarif_report
        s_file = generate_sarif_report(self.report, self.out_path)
        self.assertTrue(s_file.exists())
        data = json.loads(s_file.read_text())
        self.assertEqual(data["version"], "2.1.0")

    def test_remediation_sql(self):
        from ledgerlens.remediation.fixer import generate_remediation_sql
        f_file = generate_remediation_sql(self.report, self.out_path)
        self.assertTrue(f_file.exists())
        self.assertIn("ALTER TABLE ledger_entries", f_file.read_text())

    def test_zk_compliance_proof(self):
        from ledgerlens.engine.zk_proof import ZKProofGenerator
        zk_file = ZKProofGenerator.generate_proof(self.report, self.out_path)
        self.assertTrue(zk_file.exists())
        data = json.loads(zk_file.read_text())
        self.assertIn("zk_proof_version", data)
        self.assertIn("merkle_root", data)
        self.assertIn("zero_knowledge_verifier_hash", data)

    def test_formal_verifier(self):
        from ledgerlens.engine.formal_verifier import SymbolicLedgerVerifier
        from ledgerlens.models import TableDef, ColumnDef
        table = TableDef(
            name="ledger_entries",
            columns=[ColumnDef("debit", "DECIMAL"), ColumnDef("credit", "DECIMAL")],
            constraints=[],
            is_ledger_table=True
        )
        res = SymbolicLedgerVerifier.verify_table_invariants(table)
        self.assertFalse(res.is_mathematically_sound)

    def test_ast_parser(self):
        from ledgerlens.ingestion.ast_parser import parse_sql_ast
        from ledgerlens.models import ScannedSchemaFile, DBEngineType
        scanned = ScannedSchemaFile(
            path=Path("schema.sql"),
            relative_path="schema.sql",
            engine_type=DBEngineType.POSTGRESQL,
            raw_content="CREATE TABLE wallets (id INT PRIMARY KEY, balance DECIMAL(15,2));"
        )
        parsed = parse_sql_ast(scanned)
        self.assertEqual(len(parsed.tables), 1)
        self.assertEqual(parsed.tables[0].name, "wallets")

    def test_semantic_pii_classifier(self):
        from ledgerlens.engine.pii_classifier import SemanticPIIClassifier, PIIClassification
        from ledgerlens.models import ColumnDef
        col_plain = ColumnDef("bvn", "VARCHAR(11)")
        res1 = SemanticPIIClassifier.analyze_column(col_plain)
        self.assertTrue(res1.is_violation)
        self.assertEqual(res1.classification, PIIClassification.UNENCRYPTED_BVN_NIN)

        col_enc = ColumnDef("bvn_encrypted", "BYTEA")
        res2 = SemanticPIIClassifier.analyze_column(col_enc)
        self.assertFalse(res2.is_violation)
        self.assertEqual(res2.classification, PIIClassification.SECURE_ENCRYPTED_PII)


if __name__ == "__main__":
    unittest.main()
