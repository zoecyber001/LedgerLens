"""Tests for JSON and PDF report generation."""

import json
from pathlib import Path

from ledgerlens.models import AuditReport
from ledgerlens.reporting.json_report import generate_json_report
from ledgerlens.reporting.pdf_report import generate_pdf_report


def test_generate_json_report(sample_audit_report: AuditReport, tmp_path: Path):
    json_path = generate_json_report(sample_audit_report, tmp_path)

    assert json_path.exists()
    assert json_path.name == "audit_summary.json"

    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data["metadata"]["tool"] == "LedgerLens"
    assert data["summary"]["total_files_scanned"] == 5
    assert len(data["findings"]) == 1
    assert data["findings"][0]["rule_id"] == "NDPA-001"


def test_generate_pdf_report(sample_audit_report: AuditReport, tmp_path: Path):
    pdf_path = generate_pdf_report(sample_audit_report, tmp_path)

    assert pdf_path.exists()
    assert pdf_path.name == "Compliance_Audit_Return.pdf"
    assert pdf_path.stat().st_size > 1000  # Non-trivial PDF generated
