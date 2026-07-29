import json
from pathlib import Path

from ledgerlens.models import AuditReport

def generate_json_report(report: AuditReport, output_dir: Path) -> Path:
    """Generates a JSON audit report from an AuditReport instance.
    
    Args:
        report: The AuditReport instance to serialize.
        output_dir: The directory to write the JSON report to.
        
    Returns:
        The path to the generated JSON report.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / "audit_summary.json"
    
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report.to_dict(), f, indent=2)
        
    return report_path
