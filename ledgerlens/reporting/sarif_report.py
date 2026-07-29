"""SARIF (Static Analysis Results Interchange Format) v2.1.0 report generator for LedgerLens."""

import json
from pathlib import Path

from ledgerlens.models import AuditReport, RiskTier


def _risk_tier_to_sarif_level(tier: RiskTier) -> str:
    """Map LedgerLens RiskTier to SARIF notification level."""
    if tier in (RiskTier.CRITICAL, RiskTier.HIGH):
        return "error"
    elif tier == RiskTier.MEDIUM:
        return "warning"
    return "note"


def generate_sarif_report(report: AuditReport, output_dir: Path) -> Path:
    """Generate a SARIF v2.1.0 audit file for IDE & CI/CD integration (GitHub Security / VS Code).

    Args:
        report: The complete AuditReport model.
        output_dir: Output directory path.

    Returns:
        Path to the generated SARIF file.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "ledgerlens_audit.sarif"

    rules_meta = []
    results = []

    seen_rules = set()

    for finding in report.findings:
        if finding.rule_id not in seen_rules:
            seen_rules.add(finding.rule_id)
            rules_meta.append({
                "id": finding.rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.description},
                "help": {
                    "text": f"Remediation: {finding.remediation}\nReference: {finding.reference}"
                },
                "properties": {
                    "tags": ["compliance", "financial-ledger", finding.framework.value],
                    "precision": "high"
                }
            })

        results.append({
            "ruleId": finding.rule_id,
            "level": _risk_tier_to_sarif_level(finding.risk_tier),
            "message": {
                "text": f"{finding.description} (Table: {finding.table_name or 'N/A'})"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.file_path
                        },
                        "region": {
                            "startLine": finding.line_number or 1
                        }
                    }
                }
            ]
        })

    sarif_log = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "LedgerLens",
                        "version": "2.0.0",
                        "informationUri": "https://github.com/zoecyber001/LedgerLens",
                        "rules": rules_meta
                    }
                },
                "results": results
            }
        ]
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sarif_log, f, indent=2)

    return output_path
