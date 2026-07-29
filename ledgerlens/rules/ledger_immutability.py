from typing import List

from ledgerlens.models import FinancialFramework, RedactedContent, Finding, RiskTier
from ledgerlens.rules.base import ComplianceRule


class MissingImmutabilityTriggersRule(ComplianceRule):
    rule_id = "FIN-IMM-001"
    rule_name = "Missing Immutability Triggers / Mutable Ledger"
    framework = FinancialFramework.CBN_E_PAYMENT
    description = "Checks if financial ledger tables (ledger, transaction, journal_entry, payment_log) lack triggers or policies preventing UPDATE or DELETE operations."

    def evaluate(self, file: RedactedContent) -> List[Finding]:
        findings = []
        for table in file.file.tables:
            if not table.is_ledger_table:
                continue
            has_trigger = any("update" in t.lower() or "delete" in t.lower() for t in table.triggers)
            if not has_trigger:
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.rule_name,
                    description=self.description,
                    framework=self.framework,
                    risk_tier=RiskTier.CRITICAL,
                    file_path=str(file.file.path),
                    table_name=table.name,
                    remediation="Implement BEFORE UPDATE OR DELETE triggers that raise exceptions to enforce append-only immutable ledgers.",
                    reference="CBN e-Payment Guidelines (PSPs/MMOs)"
                ))
        return findings


class MissingImmutableTimestampsRule(ComplianceRule):
    rule_id = "FIN-IMM-002"
    rule_name = "Missing Immutable Timestamps"
    framework = FinancialFramework.CBN_CYBERSECURITY
    description = "Checks if ledger tables lack created_at or timestamp default constraints (DEFAULT CURRENT_TIMESTAMP / DEFAULT NOW())."

    def evaluate(self, file: RedactedContent) -> List[Finding]:
        findings = []
        for table in file.file.tables:
            if not table.is_ledger_table:
                continue
            has_created_at = any(col.name.lower() in ("created_at", "created") for col in table.columns)
            if not has_created_at:
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.rule_name,
                    description=self.description,
                    framework=self.framework,
                    risk_tier=RiskTier.HIGH,
                    file_path=str(file.file.path),
                    table_name=table.name,
                    remediation="Add created_at timestamp column with DEFAULT CURRENT_TIMESTAMP constraint.",
                    reference="CBN Risk-Based Cybersecurity Framework"
                ))
        return findings
