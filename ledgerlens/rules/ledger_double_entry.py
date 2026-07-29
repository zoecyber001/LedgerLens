from typing import List

from ledgerlens.models import FinancialFramework, RedactedContent, Finding, RiskTier
from ledgerlens.rules.base import ComplianceRule


class MissingDebitCreditBalanceConstraintRule(ComplianceRule):
    rule_id = "FIN-DE-001"
    rule_name = "Missing Debit/Credit Balance Constraint"
    framework = FinancialFramework.DOUBLE_ENTRY_STANDARD
    description = "Checks if a ledger/journal/transaction table lacks a CHECK constraint ensuring debits equal credits or balance invariants (amount != 0, balance >= 0, debit >= 0 AND credit >= 0)."

    def evaluate(self, file: RedactedContent) -> List[Finding]:
        findings = []
        for table in file.file.tables:
            if not table.is_ledger_table:
                continue
            has_check = any("check" in c.lower() for c in table.constraints)
            has_amount = any(c.name.lower() in ["amount", "balance", "debit", "credit"] for c in table.columns)
            if has_amount and not has_check:
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.rule_name,
                    description=self.description,
                    framework=self.framework,
                    risk_tier=RiskTier.CRITICAL,
                    file_path=str(file.file.path),
                    table_name=table.name,
                    remediation="Add database CHECK constraint or trigger enforcing debit/credit non-negative and zero-sum balance invariants.",
                    reference="GAAP / IFRS Double-Entry Invariant Standard"
                ))
        return findings


class UnsafeCascadeDeleteRule(ComplianceRule):
    rule_id = "FIN-DE-002"
    rule_name = "Unsafe Cascade Delete on Ledger Tables"
    framework = FinancialFramework.DOUBLE_ENTRY_STANDARD
    description = "Checks for ON DELETE CASCADE or ON UPDATE CASCADE on ledger, transaction, payment, or wallet foreign key references."

    def evaluate(self, file: RedactedContent) -> List[Finding]:
        findings = []
        raw_lower = file.redacted_text.lower()

        for table in file.file.tables:
            if not table.is_ledger_table:
                continue
            
            # Check constraints or raw file text for ON DELETE CASCADE
            has_cascade = any("cascade" in c.lower() for c in table.constraints) or "on delete cascade" in raw_lower or "on update cascade" in raw_lower
            if has_cascade:
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.rule_name,
                    description=self.description,
                    framework=self.framework,
                    risk_tier=RiskTier.CRITICAL,
                    file_path=str(file.file.path),
                    table_name=table.name,
                    remediation="Remove CASCADE delete/update on financial ledgers. Set ON DELETE RESTRICT or ON DELETE NO ACTION.",
                    reference="GAAP / IFRS Double-Entry Invariant Standard & CBN Guidelines"
                ))
        return findings
