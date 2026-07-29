from typing import List

from ledgerlens.models import FinancialFramework, RedactedContent, Finding, RiskTier
from ledgerlens.rules.base import ComplianceRule


class MissingAuditTrailLoggingRule(ComplianceRule):
    rule_id = "FIN-CBN-001"
    rule_name = "Missing Audit Trail Logging"
    framework = FinancialFramework.CBN_E_PAYMENT
    description = "Checks for missing audit log tables or CDC (Change Data Capture) configuration in database schema."

    def evaluate(self, file: RedactedContent) -> List[Finding]:
        findings = []
        has_audit_table = any("audit" in t.name.lower() or "log" in t.name.lower() for t in file.file.tables)
        has_ledger = any(t.is_ledger_table for t in file.file.tables)
        if has_ledger and not has_audit_table:
            findings.append(Finding(
                rule_id=self.rule_id,
                title=self.rule_name,
                description=self.description,
                framework=self.framework,
                risk_tier=RiskTier.HIGH,
                file_path=str(file.file.path),
                remediation="Configure dedicated audit_log table with trigger-based CDC for all balance mutations per CBN guidelines.",
                reference="CBN e-Payment Guidelines (PSPs/MMOs)"
            ))
        return findings


class InsecureDefaultDBUserPermissionsRule(ComplianceRule):
    rule_id = "FIN-CBN-002"
    rule_name = "Insecure Default DB User Permissions"
    framework = FinancialFramework.CBN_CYBERSECURITY
    description = "Checks for schema files executing as SUPERUSER or postgres / root application connections."

    def evaluate(self, file: RedactedContent) -> List[Finding]:
        findings = []
        raw = file.file.raw_content.lower()
        if "superuser" in raw or "postgres" in raw or "root" in raw:
            findings.append(Finding(
                rule_id=self.rule_id,
                title=self.rule_name,
                description=self.description,
                framework=self.framework,
                risk_tier=RiskTier.MEDIUM,
                file_path=str(file.file.path),
                remediation="Grant principle of least privilege. Application user must not hold SUPERUSER or DROP TABLE privileges.",
                reference="CBN Risk-Based Cybersecurity Framework"
            ))
        return findings


def get_rules() -> List[ComplianceRule]:
    from ledgerlens.rules.ledger_double_entry import (
        MissingDebitCreditBalanceConstraintRule,
        UnsafeCascadeDeleteRule
    )
    from ledgerlens.rules.ledger_pii_encryption import (
        PlaintextBVNNINColumnRule,
        PlaintextCardPANCVVRule
    )
    from ledgerlens.rules.ledger_immutability import (
        MissingImmutabilityTriggersRule,
        MissingImmutableTimestampsRule
    )

    return [
        MissingDebitCreditBalanceConstraintRule(),
        UnsafeCascadeDeleteRule(),
        PlaintextBVNNINColumnRule(),
        PlaintextCardPANCVVRule(),
        MissingImmutabilityTriggersRule(),
        MissingImmutableTimestampsRule(),
        MissingAuditTrailLoggingRule(),
        InsecureDefaultDBUserPermissionsRule()
    ]
