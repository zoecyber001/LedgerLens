from typing import List

from ledgerlens.engine.pii_classifier import PIIClassification, SemanticPIIClassifier
from ledgerlens.models import Finding, FinancialFramework, RedactedContent, RiskTier
from ledgerlens.rules.base import ComplianceRule


class PlaintextBVNNINColumnRule(ComplianceRule):
    rule_id = "FIN-PII-001"
    rule_name = "Plaintext BVN/NIN Column Definition"
    framework = FinancialFramework.NDPA_2023_DB
    description = "Checks table columns named bvn, nin, national_id, bank_verification_number defined as unencrypted VARCHAR, TEXT, CHAR, INT, BIGINT."

    def evaluate(self, file: RedactedContent) -> List[Finding]:
        findings = []
        for table in file.file.tables:
            for col in table.columns:
                analysis = SemanticPIIClassifier.analyze_column(col)
                if analysis.is_violation and analysis.classification == PIIClassification.UNENCRYPTED_BVN_NIN:
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        title=self.rule_name,
                        description=analysis.risk_reason,
                        framework=self.framework,
                        risk_tier=RiskTier.CRITICAL,
                        file_path=str(file.file.path),
                        table_name=table.name,
                        column_name=col.name,
                        remediation=analysis.remediation_hint,
                        reference="NDPA 2023 S.29 (Database PII Encryption)"
                    ))
        return findings


class PlaintextCardPANCVVRule(ComplianceRule):
    rule_id = "FIN-PII-002"
    rule_name = "Plaintext Card PAN / CVV Column Definition"
    framework = FinancialFramework.NDPA_2023_DB
    description = "Checks columns named card_number, card_pan, pan, cvv, card_cvv defined as plaintext VARCHAR/TEXT/INT."

    def evaluate(self, file: RedactedContent) -> List[Finding]:
        findings = []
        for table in file.file.tables:
            for col in table.columns:
                analysis = SemanticPIIClassifier.analyze_column(col)
                if analysis.is_violation and analysis.classification == PIIClassification.UNENCRYPTED_CARD_PAN:
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        title=self.rule_name,
                        description=analysis.risk_reason,
                        framework=self.framework,
                        risk_tier=RiskTier.CRITICAL,
                        file_path=str(file.file.path),
                        table_name=table.name,
                        column_name=col.name,
                        remediation=analysis.remediation_hint,
                        reference="NDPA 2023 S.29 & PCI-DSS v4.0 Requirements"
                    ))
        return findings
