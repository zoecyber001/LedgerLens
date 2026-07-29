from typing import List

from ledgerlens.models import FinancialFramework, RedactedContent, Finding, RiskTier
from ledgerlens.rules.base import ComplianceRule


class PlaintextBVNNINColumnRule(ComplianceRule):
    rule_id = "FIN-PII-001"
    rule_name = "Plaintext BVN/NIN Column Definition"
    framework = FinancialFramework.NDPA_2023_DB
    description = "Checks table columns named bvn, nin, national_id, bank_verification_number defined as unencrypted VARCHAR, TEXT, CHAR, INT, BIGINT."

    def evaluate(self, file: RedactedContent) -> List[Finding]:
        findings = []
        target_names = {"bvn", "nin", "national_id", "bank_verification_number"}
        bad_types = {"varchar", "text", "char", "int", "bigint"}
        for table in file.file.tables:
            for col in table.columns:
                if col.name.lower() in target_names:
                    dtype = col.data_type.lower()
                    if any(t in dtype for t in bad_types) and "bytea" not in dtype:
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            title=self.rule_name,
                            description=self.description,
                            framework=self.framework,
                            risk_tier=RiskTier.CRITICAL,
                            file_path=str(file.file.path),
                            table_name=table.name,
                            column_name=col.name,
                            remediation="Store BVN and NIN using column-level encryption (pgcrypto/AES-256 bytea) or irreversible cryptographic hash (HMAC-SHA256).",
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
        target_names = {"card_number", "card_pan", "pan", "cvv", "card_cvv"}
        bad_types = {"varchar", "text", "char", "int", "bigint"}
        for table in file.file.tables:
            for col in table.columns:
                if col.name.lower() in target_names:
                    dtype = col.data_type.lower()
                    if any(t in dtype for t in bad_types):
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            title=self.rule_name,
                            description=self.description,
                            framework=self.framework,
                            risk_tier=RiskTier.CRITICAL,
                            file_path=str(file.file.path),
                            table_name=table.name,
                            column_name=col.name,
                            remediation="Never store raw Card PAN or CVV in database tables. Use tokenization via PCI-DSS compliant payment gateway.",
                            reference="NDPA 2023 S.29 & PCI-DSS v4.0 Requirements"
                        ))
        return findings
