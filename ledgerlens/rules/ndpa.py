import re
from typing import List

from ledgerlens.models import ComplianceFramework, Finding, RedactedContent, RiskTier
from ledgerlens.rules.base import ComplianceRule


class NDPA001(ComplianceRule):
    rule_id = "NDPA-001"
    rule_name = "Transport Layer Encryption"
    framework = ComplianceFramework.NDPA_2023
    description = "Checks for unencrypted database connections and HTTP endpoints."
    
    def evaluate(self, file: RedactedContent) -> List[Finding]:
        findings = []
        content = file.redacted_text.lower()
        lines = content.splitlines()

        # Build map of line numbers with database URI redactions
        db_hit_lines = {
            hit.line_number for hit in file.hits
            if hit.category.name == "DATABASE_URI" or "DATABASE" in hit.category.name
        }

        for i, line in enumerate(lines):
            line_num = i + 1

            # Check for explicitly disabled SSL
            if "ssl=false" in line or "ssl=off" in line:
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.rule_name,
                    description="Disabled SSL detected.",
                    framework=self.framework,
                    risk_tier=RiskTier.CRITICAL,
                    file_path=file.file.relative_path,
                    line_number=line_num,
                    remediation="Enforce TLS/SSL on all database connections and API endpoints. Set sslmode=require or sslmode=verify-full.",
                    reference="NDPA 2023 S.29"
                ))

            # Check for HTTP URLs
            if "http://" in line and "localhost" not in line and "127.0.0.1" not in line:
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.rule_name,
                    description="HTTP URL detected. Use HTTPS.",
                    framework=self.framework,
                    risk_tier=RiskTier.CRITICAL,
                    file_path=file.file.relative_path,
                    line_number=line_num,
                    remediation="Enforce TLS/SSL on all database connections and API endpoints. Set sslmode=require or sslmode=verify-full.",
                    reference="NDPA 2023 S.29"
                ))

            # Check DB strings or redacted DB URIs for missing sslmode
            is_db_line = (
                line_num in db_hit_lines
                or "[redacted:" in line
                or any(db in line for db in ["postgres", "mysql", "mongodb", "database_url", "db_url"])
            )
            if is_db_line:
                if "sslmode=require" not in line and "sslmode=verify-full" not in line and "ssl=true" not in line:
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        title=self.rule_name,
                        description="Database connection missing SSL requirement.",
                        framework=self.framework,
                        risk_tier=RiskTier.CRITICAL,
                        file_path=file.file.relative_path,
                        line_number=line_num,
                        remediation="Enforce TLS/SSL on all database connections and API endpoints. Set sslmode=require or sslmode=verify-full.",
                        reference="NDPA 2023 S.29"
                    ))
        return findings


class NDPA002(ComplianceRule):
    rule_id = "NDPA-002"
    rule_name = "Data-at-Rest Encryption"
    framework = ComplianceFramework.NDPA_2023
    description = "Checks for disabled encryption-at-rest."
    
    def evaluate(self, file: RedactedContent) -> List[Finding]:
        findings = []
        lines = file.redacted_text.lower().splitlines()

        pattern = re.compile(r"(encrypt|encryption|encrypted)\s*[:=]\s*(false|none|off)")

        for i, line in enumerate(lines):
            if pattern.search(line):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.rule_name,
                    description="Data-at-rest encryption explicitly disabled.",
                    framework=self.framework,
                    risk_tier=RiskTier.HIGH,
                    file_path=file.file.relative_path,
                    line_number=i + 1,
                    remediation="Enable encryption at rest for all data stores. Use AES-256 or equivalent.",
                    reference="NDPA 2023 S.29"
                ))
        return findings


class NDPA003(ComplianceRule):
    rule_id = "NDPA-003"
    rule_name = "PII Exposure in Static Config"
    framework = ComplianceFramework.NDPA_2023
    description = "Checks for PII (email, phone, BVN, NIN, names) in configs or seed data."
    
    def evaluate(self, file: RedactedContent) -> List[Finding]:
        findings = []
        lines = file.redacted_text.splitlines()
        
        email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
        # Basic 11 digit pattern for BVN and NIN
        digits_11_pattern = re.compile(r'\b\d{11}\b')
        nigerian_names = ["chukwu", "ade", "okafor", "abubakar", "chioma", "sani"]

        for i, line in enumerate(lines):
            has_pii = False
            if email_pattern.search(line) or digits_11_pattern.search(line):
                has_pii = True
            
            line_lower = line.lower()
            if any(name in line_lower for name in nigerian_names) and ("seed" in file.file.relative_path.lower() or "test" in file.file.relative_path.lower()):
                has_pii = True
                
            if has_pii:
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.rule_name,
                    description="PII (Email, BVN, NIN, or Name) detected.",
                    framework=self.framework,
                    risk_tier=RiskTier.CRITICAL,
                    file_path=file.file.relative_path,
                    line_number=i + 1,
                    remediation="Remove all PII from configuration files. Use environment variables or secret managers.",
                    reference="NDPA 2023 S.29"
                ))
        return findings


class NDPA004(ComplianceRule):
    rule_id = "NDPA-004"
    rule_name = "Data Retention Policy"
    framework = ComplianceFramework.NDPA_2023
    description = "Checks for unlimited data retention patterns."
    
    def evaluate(self, file: RedactedContent) -> List[Finding]:
        findings = []
        lines = file.redacted_text.lower().splitlines()

        for i, line in enumerate(lines):
            if "ttl=0" in line or "retention=-1" in line or "never_expire" in line or "retention=unlimited" in line:
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.rule_name,
                    description="Unlimited data retention detected.",
                    framework=self.framework,
                    risk_tier=RiskTier.MEDIUM,
                    file_path=file.file.relative_path,
                    line_number=i + 1,
                    remediation="Implement data retention policies with automatic purge. NDPA S.29 requires defined retention periods.",
                    reference="NDPA 2023 S.29"
                ))
        return findings


class NDPA005(ComplianceRule):
    rule_id = "NDPA-005"
    rule_name = "Consent & Purpose Limitation"
    framework = ComplianceFramework.NDPA_2023
    description = "Checks for tracking/analytics without consent mechanisms."
    
    def evaluate(self, file: RedactedContent) -> List[Finding]:
        findings = []
        lines = file.redacted_text.lower().splitlines()

        for i, line in enumerate(lines):
            if ("analytics" in line or "tracking" in line) and "consent=false" in line:
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.rule_name,
                    description="Tracking/analytics configured without explicit consent.",
                    framework=self.framework,
                    risk_tier=RiskTier.MEDIUM,
                    file_path=file.file.relative_path,
                    line_number=i + 1,
                    remediation="Implement consent management. NDPA requires explicit consent for data processing.",
                    reference="NDPA 2023 S.29"
                ))
        return findings


NDPA_RULES = [
    NDPA001(),
    NDPA002(),
    NDPA003(),
    NDPA004(),
    NDPA005()
]

def get_rules() -> List[ComplianceRule]:
    return NDPA_RULES
