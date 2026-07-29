import re
from typing import List

from ledgerlens.models import ComplianceFramework, Finding, RedactedContent, RiskTier
from ledgerlens.rules.base import ComplianceRule


class CBN001(ComplianceRule):
    rule_id = "CBN-001"
    rule_name = "Hardcoded Credentials"
    framework = ComplianceFramework.CBN_CYBERSECURITY
    description = "Checks for hardcoded credentials cross-referencing redaction hits."
    
    def evaluate(self, file: RedactedContent) -> List[Finding]:
        findings = []
        if file.hits:
            for hit in file.hits:
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.rule_name,
                    description=f"Hardcoded credential detected: {hit.category.value}",
                    framework=self.framework,
                    risk_tier=RiskTier.CRITICAL,
                    file_path=file.file.relative_path,
                    line_number=hit.line_number,
                    remediation="Move all credentials to a secrets manager (HashiCorp Vault, AWS Secrets Manager). Never hardcode credentials.",
                    reference="CBN Risk-Based Cybersecurity Framework"
                ))
        return findings


class CBN002(ComplianceRule):
    rule_id = "CBN-002"
    rule_name = "Permissive CORS Policy"
    framework = ComplianceFramework.CBN_CYBERSECURITY
    description = "Checks for wildcard CORS origins."
    
    def evaluate(self, file: RedactedContent) -> List[Finding]:
        findings = []
        lines = file.redacted_text.splitlines()

        in_cors_block = False
        cors_pattern = re.compile(r"(?i)(cors|access-control-allow-origin|allowed_origins)")

        for i, line in enumerate(lines):
            line_cleaned = line.replace(" ", "").lower()
            if cors_pattern.search(line):
                in_cors_block = True
                
            if "access-control-allow-origin:*" in line_cleaned or "origin:'*'" in line_cleaned or "origin:\"*\"" in line_cleaned or "cors_origin_allow_all=true" in line_cleaned:
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.rule_name,
                    description="Permissive CORS policy detected.",
                    framework=self.framework,
                    risk_tier=RiskTier.HIGH,
                    file_path=file.file.relative_path,
                    line_number=i + 1,
                    remediation="Restrict CORS origins to known, trusted domains. Never use wildcard (*) in production.",
                    reference="CBN Risk-Based Cybersecurity Framework"
                ))
            elif in_cors_block and ('"*"' in line_cleaned or "'*'" in line_cleaned or 'origin:*' in line_cleaned or '-"*"' in line_cleaned or "-'*'" in line_cleaned):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.rule_name,
                    description="Permissive CORS wildcard origin detected.",
                    framework=self.framework,
                    risk_tier=RiskTier.HIGH,
                    file_path=file.file.relative_path,
                    line_number=i + 1,
                    remediation="Restrict CORS origins to known, trusted domains. Never use wildcard (*) in production.",
                    reference="CBN Risk-Based Cybersecurity Framework"
                ))
                in_cors_block = False
        return findings


class CBN003(ComplianceRule):
    rule_id = "CBN-003"
    rule_name = "Missing Log Retention"
    framework = ComplianceFramework.CBN_CYBERSECURITY
    description = "Checks for missing or inadequate log retention configurations."
    
    def evaluate(self, file: RedactedContent) -> List[Finding]:
        findings = []
        lines = file.redacted_text.lower().splitlines()

        retention_pattern = re.compile(r'retention.*?(\d+)')
        
        for i, line in enumerate(lines):
            match = retention_pattern.search(line)
            if match:
                days = int(match.group(1))
                if days < 90:
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        title=self.rule_name,
                        description=f"Log retention is {days} days, which is less than the required 90 days.",
                        framework=self.framework,
                        risk_tier=RiskTier.MEDIUM,
                        file_path=file.file.relative_path,
                        line_number=i + 1,
                        remediation="Configure log retention for minimum 90 days per CBN guidelines. Implement centralized logging.",
                        reference="CBN Risk-Based Cybersecurity Framework"
                    ))
        return findings


class CBN004(ComplianceRule):
    rule_id = "CBN-004"
    rule_name = "Debug Mode in Production"
    framework = ComplianceFramework.CBN_CYBERSECURITY
    description = "Checks for debug modes enabled."
    
    def evaluate(self, file: RedactedContent) -> List[Finding]:
        findings = []
        lines = file.redacted_text.splitlines()

        for i, line in enumerate(lines):
            line_cleaned = line.replace(" ", "")
            # Mix of case sensitive and insensitive patterns
            if "DEBUG=true" in line_cleaned or "debug:true" in line_cleaned.lower() or "NODE_ENV=development" in line_cleaned or "FLASK_DEBUG=1" in line_cleaned or "DJANGO_DEBUG=True" in line_cleaned:
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.rule_name,
                    description="Debug mode enabled.",
                    framework=self.framework,
                    risk_tier=RiskTier.HIGH,
                    file_path=file.file.relative_path,
                    line_number=i + 1,
                    remediation="Disable debug mode in production. Set DEBUG=false and use production environment settings.",
                    reference="CBN Risk-Based Cybersecurity Framework"
                ))
        return findings


class CBN005(ComplianceRule):
    rule_id = "CBN-005"
    rule_name = "Missing Rate Limiting"
    framework = ComplianceFramework.CBN_CYBERSECURITY
    description = "Checks for disabled rate limiting."
    
    def evaluate(self, file: RedactedContent) -> List[Finding]:
        findings = []
        lines = file.redacted_text.lower().splitlines()

        for i, line in enumerate(lines):
            line_cleaned = line.replace(" ", "")
            if "ratelimit=0" in line_cleaned or "rate_limit=0" in line_cleaned or "ratelimit=false" in line_cleaned or "rate_limit=false" in line_cleaned or "ratelimiting=false" in line_cleaned:
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.rule_name,
                    description="Rate limiting appears to be disabled.",
                    framework=self.framework,
                    risk_tier=RiskTier.MEDIUM,
                    file_path=file.file.relative_path,
                    line_number=i + 1,
                    remediation="Implement API rate limiting. CBN guidelines require protection against brute-force and DDoS attacks.",
                    reference="CBN Risk-Based Cybersecurity Framework"
                ))
        return findings


class CBN006(ComplianceRule):
    rule_id = "CBN-006"
    rule_name = "Insecure Default Configurations"
    framework = ComplianceFramework.CBN_CYBERSECURITY
    description = "Checks for default ports and open bind addresses."
    
    def evaluate(self, file: RedactedContent) -> List[Finding]:
        findings = []
        lines = file.redacted_text.splitlines()

        for i, line in enumerate(lines):
            line_cleaned = line.replace(" ", "").lower()
            if "bind_address=0.0.0.0" in line_cleaned or "bind=0.0.0.0" in line_cleaned:
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.rule_name,
                    description="Service bound to all interfaces (0.0.0.0).",
                    framework=self.framework,
                    risk_tier=RiskTier.LOW,
                    file_path=file.file.relative_path,
                    line_number=i + 1,
                    remediation="Change default configurations. Restrict service binding and implement network-level access controls.",
                    reference="CBN Risk-Based Cybersecurity Framework"
                ))
            elif any(port in line_cleaned for port in ["port=3306", "port=5432", "port=27017", "port:3306", "port:5432", "port:27017"]):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.rule_name,
                    description="Default database port in use.",
                    framework=self.framework,
                    risk_tier=RiskTier.LOW,
                    file_path=file.file.relative_path,
                    line_number=i + 1,
                    remediation="Change default configurations. Restrict service binding and implement network-level access controls.",
                    reference="CBN Risk-Based Cybersecurity Framework"
                ))
        return findings


CBN_RULES = [
    CBN001(),
    CBN002(),
    CBN003(),
    CBN004(),
    CBN005(),
    CBN006()
]

def get_rules() -> List[ComplianceRule]:
    return CBN_RULES
