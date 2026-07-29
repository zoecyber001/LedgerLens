from abc import ABC, abstractmethod
from typing import List

from ledgerlens.models import FinancialFramework, RedactedContent, Finding, RuleResult


class ComplianceRule(ABC):
    rule_id: str
    rule_name: str
    framework: FinancialFramework
    description: str

    @abstractmethod
    def evaluate(self, file: RedactedContent) -> List[Finding]:
        """Evaluate the rule against the redacted file content."""
        pass


class RuleRegistry:
    def __init__(self) -> None:
        self.rules: List[ComplianceRule] = []

    def register(self, rule: ComplianceRule) -> None:
        self.rules.append(rule)

    def run_all(self, files: List[RedactedContent]) -> List[RuleResult]:
        results: List[RuleResult] = []
        for rule in self.rules:
            findings: List[Finding] = []
            for file in files:
                findings.extend(rule.evaluate(file))
            passed = len(findings) == 0
            results.append(RuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.rule_name,
                framework=rule.framework,
                passed=passed,
                findings=findings,
            ))
        return results

    def get_rules_by_framework(self, framework: FinancialFramework) -> List[ComplianceRule]:
        return [rule for rule in self.rules if rule.framework == framework]
