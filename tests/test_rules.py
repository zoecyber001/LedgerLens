"""Tests for NDPA and CBN compliance rules."""

from ledgerlens.models import ComplianceFramework, RiskTier
from ledgerlens.redaction.engine import redact_file
from ledgerlens.rules.base import RuleRegistry
from ledgerlens.rules.cbn import get_rules as get_cbn_rules
from ledgerlens.rules.ndpa import get_rules as get_ndpa_rules


def test_ndpa_and_cbn_rules(sample_scanned_files: list):
    redacted_files = [redact_file(f) for f in sample_scanned_files]

    registry = RuleRegistry()
    for r in get_ndpa_rules():
        registry.register(r)
    for r in get_cbn_rules():
        registry.register(r)

    results = registry.run_all(redacted_files)
    all_findings = [f for rr in results for f in rr.findings]

    rule_ids = {f.rule_id for f in all_findings}

    # Check for expected rule findings
    assert "NDPA-001" in rule_ids  # DB SSL missing
    assert "NDPA-002" in rule_ids  # Encryption false in terraform/yaml
    assert "CBN-001" in rule_ids   # Hardcoded credentials
    assert "CBN-002" in rule_ids   # Permissive CORS (*)
    assert "CBN-004" in rule_ids   # Debug mode true

    # Verify risk tiers assigned properly
    critical_findings = [f for f in all_findings if f.risk_tier == RiskTier.CRITICAL]
    assert len(critical_findings) > 0
