"""Data models for LedgerLens financial audit pipeline."""

from __future__ import annotations

import enum
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


class RiskTier(enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @property
    def weight(self) -> int:
        return {
            RiskTier.CRITICAL: 4,
            RiskTier.HIGH: 3,
            RiskTier.MEDIUM: 2,
            RiskTier.LOW: 1,
        }[self]

    def __lt__(self, other: RiskTier) -> bool:
        return self.weight < other.weight


class FinancialFramework(enum.Enum):
    CBN_E_PAYMENT = "CBN e-Payment Guidelines (PSPs/MMOs)"
    CBN_CYBERSECURITY = "CBN Risk-Based Cybersecurity Framework"
    NDPA_2023_DB = "NDPA 2023 S.29 (Database PII Encryption)"
    DOUBLE_ENTRY_STANDARD = "GAAP / IFRS Double-Entry Invariant Standard"


class RedactionCategory(enum.Enum):
    DATABASE_URI = "Database Connection URI"
    ENCRYPTION_KEY = "Database Encryption Key"
    PLAINTEXT_BVN = "Plaintext BVN"
    PLAINTEXT_NIN = "Plaintext NIN"
    PLAINTEXT_PAN = "Plaintext Card PAN"
    GENERIC_SECRET = "Generic Secret"


class DBEngineType(enum.Enum):
    POSTGRESQL = "PostgreSQL"
    MYSQL = "MySQL"
    SQLITE = "SQLite"
    PRISMA = "Prisma ORM"
    GENERIC_SQL = "Generic SQL / Migration DDL"


@dataclass
class ColumnDef:
    name: str
    data_type: str
    is_nullable: bool = True
    is_primary_key: bool = False
    is_foreign_key: bool = False
    references: Optional[str] = None


@dataclass
class TableDef:
    name: str
    columns: list[ColumnDef] = field(default_factory=list)
    constraints: list[str] = field(default_factory=list)
    triggers: list[str] = field(default_factory=list)
    is_ledger_table: bool = False


@dataclass
class ScannedSchemaFile:
    path: Path
    relative_path: str
    engine_type: DBEngineType
    raw_content: str
    tables: list[TableDef] = field(default_factory=list)


@dataclass
class SchemaTarget:
    root_path: Path
    scan_started_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    @property
    def fingerprint(self) -> str:
        raw = f"{self.root_path.resolve()}|{self.scan_started_at.isoformat()}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


@dataclass
class RedactionHit:
    line_number: int
    category: RedactionCategory
    original_snippet: str
    redacted_snippet: str
    pattern_name: str


@dataclass
class RedactedContent:
    file: ScannedSchemaFile
    redacted_text: str
    hits: list[RedactionHit] = field(default_factory=list)

    @property
    def secret_count(self) -> int:
        return len(self.hits)


@dataclass
class Finding:
    rule_id: str
    title: str
    description: str
    framework: FinancialFramework
    risk_tier: RiskTier
    file_path: str
    line_number: Optional[int] = None
    table_name: Optional[str] = None
    column_name: Optional[str] = None
    code_snippet: str = ""
    remediation: str = ""
    reference: str = ""

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "framework": self.framework.value,
            "risk_tier": self.risk_tier.value,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "table_name": self.table_name,
            "column_name": self.column_name,
            "code_snippet": self.code_snippet,
            "remediation": self.remediation,
            "reference": self.reference,
        }


@dataclass
class RuleResult:
    rule_id: str
    rule_name: str
    framework: FinancialFramework
    passed: bool
    findings: list[Finding] = field(default_factory=list)


@dataclass
class AuditReport:
    target: SchemaTarget
    scan_completed_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    total_files_scanned: int = 0
    total_tables_audited: int = 0
    total_ledger_tables_found: int = 0
    total_secrets_redacted: int = 0
    findings: list[Finding] = field(default_factory=list)
    rule_results: list[RuleResult] = field(default_factory=list)

    @property
    def risk_summary(self) -> dict[str, int]:
        counts = {tier.value: 0 for tier in RiskTier}
        for f in self.findings:
            counts[f.risk_tier.value] += 1
        return counts

    @property
    def framework_summary(self) -> dict[str, int]:
        counts = {fw.value: 0 for fw in FinancialFramework}
        for f in self.findings:
            counts[f.framework.value] += 1
        return counts

    @property
    def overall_risk_tier(self) -> RiskTier:
        if not self.findings:
            return RiskTier.LOW
        return max(f.risk_tier for f in self.findings)

    @property
    def compliance_score(self) -> float:
        if not self.rule_results:
            return 100.0
        passed = sum(1 for r in self.rule_results if r.passed)
        return round((passed / len(self.rule_results)) * 100, 1)

    def to_dict(self) -> dict:
        return {
            "metadata": {
                "tool": "LedgerLens Financial Audit Engine",
                "version": "2.0.0",
                "scan_target": str(self.target.root_path),
                "fingerprint": self.target.fingerprint,
                "scan_started_at": self.target.scan_started_at.isoformat(),
                "scan_completed_at": self.scan_completed_at.isoformat(),
            },
            "summary": {
                "total_files_scanned": self.total_files_scanned,
                "total_tables_audited": self.total_tables_audited,
                "total_ledger_tables_found": self.total_ledger_tables_found,
                "total_secrets_redacted": self.total_secrets_redacted,
                "overall_risk_tier": self.overall_risk_tier.value,
                "compliance_score": self.compliance_score,
                "risk_breakdown": self.risk_summary,
                "framework_breakdown": self.framework_summary,
            },
            "findings": [f.to_dict() for f in self.findings],
            "rules": [
                {
                    "rule_id": r.rule_id,
                    "rule_name": r.rule_name,
                    "framework": r.framework.value,
                    "passed": r.passed,
                    "finding_count": len(r.findings),
                }
                for r in self.rule_results
            ],
        }
