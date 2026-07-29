"""Shared test fixtures for the LedgerLens test suite."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from ledgerlens.models import (
    AuditReport,
    ComplianceFramework,
    Finding,
    RedactedContent,
    RedactionCategory,
    RedactionHit,
    RiskTier,
    RuleResult,
    ScanTarget,
    ScannedFile,
)


# ──────────────────────────────────────────────
# Sample file contents for testing
# ──────────────────────────────────────────────

SAMPLE_ENV = textwrap.dedent("""\
    DATABASE_URL=postgres://admin:SuperSecret123@prod-db.example.com:5432/ledger
    PAYSTACK_SECRET_KEY=sk_test_mock1234567890abcdef1234567890
    FLUTTERWAVE_SECRET=FLWSECK-abcdef1234567890abcdef1234567890ab-X
    AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
    AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
    DEBUG=true
    CORS_ORIGIN=*
    OPENAI_API_KEY=sk-proj-abc123def456ghi789jkl012mno345pqr
    REDIS_URL=redis://default:redis_password@cache.internal:6379/0
""")

SAMPLE_YAML = textwrap.dedent("""\
    server:
      host: 0.0.0.0
      port: 8080
      debug: true
      cors:
        allowed_origins:
          - "*"
    database:
      url: mysql+pymysql://root:password123@db.prod:3306/app
      ssl: false
      encrypt: false
    logging:
      level: DEBUG
      retention_days: 30
""")

SAMPLE_DOCKERFILE = textwrap.dedent("""\
    FROM python:3.11-slim
    ENV DATABASE_PASSWORD=hardcoded_password_123
    ENV API_KEY=sk-proj-testkey1234567890abcdefghij
    EXPOSE 5432
    EXPOSE 3306
    CMD ["python", "app.py"]
""")

SAMPLE_TERRAFORM = textwrap.dedent("""\
    resource "aws_s3_bucket" "data" {
      bucket = "company-data-bucket"
    }

    resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
      bucket = aws_s3_bucket.data.id
    }

    resource "aws_db_instance" "main" {
      engine         = "postgres"
      instance_class = "db.t3.medium"
      password       = "RDSpassword456!"
      storage_encrypted = false
    }
""")

SAMPLE_CLEAN_CONFIG = textwrap.dedent("""\
    server:
      host: 127.0.0.1
      port: 8443
      ssl:
        enabled: true
        cert_path: /etc/ssl/certs/app.pem
    database:
      sslmode: verify-full
      encrypt: true
    logging:
      retention_days: 365
      level: WARNING
    cors:
      allowed_origins:
        - "https://app.example.com"
        - "https://admin.example.com"
""")


# ──────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────

@pytest.fixture
def tmp_project(tmp_path: Path) -> Path:
    """Create a temporary project directory with sample config files."""
    # .env file
    env_file = tmp_path / ".env"
    env_file.write_text(SAMPLE_ENV)

    # config.yaml
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    yaml_file = config_dir / "config.yaml"
    yaml_file.write_text(SAMPLE_YAML)

    # Dockerfile
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(SAMPLE_DOCKERFILE)

    # Terraform
    tf_dir = tmp_path / "infra"
    tf_dir.mkdir()
    tf_file = tf_dir / "main.tf"
    tf_file.write_text(SAMPLE_TERRAFORM)

    # Clean config (should pass most checks)
    clean_file = config_dir / "production.yaml"
    clean_file.write_text(SAMPLE_CLEAN_CONFIG)

    # node_modules (should be ignored)
    nm_dir = tmp_path / "node_modules" / "some-package"
    nm_dir.mkdir(parents=True)
    (nm_dir / "package.json").write_text('{"name": "test"}')

    return tmp_path


@pytest.fixture
def scan_target(tmp_project: Path) -> ScanTarget:
    """ScanTarget pointing at the temporary project."""
    return ScanTarget(root_path=tmp_project)


@pytest.fixture
def sample_scanned_file(tmp_project: Path) -> ScannedFile:
    """A single ScannedFile with the .env content."""
    env_path = tmp_project / ".env"
    return ScannedFile(
        path=env_path,
        relative_path=".env",
        size_bytes=len(SAMPLE_ENV.encode()),
        content=SAMPLE_ENV,
    )


@pytest.fixture
def sample_scanned_files(tmp_project: Path) -> list[ScannedFile]:
    """All sample ScannedFiles from the temporary project."""
    files = []
    file_map = {
        ".env": SAMPLE_ENV,
        "config/config.yaml": SAMPLE_YAML,
        "Dockerfile": SAMPLE_DOCKERFILE,
        "infra/main.tf": SAMPLE_TERRAFORM,
        "config/production.yaml": SAMPLE_CLEAN_CONFIG,
    }
    for rel_path, content in file_map.items():
        full_path = tmp_project / rel_path
        files.append(ScannedFile(
            path=full_path,
            relative_path=rel_path,
            size_bytes=len(content.encode()),
            content=content,
        ))
    return files


@pytest.fixture
def sample_finding() -> Finding:
    """A single sample compliance finding."""
    return Finding(
        rule_id="NDPA-001",
        title="Transport Layer Encryption Missing",
        description="Database connection string lacks SSL/TLS enforcement.",
        framework=ComplianceFramework.NDPA_2023,
        risk_tier=RiskTier.CRITICAL,
        file_path=".env",
        line_number=1,
        code_snippet="DATABASE_URL=post[REDACTED:Database URI]",
        remediation="Enforce TLS/SSL on all database connections. Set sslmode=require.",
        reference="NDPA 2023 S.29",
    )


@pytest.fixture
def sample_audit_report(scan_target: ScanTarget, sample_finding: Finding) -> AuditReport:
    """A minimal AuditReport for testing report generators."""
    return AuditReport(
        target=scan_target,
        total_files_scanned=5,
        total_secrets_redacted=8,
        findings=[sample_finding],
        rule_results=[
            RuleResult(
                rule_id="NDPA-001",
                rule_name="Transport Layer Encryption",
                framework=ComplianceFramework.NDPA_2023,
                passed=False,
                findings=[sample_finding],
            ),
        ],
    )
