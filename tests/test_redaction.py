"""Tests for secret redaction engine."""

from ledgerlens.models import RedactionCategory, ScannedFile
from ledgerlens.redaction.engine import redact_file


def test_redact_paystack_secret():
    content = "PAYSTACK_KEY=sk_test_mock1234567890abcdef1234567890"
    scanned = ScannedFile(
        path=None, relative_path=".env", size_bytes=len(content), content=content
    )
    redacted = redact_file(scanned)

    assert "[REDACTED:PAYMENT_GATEWAY]" in redacted.redacted_text
    assert "sk_test_mock1234567890" not in redacted.redacted_text
    assert len(redacted.hits) == 1
    assert redacted.hits[0].category == RedactionCategory.PAYMENT_GATEWAY


def test_redact_aws_and_postgres(sample_scanned_file: ScannedFile):
    redacted = redact_file(sample_scanned_file)

    assert "[REDACTED:CLOUD_API_KEY]" in redacted.redacted_text
    assert "[REDACTED:DATABASE_URI]" in redacted.redacted_text
    assert "[REDACTED:PAYMENT_GATEWAY]" in redacted.redacted_text
    assert "SuperSecret123" not in redacted.redacted_text
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted.redacted_text
    assert len(redacted.hits) >= 4
