"""Semantic PII Column Classifier for LedgerLens v2.0."""

import enum
from dataclasses import dataclass
from typing import Tuple

from ledgerlens.models import ColumnDef


class PIIClassification(enum.Enum):
    UNENCRYPTED_BVN_NIN = "UNENCRYPTED_BVN_NIN"
    UNENCRYPTED_CARD_PAN = "UNENCRYPTED_CARD_PAN"
    SECURE_ENCRYPTED_PII = "SECURE_ENCRYPTED_PII"
    SECURE_TOKENIZED_CARD = "SECURE_TOKENIZED_CARD"
    NON_SENSITIVE = "NON_SENSITIVE"


@dataclass
class ColumnPIIAnalysis:
    classification: PIIClassification
    is_violation: bool
    risk_reason: str
    remediation_hint: str


class SemanticPIIClassifier:
    """Semantic classifier for database columns evaluating PII exposure vs encrypted storage."""

    ENCRYPTED_TYPES = {"bytea", "blob", "varbinary", "binary"}
    ENCRYPTED_SUFFIXES = {"_encrypted", "_hash", "_token", "_vault", "_enc", "_digest", "_masked", "_last4"}

    @classmethod
    def analyze_column(cls, col: ColumnDef) -> ColumnPIIAnalysis:
        col_name = col.name.lower()
        col_type = col.data_type.lower()

        # Check if column name suggests BVN or NIN
        is_bvn_nin_name = any(kw in col_name for kw in ["bvn", "nin", "national_id", "bank_verification_number"])

        # Check if column name suggests Card PAN / CVV
        is_card_name = any(kw in col_name for kw in ["card_number", "card_pan", "pan", "cvv", "card_cvv"])

        if not (is_bvn_nin_name or is_card_name):
            return ColumnPIIAnalysis(
                classification=PIIClassification.NON_SENSITIVE,
                is_violation=False,
                risk_reason="Non-sensitive column.",
                remediation_hint="",
            )

        # Check if column is cryptographically secured via naming convention or data type
        is_encrypted_type = any(t in col_type for t in cls.ENCRYPTED_TYPES)
        is_encrypted_name = any(col_name.endswith(suf) for suf in cls.ENCRYPTED_SUFFIXES)

        if is_bvn_nin_name:
            if is_encrypted_type or is_encrypted_name:
                return ColumnPIIAnalysis(
                    classification=PIIClassification.SECURE_ENCRYPTED_PII,
                    is_violation=False,
                    risk_reason="Column uses encrypted storage type or cryptographic token suffix.",
                    remediation_hint="",
                )
            return ColumnPIIAnalysis(
                classification=PIIClassification.UNENCRYPTED_BVN_NIN,
                is_violation=True,
                risk_reason=f"Column '{col.name}' stores BVN/NIN in unencrypted plaintext type '{col.data_type}'.",
                remediation_hint="Encrypt BVN/NIN using column-level encryption (pgcrypto BYTEA) or HMAC-SHA256 hash.",
            )

        if is_card_name:
            if col_name.endswith("_last4") or col_name.endswith("_token") or col_name.endswith("_masked"):
                return ColumnPIIAnalysis(
                    classification=PIIClassification.SECURE_TOKENIZED_CARD,
                    is_violation=False,
                    risk_reason="Column stores masked last4 digits or payment token.",
                    remediation_hint="",
                )
            return ColumnPIIAnalysis(
                classification=PIIClassification.UNENCRYPTED_CARD_PAN,
                is_violation=True,
                risk_reason=f"Column '{col.name}' stores raw Card PAN/CVV in plain text.",
                remediation_hint="Never store raw Card PAN or CVV. Use PCI-DSS compliant payment gateway tokenization.",
            )

        return ColumnPIIAnalysis(
            classification=PIIClassification.NON_SENSITIVE,
            is_violation=False,
            risk_reason="",
            remediation_hint="",
        )
