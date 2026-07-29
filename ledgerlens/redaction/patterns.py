import re
from dataclasses import dataclass
from typing import Pattern

from ledgerlens.models import RedactionCategory

@dataclass
class SecretPattern:
    """Represents a regex pattern for discovering secrets or PII."""
    name: str
    pattern: Pattern[str]
    category: RedactionCategory

ALL_PATTERNS: list[SecretPattern] = [
    SecretPattern(
        name="Cloud API Keys & DB Passwords",
        pattern=re.compile(r"(AKIA[0-9A-Z]{16}|sk_live_[a-zA-Z0-9]+|FLWSECK-[a-zA-Z0-9]+|MK_PROD_[a-zA-Z0-9]+|sk-[a-zA-Z0-9]{20,})"),
        category=RedactionCategory.GENERIC_SECRET
    ),
    SecretPattern(
        name="Database Connection URIs",
        pattern=re.compile(r"(postgres|mysql|mongodb|redis)://\S+"),
        category=RedactionCategory.DATABASE_URI
    ),
    SecretPattern(
        name="Plaintext BVN",
        pattern=re.compile(r"(?i)(?:\bbvn\s*[:=]\s*['\"]?\d{11}['\"]?|['\"]2\d{10}['\"])"),
        category=RedactionCategory.PLAINTEXT_BVN
    ),
    SecretPattern(
        name="Plaintext NIN",
        pattern=re.compile(r"(?i)(?:\bnin\s*[:=]\s*['\"]?\d{11}['\"]?|['\"]1\d{10}['\"])"),
        category=RedactionCategory.PLAINTEXT_NIN
    ),
    SecretPattern(
        name="Plaintext Card PAN",
        pattern=re.compile(r"(?i)(?:\b(?:card_number|pan)\s*[:=]\s*['\"]?\d{16}['\"]?|['\"]4\d{15}['\"])"),
        category=RedactionCategory.PLAINTEXT_PAN
    ),
    SecretPattern(
        name="Database Encryption Keys",
        pattern=re.compile(r"(?i)(?:pgcrypto|secret_key)\s*[:=]\s*['\"][^'\"]+['\"]"),
        category=RedactionCategory.ENCRYPTION_KEY
    ),
]
