# LedgerLens

LedgerLens is an automated database auditor for banks, fintechs, and compliance consultants.

It scans database schemas (`.sql`, `schema.prisma`, migrations) before deployment to check for three critical flaws:

1. **Broken Accounting Math**: Verifies that debits equal credits and flags unsafe delete rules on transaction tables.
2. **Exposed Customer Privacy**: Flags unencrypted BVN, NIN, and credit card columns under NDPA 2023 laws.
3. **Editable Payment History**: Checks if past transaction records can be altered or deleted instead of being permanent and append-only.

After scanning, it outputs a printable PDF audit return, an interactive HTML dashboard, a SARIF log, and a script with exact SQL fixes.

---

## Quick Start

```bash
# Install
pip install -e .

# Run Audit
ledgerlens audit-ledger /path/to/schema_dir --output ./reports

# Generate SQL Fixes
ledgerlens fix /path/to/schema_dir --output ./reports
```

---

## What Gets Checked

| Rule ID | Standard | Rule Check | Risk |
|---|---|---|---|
| **FIN-DE-001** | GAAP / IFRS | Missing Debit/Credit CHECK Constraint | CRITICAL |
| **FIN-DE-002** | GAAP / IFRS | Unsafe CASCADE Delete on Ledger Tables | CRITICAL |
| **FIN-PII-001** | NDPA 2023 S.29 | Plaintext BVN or NIN Column | CRITICAL |
| **FIN-PII-002** | NDPA 2023 / PCI | Plaintext Card PAN or CVV Column | CRITICAL |
| **FIN-IMM-001** | CBN e-Payment | Missing Immutability Triggers (Mutable Ledger) | CRITICAL |
| **FIN-IMM-002** | CBN Cybersecurity | Missing created_at Timestamp Default | HIGH |
| **FIN-CBN-001** | CBN e-Payment | Missing Audit Trail / CDC Tables | HIGH |
| **FIN-CBN-002** | CBN Cybersecurity | Insecure SUPERUSER DB Connections | MEDIUM |

---

## Supported Inputs

- PostgreSQL (`.sql`, Alembic)
- MySQL / MariaDB (`.sql`)
- SQLite (`.sql`)
- Prisma ORM (`schema.prisma`)
- TypeORM / Knex / Sequelize (`.ts`, `.js`)

---

## Testing

```bash
PYTHONPATH=. python3 tests/run_tests.py
```

---

## License

MIT License. See LICENSE file.
