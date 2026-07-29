-- ====================================================================
-- LedgerLens v2.0 — Automated SQL Remediation Script
-- Target: /home/zoecyber/LedgerLens/demo_db
-- Fingerprint: a19da5ca0392a35b
-- Total Findings: 14
-- ====================================================================

-- [FIN-DE-001] Missing Debit/Credit Balance Constraint
-- Risk: CRITICAL | Table: wallet_ledger
ALTER TABLE wallet_ledger ADD CONSTRAINT chk_wallet_ledger_balance_non_negative CHECK (debit >= 0 AND credit >= 0);

-- [FIN-DE-001] Missing Debit/Credit Balance Constraint
-- Risk: CRITICAL | Table: wallet_ledger
ALTER TABLE wallet_ledger ADD CONSTRAINT chk_wallet_ledger_balance_non_negative CHECK (debit >= 0 AND credit >= 0);

-- [FIN-PII-001] Plaintext BVN/NIN Column Definition
-- Risk: CRITICAL | Table: customer_identities
ALTER TABLE customer_identities ADD COLUMN bvn_encrypted BYTEA;

-- [FIN-PII-001] Plaintext BVN/NIN Column Definition
-- Risk: CRITICAL | Table: customer_identities
ALTER TABLE customer_identities ADD COLUMN bvn_encrypted BYTEA;

-- [FIN-PII-001] Plaintext BVN/NIN Column Definition
-- Risk: CRITICAL | Table: customer_identities
ALTER TABLE customer_identities ADD COLUMN bvn_encrypted BYTEA;

-- [FIN-PII-001] Plaintext BVN/NIN Column Definition
-- Risk: CRITICAL | Table: customer_identities
ALTER TABLE customer_identities ADD COLUMN bvn_encrypted BYTEA;

-- [FIN-PII-002] Plaintext Card PAN / CVV Column Definition
-- Risk: CRITICAL | Table: customer_identities
-- Replace raw Card PAN/CVV on customer_identities with gateway tokens.

-- [FIN-PII-002] Plaintext Card PAN / CVV Column Definition
-- Risk: CRITICAL | Table: customer_identities
-- Replace raw Card PAN/CVV on customer_identities with gateway tokens.

-- [FIN-IMM-001] Missing Immutability Triggers / Mutable Ledger
-- Risk: CRITICAL | Table: wallet_ledger
CREATE OR REPLACE FUNCTION prevent_wallet_ledger_modification()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Financial ledger tables are immutable. UPDATE/DELETE operations prohibited.';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_prevent_mod_wallet_ledger
BEFORE UPDATE OR DELETE ON wallet_ledger
FOR EACH ROW EXECUTE FUNCTION prevent_wallet_ledger_modification();

-- [FIN-IMM-001] Missing Immutability Triggers / Mutable Ledger
-- Risk: CRITICAL | Table: audit_log
CREATE OR REPLACE FUNCTION prevent_audit_log_modification()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Financial ledger tables are immutable. UPDATE/DELETE operations prohibited.';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_prevent_mod_audit_log
BEFORE UPDATE OR DELETE ON audit_log
FOR EACH ROW EXECUTE FUNCTION prevent_audit_log_modification();

-- [FIN-IMM-002] Missing Immutable Timestamps
-- Risk: HIGH | Table: wallet_ledger
ALTER TABLE wallet_ledger ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP;

-- [FIN-IMM-002] Missing Immutable Timestamps
-- Risk: HIGH | Table: wallet_ledger
ALTER TABLE wallet_ledger ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP;

-- [FIN-IMM-002] Missing Immutable Timestamps
-- Risk: HIGH | Table: audit_log
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP;

-- [FIN-CBN-001] Missing Audit Trail Logging
-- Risk: HIGH | Table: N/A
CREATE TABLE IF NOT EXISTS audit_log (
    id BIGSERIAL PRIMARY KEY,
    table_name VARCHAR(100) NOT NULL,
    operation VARCHAR(20) NOT NULL,
    record_id VARCHAR(100),
    old_data JSONB,
    new_data JSONB,
    performed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
