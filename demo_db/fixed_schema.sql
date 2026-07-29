CREATE TABLE wallet_ledger (id SERIAL PRIMARY KEY,    
  wallet_id INT NOT NULL, debit DECIMAL(15,2), credit           
  DECIMAL(15,2), balance DECIMAL(15,2)); CREATE TABLE           
  customer_identities (id SERIAL PRIMARY KEY, bvn VARCHAR(11),  
  nin VARCHAR(11), card_pan VARCHAR(16));
-- ====================================================================
-- LedgerLens v2.0 — Automated SQL Remediation Script
-- Target: /home/zoecyber/LedgerLens/demo_db
-- Fingerprint: db2b2189e53a548e
-- Total Findings: 7
-- ====================================================================

-- [FIN-DE-001] Missing Debit/Credit Balance Constraint
-- Risk: CRITICAL | Table: wallet_ledger
-- Checks if a ledger/journal/transaction table lacks a CHECK constraint ensuring debits equal credits or balance invariants (amount != 0, balance >= 0, debit >= 0 AND credit >= 0).
ALTER TABLE wallet_ledger ADD CONSTRAINT chk_wallet_ledger_balance_non_negative CHECK (debit >= 0 AND credit >= 0);

-- [FIN-PII-001] Plaintext BVN/NIN Column Definition
-- Risk: CRITICAL | Table: customer_identities
-- Checks table columns named bvn, nin, national_id, bank_verification_number defined as unencrypted VARCHAR, TEXT, CHAR, INT, BIGINT.
-- Encrypt plaintext BVN/NIN columns on table: customer_identities
ALTER TABLE customer_identities ADD COLUMN bvn_encrypted BYTEA;
-- UPDATE customer_identities SET bvn_encrypted = pgcrypto.pgp_sym_encrypt(bvn, 'YOUR-VAULT-KEY');
-- ALTER TABLE customer_identities DROP COLUMN bvn;

-- [FIN-PII-001] Plaintext BVN/NIN Column Definition
-- Risk: CRITICAL | Table: customer_identities
-- Checks table columns named bvn, nin, national_id, bank_verification_number defined as unencrypted VARCHAR, TEXT, CHAR, INT, BIGINT.
-- Encrypt plaintext BVN/NIN columns on table: customer_identities
ALTER TABLE customer_identities ADD COLUMN bvn_encrypted BYTEA;
-- UPDATE customer_identities SET bvn_encrypted = pgcrypto.pgp_sym_encrypt(bvn, 'YOUR-VAULT-KEY');
-- ALTER TABLE customer_identities DROP COLUMN bvn;

-- [FIN-PII-002] Plaintext Card PAN / CVV Column Definition
-- Risk: CRITICAL | Table: customer_identities
-- Checks columns named card_number, card_pan, pan, cvv, card_cvv defined as plaintext VARCHAR/TEXT/INT.
-- WARNING: Remove raw Card PAN/CVV from table: customer_identities
-- Replace raw card columns with gateway tokenization references.

-- [FIN-IMM-001] Missing Immutability Triggers / Mutable Ledger
-- Risk: CRITICAL | Table: wallet_ledger
-- Checks if financial ledger tables (ledger, transaction, journal_entry, payment_log) lack triggers or policies preventing UPDATE or DELETE operations.
CREATE OR REPLACE FUNCTION prevent_wallet_ledger_modification()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Financial ledger tables are immutable. UPDATE/DELETE operations prohibited.';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_prevent_mod_wallet_ledger
BEFORE UPDATE OR DELETE ON wallet_ledger
FOR EACH ROW EXECUTE FUNCTION prevent_wallet_ledger_modification();

-- [FIN-IMM-002] Missing Immutable Timestamps
-- Risk: HIGH | Table: wallet_ledger
-- Checks if ledger tables lack created_at or timestamp default constraints (DEFAULT CURRENT_TIMESTAMP / DEFAULT NOW()).
ALTER TABLE wallet_ledger ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP;

-- [FIN-CBN-001] Missing Audit Trail Logging
-- Risk: HIGH | Table: N/A
-- Checks for missing audit log tables or CDC (Change Data Capture) configuration in database schema.
CREATE TABLE IF NOT EXISTS audit_log (
    id BIGSERIAL PRIMARY KEY,
    table_name VARCHAR(100) NOT NULL,
    operation VARCHAR(20) NOT NULL,
    record_id VARCHAR(100),
    old_data JSONB,
    new_data JSONB,
    performed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
