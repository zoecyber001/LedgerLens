CREATE TABLE wallet_ledger (id SERIAL PRIMARY KEY,    
  wallet_id INT NOT NULL, debit DECIMAL(15,2), credit           
  DECIMAL(15,2), balance DECIMAL(15,2)); CREATE TABLE           
  customer_identities (id SERIAL PRIMARY KEY, bvn VARCHAR(11),  
  nin VARCHAR(11), card_pan VARCHAR(16));
