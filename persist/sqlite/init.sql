CREATE TABLE wallet_utxos (
	id BLOB PRIMARY KEY,
	amount BLOB NOT NULL,
	unlock_hash BLOB NOT NULL
);

CREATE TABLE wallet_transactions (
	id INTEGER PRIMARY KEY,
	transaction_id BLOB NOT NULL,
	block_id BLOB NOT NULL,
	inflow BLOB NOT NULL,
	outflow BLOB NOT NULL,
	raw_transaction BLOB NOT NULL, -- binary serialized transaction
	source TEXT NOT NULL,
	block_height INTEGER NOT NULL,
	date_created INTEGER NOT NULL
);
CREATE INDEX wallet_transactions_date_created_index ON wallet_transactions(date_created);
CREATE INDEX wallet_transactions_block_id ON wallet_transactions(block_id);
CREATE INDEX wallet_transactions_date_created ON wallet_transactions(date_created);
CREATE INDEX wallet_transactions_block_height_id ON wallet_transactions(block_height DESC, id);

CREATE TABLE global_settings (
	id INTEGER PRIMARY KEY NOT NULL DEFAULT 0 CHECK (id = 0), -- enforce a single row
	db_version INTEGER NOT NULL, -- used for migrations
	wallet_hash BLOB, -- used to prevent wallet seed changes
	wallet_last_processed_change BLOB, -- last processed consensus change for the wallet
	wallet_height INTEGER -- height of the wallet as of the last processed change
);

INSERT INTO global_settings (id, db_version) VALUES (0, 1); -- version must be updated when the schema changes