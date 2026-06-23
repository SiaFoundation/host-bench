CREATE TABLE wallet_siacoin_elements (
	id BLOB PRIMARY KEY,
	siacoin_value BLOB NOT NULL,
	sia_address BLOB NOT NULL,
	merkle_proof BLOB NOT NULL,
	leaf_index BLOB NOT NULL,
	maturity_height INTEGER NOT NULL
);

CREATE TABLE wallet_broadcasted_txnsets (
	id BLOB PRIMARY KEY,
	basis BLOB NOT NULL,
	raw_transactions BLOB NOT NULL,
	date_created INTEGER NOT NULL
);
CREATE INDEX wallet_broadcasted_txnsets_date_created ON wallet_broadcasted_txnsets(date_created);

CREATE TABLE wallet_events (
	id BLOB PRIMARY KEY,
	chain_index BLOB NOT NULL,
	maturity_height INTEGER NOT NULL,
	event_type TEXT NOT NULL,
	raw_data BLOB NOT NULL
);
CREATE INDEX wallet_events_chain_index ON wallet_events(chain_index);
CREATE INDEX wallet_events_maturity_height ON wallet_events(maturity_height DESC);

CREATE TABLE syncer_peers (
	peer_address TEXT PRIMARY KEY NOT NULL,
	first_seen INTEGER NOT NULL
);

CREATE TABLE syncer_bans (
	net_cidr TEXT PRIMARY KEY NOT NULL,
	expiration INTEGER NOT NULL,
	reason TEXT NOT NULL
);
CREATE INDEX syncer_bans_expiration ON syncer_bans(expiration);

CREATE TABLE global_settings (
	id INTEGER PRIMARY KEY NOT NULL DEFAULT 0 CHECK (id = 0),
	db_version INTEGER NOT NULL,
	wallet_hash BLOB,
	last_scanned_index BLOB
);

INSERT INTO global_settings (id, db_version) VALUES (0, 2);
