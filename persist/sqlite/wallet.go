package sqlite

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/wallet"
)

var _ wallet.SingleAddressStore = (*Store)(nil)

type (
	// WalletUpdateTx atomically updates the wallet's indexed chain state.
	WalletUpdateTx interface {
		wallet.UpdateTx
		SetLastIndex(types.ChainIndex) error
	}

	updateWalletTxn struct {
		tx txn
	}

	stateElement struct {
		ID          types.SiacoinOutputID
		LeafIndex   uint64
		MerkleProof []types.Hash256
	}
)

// AddBroadcastedSet adds a set of broadcasted transactions. The wallet
// periodically rebroadcasts the set until it expires or leaves the pool.
func (s *Store) AddBroadcastedSet(txnset wallet.BroadcastedSet) error {
	return s.transaction(func(tx txn) error {
		_, err := tx.Exec(`INSERT INTO wallet_broadcasted_txnsets (id, basis, raw_transactions, date_created) VALUES (?, ?, ?, ?) ON CONFLICT (id) DO NOTHING`,
			encode(txnset.ID()), encode(txnset.Basis), encodeSlice(txnset.Transactions), encode(txnset.BroadcastedAt))
		return err
	})
}

// BroadcastedSets returns recently broadcasted transaction sets.
func (s *Store) BroadcastedSets() (sets []wallet.BroadcastedSet, err error) {
	err = s.transaction(func(tx txn) error {
		rows, err := tx.Query(`SELECT basis, raw_transactions, date_created FROM wallet_broadcasted_txnsets ORDER BY date_created DESC`)
		if err != nil {
			return fmt.Errorf("failed to query broadcasted sets: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var buf []byte
			var set wallet.BroadcastedSet
			if err := rows.Scan(decode(&set.Basis), &buf, decode(&set.BroadcastedAt)); err != nil {
				return fmt.Errorf("failed to scan broadcasted set: %w", err)
			}
			dec := types.NewBufDecoder(buf)
			types.DecodeSlice(dec, &set.Transactions)
			if err := dec.Err(); err != nil {
				return fmt.Errorf("failed to decode broadcasted set transactions: %w", err)
			}
			sets = append(sets, set)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("failed to iterate broadcasted sets: %w", err)
		}
		return nil
	})
	return
}

// RemoveBroadcastedSet removes a set from the rebroadcast queue.
func (s *Store) RemoveBroadcastedSet(txnset wallet.BroadcastedSet) error {
	return s.transaction(func(tx txn) error {
		_, err := tx.Exec(`DELETE FROM wallet_broadcasted_txnsets WHERE id = ?`, encode(txnset.ID()))
		return err
	})
}

// Tip returns the last scanned chain index.
func (s *Store) Tip() (index types.ChainIndex, err error) {
	err = s.transaction(func(tx txn) error {
		return tx.QueryRow(`SELECT last_scanned_index FROM global_settings`).Scan(decodeNullable(&index))
	})
	return
}

// SetCheckpoint sets the wallet scan checkpoint index.
func (s *Store) SetCheckpoint(index types.ChainIndex) error {
	return s.transaction(func(tx txn) error {
		_, err := tx.Exec(`UPDATE global_settings SET last_scanned_index=?`, encode(index))
		return err
	})
}

// ResetChainState clears derived wallet chain state.
func (s *Store) ResetChainState() error {
	return s.transaction(func(tx txn) error {
		if _, err := tx.Exec(`DELETE FROM wallet_siacoin_elements`); err != nil {
			return fmt.Errorf("failed to delete wallet siacoin elements: %w", err)
		} else if _, err := tx.Exec(`DELETE FROM wallet_events`); err != nil {
			return fmt.Errorf("failed to delete wallet events: %w", err)
		} else if _, err := tx.Exec(`DELETE FROM wallet_broadcasted_txnsets`); err != nil {
			return fmt.Errorf("failed to delete broadcasted transaction sets: %w", err)
		} else if _, err := tx.Exec(`UPDATE global_settings SET last_scanned_index=NULL`); err != nil {
			return fmt.Errorf("failed to reset wallet index: %w", err)
		}
		return nil
	})
}

// UpdateChainState updates wallet state with the given consensus changes.
func (s *Store) UpdateChainState(fn func(WalletUpdateTx) error) error {
	return s.transaction(func(tx txn) error {
		return fn(&updateWalletTxn{tx: tx})
	})
}

func getProofBasis(tx txn) (index types.ChainIndex, err error) {
	err = tx.QueryRow(`SELECT last_scanned_index FROM global_settings`).Scan(decodeNullable(&index))
	return
}

func getSiacoinStateElements(tx txn) (elements []stateElement, err error) {
	rows, err := tx.Query(`SELECT id, leaf_index, merkle_proof FROM wallet_siacoin_elements`)
	if err != nil {
		return nil, fmt.Errorf("failed to query siacoin elements: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var se stateElement
		if err := rows.Scan(decode(&se.ID), decode(&se.LeafIndex), decode(&se.MerkleProof)); err != nil {
			return nil, fmt.Errorf("failed to scan siacoin element: %w", err)
		}
		elements = append(elements, se)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to scan siacoin elements: %w", err)
	}
	return elements, nil
}

func updateSiacoinStateElements(tx txn, elements []stateElement) error {
	stmt, err := tx.Prepare(`UPDATE wallet_siacoin_elements SET merkle_proof=?, leaf_index=? WHERE id=?`)
	if err != nil {
		return fmt.Errorf("failed to prepare update statement: %w", err)
	}
	defer stmt.Close()

	for _, se := range elements {
		if res, err := stmt.Exec(encode(se.MerkleProof), encode(se.LeafIndex), encode(se.ID)); err != nil {
			return fmt.Errorf("failed to update siacoin element: %w", err)
		} else if n, err := res.RowsAffected(); err != nil {
			return fmt.Errorf("failed to get rows affected: %w", err)
		} else if n != 1 {
			return fmt.Errorf("failed to update siacoin element %v: not found", se.ID)
		}
	}
	return nil
}

// UpdateWalletSiacoinElementProofs updates the proofs of all wallet siacoin elements.
func (tx *updateWalletTxn) UpdateWalletSiacoinElementProofs(updater wallet.ProofUpdater) error {
	elements, err := getSiacoinStateElements(tx.tx)
	if err != nil {
		return err
	}
	for i := range elements {
		se := types.StateElement{
			LeafIndex:   elements[i].LeafIndex,
			MerkleProof: elements[i].MerkleProof,
		}
		updater.UpdateElementProof(&se)
		elements[i].LeafIndex = se.LeafIndex
		elements[i].MerkleProof = se.MerkleProof
	}
	return updateSiacoinStateElements(tx.tx, elements)
}

// WalletApplyIndex applies one wallet-relevant chain index.
func (tx *updateWalletTxn) WalletApplyIndex(index types.ChainIndex, created, spent []types.SiacoinElement, events []wallet.Event, _ time.Time) error {
	if err := deleteSiacoinElements(tx.tx, index, spent); err != nil {
		return fmt.Errorf("failed to delete spent siacoin elements: %w", err)
	} else if err := createSiacoinElements(tx.tx, created); err != nil {
		return fmt.Errorf("failed to create siacoin elements: %w", err)
	} else if err := createWalletEvents(tx.tx, events); err != nil {
		return fmt.Errorf("failed to create wallet events: %w", err)
	}
	return nil
}

// WalletRevertIndex reverts one wallet-relevant chain index.
func (tx *updateWalletTxn) WalletRevertIndex(index types.ChainIndex, removed, unspent []types.SiacoinElement, _ time.Time) error {
	if err := deleteSiacoinElements(tx.tx, index, removed); err != nil {
		return fmt.Errorf("failed to delete removed siacoin elements: %w", err)
	} else if err := createSiacoinElements(tx.tx, unspent); err != nil {
		return fmt.Errorf("failed to restore siacoin elements: %w", err)
	} else if _, err := tx.tx.Exec(`DELETE FROM wallet_events WHERE chain_index=?`, encode(index)); err != nil {
		return fmt.Errorf("failed to delete wallet events: %w", err)
	}
	return nil
}

// SetLastIndex sets the last wallet-scanned chain index.
func (tx *updateWalletTxn) SetLastIndex(index types.ChainIndex) error {
	_, err := tx.tx.Exec(`UPDATE global_settings SET last_scanned_index=?`, encode(index))
	return err
}

func createSiacoinElements(tx txn, created []types.SiacoinElement) error {
	if len(created) == 0 {
		return nil
	}
	stmt, err := tx.Prepare(`INSERT INTO wallet_siacoin_elements (id, siacoin_value, sia_address, merkle_proof, leaf_index, maturity_height) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (id) DO NOTHING`)
	if err != nil {
		return fmt.Errorf("failed to prepare insert statement: %w", err)
	}
	defer stmt.Close()

	for _, elem := range created {
		if _, err := stmt.Exec(encode(elem.ID), encode(elem.SiacoinOutput.Value), encode(elem.SiacoinOutput.Address), encode(elem.StateElement.MerkleProof), encode(elem.StateElement.LeafIndex), elem.MaturityHeight); err != nil {
			return fmt.Errorf("failed to insert siacoin element %q: %w", elem.ID, err)
		}
	}
	return nil
}

func deleteSiacoinElements(tx txn, _ types.ChainIndex, removed []types.SiacoinElement) error {
	if len(removed) == 0 {
		return nil
	}
	stmt, err := tx.Prepare(`DELETE FROM wallet_siacoin_elements WHERE id=?`)
	if err != nil {
		return fmt.Errorf("failed to prepare delete statement: %w", err)
	}
	defer stmt.Close()

	for _, elem := range removed {
		if res, err := stmt.Exec(encode(elem.ID)); err != nil {
			return fmt.Errorf("failed to delete siacoin element: %w", err)
		} else if n, err := res.RowsAffected(); err != nil {
			return fmt.Errorf("failed to get rows affected: %w", err)
		} else if n != 1 {
			return fmt.Errorf("failed to delete siacoin element %q: not found", elem.ID)
		}
	}
	return nil
}

func createWalletEvents(tx txn, events []wallet.Event) error {
	if len(events) == 0 {
		return nil
	}
	stmt, err := tx.Prepare(`INSERT INTO wallet_events (id, chain_index, maturity_height, event_type, raw_data) VALUES (?, ?, ?, ?, ?) ON CONFLICT (id) DO NOTHING`)
	if err != nil {
		return fmt.Errorf("failed to prepare insert statement: %w", err)
	}
	defer stmt.Close()

	buf := bytes.NewBuffer(nil)
	enc := types.NewEncoder(buf)
	for _, event := range events {
		buf.Reset()
		event.EncodeTo(enc)
		_ = enc.Flush()
		if _, err := stmt.Exec(encode(event.ID), encode(event.Index), event.MaturityHeight, event.Type, buf.Bytes()); err != nil {
			return fmt.Errorf("failed to insert wallet event: %w", err)
		}
	}
	return nil
}

// UnspentSiacoinElements returns the wallet's unspent siacoin outputs.
func (s *Store) UnspentSiacoinElements() (basis types.ChainIndex, utxos []types.SiacoinElement, err error) {
	err = s.transaction(func(tx txn) error {
		basis, err = getProofBasis(tx)
		if err != nil {
			return fmt.Errorf("failed to get proof basis: %w", err)
		}
		rows, err := tx.Query(`SELECT id, siacoin_value, sia_address, leaf_index, merkle_proof, maturity_height FROM wallet_siacoin_elements`)
		if err != nil {
			return fmt.Errorf("failed to query unspent siacoin elements: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var se types.SiacoinElement
			if err := rows.Scan(decode(&se.ID), decode(&se.SiacoinOutput.Value), decode(&se.SiacoinOutput.Address), decode(&se.StateElement.LeafIndex), decode(&se.StateElement.MerkleProof), &se.MaturityHeight); err != nil {
				return fmt.Errorf("failed to scan unspent siacoin element: %w", err)
			}
			utxos = append(utxos, se)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("failed to iterate unspent siacoin elements: %w", err)
		}
		return nil
	})
	return
}

// WalletEvent retrieves a wallet event by ID.
func (s *Store) WalletEvent(id types.Hash256) (event wallet.Event, err error) {
	err = s.transaction(func(tx txn) error {
		err := tx.QueryRow(`SELECT raw_data FROM wallet_events WHERE id = ?`, encode(id)).Scan(decode(&event))
		if errors.Is(err, sql.ErrNoRows) {
			return wallet.ErrEventNotFound
		}
		return err
	})
	return
}

// WalletEvents returns wallet events ordered by maturity height, descending.
func (s *Store) WalletEvents(offset, limit int) (events []wallet.Event, err error) {
	err = s.transaction(func(tx txn) error {
		rows, err := tx.Query(`SELECT raw_data FROM wallet_events ORDER BY maturity_height DESC LIMIT ? OFFSET ?`, limit, offset)
		if err != nil {
			return fmt.Errorf("failed to query wallet events: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var event wallet.Event
			if err := rows.Scan(decode(&event)); err != nil {
				return fmt.Errorf("failed to scan wallet event: %w", err)
			}
			events = append(events, event)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("failed to iterate wallet events: %w", err)
		}
		return nil
	})
	return
}

// WalletEventCount returns the total number of wallet events.
func (s *Store) WalletEventCount() (count uint64, err error) {
	err = s.transaction(func(tx txn) error {
		return tx.QueryRow(`SELECT COUNT(*) FROM wallet_events`).Scan(&count)
	})
	return
}

// VerifyWalletKey checks that the wallet seed matches the seed hash.
func (s *Store) VerifyWalletKey(seedHash types.Hash256) error {
	return s.transaction(func(tx txn) error {
		var buf []byte
		err := tx.QueryRow(`SELECT wallet_hash FROM global_settings`).Scan(&buf)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return err
		case err != nil:
			return fmt.Errorf("failed to query wallet seed hash: %w", err)
		case len(buf) == 0:
			_, err := tx.Exec(`UPDATE global_settings SET wallet_hash=?`, encode(seedHash))
			return err
		case len(buf) != len(seedHash):
			return wallet.ErrDifferentSeed
		case seedHash != *(*types.Hash256)(buf):
			return wallet.ErrDifferentSeed
		default:
			return nil
		}
	})
}

// UpdateWalletHash sets the wallet seed hash after a reset.
func (s *Store) UpdateWalletHash(seedHash types.Hash256) error {
	return s.transaction(func(tx txn) error {
		_, err := tx.Exec(`UPDATE global_settings SET wallet_hash=?`, encode(seedHash))
		return err
	})
}
