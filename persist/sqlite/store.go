package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/mattn/go-sqlite3"
	"go.uber.org/zap"
)

type (
	// A Store is a persistent store that uses a SQL database as its backend.
	Store struct {
		db  *sql.DB
		log *zap.Logger
	}
)

// transaction executes a function within a database transaction. If the
// function returns an error, the transaction is rolled back. Otherwise, the
// transaction is committed.
func (s *Store) transaction(fn func(txn) error) error {
	var tx *sql.Tx
	var err error
	start := time.Now()
	for i := 1; i <= 5; i++ {
		tx, err = s.db.BeginTx(context.Background(), nil)
		if sqliteErr, ok := err.(sqlite3.Error); !ok || sqliteErr.Code != sqlite3.ErrBusy {
			break
		}
		s.log.Debug("database locked", zap.Int("attempt", i), zap.Duration("elapsed", time.Since(start)), zap.Stack("stack"))
	}
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	ltx := &loggedTxn{
		Tx:  tx,
		log: s.log.Named("transaction"),
	}
	start = time.Now()
	err = fn(ltx)
	if time.Since(start) > longTxnDuration {
		ltx.log.Debug("long transaction", zap.Duration("elapsed", time.Since(start)), zap.Stack("stack"))
	}
	commitStart := time.Now()
	if err != nil {
		if err := tx.Rollback(); err != nil {
			return fmt.Errorf("failed to rollback transaction: %w", err)
		}
		return fmt.Errorf("failed to execute transaction: %w", err)
	} else if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	if time.Since(commitStart) > longQueryDuration {
		ltx.log.Debug("long transaction commit", zap.Duration("elapsed", time.Since(commitStart)), zap.Duration("totalElapsed", time.Since(start)), zap.Stack("stack"))
	}
	return nil
}

// SetLogger sets the logger used by the store.
func (s *Store) SetLogger(log *zap.Logger) {
	s.log = log
}

// Close closes the underlying database.
func (s *Store) Close() error {
	return s.db.Close()
}

func sqliteFilepath(fp string) string {
	params := []string{
		"_busy_timeout=5000", // 5s
		"_foreign_keys=true",
		"_journal_mode=WAL",
		"_secure_delete=false",
		"_cache_size=-65536", // 64MiB
	}
	return "file:" + fp + "?" + strings.Join(params, "&")
}

// OpenDatabase creates a new SQLite store and initializes the database. If the
// database does not exist, it is created.
func OpenDatabase(fp string, log *zap.Logger) (*Store, error) {
	db, err := sql.Open("sqlite3", sqliteFilepath(fp))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	store := &Store{
		db:  db,
		log: log,
	}
	if err := store.init(); err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}
	return store, nil
}
