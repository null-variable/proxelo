package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
)

// WasmModule is an uploaded WebAssembly module, named by the SHA-256 of
// its bytes.
type WasmModule struct {
	SHA256    string `json:"sha256"`
	Name      string `json:"name"`
	Size      int64  `json:"size"`
	CreatedAt string `json:"createdAt"`
}

func migrateWasm(ctx context.Context, tx *sql.Tx) error {
	return execAll(ctx, tx,
		`CREATE TABLE wasm_modules (
			sha256 TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			size INTEGER NOT NULL,
			created_at TEXT NOT NULL,
			bytes BLOB NOT NULL
		)`,
	)
}

// PutWasm stores a module and returns it; storing the same bytes again
// keeps the first name.
func (s *Store) PutWasm(ctx context.Context, name string, b []byte) (*WasmModule, error) {
	sum := sha256.Sum256(b)
	m := &WasmModule{SHA256: hex.EncodeToString(sum[:]), Name: name, Size: int64(len(b)), CreatedAt: formatTime(s.now())}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO wasm_modules (sha256, name, size, created_at, bytes) VALUES (?, ?, ?, ?, ?) ON CONFLICT (sha256) DO NOTHING`,
		m.SHA256, m.Name, m.Size, m.CreatedAt, b); err != nil {
		return nil, err
	}
	return s.wasm(ctx, m.SHA256)
}

func (s *Store) wasm(ctx context.Context, sha string) (*WasmModule, error) {
	m := &WasmModule{}
	err := s.db.QueryRowContext(ctx, `SELECT sha256, name, size, created_at FROM wasm_modules WHERE sha256 = ?`, sha).
		Scan(&m.SHA256, &m.Name, &m.Size, &m.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return m, err
}

// WasmModules lists the stored modules, newest first.
func (s *Store) WasmModules(ctx context.Context) ([]*WasmModule, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT sha256, name, size, created_at FROM wasm_modules ORDER BY created_at DESC, sha256`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*WasmModule{}
	for rows.Next() {
		m := &WasmModule{}
		if err := rows.Scan(&m.SHA256, &m.Name, &m.Size, &m.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// WasmBytes returns the bytes of a stored module.
func (s *Store) WasmBytes(ctx context.Context, sha string) ([]byte, error) {
	var b []byte
	err := s.db.QueryRowContext(ctx, `SELECT bytes FROM wasm_modules WHERE sha256 = ?`, sha).Scan(&b)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return b, err
}

// DeleteWasm removes a module. Revisions kept that use it can no longer be
// sent to a proxy that lacks it.
func (s *Store) DeleteWasm(ctx context.Context, sha string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM wasm_modules WHERE sha256 = ?`, sha)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// wasmKnown is the set of stored module hashes.
func wasmKnown(ctx context.Context, q dbtx) (map[string]bool, error) {
	rows, err := q.QueryContext(ctx, `SELECT sha256 FROM wasm_modules`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		out[h] = true
	}
	return out, rows.Err()
}
