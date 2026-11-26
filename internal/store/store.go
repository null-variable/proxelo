// Package store keeps the control plane state in SQLite: the resources of
// the current revision (the head), change sets edited on top of it, applied
// revisions, admin accounts and the audit log.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/null-variable/proxelo/internal/model"
)

var (
	ErrNotFound = errors.New("not found")
	// ErrConflict means the resource changed since the version the caller read.
	ErrConflict = errors.New("resource version mismatch")
	// ErrNameTaken means another resource of the same kind has the name.
	ErrNameTaken = errors.New("name already in use")
	// ErrPending means a revision awaits confirmation; it must be confirmed
	// or rolled back before another is applied.
	ErrPending = errors.New("a revision is pending confirmation")
	// ErrNotPending means the revision is not awaiting confirmation.
	ErrNotPending = errors.New("revision is not pending confirmation")
)

// Store is safe for concurrent use.
type Store struct {
	db  *sql.DB
	now func() time.Time
}

// dbtx is satisfied by *sql.DB and *sql.Tx.
type dbtx interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// Open opens or creates the database at path and migrates it to the
// current schema (see migrate.go). log receives one line per migration
// step; nil discards them.
func Open(path string, log func(string)) (*Store, error) {
	if log == nil {
		log = func(string) {}
	}
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// One connection serializes writers, which SQLite requires anyway, and
	// keeps read-modify-write transactions free of SQLITE_BUSY.
	db.SetMaxOpenConns(1)
	now := time.Now()
	if err := migrate(context.Background(), db, path, now, log); err != nil {
		db.Close()
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &Store{db: db, now: func() time.Time { return time.Now().UTC().Truncate(time.Millisecond) }}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) tx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

func mapErr(err error) error {
	if err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed: resources.kind, resources.name") {
		return ErrNameTaken
	}
	return err
}

func errorsContains(err error, s string) bool {
	return err != nil && strings.Contains(err.Error(), s)
}

func formatTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339Nano, s)
}

func decode(kind model.Kind, body string) (model.Resource, error) {
	r := kind.New()
	if err := json.Unmarshal([]byte(body), r); err != nil {
		return nil, fmt.Errorf("stored %s: %w", kind.Plural, err)
	}
	return r, nil
}

// headList returns the head resources of kind.
func headList(ctx context.Context, q dbtx, kind model.Kind) ([]model.Resource, error) {
	rows, err := q.QueryContext(ctx, `SELECT body FROM resources WHERE kind = ? ORDER BY name`, kind.Plural)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Resource
	for rows.Next() {
		var body string
		if err := rows.Scan(&body); err != nil {
			return nil, err
		}
		r, err := decode(kind, body)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// headRow is one stored head resource.
type headRow struct {
	kind    string
	version int64
	body    string
}

func getHead(ctx context.Context, q dbtx, id string) (*headRow, error) {
	h := &headRow{}
	err := q.QueryRowContext(ctx, `SELECT kind, version, body FROM resources WHERE id = ?`, id).Scan(&h.kind, &h.version, &h.body)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return h, err
}

func loadConfig(ctx context.Context, q dbtx) (model.Config, error) {
	var cfg model.Config
	rows, err := q.QueryContext(ctx, `SELECT kind, body FROM resources ORDER BY id`)
	if err != nil {
		return cfg, err
	}
	defer rows.Close()
	for rows.Next() {
		var plural, body string
		if err := rows.Scan(&plural, &body); err != nil {
			return cfg, err
		}
		kind, ok := model.KindByPlural(plural)
		if !ok {
			return cfg, fmt.Errorf("stored resource of unknown kind %q", plural)
		}
		r, err := decode(kind, body)
		if err != nil {
			return cfg, err
		}
		cfg.Add(r)
	}
	return cfg, rows.Err()
}

// Head returns the resources of the current revision, including
// certificates the control plane issued since.
func (s *Store) Head(ctx context.Context) (model.Config, error) {
	return loadConfig(ctx, s.db)
}

// putHead stores r in the head as the next version of what is there.
func (s *Store) putHead(ctx context.Context, q dbtx, kind model.Kind, r model.Resource) error {
	m := r.Common()
	cur, err := getHead(ctx, q, m.ID)
	if err != nil {
		return err
	}
	m.UpdatedAt = s.now()
	if cur == nil {
		m.ResourceVersion = 1
		if m.CreatedAt.IsZero() {
			m.CreatedAt = m.UpdatedAt
		}
	} else {
		m.ResourceVersion = cur.version + 1
	}
	body, err := json.Marshal(r)
	if err != nil {
		return err
	}
	_, err = q.ExecContext(ctx, `INSERT INTO resources (kind, id, name, version, body) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET name = excluded.name, version = excluded.version, body = excluded.body`,
		kind.Plural, m.ID, m.Name, m.ResourceVersion, string(body))
	return mapErr(err)
}

// Put stores a control plane value, such as the ACME account.
func (s *Store) Put(ctx context.Context, key string, value []byte) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO state (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// Value returns a value stored with Put, or ErrNotFound.
func (s *Store) Value(ctx context.Context, key string) ([]byte, error) {
	var v []byte
	err := s.db.QueryRowContext(ctx, `SELECT value FROM state WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return v, err
}

// DeleteValue removes a value stored with Put.
func (s *Store) DeleteValue(ctx context.Context, key string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM state WHERE key = ?`, key)
	return err
}

// SetCertificate stores an issued chain and key, or only a status, on head
// certificate id, keeping the rest of the resource, and returns it. Change
// sets that edit the certificate merge onto it when applied.
func (s *Store) SetCertificate(ctx context.Context, id string, chainPEM, keyPEM string, status model.CertStatus) (*model.Certificate, error) {
	var out *model.Certificate
	err := s.tx(ctx, func(tx *sql.Tx) error {
		h, err := getHead(ctx, tx, id)
		if err != nil {
			return err
		}
		if h == nil || h.kind != model.CertificateKind.Plural {
			return ErrNotFound
		}
		r, err := decode(model.CertificateKind, h.body)
		if err != nil {
			return err
		}
		c := r.(*model.Certificate)
		issued := c.Spec.ChainPEM != chainPEM
		c.Spec.ChainPEM, c.Spec.KeyPEM, c.Spec.Status = chainPEM, keyPEM, status
		if err := s.putHead(ctx, tx, model.CertificateKind, c); err != nil {
			return err
		}
		if issued {
			if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO state (key, value) VALUES (?, x'01')`, headDirty); err != nil {
				return err
			}
		}
		out = c
		return nil
	})
	return out, err
}

// sortByName orders resources as List returns them.
func sortByName(rs []model.Resource) {
	slices.SortFunc(rs, func(a, b model.Resource) int { return strings.Compare(a.Common().Name, b.Common().Name) })
}
