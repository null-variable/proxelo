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

// schemaVersion is stored in PRAGMA user_version. Databases of another
// version are refused rather than migrated.
const schemaVersion = 2

const schema = `
CREATE TABLE IF NOT EXISTS resources (
	kind    TEXT    NOT NULL,
	id      TEXT    NOT NULL PRIMARY KEY,
	name    TEXT    NOT NULL,
	version INTEGER NOT NULL,
	body    TEXT    NOT NULL,
	UNIQUE (kind, name)
);
CREATE TABLE IF NOT EXISTS revisions (
	revision   INTEGER NOT NULL PRIMARY KEY,
	created_at TEXT    NOT NULL,
	author     TEXT    NOT NULL,
	message    TEXT    NOT NULL,
	hash       BLOB    NOT NULL,
	config     TEXT    NOT NULL,
	snapshot   BLOB    NOT NULL,
	status     TEXT    NOT NULL,
	confirm_by TEXT,
	tag        TEXT    UNIQUE,
	guard      TEXT    NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS state (
	key   TEXT NOT NULL PRIMARY KEY,
	value BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS changesets (
	id            TEXT    NOT NULL PRIMARY KEY,
	author        TEXT    NOT NULL,
	message       TEXT    NOT NULL,
	base_revision INTEGER NOT NULL,
	created_at    TEXT    NOT NULL,
	updated_at    TEXT    NOT NULL
);
CREATE TABLE IF NOT EXISTS changeset_items (
	changeset TEXT NOT NULL REFERENCES changesets (id) ON DELETE CASCADE,
	kind      TEXT NOT NULL,
	id        TEXT NOT NULL,
	base      TEXT,
	body      TEXT,
	PRIMARY KEY (changeset, id)
);
CREATE TABLE IF NOT EXISTS users (
	id           TEXT    NOT NULL PRIMARY KEY,
	name         TEXT    NOT NULL UNIQUE,
	role         TEXT    NOT NULL,
	password     TEXT    NOT NULL,
	totp_secret  TEXT    NOT NULL DEFAULT '',
	totp_enabled INTEGER NOT NULL DEFAULT 0,
	totp_last    INTEGER NOT NULL DEFAULT 0,
	failures     INTEGER NOT NULL DEFAULT 0,
	locked_until TEXT    NOT NULL DEFAULT '',
	created_at   TEXT    NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
	hash       BLOB NOT NULL PRIMARY KEY,
	user       TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
	csrf       TEXT NOT NULL,
	created_at TEXT NOT NULL,
	last_seen  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tokens (
	id         TEXT NOT NULL PRIMARY KEY,
	hash       BLOB NOT NULL,
	user       TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
	name       TEXT NOT NULL,
	role       TEXT NOT NULL,
	cidrs      TEXT NOT NULL,
	expires_at TEXT NOT NULL,
	created_at TEXT NOT NULL,
	last_used  TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS audit (
	seq    INTEGER NOT NULL PRIMARY KEY,
	at     TEXT    NOT NULL,
	actor  TEXT    NOT NULL,
	action TEXT    NOT NULL,
	target TEXT    NOT NULL,
	detail TEXT    NOT NULL,
	prev   BLOB    NOT NULL,
	hash   BLOB    NOT NULL
);
`

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

// Open opens or creates the database at path.
func Open(path string) (*Store, error) {
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// One connection serializes writers, which SQLite requires anyway, and
	// keeps read-modify-write transactions free of SQLITE_BUSY.
	db.SetMaxOpenConns(1)
	if err := initSchema(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &Store{db: db, now: func() time.Time { return time.Now().UTC().Truncate(time.Millisecond) }}, nil
}

func initSchema(db *sql.DB) error {
	var version, tables int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'`).Scan(&tables); err != nil {
		return err
	}
	if tables > 0 && version != schemaVersion {
		return fmt.Errorf("database schema version %d, want %d: it was made by another proxelo version", version, schemaVersion)
	}
	if _, err := db.Exec(schema); err != nil {
		return err
	}
	_, err := db.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, schemaVersion))
	return err
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
