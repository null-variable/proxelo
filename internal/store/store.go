// Package store keeps resources and revisions in SQLite.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"
	_ "modernc.org/sqlite"

	"github.com/null-variable/proxelo/internal/compile"
	"github.com/null-variable/proxelo/internal/model"
)

var (
	ErrNotFound = errors.New("not found")
	// ErrConflict means the resource changed since the version the caller read.
	ErrConflict = errors.New("resource version mismatch")
	// ErrNameTaken means another resource of the same kind has the name.
	ErrNameTaken = errors.New("name already in use")
)

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
	message    TEXT    NOT NULL,
	hash       BLOB    NOT NULL,
	config     TEXT    NOT NULL,
	snapshot   BLOB    NOT NULL
);
`

// Store is safe for concurrent use.
type Store struct {
	db  *sql.DB
	now func() time.Time
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
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &Store{db: db, now: func() time.Time { return time.Now().UTC().Truncate(time.Millisecond) }}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// List returns every resource of kind ordered by name.
func (s *Store) List(ctx context.Context, kind model.Kind) ([]model.Resource, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT body FROM resources WHERE kind = ? ORDER BY name`, kind.Plural)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Resource
	for rows.Next() {
		r, err := scan(kind, rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Get returns one resource.
func (s *Store) Get(ctx context.Context, kind model.Kind, id string) (model.Resource, error) {
	return get(ctx, s.db, kind, id)
}

type querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func get(ctx context.Context, q querier, kind model.Kind, id string) (model.Resource, error) {
	row := q.QueryRowContext(ctx, `SELECT body FROM resources WHERE kind = ? AND id = ?`, kind.Plural, id)
	r, err := scan(kind, row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return r, err
}

func scan(kind model.Kind, row interface{ Scan(...any) error }) (model.Resource, error) {
	var body string
	if err := row.Scan(&body); err != nil {
		return nil, err
	}
	r := kind.New()
	if err := json.Unmarshal([]byte(body), r); err != nil {
		return nil, fmt.Errorf("stored %s: %w", kind.Plural, err)
	}
	return r, nil
}

// Create assigns the ID, version and timestamps of r and stores it.
// r must pass model.Validate.
func (s *Store) Create(ctx context.Context, kind model.Kind, r model.Resource) error {
	m := r.Common()
	m.ID = kind.NewID()
	m.ResourceVersion = 1
	m.CreatedAt = s.now()
	m.UpdatedAt = m.CreatedAt
	body, err := json.Marshal(r)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO resources (kind, id, name, version, body) VALUES (?, ?, ?, ?, ?)`,
		kind.Plural, m.ID, m.Name, m.ResourceVersion, string(body))
	return mapErr(err)
}

// Update replaces the stored resource with r, keeping its ID and creation
// time. If version is non-zero it must equal the stored version.
// r must pass model.Validate.
func (s *Store) Update(ctx context.Context, kind model.Kind, id string, version int64, r model.Resource) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		cur, err := get(ctx, tx, kind, id)
		if err != nil {
			return err
		}
		cm := cur.Common()
		if version != 0 && version != cm.ResourceVersion {
			return ErrConflict
		}
		m := r.Common()
		m.ID = id
		m.ResourceVersion = cm.ResourceVersion + 1
		m.CreatedAt = cm.CreatedAt
		m.UpdatedAt = s.now()
		body, err := json.Marshal(r)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE resources SET name = ?, version = ?, body = ? WHERE id = ?`,
			m.Name, m.ResourceVersion, string(body), id)
		return mapErr(err)
	})
}

// Delete removes a resource. If version is non-zero it must equal the stored
// version.
func (s *Store) Delete(ctx context.Context, kind model.Kind, id string, version int64) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		cur, err := get(ctx, tx, kind, id)
		if err != nil {
			return err
		}
		if version != 0 && version != cur.Common().ResourceVersion {
			return ErrConflict
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM resources WHERE id = ?`, id)
		return err
	})
}

// Revision is an applied, immutable copy of all resources and the snapshot
// compiled from them.
type Revision struct {
	Revision  uint64       `json:"revision"`
	CreatedAt time.Time    `json:"createdAt"`
	Message   string       `json:"message"`
	Hash      []byte       `json:"hash"`
	Config    model.Config `json:"-"`
	Snapshot  []byte       `json:"-"`
}

// Draft returns the current resources, applied or not.
func (s *Store) Draft(ctx context.Context) (model.Config, error) {
	return loadConfig(ctx, s.db)
}

type rowsQuerier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func loadConfig(ctx context.Context, q rowsQuerier) (model.Config, error) {
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
		r := kind.New()
		if err := json.Unmarshal([]byte(body), r); err != nil {
			return cfg, err
		}
		cfg.Add(r)
	}
	return cfg, rows.Err()
}

// Apply compiles the current resources into the next revision and stores it.
// A compile failure returns model.FieldErrors and stores nothing. verify, when
// set, sees the serialized snapshot before it is stored and can reject it.
func (s *Store) Apply(ctx context.Context, message string, verify func(snapshot []byte) error) (*Revision, error) {
	var rev *Revision
	err := s.tx(ctx, func(tx *sql.Tx) error {
		cfg, err := loadConfig(ctx, tx)
		if err != nil {
			return err
		}

		var last uint64
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(revision), 0) FROM revisions`).Scan(&last); err != nil {
			return err
		}
		snap, err := compile.Compile(cfg, last+1)
		if err != nil {
			return err
		}
		snapBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(snap)
		if err != nil {
			return err
		}
		if verify != nil {
			if err := verify(snapBytes); err != nil {
				return err
			}
		}
		cfgJSON, err := json.Marshal(cfg)
		if err != nil {
			return err
		}
		rev = &Revision{Revision: last + 1, CreatedAt: s.now(), Message: message, Hash: snap.GetHash(), Config: cfg, Snapshot: snapBytes}
		_, err = tx.ExecContext(ctx, `INSERT INTO revisions (revision, created_at, message, hash, config, snapshot) VALUES (?, ?, ?, ?, ?, ?)`,
			rev.Revision, rev.CreatedAt.Format(time.RFC3339Nano), message, rev.Hash, string(cfgJSON), snapBytes)
		return err
	})
	if err != nil {
		return nil, err
	}
	return rev, nil
}

// Revisions returns all revisions, newest first, without config and snapshot.
func (s *Store) Revisions(ctx context.Context) ([]*Revision, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT revision, created_at, message, hash FROM revisions ORDER BY revision DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Revision
	for rows.Next() {
		rev, err := scanRevision(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rev)
	}
	return out, rows.Err()
}

// Latest returns the newest revision, or ErrNotFound if none was applied.
func (s *Store) Latest(ctx context.Context) (*Revision, error) {
	var n uint64
	if err := s.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(revision), 0) FROM revisions`).Scan(&n); err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, ErrNotFound
	}
	return s.Revision(ctx, n)
}

// Revision returns one revision with its config and snapshot.
func (s *Store) Revision(ctx context.Context, n uint64) (*Revision, error) {
	row := s.db.QueryRowContext(ctx, `SELECT revision, created_at, message, hash, config, snapshot FROM revisions WHERE revision = ?`, n)
	var cfg string
	var snap []byte
	rev, err := scanRevision(row, &cfg, &snap)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(cfg), &rev.Config); err != nil {
		return nil, fmt.Errorf("revision %d config: %w", n, err)
	}
	rev.Snapshot = snap
	return rev, nil
}

func scanRevision(row interface{ Scan(...any) error }, extra ...any) (*Revision, error) {
	var rev Revision
	var created string
	if err := row.Scan(append([]any{&rev.Revision, &created, &rev.Message, &rev.Hash}, extra...)...); err != nil {
		return nil, err
	}
	t, err := time.Parse(time.RFC3339Nano, created)
	if err != nil {
		return nil, err
	}
	rev.CreatedAt = t
	return &rev, nil
}

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
