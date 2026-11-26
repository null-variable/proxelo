package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"time"

	"github.com/oklog/ulid/v2"
)

// Schema changes are migrations: an ordered list where migration i brings
// a database from version i-1 to i. The version is kept in PRAGMA
// user_version. A new database runs every migration, so a migrated database
// and a new one have the same schema.
//
// To change the schema or the stored JSON, append a migration; never edit
// one that has shipped. Migrations work on SQL and raw JSON, not on the
// model package, whose types change after a migration is written. Each runs
// in one transaction with foreign keys off, so a failure leaves the
// database at the previous version, and a copy of the file is made before
// the first one runs.
type migration struct {
	name string
	up   func(ctx context.Context, tx *sql.Tx) error
}

var migrations = []migration{
	{"initial schema", migrateInitial},
	{"change sets, revision lifecycle, accounts and audit log", migrateChangeSets},
}

// SchemaVersion is the version this binary migrates databases to.
func SchemaVersion() int { return len(migrations) }

func execAll(ctx context.Context, tx *sql.Tx, stmts ...string) error {
	for _, s := range stmts {
		if _, err := tx.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("%w: %s", err, s)
		}
	}
	return nil
}

// migrate brings the database at path up to SchemaVersion. backup, when
// set, receives the file name of a copy made before any migration ran.
func migrate(ctx context.Context, db *sql.DB, path string, now time.Time, log func(string)) error {
	var version, tables int
	if err := db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'resources'`).Scan(&tables); err != nil {
		return err
	}
	// Databases made before migrations existed have the initial schema and
	// version 0.
	if version == 0 && tables > 0 {
		version = 1
	}
	if version > len(migrations) {
		return fmt.Errorf("database schema version %d is newer than this proxelo (%d); use the newer binary or restore a backup", version, len(migrations))
	}
	if version == len(migrations) {
		return nil
	}
	if version > 0 && path != "" {
		backup := fmt.Sprintf("%s.v%d-%s.bak", path, version, now.UTC().Format("20060102T150405Z"))
		if _, err := db.ExecContext(ctx, `VACUUM INTO ?`, backup); err != nil {
			return fmt.Errorf("backup before migrating: %w", err)
		}
		log(fmt.Sprintf("database backed up to %s before migrating from version %d", backup, version))
	}
	// Foreign keys stay off while tables are rebuilt, and are checked at the
	// end of each migration instead.
	if _, err := db.ExecContext(ctx, `PRAGMA foreign_keys = OFF`); err != nil {
		return err
	}
	defer db.ExecContext(ctx, `PRAGMA foreign_keys = ON`)
	for v := version; v < len(migrations); v++ {
		m := migrations[v]
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		err = m.up(ctx, tx)
		if err == nil {
			err = checkForeignKeys(ctx, tx)
		}
		if err == nil {
			_, err = tx.ExecContext(ctx, fmt.Sprintf(`PRAGMA user_version = %d`, v+1))
		}
		if err == nil {
			err = tx.Commit()
		} else {
			tx.Rollback()
		}
		if err != nil {
			return fmt.Errorf("migration %d (%s): %w", v+1, m.name, err)
		}
		if version > 0 {
			log(fmt.Sprintf("database migrated to version %d: %s", v+1, m.name))
		}
	}
	return nil
}

func checkForeignKeys(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		return err
	}
	defer rows.Close()
	if rows.Next() {
		return fmt.Errorf("foreign key check failed")
	}
	return rows.Err()
}

// migrateInitial is the schema before change sets.
func migrateInitial(ctx context.Context, tx *sql.Tx) error {
	return execAll(ctx, tx,
		`CREATE TABLE resources (
			kind    TEXT    NOT NULL,
			id      TEXT    NOT NULL PRIMARY KEY,
			name    TEXT    NOT NULL,
			version INTEGER NOT NULL,
			body    TEXT    NOT NULL,
			UNIQUE (kind, name)
		)`,
		`CREATE TABLE revisions (
			revision   INTEGER NOT NULL PRIMARY KEY,
			created_at TEXT    NOT NULL,
			message    TEXT    NOT NULL,
			hash       BLOB    NOT NULL,
			config     TEXT    NOT NULL,
			snapshot   BLOB    NOT NULL
		)`,
		`CREATE TABLE state (
			key   TEXT NOT NULL PRIMARY KEY,
			value BLOB NOT NULL
		)`,
	)
}

// migrateChangeSets adds change sets, the revision lifecycle, accounts and
// the audit log. Before it the resources table held every edit, applied or
// not; now it holds the head, the resources of the latest revision. Edits
// that were not applied move into a change set, so nothing is lost and
// nothing goes live unreviewed.
func migrateChangeSets(ctx context.Context, tx *sql.Tx) error {
	if err := execAll(ctx, tx,
		`ALTER TABLE revisions ADD COLUMN author TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE revisions ADD COLUMN status TEXT NOT NULL DEFAULT 'confirmed'`,
		`ALTER TABLE revisions ADD COLUMN confirm_by TEXT`,
		`ALTER TABLE revisions ADD COLUMN tag TEXT`,
		`ALTER TABLE revisions ADD COLUMN guard TEXT NOT NULL DEFAULT ''`,
		`CREATE UNIQUE INDEX revisions_tag ON revisions (tag)`,
		`CREATE TABLE changesets (
			id            TEXT    NOT NULL PRIMARY KEY,
			author        TEXT    NOT NULL,
			message       TEXT    NOT NULL,
			base_revision INTEGER NOT NULL,
			created_at    TEXT    NOT NULL,
			updated_at    TEXT    NOT NULL
		)`,
		`CREATE TABLE changeset_items (
			changeset TEXT NOT NULL REFERENCES changesets (id) ON DELETE CASCADE,
			kind      TEXT NOT NULL,
			id        TEXT NOT NULL,
			base      TEXT,
			body      TEXT,
			PRIMARY KEY (changeset, id)
		)`,
		`CREATE TABLE users (
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
		)`,
		`CREATE TABLE sessions (
			hash       BLOB NOT NULL PRIMARY KEY,
			user       TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
			csrf       TEXT NOT NULL,
			created_at TEXT NOT NULL,
			last_seen  TEXT NOT NULL
		)`,
		`CREATE TABLE tokens (
			id         TEXT NOT NULL PRIMARY KEY,
			hash       BLOB NOT NULL,
			user       TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
			name       TEXT NOT NULL,
			role       TEXT NOT NULL,
			cidrs      TEXT NOT NULL,
			expires_at TEXT NOT NULL,
			created_at TEXT NOT NULL,
			last_used  TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE TABLE audit (
			seq    INTEGER NOT NULL PRIMARY KEY,
			at     TEXT    NOT NULL,
			actor  TEXT    NOT NULL,
			action TEXT    NOT NULL,
			target TEXT    NOT NULL,
			detail TEXT    NOT NULL,
			prev   BLOB    NOT NULL,
			hash   BLOB    NOT NULL
		)`,
	); err != nil {
		return err
	}

	type res struct {
		kind, name, body string
		version          int64
	}
	// The head: resources of the latest revision, or none.
	head := map[string]res{}
	var latest int64
	var cfgJSON string
	err := tx.QueryRowContext(ctx, `SELECT revision, config FROM revisions ORDER BY revision DESC LIMIT 1`).Scan(&latest, &cfgJSON)
	switch {
	case err == sql.ErrNoRows:
	case err != nil:
		return err
	default:
		var cfg map[string][]json.RawMessage
		if err := json.Unmarshal([]byte(cfgJSON), &cfg); err != nil {
			return fmt.Errorf("revision %d config: %w", latest, err)
		}
		for kind, list := range cfg {
			for _, raw := range list {
				var meta struct {
					ID              string `json:"id"`
					Name            string `json:"name"`
					ResourceVersion int64  `json:"resourceVersion"`
				}
				if err := json.Unmarshal(raw, &meta); err != nil {
					return fmt.Errorf("revision %d %s: %w", latest, kind, err)
				}
				head[meta.ID] = res{kind: kind, name: meta.Name, body: string(raw), version: meta.ResourceVersion}
			}
		}
	}
	draft := map[string]res{}
	rows, err := tx.QueryContext(ctx, `SELECT kind, id, name, version, body FROM resources`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id string
		var r res
		if err := rows.Scan(&r.kind, &id, &r.name, &r.version, &r.body); err != nil {
			rows.Close()
			return err
		}
		draft[id] = r
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	same := func(a, b string) bool {
		var x, y any
		return json.Unmarshal([]byte(a), &x) == nil && json.Unmarshal([]byte(b), &y) == nil && reflect.DeepEqual(x, y)
	}
	type item struct {
		kind       string
		base, body *string
	}
	items := map[string]item{}
	for id, d := range draft {
		h, ok := head[id]
		switch {
		case !ok:
			items[id] = item{d.kind, nil, &d.body}
		case !same(h.body, d.body):
			items[id] = item{d.kind, &h.body, &d.body}
		}
	}
	for id, h := range head {
		if _, ok := draft[id]; !ok {
			items[id] = item{h.kind, &h.body, nil}
		}
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM resources`); err != nil {
		return err
	}
	for _, id := range slices.Sorted(maps.Keys(head)) {
		h := head[id]
		if _, err := tx.ExecContext(ctx, `INSERT INTO resources (kind, id, name, version, body) VALUES (?, ?, ?, ?, ?)`, h.kind, id, h.name, h.version, h.body); err != nil {
			return err
		}
	}
	if len(items) == 0 {
		return nil
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	cs := "cs_" + ulid.Make().String()
	if _, err := tx.ExecContext(ctx, `INSERT INTO changesets (id, author, message, base_revision, created_at, updated_at) VALUES (?, 'migration', 'unapplied edits from before change sets', ?, ?, ?)`,
		cs, latest, now, now); err != nil {
		return err
	}
	for _, id := range slices.Sorted(maps.Keys(items)) {
		it := items[id]
		if _, err := tx.ExecContext(ctx, `INSERT INTO changeset_items (changeset, kind, id, base, body) VALUES (?, ?, ?, ?, ?)`, cs, it.kind, id, it.base, it.body); err != nil {
			return err
		}
	}
	return nil
}
