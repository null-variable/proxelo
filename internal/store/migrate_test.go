package store

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// TestMigrateLegacy opens a database made before migrations existed: the
// initial schema at user_version 0, with revision 1 applied and edits made
// after it. The head becomes revision 1's resources and the edits move into
// a change set.
func TestMigrateLegacy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "old.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tx, _ := db.Begin()
	if err := migrateInitial(ctx, tx); err != nil {
		t.Fatal(err)
	}
	tx.Commit()
	lst := `{"id":"lst_a","name":"http","resourceVersion":1,"createdAt":"2026-01-01T00:00:00Z","updatedAt":"2026-01-01T00:00:00Z","spec":{"address":"0.0.0.0:80"}}`
	lstEdited := strings.Replace(lst, `"0.0.0.0:80"`, `"0.0.0.0:8080"`, 1)
	lstEdited = strings.Replace(lstEdited, `"resourceVersion":1`, `"resourceVersion":2`, 1)
	up := `{"id":"up_a","name":"api","resourceVersion":1,"createdAt":"2026-01-01T00:00:00Z","updatedAt":"2026-01-01T00:00:00Z","spec":{"targets":[{"address":"127.0.0.1:9000"}],"keepalive":{}}}`
	newUp := strings.ReplaceAll(strings.Replace(up, `"api"`, `"api2"`, 1), "up_a", "up_b")
	for _, q := range []string{
		`INSERT INTO revisions VALUES (1, '2026-01-01T00:00:00Z', 'first', x'00', '{"listeners":[` + lst + `],"upstreams":[` + up + `]}', x'')`,
		// After revision 1: the listener was edited, up_a deleted, up_b added.
		`INSERT INTO resources VALUES ('listeners', 'lst_a', 'http', 2, '` + lstEdited + `')`,
		`INSERT INTO resources VALUES ('upstreams', 'up_b', 'api2', 1, '` + newUp + `')`,
		`INSERT INTO state VALUES ('acme/account/x', x'01')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%v: %s", err, q)
		}
	}
	db.Close()

	var logs []string
	st, err := Open(path, func(m string) { logs = append(logs, m) })
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	var v int
	st.db.QueryRow(`PRAGMA user_version`).Scan(&v)
	if v != SchemaVersion() || len(logs) != 2 {
		t.Fatalf("version %d, logs %q", v, logs)
	}
	baks, _ := filepath.Glob(filepath.Join(dir, "old.db.v1-*.bak"))
	if len(baks) != 1 {
		t.Fatalf("backups = %v", baks)
	}
	if fi, err := os.Stat(baks[0]); err != nil || fi.Size() == 0 {
		t.Fatalf("backup: %v", err)
	}

	head, err := st.Head(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(head.Listeners) != 1 || head.Listeners[0].Spec.Address != "0.0.0.0:80" || len(head.Upstreams) != 1 || head.Upstreams[0].ID != "up_a" {
		t.Fatalf("head = %+v %+v", head.Listeners, head.Upstreams)
	}
	rev, err := st.Revision(ctx, 1)
	if err != nil || rev.Status != StatusConfirmed {
		t.Fatalf("revision 1 = %+v, %v", rev, err)
	}
	css, _ := st.ChangeSets(ctx)
	if len(css) != 1 {
		t.Fatalf("change sets = %+v", css)
	}
	ops := map[string]Op{}
	for _, it := range css[0].Items {
		ops[it.ID] = it.Op
	}
	if want := map[string]Op{"lst_a": OpUpdate, "up_a": OpDelete, "up_b": OpCreate}; !reflect.DeepEqual(ops, want) {
		t.Fatalf("items = %v", ops)
	}
	view, err := st.View(ctx, css[0].ID)
	if err != nil || view.Listeners[0].Spec.Address != "0.0.0.0:8080" || len(view.Upstreams) != 1 || view.Upstreams[0].ID != "up_b" {
		t.Fatalf("view = %+v, %v", view, err)
	}
	if _, err := st.Value(ctx, "acme/account/x"); err != nil {
		t.Fatal("state lost")
	}
	// The migrated change set applies.
	if _, err := st.ApplyChangeSet(ctx, css[0].ID, "t", time.Time{}, nil); err != nil {
		t.Fatal(err)
	}
	head, _ = st.Head(ctx)
	if head.Listeners[0].Spec.Address != "0.0.0.0:8080" {
		t.Fatalf("after apply = %+v", head.Listeners[0].Spec)
	}

	// Opening again runs nothing.
	st.Close()
	logs = nil
	st2, err := Open(path, func(m string) { logs = append(logs, m) })
	if err != nil || len(logs) != 0 {
		t.Fatalf("reopen: %v %q", err, logs)
	}
	st2.Close()
}

// A new database and a migrated one have the same schema.
func TestNewAndMigratedSchemasMatch(t *testing.T) {
	dir := t.TempDir()
	fresh, err := Open(filepath.Join(dir, "new.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	path := filepath.Join(dir, "old.db")
	db, _ := sql.Open("sqlite", "file:"+path)
	tx, _ := db.Begin()
	migrateInitial(context.Background(), tx)
	tx.Commit()
	db.Close()
	old, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	if a, b := schemaOf(t, fresh.db), schemaOf(t, old.db); a != b {
		t.Fatalf("schemas differ:\n%s\n---\n%s", a, b)
	}
}

func schemaOf(t *testing.T, db *sql.DB) string {
	rows, err := db.Query(`SELECT name, sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var b strings.Builder
	for rows.Next() {
		var n, s string
		rows.Scan(&n, &s)
		b.WriteString(n + ": " + s + "\n")
	}
	return b.String()
}

func TestNewerSchemaRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "t.db")
	st, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	st.db.Exec(`PRAGMA user_version = 999`)
	st.Close()
	if _, err := Open(path, nil); err == nil || !strings.Contains(err.Error(), "newer") {
		t.Fatalf("err = %v", err)
	}
}
