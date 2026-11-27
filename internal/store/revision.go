package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/null-variable/proxelo/internal/compile"
	"github.com/null-variable/proxelo/internal/model"
)

// Keep is how many revisions are retained; tagged ones are kept forever.
const Keep = 500

// RevisionStatus is where a revision is in commit-confirm.
type RevisionStatus string

const (
	// Applied and waiting for Confirm before ConfirmBy.
	StatusPending   RevisionStatus = "pending"
	StatusConfirmed RevisionStatus = "confirmed"
	// Was pending and got rolled back, by timeout, guard or hand.
	StatusReverted RevisionStatus = "reverted"
)

// Revision is an applied, immutable copy of all resources and the snapshot
// compiled from them.
type Revision struct {
	Revision  uint64         `json:"revision"`
	CreatedAt time.Time      `json:"createdAt"`
	Author    string         `json:"author"`
	Message   string         `json:"message"`
	Hash      []byte         `json:"hash"`
	Status    RevisionStatus `json:"status"`
	ConfirmBy time.Time      `json:"confirmBy,omitzero"`
	Tag       string         `json:"tag,omitempty"`
	// Set by the guard when traffic got worse while pending.
	Guard string `json:"guard,omitempty"`
	// Groups of the resources this revision added, changed or removed.
	Groups   []string     `json:"groups,omitempty"`
	Config   model.Config `json:"-"`
	Snapshot []byte       `json:"-"`
}

// Verify sees a serialized snapshot before its revision is stored and can
// reject it.
type Verify func(snapshot []byte) error

// headDirty is set while the head holds changes no revision has, such as
// an issued certificate.
const headDirty = "head/dirty"

func latestRevision(ctx context.Context, q dbtx) (uint64, error) {
	var n uint64
	err := q.QueryRowContext(ctx, `SELECT COALESCE(MAX(revision), 0) FROM revisions`).Scan(&n)
	return n, err
}

func pendingRevision(ctx context.Context, q dbtx) (uint64, error) {
	var n uint64
	err := q.QueryRowContext(ctx, `SELECT revision FROM revisions WHERE status = ?`, StatusPending).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return n, err
}

// newRevision compiles the head into the next revision and stores it.
func (s *Store) newRevision(ctx context.Context, tx *sql.Tx, author, message string, confirmBy time.Time, verify Verify) (*Revision, error) {
	cfg, err := loadConfig(ctx, tx)
	if err != nil {
		return nil, err
	}
	last, err := latestRevision(ctx, tx)
	if err != nil {
		return nil, err
	}
	snap, err := compile.Compile(cfg, last+1)
	if err != nil {
		return nil, err
	}
	if len(snap.GetWasmModules()) > 0 {
		known, err := wasmKnown(ctx, tx)
		if err != nil {
			return nil, err
		}
		var fe model.FieldErrors
		for _, m := range snap.GetWasmModules() {
			if !known[m.GetSha256()] {
				fe = append(fe, model.FieldError{Path: "policies", Message: fmt.Sprintf("wasm module %s is not uploaded", m.GetSha256())})
			}
		}
		if len(fe) > 0 {
			return nil, fe
		}
	}
	snapBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(snap)
	if err != nil {
		return nil, err
	}
	if verify != nil {
		if err := verify(snapBytes); err != nil {
			return nil, err
		}
	}
	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	var prev model.Config
	if last > 0 {
		p, err := revision(ctx, tx, last)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return nil, err
		}
		if p != nil {
			prev = p.Config
		}
	}
	groups := touchedGroups(prev, cfg)
	groupsJSON, _ := json.Marshal(groups)
	rev := &Revision{
		Revision: last + 1, CreatedAt: s.now(), Author: author, Message: message,
		Hash: snap.GetHash(), Status: StatusConfirmed, Config: cfg, Snapshot: snapBytes, Groups: groups,
	}
	var by any
	if !confirmBy.IsZero() {
		rev.Status, rev.ConfirmBy = StatusPending, confirmBy.UTC().Truncate(time.Millisecond)
		by = formatTime(rev.ConfirmBy)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO revisions (revision, created_at, author, message, hash, config, snapshot, status, confirm_by, groups) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rev.Revision, formatTime(rev.CreatedAt), author, message, rev.Hash, string(cfgJSON), snapBytes, rev.Status, by, string(groupsJSON)); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM state WHERE key = ?`, headDirty); err != nil {
		return nil, err
	}
	// Retention never drops the last confirmed or a pending revision: both
	// are among the newest.
	if _, err := tx.ExecContext(ctx, `DELETE FROM revisions WHERE revision <= ? AND tag IS NULL`, int64(rev.Revision)-Keep); err != nil {
		return nil, err
	}
	return rev, nil
}

// ApplyChangeSet merges change set cs into the head and stores the next
// revision. With a non-zero confirmBy the revision is pending until
// Confirm; otherwise it is confirmed. A merge conflict or compile failure
// returns model.FieldErrors and changes nothing; on success cs is removed.
func (s *Store) ApplyChangeSet(ctx context.Context, cs, author string, confirmBy time.Time, verify Verify) (*Revision, error) {
	var rev *Revision
	err := s.tx(ctx, func(tx *sql.Tx) error {
		c, err := changeSet(ctx, tx, cs)
		if err != nil {
			return err
		}
		if p, err := pendingRevision(ctx, tx); err != nil {
			return err
		} else if p != 0 {
			return fmt.Errorf("revision %d: %w", p, ErrPending)
		}
		if err := s.mergeItems(ctx, tx, cs); err != nil {
			return err
		}
		if rev, err = s.newRevision(ctx, tx, author, c.Message, confirmBy, verify); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM changesets WHERE id = ?`, cs)
		return err
	})
	return rev, err
}

// ApplyHead stores the head as the next confirmed revision if it holds
// changes the control plane made itself since the last one, such as an
// issued certificate. It returns nil when there is nothing to apply and
// ErrPending while a revision awaits confirmation.
func (s *Store) ApplyHead(ctx context.Context, author, message string, verify Verify) (*Revision, error) {
	var rev *Revision
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var one int
		err := tx.QueryRowContext(ctx, `SELECT 1 FROM state WHERE key = ?`, headDirty).Scan(&one)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if p, err := pendingRevision(ctx, tx); err != nil {
			return err
		} else if p != 0 {
			return fmt.Errorf("revision %d: %w", p, ErrPending)
		}
		if n, err := latestRevision(ctx, tx); err != nil {
			return err
		} else if n == 0 {
			return nil // nothing applied yet; the first apply includes it
		}
		rev, err = s.newRevision(ctx, tx, author, message, time.Time{}, verify)
		return err
	})
	return rev, err
}

// Confirm marks pending revision n confirmed.
func (s *Store) Confirm(ctx context.Context, n uint64) (*Revision, error) {
	err := s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE revisions SET status = ?, confirm_by = NULL WHERE revision = ? AND status = ?`, StatusConfirmed, n, StatusPending)
		if err != nil {
			return err
		}
		if k, _ := res.RowsAffected(); k == 0 {
			if _, err := revision(ctx, tx, n); err != nil {
				return err
			}
			return ErrNotPending
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return s.Revision(ctx, n)
}

// Rollback replaces the head with the resources of revision to (0: none) and stores
// them as the next revision, so history stays linear. A
// pending revision is marked reverted. ACME certificates keep the chain and
// key the head has, so a rollback never brings back an expired one.
func (s *Store) Rollback(ctx context.Context, to uint64, author, message string, confirmBy time.Time, verify Verify) (*Revision, error) {
	var rev *Revision
	err := s.tx(ctx, func(tx *sql.Tx) error {
		// Revision 0 is the empty configuration before the first apply.
		var cfg model.Config
		if to != 0 {
			target, err := revision(ctx, tx, to)
			if err != nil {
				return err
			}
			cfg = target.Config
		}
		if _, err := tx.ExecContext(ctx, `UPDATE revisions SET status = ?, confirm_by = NULL WHERE status = ?`, StatusReverted, StatusPending); err != nil {
			return err
		}
		if err := s.replaceHead(ctx, tx, cfg); err != nil {
			return err
		}
		var err error
		rev, err = s.newRevision(ctx, tx, author, message, confirmBy, verify)
		return err
	})
	return rev, err
}

// LastConfirmed returns the newest confirmed revision.
func (s *Store) LastConfirmed(ctx context.Context) (*Revision, error) {
	var n uint64
	err := s.db.QueryRowContext(ctx, `SELECT revision FROM revisions WHERE status = ? ORDER BY revision DESC LIMIT 1`, StatusConfirmed).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return s.Revision(ctx, n)
}

// Pending returns the revision awaiting confirmation, or ErrNotFound.
func (s *Store) Pending(ctx context.Context) (*Revision, error) {
	n, err := pendingRevision(ctx, s.db)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, ErrNotFound
	}
	return s.Revision(ctx, n)
}

// SetGuard records a guard finding on revision n.
func (s *Store) SetGuard(ctx context.Context, n uint64, finding string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE revisions SET guard = ? WHERE revision = ?`, finding, n)
	return err
}

// SetTag names revision n, which retention then keeps; "" removes the tag.
func (s *Store) SetTag(ctx context.Context, n uint64, tag string) error {
	var t any
	if tag != "" {
		t = tag
	}
	res, err := s.db.ExecContext(ctx, `UPDATE revisions SET tag = ? WHERE revision = ?`, t, n)
	if err != nil {
		if errorsContains(err, "UNIQUE constraint failed: revisions.tag") {
			return ErrNameTaken
		}
		return err
	}
	if k, _ := res.RowsAffected(); k == 0 {
		return ErrNotFound
	}
	return nil
}

// replaceHead makes the head hold exactly cfg.
func (s *Store) replaceHead(ctx context.Context, tx *sql.Tx, cfg model.Config) error {
	head, err := loadConfig(ctx, tx)
	if err != nil {
		return err
	}
	certs := map[string]*model.Certificate{}
	for _, c := range head.Certificates {
		certs[c.ID] = c
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM resources`); err != nil {
		return err
	}
	for _, k := range model.Kinds {
		for _, r := range cfg.Of(k) {
			if c, ok := r.(*model.Certificate); ok && c.Spec.Source == model.CertACME {
				if cur := certs[c.ID]; cur != nil && cur.Spec.Source == model.CertACME && cur.Spec.Status.NotAfter.After(c.Spec.Status.NotAfter) {
					c.Spec.ChainPEM, c.Spec.KeyPEM, c.Spec.Status = cur.Spec.ChainPEM, cur.Spec.KeyPEM, cur.Spec.Status
				}
			}
			if err := s.putHead(ctx, tx, k, r); err != nil {
				return err
			}
		}
	}
	return nil
}

// Revisions returns all revisions, newest first, without config and snapshot.
func (s *Store) Revisions(ctx context.Context) ([]*Revision, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+revisionCols+` FROM revisions ORDER BY revision DESC`)
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
	n, err := latestRevision(ctx, s.db)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, ErrNotFound
	}
	return s.Revision(ctx, n)
}

// Revision returns one revision with its config and snapshot.
func (s *Store) Revision(ctx context.Context, n uint64) (*Revision, error) {
	return revision(ctx, s.db, n)
}

const revisionCols = `revision, created_at, author, message, hash, status, COALESCE(confirm_by, ''), COALESCE(tag, ''), guard, groups`

func revision(ctx context.Context, q dbtx, n uint64) (*Revision, error) {
	row := q.QueryRowContext(ctx, `SELECT `+revisionCols+`, config, snapshot FROM revisions WHERE revision = ?`, n)
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
	var created, confirmBy, groups string
	if err := row.Scan(append([]any{&rev.Revision, &created, &rev.Author, &rev.Message, &rev.Hash, &rev.Status, &confirmBy, &rev.Tag, &rev.Guard, &groups}, extra...)...); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(groups), &rev.Groups); err != nil {
		return nil, err
	}
	var err error
	if rev.CreatedAt, err = parseTime(created); err != nil {
		return nil, err
	}
	if rev.ConfirmBy, err = parseTime(confirmBy); err != nil {
		return nil, err
	}
	return &rev, nil
}

// touchedGroups lists, sorted, the groups of resources that differ between
// prev and next, with both the old and the new group of a moved resource.
func touchedGroups(prev, next model.Config) []string {
	body := func(r model.Resource) string {
		b, _ := json.Marshal(r)
		return string(b)
	}
	old := map[string]model.Resource{}
	for _, k := range model.Kinds {
		for _, r := range prev.Of(k) {
			old[r.Common().ID] = r
		}
	}
	set := map[string]bool{}
	mark := func(r model.Resource) {
		if g := r.Common().Group; g != "" {
			set[g] = true
		}
	}
	for _, k := range model.Kinds {
		for _, r := range next.Of(k) {
			o, ok := old[r.Common().ID]
			delete(old, r.Common().ID)
			if ok && body(o) == body(r) {
				continue
			}
			mark(r)
			if ok {
				mark(o)
			}
		}
	}
	for _, r := range old {
		mark(r)
	}
	out := make([]string, 0, len(set))
	for g := range set {
		out = append(out, g)
	}
	slices.Sort(out)
	return out
}
