package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/null-variable/proxelo/internal/diff"
	"github.com/null-variable/proxelo/internal/model"
)

// ChangeSet is a draft of edits on top of the head. Reads in a
// change set see the head with its edits applied.
type ChangeSet struct {
	ID      string `json:"id"`
	Author  string `json:"author"`
	Message string `json:"message"`
	// Latest revision when the change set was created.
	BaseRevision uint64    `json:"baseRevision"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
	Items        []Item    `json:"items"`
}

// Op is what a change set does to one resource.
type Op string

const (
	OpCreate Op = "create"
	OpUpdate Op = "update"
	OpDelete Op = "delete"
)

// Item is one resource a change set touches.
type Item struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
	Op   Op     `json:"op"`
}

// item is a stored change set item. base is the head body when the change
// set first touched the resource, nil for one it created; body is the
// desired resource, nil to delete it.
type item struct {
	kind string
	id   string
	base *string
	body *string
}

func (it *item) op() Op {
	switch {
	case it.base == nil:
		return OpCreate
	case it.body == nil:
		return OpDelete
	}
	return OpUpdate
}

// CreateChangeSet starts an empty change set.
func (s *Store) CreateChangeSet(ctx context.Context, author, message string) (*ChangeSet, error) {
	cs := &ChangeSet{ID: "cs_" + ulid.Make().String(), Author: author, Message: message, CreatedAt: s.now(), Items: []Item{}}
	cs.UpdatedAt = cs.CreatedAt
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var err error
		if cs.BaseRevision, err = latestRevision(ctx, tx); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO changesets (id, author, message, base_revision, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`,
			cs.ID, author, message, cs.BaseRevision, formatTime(cs.CreatedAt), formatTime(cs.UpdatedAt))
		return err
	})
	if err != nil {
		return nil, err
	}
	return cs, nil
}

// ChangeSets returns every open change set, oldest first.
func (s *Store) ChangeSets(ctx context.Context) ([]*ChangeSet, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM changesets ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]*ChangeSet, 0, len(ids))
	for _, id := range ids {
		cs, err := changeSet(ctx, s.db, id)
		if err != nil {
			return nil, err
		}
		out = append(out, cs)
	}
	return out, nil
}

// ChangeSet returns one change set and the resources it touches.
func (s *Store) ChangeSet(ctx context.Context, id string) (*ChangeSet, error) {
	return changeSet(ctx, s.db, id)
}

func changeSet(ctx context.Context, q dbtx, id string) (*ChangeSet, error) {
	cs := &ChangeSet{ID: id, Items: []Item{}}
	var created, updated string
	err := q.QueryRowContext(ctx, `SELECT author, message, base_revision, created_at, updated_at FROM changesets WHERE id = ?`, id).
		Scan(&cs.Author, &cs.Message, &cs.BaseRevision, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if cs.CreatedAt, err = parseTime(created); err != nil {
		return nil, err
	}
	if cs.UpdatedAt, err = parseTime(updated); err != nil {
		return nil, err
	}
	items, err := items(ctx, q, id)
	if err != nil {
		return nil, err
	}
	for _, it := range items {
		cs.Items = append(cs.Items, Item{Kind: it.kind, ID: it.id, Op: it.op()})
	}
	return cs, nil
}

// DeleteChangeSet discards a change set.
func (s *Store) DeleteChangeSet(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM changesets WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func items(ctx context.Context, q dbtx, cs string) ([]*item, error) {
	rows, err := q.QueryContext(ctx, `SELECT kind, id, base, body FROM changeset_items WHERE changeset = ? ORDER BY id`, cs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*item
	for rows.Next() {
		it := &item{}
		if err := rows.Scan(&it.kind, &it.id, &it.base, &it.body); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

func getItem(ctx context.Context, q dbtx, cs, id string) (*item, error) {
	it := &item{id: id}
	err := q.QueryRowContext(ctx, `SELECT kind, base, body FROM changeset_items WHERE changeset = ? AND id = ?`, cs, id).
		Scan(&it.kind, &it.base, &it.body)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return it, err
}

func requireChangeSet(ctx context.Context, q dbtx, cs string) error {
	var one int
	err := q.QueryRowContext(ctx, `SELECT 1 FROM changesets WHERE id = ?`, cs).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("change set %s: %w", cs, ErrNotFound)
	}
	return err
}

// List returns every resource of kind ordered by name, as change set cs
// sees them; cs "" reads the head.
func (s *Store) List(ctx context.Context, cs string, kind model.Kind) ([]model.Resource, error) {
	return list(ctx, s.db, cs, kind)
}

func list(ctx context.Context, q dbtx, cs string, kind model.Kind) ([]model.Resource, error) {
	head, err := headList(ctx, q, kind)
	if err != nil || cs == "" {
		return head, err
	}
	if err := requireChangeSet(ctx, q, cs); err != nil {
		return nil, err
	}
	its, err := items(ctx, q, cs)
	if err != nil {
		return nil, err
	}
	touched := map[string]*item{}
	for _, it := range its {
		if it.kind == kind.Plural {
			touched[it.id] = it
		}
	}
	var out []model.Resource
	for _, r := range head {
		if _, ok := touched[r.Common().ID]; !ok {
			out = append(out, r)
		}
	}
	for _, it := range touched {
		if it.body == nil {
			continue
		}
		r, err := decode(kind, *it.body)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	sortByName(out)
	return out, nil
}

// Get returns one resource as change set cs sees it; cs "" reads the head.
func (s *Store) Get(ctx context.Context, cs string, kind model.Kind, id string) (model.Resource, error) {
	return get(ctx, s.db, cs, kind, id)
}

func get(ctx context.Context, q dbtx, cs string, kind model.Kind, id string) (model.Resource, error) {
	if cs != "" {
		if err := requireChangeSet(ctx, q, cs); err != nil {
			return nil, err
		}
		it, err := getItem(ctx, q, cs, id)
		if err != nil {
			return nil, err
		}
		if it != nil {
			if it.body == nil || it.kind != kind.Plural {
				return nil, ErrNotFound
			}
			return decode(kind, *it.body)
		}
	}
	h, err := getHead(ctx, q, id)
	if err != nil {
		return nil, err
	}
	if h == nil || h.kind != kind.Plural {
		return nil, ErrNotFound
	}
	return decode(kind, h.body)
}

// View returns every resource as change set cs sees it.
func (s *Store) View(ctx context.Context, cs string) (model.Config, error) {
	var cfg model.Config
	for _, k := range model.Kinds {
		rs, err := list(ctx, s.db, cs, k)
		if err != nil {
			return cfg, err
		}
		for _, r := range rs {
			cfg.Add(r)
		}
	}
	return cfg, nil
}

// checkName rejects a name another resource of kind has in the view.
func checkName(ctx context.Context, q dbtx, cs string, kind model.Kind, r model.Resource) error {
	rs, err := list(ctx, q, cs, kind)
	if err != nil {
		return err
	}
	m := r.Common()
	for _, o := range rs {
		if o.Common().Name == m.Name && o.Common().ID != m.ID {
			return ErrNameTaken
		}
	}
	return nil
}

func (s *Store) touch(ctx context.Context, q dbtx, cs string) error {
	_, err := q.ExecContext(ctx, `UPDATE changesets SET updated_at = ? WHERE id = ?`, formatTime(s.now()), cs)
	return err
}

// putItem records body (nil deletes) for resource id in cs. base is the
// head body, used only when cs did not touch the resource yet.
func putItem(ctx context.Context, q dbtx, cs string, kind model.Kind, id string, base, body *string) error {
	_, err := q.ExecContext(ctx, `INSERT INTO changeset_items (changeset, kind, id, base, body) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (changeset, id) DO UPDATE SET body = excluded.body`, cs, kind.Plural, id, base, body)
	return err
}

// Create assigns the ID, version and timestamps of r and adds it to change
// set cs. r must pass model.Validate.
func (s *Store) Create(ctx context.Context, cs string, kind model.Kind, r model.Resource) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if err := requireChangeSet(ctx, tx, cs); err != nil {
			return err
		}
		m := r.Common()
		m.ID = kind.NewID()
		m.ResourceVersion = 1
		m.CreatedAt = s.now()
		m.UpdatedAt = m.CreatedAt
		if err := checkName(ctx, tx, cs, kind, r); err != nil {
			return err
		}
		body, err := json.Marshal(r)
		if err != nil {
			return err
		}
		b := string(body)
		if err := putItem(ctx, tx, cs, kind, m.ID, nil, &b); err != nil {
			return err
		}
		return s.touch(ctx, tx, cs)
	})
}

// Update replaces resource id in change set cs with r, keeping its ID and
// creation time. If version is non-zero it must equal the version cs sees.
// r must pass model.Validate.
func (s *Store) Update(ctx context.Context, cs string, kind model.Kind, id string, version int64, r model.Resource) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		cur, err := get(ctx, tx, cs, kind, id)
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
		if err := checkName(ctx, tx, cs, kind, r); err != nil {
			return err
		}
		body, err := json.Marshal(r)
		if err != nil {
			return err
		}
		b := string(body)
		base, err := headBody(ctx, tx, id)
		if err != nil {
			return err
		}
		if err := putItem(ctx, tx, cs, kind, id, base, &b); err != nil {
			return err
		}
		return s.touch(ctx, tx, cs)
	})
}

// Delete removes resource id in change set cs. If version is non-zero it
// must equal the version cs sees.
func (s *Store) Delete(ctx context.Context, cs string, kind model.Kind, id string, version int64) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		cur, err := get(ctx, tx, cs, kind, id)
		if err != nil {
			return err
		}
		if version != 0 && version != cur.Common().ResourceVersion {
			return ErrConflict
		}
		it, err := getItem(ctx, tx, cs, id)
		if err != nil {
			return err
		}
		if it != nil && it.base == nil {
			// Created in this change set: forget it.
			_, err = tx.ExecContext(ctx, `DELETE FROM changeset_items WHERE changeset = ? AND id = ?`, cs, id)
		} else {
			var base *string
			if base, err = headBody(ctx, tx, id); err != nil {
				return err
			}
			err = putItem(ctx, tx, cs, kind, id, base, nil)
		}
		if err != nil {
			return err
		}
		return s.touch(ctx, tx, cs)
	})
}

func headBody(ctx context.Context, q dbtx, id string) (*string, error) {
	h, err := getHead(ctx, q, id)
	if err != nil || h == nil {
		return nil, err
	}
	return &h.body, nil
}

// Import makes change set cs hold exactly the resources of cfg: resources
// with a known ID are replaced, new ones are created with their ID, and
// resources missing from cfg are deleted. An uploaded certificate without a
// key keeps the stored one.
func (s *Store) Import(ctx context.Context, cs string, cfg model.Config) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if err := requireChangeSet(ctx, tx, cs); err != nil {
			return err
		}
		keep := map[string]bool{}
		for _, k := range model.Kinds {
			for _, r := range cfg.Of(k) {
				m := r.Common()
				keep[m.ID] = true
				cur, err := get(ctx, tx, cs, k, m.ID)
				switch {
				case errors.Is(err, ErrNotFound):
					m.ResourceVersion = 1
					m.CreatedAt = s.now()
				case err != nil:
					return err
				default:
					m.ResourceVersion = cur.Common().ResourceVersion + 1
					m.CreatedAt = cur.Common().CreatedAt
					if c, ok := r.(*model.Certificate); ok && c.Spec.KeyPEM == "" {
						c.Spec.KeyPEM = cur.(*model.Certificate).Spec.KeyPEM
					}
				}
				m.UpdatedAt = s.now()
				body, err := json.Marshal(r)
				if err != nil {
					return err
				}
				b := string(body)
				base, err := headBody(ctx, tx, m.ID)
				if err != nil {
					return err
				}
				if h, err := getHead(ctx, tx, m.ID); err != nil {
					return err
				} else if h != nil && h.kind != k.Plural {
					return model.FieldErrors{{Path: fmt.Sprintf("%s[%s].id", k.Plural, m.ID), Message: "is used by a " + h.kind + " resource"}}
				}
				if err := putItem(ctx, tx, cs, k, m.ID, base, &b); err != nil {
					return err
				}
			}
		}
		for _, k := range model.Kinds {
			rs, err := list(ctx, tx, cs, k)
			if err != nil {
				return err
			}
			for _, r := range rs {
				id := r.Common().ID
				if keep[id] {
					continue
				}
				base, err := headBody(ctx, tx, id)
				if err != nil {
					return err
				}
				if base == nil {
					_, err = tx.ExecContext(ctx, `DELETE FROM changeset_items WHERE changeset = ? AND id = ?`, cs, id)
				} else {
					err = putItem(ctx, tx, cs, k, id, base, nil)
				}
				if err != nil {
					return err
				}
			}
		}
		for _, k := range model.Kinds {
			seen := map[string]string{}
			rs, err := list(ctx, tx, cs, k)
			if err != nil {
				return err
			}
			for _, r := range rs {
				m := r.Common()
				if other, ok := seen[m.Name]; ok {
					return model.FieldErrors{{Path: fmt.Sprintf("%s[%s].name", k.Plural, m.ID), Message: "is also used by " + other}}
				}
				seen[m.Name] = m.ID
			}
		}
		return s.touch(ctx, tx, cs)
	})
}

// ItemState is one resource a change set touches: Base is the head state
// when the change set first touched it (nil if it created it), New what it
// makes of it (nil if it deletes it), and Drifted whether the head changed
// since.
type ItemState struct {
	Kind    string
	ID      string
	Op      Op
	Base    model.Resource
	New     model.Resource
	Drifted bool
}

// Items returns what change set cs touches.
func (s *Store) Items(ctx context.Context, cs string) ([]ItemState, error) {
	if err := requireChangeSet(ctx, s.db, cs); err != nil {
		return nil, err
	}
	its, err := items(ctx, s.db, cs)
	if err != nil {
		return nil, err
	}
	out := []ItemState{}
	for _, it := range its {
		kind, ok := model.KindByPlural(it.kind)
		if !ok {
			return nil, fmt.Errorf("change set item of unknown kind %q", it.kind)
		}
		st := ItemState{Kind: it.kind, ID: it.id, Op: it.op()}
		if st.Base, err = decodeOpt(kind, it.base); err != nil {
			return nil, err
		}
		if st.New, err = decodeOpt(kind, it.body); err != nil {
			return nil, err
		}
		h, err := getHead(ctx, s.db, it.id)
		if err != nil {
			return nil, err
		}
		switch {
		case it.base == nil:
			st.Drifted = h != nil
		case h == nil:
			st.Drifted = true
		default:
			st.Drifted = !jsonEqual(mergeDoc(*it.base), mergeDoc(h.body))
		}
		out = append(out, st)
	}
	return out, nil
}

// serverFields are kept out of merges: the store sets them.
var serverFields = []string{"resourceVersion", "updatedAt"}

func mergeDoc(body string) any {
	var v any
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		return nil
	}
	if m, ok := v.(map[string]any); ok {
		for _, f := range serverFields {
			delete(m, f)
		}
	}
	return v
}

// mergeItems writes the items of cs into the head inside tx. Where the head
// changed since cs first touched a resource the edits are merged field by
// field; a field changed on both sides is a conflict.
func (s *Store) mergeItems(ctx context.Context, tx *sql.Tx, cs string) error {
	its, err := items(ctx, tx, cs)
	if err != nil {
		return err
	}
	var conflicts model.FieldErrors
	for _, it := range its {
		kind, ok := model.KindByPlural(it.kind)
		if !ok {
			return fmt.Errorf("change set item of unknown kind %q", it.kind)
		}
		path := fmt.Sprintf("%s[%s]", it.kind, it.id)
		h, err := getHead(ctx, tx, it.id)
		if err != nil {
			return err
		}
		switch {
		case it.base == nil:
			if h != nil {
				conflicts = append(conflicts, model.FieldError{Path: path, Message: "was created in the current revision too"})
				continue
			}
		case h == nil:
			if it.body != nil {
				conflicts = append(conflicts, model.FieldError{Path: path, Message: "was deleted in the current revision"})
			}
			continue
		case it.body == nil:
			if !jsonEqual(mergeDoc(*it.base), mergeDoc(h.body)) {
				conflicts = append(conflicts, model.FieldError{Path: path, Message: "changed in the current revision since this change set deleted it"})
				continue
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM resources WHERE id = ?`, it.id); err != nil {
				return err
			}
			continue
		}
		body := *it.body
		if it.base != nil && *it.base != h.body {
			merged, cs := diff.Merge3(mergeDoc(*it.base), mergeDoc(*it.body), mergeDoc(h.body))
			for _, p := range cs {
				conflicts = append(conflicts, model.FieldError{Path: path + "." + p, Message: "changed in the current revision too"})
			}
			if len(cs) > 0 {
				continue
			}
			b, err := json.Marshal(merged)
			if err != nil {
				return err
			}
			body = string(b)
		}
		r, err := decode(kind, body)
		if err != nil {
			return err
		}
		if es := model.Validate(r); len(es) > 0 {
			for _, e := range es {
				conflicts = append(conflicts, model.FieldError{Path: path + "." + e.Path, Message: e.Message})
			}
			continue
		}
		if err := s.putHead(ctx, tx, kind, r); err != nil {
			if errors.Is(err, ErrNameTaken) {
				conflicts = append(conflicts, model.FieldError{Path: path + ".name", Message: err.Error()})
				continue
			}
			return err
		}
	}
	return conflicts.Err()
}

// errPreview ends a preview transaction without committing it.
var errPreview = errors.New("preview")

// Preview returns the resources the head would hold after applying change
// set cs. Merge conflicts and invalid merged resources are returned as
// model.FieldErrors.
func (s *Store) Preview(ctx context.Context, cs string) (model.Config, error) {
	var cfg model.Config
	var mergeErr error
	err := s.tx(ctx, func(tx *sql.Tx) error {
		if err := requireChangeSet(ctx, tx, cs); err != nil {
			return err
		}
		mergeErr = s.mergeItems(ctx, tx, cs)
		var fe model.FieldErrors
		if mergeErr != nil && !errors.As(mergeErr, &fe) {
			return mergeErr
		}
		var err error
		if cfg, err = loadConfig(ctx, tx); err != nil {
			return err
		}
		return errPreview
	})
	if !errors.Is(err, errPreview) {
		return cfg, err
	}
	return cfg, mergeErr
}

func jsonEqual(a, b any) bool {
	return len(diff.Compare(a, b)) == 0
}

func decodeOpt(kind model.Kind, body *string) (model.Resource, error) {
	if body == nil {
		return nil, nil
	}
	return decode(kind, *body)
}
