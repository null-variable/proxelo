package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/null-variable/proxelo/internal/model"
)

// Group scopes resources and member roles. Subgroups inherit the members
// of every ancestor, and a group without domains inherits its parent's.
type Group struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Parent      string `json:"parent,omitempty"`
	Description string `json:"description,omitempty"`
	// Domains bound the hostnames of the group's sites: "example.com"
	// covers example.com and every name under it.
	Domains   []string  `json:"domains"`
	Members   []Member  `json:"members"`
	CreatedAt time.Time `json:"createdAt"`
}

// Member is a user's role in a group.
type Member struct {
	User string `json:"user"`
	Role string `json:"role"`
}

// ErrGroupInUse refuses deleting a group that still has subgroups or
// resources.
var ErrGroupInUse = errors.New("group has subgroups or resources")

func migrateGroups(ctx context.Context, tx *sql.Tx) error {
	return execAll(ctx, tx,
		`CREATE TABLE groups (
			id          TEXT NOT NULL PRIMARY KEY,
			name        TEXT NOT NULL UNIQUE,
			parent      TEXT REFERENCES groups (id),
			description TEXT NOT NULL DEFAULT '',
			domains     TEXT NOT NULL DEFAULT '[]',
			created_at  TEXT NOT NULL
		)`,
		`CREATE TABLE group_members (
			grp  TEXT NOT NULL REFERENCES groups (id) ON DELETE CASCADE,
			user TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
			role TEXT NOT NULL,
			PRIMARY KEY (grp, user)
		)`,
	)
}

// migrateRevisionGroups records on each revision the groups it touched,
// so group members see the history of their groups. Older revisions are
// filled in by comparing each with the one before.
func migrateRevisionGroups(ctx context.Context, tx *sql.Tx) error {
	if err := execAll(ctx, tx, `ALTER TABLE revisions ADD COLUMN groups TEXT NOT NULL DEFAULT '[]'`); err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT revision, config FROM revisions ORDER BY revision`)
	if err != nil {
		return err
	}
	type rev struct {
		n   uint64
		cfg model.Config
	}
	var revs []rev
	for rows.Next() {
		var r rev
		var cfg string
		if err := rows.Scan(&r.n, &cfg); err != nil {
			rows.Close()
			return err
		}
		if err := json.Unmarshal([]byte(cfg), &r.cfg); err != nil {
			rows.Close()
			return err
		}
		revs = append(revs, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	var prev model.Config
	for _, r := range revs {
		g, _ := json.Marshal(touchedGroups(prev, r.cfg))
		if _, err := tx.ExecContext(ctx, `UPDATE revisions SET groups = ? WHERE revision = ?`, string(g), r.n); err != nil {
			return err
		}
		prev = r.cfg
	}
	return nil
}

// Groups lists every group by name, with its members.
func (s *Store) Groups(ctx context.Context) ([]*Group, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, COALESCE(parent, ''), description, domains, created_at FROM groups ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Group{}
	byID := map[string]*Group{}
	for rows.Next() {
		g := &Group{Members: []Member{}}
		var domains, created string
		if err := rows.Scan(&g.ID, &g.Name, &g.Parent, &g.Description, &domains, &created); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(domains), &g.Domains); err != nil {
			return nil, err
		}
		if g.CreatedAt, err = parseTime(created); err != nil {
			return nil, err
		}
		out = append(out, g)
		byID[g.ID] = g
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	mrows, err := s.db.QueryContext(ctx, `SELECT grp, user, role FROM group_members ORDER BY grp, user`)
	if err != nil {
		return nil, err
	}
	defer mrows.Close()
	for mrows.Next() {
		var gid string
		var m Member
		if err := mrows.Scan(&gid, &m.User, &m.Role); err != nil {
			return nil, err
		}
		if g := byID[gid]; g != nil {
			g.Members = append(g.Members, m)
		}
	}
	return out, mrows.Err()
}

func groupErr(err error) error {
	switch {
	case errorsContains(err, "UNIQUE constraint failed: groups.name"):
		return ErrNameTaken
	case errorsContains(err, "FOREIGN KEY constraint failed"):
		return ErrNotFound
	}
	return err
}

// CreateGroup stores g and sets its ID.
func (s *Store) CreateGroup(ctx context.Context, g *Group) error {
	g.ID = "grp_" + ulid.Make().String()
	g.CreatedAt = s.now()
	if g.Domains == nil {
		g.Domains = []string{}
	}
	g.Members = []Member{}
	domains, _ := json.Marshal(g.Domains)
	var parent any
	if g.Parent != "" {
		parent = g.Parent
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO groups (id, name, parent, description, domains, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		g.ID, g.Name, parent, g.Description, string(domains), formatTime(g.CreatedAt))
	return groupErr(err)
}

// UpdateGroup replaces the name, description and domains of group g.ID.
func (s *Store) UpdateGroup(ctx context.Context, g *Group) error {
	domains, _ := json.Marshal(g.Domains)
	res, err := s.db.ExecContext(ctx, `UPDATE groups SET name = ?, description = ?, domains = ? WHERE id = ?`, g.Name, g.Description, string(domains), g.ID)
	if err != nil {
		return groupErr(err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteGroup removes a group without subgroups whose ID no resource, in
// the head or a change set, carries.
func (s *Store) DeleteGroup(ctx context.Context, id string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT
			(SELECT COUNT(*) FROM groups WHERE parent = ?1) +
			(SELECT COUNT(*) FROM resources WHERE json_extract(body, '$.group') = ?1) +
			(SELECT COUNT(*) FROM changeset_items WHERE body IS NOT NULL AND json_extract(body, '$.group') = ?1)`, id).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return ErrGroupInUse
		}
		res, err := tx.ExecContext(ctx, `DELETE FROM groups WHERE id = ?`, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// SetMember gives user role in group, replacing any role it had there.
func (s *Store) SetMember(ctx context.Context, group, user, role string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO group_members (grp, user, role) VALUES (?, ?, ?)
		ON CONFLICT (grp, user) DO UPDATE SET role = excluded.role`, group, user, role)
	return groupErr(err)
}

// RemoveMember drops user from group.
func (s *Store) RemoveMember(ctx context.Context, group, user string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM group_members WHERE grp = ? AND user = ?`, group, user)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
