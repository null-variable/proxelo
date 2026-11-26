package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// ErrAuditChain means the audit log was altered.
var ErrAuditChain = errors.New("audit chain broken")

// AuditEntry is one record of the append-only audit log.
// Each entry's hash covers the previous entry's hash, so editing or
// removing a row breaks the chain from there on.
type AuditEntry struct {
	Seq    uint64          `json:"seq"`
	At     time.Time       `json:"at"`
	Actor  string          `json:"actor"`
	Action string          `json:"action"`
	Target string          `json:"target"`
	Detail json.RawMessage `json:"detail,omitempty"`
	Prev   []byte          `json:"prev"`
	Hash   []byte          `json:"hash"`
}

func (e *AuditEntry) sum() []byte {
	h := sha256.New()
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], e.Seq)
	h.Write(n[:])
	for _, f := range []string{formatTime(e.At), e.Actor, e.Action, e.Target, string(e.Detail)} {
		binary.BigEndian.PutUint64(n[:], uint64(len(f)))
		h.Write(n[:])
		h.Write([]byte(f))
	}
	h.Write(e.Prev)
	return h.Sum(nil)
}

// Audit appends an entry. detail is marshalled to JSON; nil leaves it empty.
func (s *Store) Audit(ctx context.Context, actor, action, target string, detail any) (*AuditEntry, error) {
	var d json.RawMessage
	if detail != nil {
		b, err := json.Marshal(detail)
		if err != nil {
			return nil, err
		}
		d = b
	}
	e := &AuditEntry{At: s.now(), Actor: actor, Action: action, Target: target, Detail: d}
	err := s.tx(ctx, func(tx *sql.Tx) error {
		e.Prev = make([]byte, sha256.Size)
		err := tx.QueryRowContext(ctx, `SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1`).Scan(&e.Seq, &e.Prev)
		if err != nil && err != sql.ErrNoRows {
			return err
		}
		e.Seq++
		e.Hash = e.sum()
		_, err = tx.ExecContext(ctx, `INSERT INTO audit (seq, at, actor, action, target, detail, prev, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			e.Seq, formatTime(e.At), e.Actor, e.Action, e.Target, string(e.Detail), e.Prev, e.Hash)
		return err
	})
	if err != nil {
		return nil, err
	}
	return e, nil
}

// AuditLog returns up to limit entries with seq greater than after, oldest
// first.
func (s *Store) AuditLog(ctx context.Context, after uint64, limit int) ([]*AuditEntry, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT seq, at, actor, action, target, detail, prev, hash FROM audit WHERE seq > ? ORDER BY seq LIMIT ?`, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*AuditEntry{}
	for rows.Next() {
		e := &AuditEntry{}
		var at, detail string
		if err := rows.Scan(&e.Seq, &at, &e.Actor, &e.Action, &e.Target, &detail, &e.Prev, &e.Hash); err != nil {
			return nil, err
		}
		if e.At, err = parseTime(at); err != nil {
			return nil, err
		}
		if detail != "" {
			e.Detail = json.RawMessage(detail)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// VerifyAudit checks the whole hash chain and returns the number of
// entries. The error names the first entry that does not match.
func (s *Store) VerifyAudit(ctx context.Context) (uint64, error) {
	prev := make([]byte, sha256.Size)
	var n uint64
	for {
		es, err := s.AuditLog(ctx, n, 1000)
		if err != nil {
			return n, err
		}
		if len(es) == 0 {
			return n, nil
		}
		for _, e := range es {
			if e.Seq != n+1 {
				return n, fmt.Errorf("%w: entry %d is missing", ErrAuditChain, n+1)
			}
			if !bytes.Equal(e.Prev, prev) || !bytes.Equal(e.sum(), e.Hash) {
				return n, fmt.Errorf("%w: entry %d does not match", ErrAuditChain, e.Seq)
			}
			prev, n = e.Hash, e.Seq
		}
	}
}
