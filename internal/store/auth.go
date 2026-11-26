package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/oklog/ulid/v2"
)

// User is a local admin account. Password holds an encoded hash.
type User struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Role        string    `json:"role"`
	TOTPEnabled bool      `json:"totpEnabled"`
	CreatedAt   time.Time `json:"createdAt"`

	Password    string    `json:"-"`
	TOTPSecret  string    `json:"-"`
	TOTPLast    int64     `json:"-"`
	Failures    int       `json:"-"`
	LockedUntil time.Time `json:"-"`
}

const userCols = `id, name, role, password, totp_secret, totp_enabled, totp_last, failures, locked_until, created_at`

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	u := &User{}
	var locked, created string
	if err := row.Scan(&u.ID, &u.Name, &u.Role, &u.Password, &u.TOTPSecret, &u.TOTPEnabled, &u.TOTPLast, &u.Failures, &locked, &created); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	var err error
	if u.LockedUntil, err = parseTime(locked); err != nil {
		return nil, err
	}
	if u.CreatedAt, err = parseTime(created); err != nil {
		return nil, err
	}
	return u, nil
}

// CountUsers returns how many accounts exist.
func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// CreateUser stores a new account and sets its ID.
func (s *Store) CreateUser(ctx context.Context, u *User) error {
	u.ID = "usr_" + ulid.Make().String()
	u.CreatedAt = s.now()
	_, err := s.db.ExecContext(ctx, `INSERT INTO users (id, name, role, password, created_at) VALUES (?, ?, ?, ?, ?)`,
		u.ID, u.Name, u.Role, u.Password, formatTime(u.CreatedAt))
	if errorsContains(err, "UNIQUE constraint failed: users.name") {
		return ErrNameTaken
	}
	return err
}

// CreateFirstUser stores u only if no account exists yet, consuming the
// setup token stored under key.
func (s *Store) CreateFirstUser(ctx context.Context, u *User, key string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return ErrConflict
		}
		u.ID = "usr_" + ulid.Make().String()
		u.CreatedAt = s.now()
		if _, err := tx.ExecContext(ctx, `INSERT INTO users (id, name, role, password, created_at) VALUES (?, ?, ?, ?, ?)`,
			u.ID, u.Name, u.Role, u.Password, formatTime(u.CreatedAt)); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM state WHERE key = ?`, key)
		return err
	})
}

// Users lists accounts by name.
func (s *Store) Users(ctx context.Context) ([]*User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+userCols+` FROM users ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// User returns an account by ID.
func (s *Store) User(ctx context.Context, id string) (*User, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE id = ?`, id))
}

// UserByName returns an account by name.
func (s *Store) UserByName(ctx context.Context, name string) (*User, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE name = ?`, name))
}

// DeleteUser removes an account with its sessions and tokens. The last
// owner cannot be removed.
func (s *Store) DeleteUser(ctx context.Context, id string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		u, err := scanUser(tx.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE id = ?`, id))
		if err != nil {
			return err
		}
		if err := keepOwner(ctx, tx, u, ""); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
		return err
	})
}

// ErrLastOwner refuses a change that leaves no owner.
var ErrLastOwner = errors.New("the last owner cannot be removed or demoted")

func keepOwner(ctx context.Context, tx *sql.Tx, u *User, newRole string) error {
	if u.Role != "owner" || newRole == "owner" {
		return nil
	}
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role = 'owner'`).Scan(&n); err != nil {
		return err
	}
	if n <= 1 {
		return ErrLastOwner
	}
	return nil
}

// SetRole changes an account's role, dropping its tokens, whose roles may
// exceed the new one.
func (s *Store) SetRole(ctx context.Context, id, role string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		u, err := scanUser(tx.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE id = ?`, id))
		if err != nil {
			return err
		}
		if err := keepOwner(ctx, tx, u, role); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE users SET role = ? WHERE id = ?`, role, id); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM tokens WHERE user = ?`, id)
		return err
	})
}

// SetPassword replaces the password hash, clears lockout and ends every
// session of the account. With resetTOTP the second factor is removed too.
func (s *Store) SetPassword(ctx context.Context, id, hash string, resetTOTP bool) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		q := `UPDATE users SET password = ?, failures = 0, locked_until = '' WHERE id = ?`
		if resetTOTP {
			q = `UPDATE users SET password = ?, failures = 0, locked_until = '', totp_secret = '', totp_enabled = 0, totp_last = 0 WHERE id = ?`
		}
		res, err := tx.ExecContext(ctx, q, hash, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM sessions WHERE user = ?`, id)
		return err
	})
}

// SetTOTP stores a second-factor secret; enabled false keeps it pending
// until the first code is checked.
func (s *Store) SetTOTP(ctx context.Context, id, secret string, enabled bool) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET totp_secret = ?, totp_enabled = ?, totp_last = 0 WHERE id = ?`, secret, enabled, id)
	return err
}

// UseTOTPStep records the time step of an accepted code, refusing a step
// that is not newer than the last one so a code works once.
func (s *Store) UseTOTPStep(ctx context.Context, id string, step int64) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE users SET totp_last = ? WHERE id = ? AND totp_last < ?`, step, id, step)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// LoginFailed counts a failed login and locks the account for lock once
// max failures are reached.
func (s *Store) LoginFailed(ctx context.Context, id string, max int, lock time.Duration) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `UPDATE users SET failures = failures + 1 WHERE id = ? RETURNING failures`, id).Scan(&n); err != nil {
			return err
		}
		if n >= max {
			_, err := tx.ExecContext(ctx, `UPDATE users SET failures = 0, locked_until = ? WHERE id = ?`, formatTime(s.now().Add(lock)), id)
			return err
		}
		return nil
	})
}

// LoginSucceeded clears the failure count.
func (s *Store) LoginSucceeded(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET failures = 0, locked_until = '' WHERE id = ?`, id)
	return err
}

// Session is a browser login. Only the token's hash is stored.
type Session struct {
	User      string
	CSRF      string
	CreatedAt time.Time
	LastSeen  time.Time
}

func (s *Store) CreateSession(ctx context.Context, hash []byte, user, csrf string) error {
	now := formatTime(s.now())
	_, err := s.db.ExecContext(ctx, `INSERT INTO sessions (hash, user, csrf, created_at, last_seen) VALUES (?, ?, ?, ?, ?)`, hash, user, csrf, now, now)
	return err
}

// Session returns the session with token hash, ending it if it has been
// idle longer than idle or lives longer than max.
func (s *Store) Session(ctx context.Context, hash []byte, idle, max time.Duration) (*Session, error) {
	se := &Session{}
	var created, seen string
	err := s.db.QueryRowContext(ctx, `SELECT user, csrf, created_at, last_seen FROM sessions WHERE hash = ?`, hash).Scan(&se.User, &se.CSRF, &created, &seen)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if se.CreatedAt, err = parseTime(created); err != nil {
		return nil, err
	}
	if se.LastSeen, err = parseTime(seen); err != nil {
		return nil, err
	}
	now := s.now()
	if now.Sub(se.LastSeen) > idle || now.Sub(se.CreatedAt) > max {
		s.DeleteSession(ctx, hash)
		return nil, ErrNotFound
	}
	// Coarse updates keep reads from writing on every request.
	if now.Sub(se.LastSeen) > time.Minute {
		if _, err := s.db.ExecContext(ctx, `UPDATE sessions SET last_seen = ? WHERE hash = ?`, formatTime(now), hash); err != nil {
			return nil, err
		}
	}
	return se, nil
}

func (s *Store) DeleteSession(ctx context.Context, hash []byte) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE hash = ?`, hash)
	return err
}

// Token is an API token. Only its secret's hash is stored.
type Token struct {
	ID        string    `json:"id"`
	User      string    `json:"user"`
	Name      string    `json:"name"`
	Role      string    `json:"role"`
	CIDRs     []string  `json:"cidrs,omitempty"`
	ExpiresAt time.Time `json:"expiresAt"`
	CreatedAt time.Time `json:"createdAt"`
	LastUsed  time.Time `json:"lastUsed,omitzero"`

	Hash []byte `json:"-"`
}

func (s *Store) CreateToken(ctx context.Context, t *Token) error {
	t.CreatedAt = s.now()
	cidrs, err := json.Marshal(t.CIDRs)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO tokens (id, hash, user, name, role, cidrs, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		t.ID, t.Hash, t.User, t.Name, t.Role, string(cidrs), formatTime(t.ExpiresAt), formatTime(t.CreatedAt))
	return err
}

const tokenCols = `id, hash, user, name, role, cidrs, expires_at, created_at, last_used`

func scanToken(row interface{ Scan(...any) error }) (*Token, error) {
	t := &Token{}
	var cidrs, exp, created, used string
	if err := row.Scan(&t.ID, &t.Hash, &t.User, &t.Name, &t.Role, &cidrs, &exp, &created, &used); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if err := json.Unmarshal([]byte(cidrs), &t.CIDRs); err != nil {
		return nil, err
	}
	var err error
	if t.ExpiresAt, err = parseTime(exp); err != nil {
		return nil, err
	}
	if t.CreatedAt, err = parseTime(created); err != nil {
		return nil, err
	}
	if t.LastUsed, err = parseTime(used); err != nil {
		return nil, err
	}
	return t, nil
}

// Token returns a token by ID.
func (s *Store) Token(ctx context.Context, id string) (*Token, error) {
	return scanToken(s.db.QueryRowContext(ctx, `SELECT `+tokenCols+` FROM tokens WHERE id = ?`, id))
}

// Tokens lists the tokens of user.
func (s *Store) Tokens(ctx context.Context, user string) ([]*Token, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+tokenCols+` FROM tokens WHERE user = ? ORDER BY created_at`, user)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Token{}
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// TokenUsed records when a token was last used, at most once a minute.
func (s *Store) TokenUsed(ctx context.Context, t *Token) error {
	now := s.now()
	if now.Sub(t.LastUsed) < time.Minute {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `UPDATE tokens SET last_used = ? WHERE id = ?`, formatTime(now), t.ID)
	return err
}

// DeleteToken removes token id of user.
func (s *Store) DeleteToken(ctx context.Context, user, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM tokens WHERE id = ? AND user = ?`, id, user)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
