// Package breakglass serves the local recovery commands on a
// local Unix socket. File permissions are the only check: the socket is
// 0660 in a 0750 directory, so root and the proxelo group can use it.
// Every command is audited.
package breakglass

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"

	"github.com/null-variable/proxelo/internal/auth"
	"github.com/null-variable/proxelo/internal/deploy"
	"github.com/null-variable/proxelo/internal/store"
)

// actor names break-glass actions in the audit log.
const actor = "break-glass"

// Binder moves the admin API to another address.
type Binder interface {
	Bind(addr string) error
}

// Handler serves the commands.
func Handler(st *store.Store, dep *deploy.Manager, b Binder) http.Handler {
	s := &server{st: st, dep: dep, b: b}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /reset-password", s.resetPassword)
	mux.HandleFunc("POST /rollback", s.rollback)
	mux.HandleFunc("POST /bind", s.bind)
	return mux
}

type server struct {
	st  *store.Store
	dep *deploy.Manager
	b   Binder
}

func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	if errors.Is(err, store.ErrNotFound) {
		status = http.StatusNotFound
	}
	reply(w, status, map[string]string{"error": err.Error()})
}

func read(r *http.Request, v any) error {
	b, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// resetPassword gives the account a new random password and removes its
// second factor and sessions.
func (s *server) resetPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		User string `json:"user"`
	}
	if err := read(r, &req); err != nil {
		reply(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	u, err := s.st.UserByName(r.Context(), req.User)
	if err != nil {
		fail(w, fmt.Errorf("user %q: %w", req.User, err))
		return
	}
	password := auth.Secret(18)
	if err := s.st.SetPassword(r.Context(), u.ID, auth.HashPassword(password), true); err != nil {
		fail(w, err)
		return
	}
	s.st.Audit(r.Context(), actor, "user.reset", u.ID, map[string]any{"password": true, "totp": true})
	reply(w, http.StatusOK, map[string]string{"user": u.Name, "password": password})
}

// rollback returns to the newest confirmed revision ("last-confirmed") or a
// numbered one, confirmed at once.
func (s *server) rollback(w http.ResponseWriter, r *http.Request) {
	var req struct {
		To string `json:"to"`
	}
	if err := read(r, &req); err != nil {
		reply(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	var rev *store.Revision
	var err error
	if req.To == "last-confirmed" {
		rev, err = s.dep.RollbackToConfirmed(r.Context(), actor, "break-glass rollback to the last confirmed revision")
	} else {
		var n uint64
		if _, perr := fmt.Sscan(req.To, &n); perr != nil {
			reply(w, http.StatusBadRequest, map[string]string{"error": `to: must be a revision number or "last-confirmed"`})
			return
		}
		rev, err = s.dep.Rollback(r.Context(), n, actor, "", 0)
	}
	if err != nil {
		fail(w, err)
		return
	}
	s.st.Audit(r.Context(), actor, "revision.rollback", req.To, map[string]any{"revision": rev.Revision})
	reply(w, http.StatusOK, rev)
}

// bind moves the admin API, for example back to loopback after a bad
// address change. The address is kept across restarts.
func (s *server) bind(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Addr string `json:"addr"`
	}
	if err := read(r, &req); err != nil {
		reply(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if _, _, err := net.SplitHostPort(req.Addr); err != nil {
		reply(w, http.StatusBadRequest, map[string]string{"error": "addr: " + err.Error()})
		return
	}
	if err := s.b.Bind(req.Addr); err != nil {
		fail(w, err)
		return
	}
	if err := s.st.Put(r.Context(), ListenKey, []byte(req.Addr)); err != nil {
		fail(w, err)
		return
	}
	s.st.Audit(r.Context(), actor, "admin.bind", req.Addr, nil)
	reply(w, http.StatusOK, map[string]string{"addr": req.Addr})
}

// ListenKey holds an admin address set by break-glass; it overrides the
// configured one.
const ListenKey = "admin/listen"

// Listen opens the socket, replacing a stale one.
func Listen(path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o660); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

// Call sends one command over the socket at path and decodes the reply.
func Call(ctx context.Context, path, cmd string, req, resp any) error {
	c := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		},
	}}
	b, err := json.Marshal(req)
	if err != nil {
		return err
	}
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://break-glass/"+cmd, bytes.NewReader(b))
	if err != nil {
		return err
	}
	res, err := c.Do(hr)
	if err != nil {
		return fmt.Errorf("break-glass socket %s: %w", path, err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}
	if res.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		json.Unmarshal(raw, &e)
		return errors.New(e.Error)
	}
	return json.Unmarshal(raw, resp)
}
