package api

import (
	"cmp"
	"context"
	"crypto/subtle"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/null-variable/proxelo/internal/auth"
	"github.com/null-variable/proxelo/internal/store"
)

// Session limits.
const (
	sessionCookie = "proxelo_session"
	sessionIdle   = 30 * time.Minute
	sessionMax    = 24 * time.Hour
	// Failed logins before an account is locked, and for how long.
	maxFailures = 5
	lockFor     = 15 * time.Minute
	// Second-factor logins wait this long for the code.
	mfaWindow = 5 * time.Minute
	// SetupTokenKey holds the one-time token that creates the first owner.
	SetupTokenKey = "auth/setup-token"
)

// principal is who makes a request.
type principal struct {
	user *store.User
	role auth.Role
	// Upper bound on group roles: the token's role, owner for sessions.
	cap auth.Role
	// "session" or "token".
	via string
	// The session's CSRF token, for a reloaded UI to recover it.
	csrf string
}

func (p *principal) name() string {
	if p == nil {
		return "anonymous"
	}
	return p.user.Name
}

type principalKey struct{}

func who(r *http.Request) *principal {
	p, _ := r.Context().Value(principalKey{}).(*principal)
	return p
}

// authenticate resolves the session cookie or bearer token of r.
func (a *api) authenticate(r *http.Request) (*principal, error) {
	ctx := r.Context()
	if h := r.Header.Get("Authorization"); h != "" {
		secret, ok := strings.CutPrefix(h, "Bearer ")
		if !ok {
			return nil, errUnauthenticated
		}
		id, key, ok := strings.Cut(secret, ".")
		if !ok {
			return nil, errUnauthenticated
		}
		t, err := a.st.Token(ctx, id)
		if errors.Is(err, store.ErrNotFound) {
			return nil, errUnauthenticated
		}
		if err != nil {
			return nil, err
		}
		if subtle.ConstantTimeCompare(auth.Hash(key), t.Hash) != 1 || !time.Now().Before(t.ExpiresAt) {
			return nil, errUnauthenticated
		}
		if len(t.CIDRs) > 0 && !allowed(t.CIDRs, clientIP(r)) {
			return nil, httpError{status: http.StatusForbidden, msg: "token not allowed from this address"}
		}
		u, err := a.st.User(ctx, t.User)
		if err != nil {
			return nil, errUnauthenticated
		}
		a.st.TokenUsed(ctx, t)
		role := auth.Role(t.Role).Lower(auth.Role(u.Role))
		return &principal{user: u, role: role, cap: auth.Role(t.Role), via: "token"}, nil
	}
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil, errUnauthenticated
	}
	se, err := a.st.Session(ctx, auth.Hash(c.Value), sessionIdle, sessionMax)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errUnauthenticated
	}
	if err != nil {
		return nil, err
	}
	// Browsers send the cookie on cross-site requests too; writes must
	// echo the session's CSRF token.
	if r.Method != http.MethodGet && r.Method != http.MethodHead &&
		subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(se.CSRF)) != 1 {
		return nil, httpError{status: http.StatusForbidden, msg: "missing or wrong X-CSRF-Token"}
	}
	u, err := a.st.User(ctx, se.User)
	if err != nil {
		return nil, errUnauthenticated
	}
	return &principal{user: u, role: auth.Role(u.Role), cap: auth.Owner, via: "session", csrf: se.CSRF}, nil
}

var errUnauthenticated = httpError{status: http.StatusUnauthorized, msg: "authentication required"}

func allowed(cidrs []string, ip netip.Addr) bool {
	for _, c := range cidrs {
		if p, err := netip.ParsePrefix(c); err == nil && p.Contains(ip) {
			return true
		}
	}
	return false
}

// clientIP is the peer address; the admin API is not behind a proxy.
func clientIP(r *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	ip, _ := netip.ParseAddr(host)
	return ip.Unmap()
}

// require wraps h so only principals with at least min may call it.
func (a *api) require(min auth.Role, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, err := a.authenticate(r)
		if err != nil {
			a.fail(w, err)
			return
		}
		if !p.role.Allows(min) {
			a.fail(w, httpError{status: http.StatusForbidden, msg: "requires role " + string(min) + " or higher"})
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, p)))
	}
}

// audit records an action of the request's principal. A failure is logged:
// the action already happened.
func (a *api) audit(r *http.Request, action, target string, detail any) {
	if _, err := a.st.Audit(r.Context(), who(r).name(), action, target, detail); err != nil {
		a.log.Error("audit", "action", action, "err", err)
	}
}

func (a *api) auditAs(ctx context.Context, actor, action, target string, detail any) {
	if _, err := a.st.Audit(ctx, actor, action, target, detail); err != nil {
		a.log.Error("audit", "action", action, "err", err)
	}
}

func (a *api) setSession(w http.ResponseWriter, r *http.Request, u *store.User) error {
	secret := auth.Secret(32)
	csrf := auth.Secret(32)
	if err := a.st.CreateSession(r.Context(), auth.Hash(secret), u.ID, csrf); err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: secret, Path: "/",
		HttpOnly: true, Secure: r.TLS != nil || a.secureCookies, SameSite: http.SameSiteStrictMode,
		MaxAge: int(sessionMax / time.Second),
	})
	writeJSON(w, http.StatusOK, map[string]any{"user": u, "csrfToken": csrf})
	return nil
}

// authStatus tells a login page whether the owner must be created first.
func (a *api) authStatus(w http.ResponseWriter, r *http.Request) {
	_, err := a.st.Value(r.Context(), SetupTokenKey)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		a.fail(w, err)
		return
	}
	out := map[string]any{"setupRequired": err == nil}
	if s, err := a.oidcSettings(r.Context()); err == nil && s.Enabled {
		out["sso"] = map[string]any{"label": cmp.Or(s.Label, "Sign in with single sign-on"), "url": "/api/v1/auth/oidc/start"}
	}
	writeJSON(w, http.StatusOK, out)
}

// setup creates the first owner with the setup token printed at first
// start.
func (a *api) setup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token    string `json:"token"`
		Name     string `json:"name"`
		Password string `json:"password"`
	}
	if err := a.decode(r, &req); err != nil {
		a.fail(w, err)
		return
	}
	want, err := a.st.Value(r.Context(), SetupTokenKey)
	if errors.Is(err, store.ErrNotFound) {
		a.fail(w, httpError{status: http.StatusConflict, msg: "setup is done"})
		return
	}
	if err != nil {
		a.fail(w, err)
		return
	}
	if subtle.ConstantTimeCompare([]byte(req.Token), want) != 1 {
		a.auditAs(r.Context(), "anonymous", "auth.setup.failed", "", map[string]any{"ip": clientIP(r).String()})
		a.fail(w, httpError{status: http.StatusForbidden, msg: "wrong setup token"})
		return
	}
	if err := checkAccount(req.Name, req.Password); err != nil {
		a.fail(w, err)
		return
	}
	u := &store.User{Name: req.Name, Role: string(auth.Owner), Password: auth.HashPassword(req.Password)}
	if err := a.st.CreateFirstUser(r.Context(), u, SetupTokenKey); err != nil {
		if errors.Is(err, store.ErrConflict) {
			err = httpError{status: http.StatusConflict, msg: "setup is done"}
		}
		a.fail(w, err)
		return
	}
	a.auditAs(r.Context(), u.Name, "auth.setup", u.ID, nil)
	if err := a.setSession(w, r, u); err != nil {
		a.fail(w, err)
	}
}

// login checks a password and, when enabled, a TOTP code.
func (a *api) login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name     string `json:"name"`
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if err := a.decode(r, &req); err != nil {
		a.fail(w, err)
		return
	}
	ctx := r.Context()
	fail := func(u *store.User, why string) {
		detail := map[string]any{"name": req.Name, "reason": why, "ip": clientIP(r).String()}
		if u != nil {
			a.st.LoginFailed(ctx, u.ID, maxFailures, lockFor)
		}
		a.auditAs(ctx, "anonymous", "auth.login.failed", "", detail)
		a.fail(w, httpError{status: http.StatusUnauthorized, msg: "wrong name, password or code"})
	}
	u, err := a.st.UserByName(ctx, req.Name)
	if errors.Is(err, store.ErrNotFound) {
		auth.CheckNoUser(req.Password)
		fail(nil, "unknown user")
		return
	}
	if err != nil {
		a.fail(w, err)
		return
	}
	if time.Now().Before(u.LockedUntil) {
		a.auditAs(ctx, "anonymous", "auth.login.failed", u.ID, map[string]any{"reason": "locked", "ip": clientIP(r).String()})
		a.fail(w, httpError{status: http.StatusTooManyRequests, msg: "account locked after failed logins; try later"})
		return
	}
	if !auth.CheckPassword(u.Password, req.Password) {
		fail(u, "password")
		return
	}
	if u.TOTPEnabled {
		if req.Code == "" {
			a.fail(w, httpError{status: http.StatusUnauthorized, msg: "two-factor code required", code: "totp_required"})
			return
		}
		step, ok := auth.CheckTOTP(u.TOTPSecret, req.Code, time.Now())
		if ok {
			ok, err = a.st.UseTOTPStep(ctx, u.ID, step)
			if err != nil {
				a.fail(w, err)
				return
			}
		}
		if !ok {
			fail(u, "code")
			return
		}
	}
	a.st.LoginSucceeded(ctx, u.ID)
	a.auditAs(ctx, u.Name, "auth.login", u.ID, map[string]any{"ip": clientIP(r).String()})
	if err := a.setSession(w, r, u); err != nil {
		a.fail(w, err)
	}
}

func (a *api) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		a.st.DeleteSession(r.Context(), auth.Hash(c.Value))
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	a.audit(r, "auth.logout", who(r).user.ID, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (a *api) me(w http.ResponseWriter, r *http.Request, ac *access) {
	p := who(r)
	out := map[string]any{"user": p.user, "role": p.role, "via": p.via, "groupRoles": ac.groupRoles()}
	if p.csrf != "" {
		out["csrfToken"] = p.csrf
	}
	writeJSON(w, http.StatusOK, out)
}

func checkAccount(name, password string) error {
	if !nameOK(name) {
		return httpError{status: http.StatusUnprocessableEntity, msg: "name: must be 1-64 lowercase letters, digits, '.', '_' or '-'"}
	}
	if err := auth.ValidatePassword(password); err != nil {
		return httpError{status: http.StatusUnprocessableEntity, msg: "password: " + err.Error()}
	}
	return nil
}

func nameOK(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
