package api

import (
	"errors"
	"net/http"
	"net/netip"
	"time"

	"github.com/null-variable/proxelo/internal/auth"
	"github.com/null-variable/proxelo/internal/store"
)

// maxTokenLife bounds API token expiry.
const maxTokenLife = 366 * 24 * time.Hour

func (a *api) users(w http.ResponseWriter, r *http.Request) {
	us, err := a.st.Users(r.Context())
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": us})
}

// mayManage reports whether p can create, change or remove accounts of
// role: only owners manage owners.
func mayManage(p *principal, role auth.Role) bool {
	return role != auth.Owner || p.role == auth.Owner
}

func (a *api) createUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name     string `json:"name"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := a.decode(r, &req); err != nil {
		a.fail(w, err)
		return
	}
	role, err := auth.ParseRole(req.Role)
	if err != nil {
		a.fail(w, httpError{http.StatusUnprocessableEntity, "role: " + err.Error()})
		return
	}
	if !mayManage(who(r), role) {
		a.fail(w, httpError{http.StatusForbidden, "only owners create owners"})
		return
	}
	if err := checkAccount(req.Name, req.Password); err != nil {
		a.fail(w, err)
		return
	}
	u := &store.User{Name: req.Name, Role: string(role), Password: auth.HashPassword(req.Password)}
	if err := a.st.CreateUser(r.Context(), u); err != nil {
		a.fail(w, err)
		return
	}
	a.audit(r, "user.create", u.ID, map[string]any{"name": u.Name, "role": u.Role})
	writeJSON(w, http.StatusCreated, u)
}

func (a *api) loadUser(w http.ResponseWriter, r *http.Request) (*store.User, bool) {
	u, err := a.st.User(r.Context(), r.PathValue("id"))
	if err != nil {
		a.fail(w, err)
		return nil, false
	}
	if !mayManage(who(r), auth.Role(u.Role)) {
		a.fail(w, httpError{http.StatusForbidden, "only owners manage owners"})
		return nil, false
	}
	return u, true
}

// updateUser changes the role or resets the password (and second factor)
// of another account.
func (a *api) updateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Role      string `json:"role"`
		Password  string `json:"password"`
		ResetTOTP bool   `json:"resetTotp"`
	}
	if err := a.decode(r, &req); err != nil {
		a.fail(w, err)
		return
	}
	u, ok := a.loadUser(w, r)
	if !ok {
		return
	}
	if req.Role != "" {
		role, err := auth.ParseRole(req.Role)
		if err != nil {
			a.fail(w, httpError{http.StatusUnprocessableEntity, "role: " + err.Error()})
			return
		}
		if !mayManage(who(r), role) {
			a.fail(w, httpError{http.StatusForbidden, "only owners make owners"})
			return
		}
		if err := a.st.SetRole(r.Context(), u.ID, string(role)); err != nil {
			a.fail(w, roleErr(err))
			return
		}
		a.audit(r, "user.role", u.ID, map[string]any{"from": u.Role, "to": role})
	}
	if req.Password != "" || req.ResetTOTP {
		hash := u.Password
		if req.Password != "" {
			if err := auth.ValidatePassword(req.Password); err != nil {
				a.fail(w, httpError{http.StatusUnprocessableEntity, "password: " + err.Error()})
				return
			}
			hash = auth.HashPassword(req.Password)
		}
		if err := a.st.SetPassword(r.Context(), u.ID, hash, req.ResetTOTP); err != nil {
			a.fail(w, err)
			return
		}
		a.audit(r, "user.reset", u.ID, map[string]any{"password": req.Password != "", "totp": req.ResetTOTP})
	}
	u, err := a.st.User(r.Context(), u.ID)
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, u)
}

func roleErr(err error) error {
	if errors.Is(err, store.ErrLastOwner) {
		return httpError{http.StatusConflict, err.Error()}
	}
	return err
}

func (a *api) deleteUser(w http.ResponseWriter, r *http.Request) {
	u, ok := a.loadUser(w, r)
	if !ok {
		return
	}
	if err := a.st.DeleteUser(r.Context(), u.ID); err != nil {
		a.fail(w, roleErr(err))
		return
	}
	a.audit(r, "user.delete", u.ID, map[string]any{"name": u.Name})
	w.WriteHeader(http.StatusNoContent)
}

// changePassword lets a session user replace their own password.
func (a *api) changePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Current  string `json:"current"`
		Password string `json:"password"`
	}
	if err := a.decode(r, &req); err != nil {
		a.fail(w, err)
		return
	}
	u := who(r).user
	if !auth.CheckPassword(u.Password, req.Current) {
		a.fail(w, httpError{http.StatusForbidden, "current password is wrong"})
		return
	}
	if err := auth.ValidatePassword(req.Password); err != nil {
		a.fail(w, httpError{http.StatusUnprocessableEntity, "password: " + err.Error()})
		return
	}
	if err := a.st.SetPassword(r.Context(), u.ID, auth.HashPassword(req.Password), false); err != nil {
		a.fail(w, err)
		return
	}
	a.audit(r, "user.password", u.ID, nil)
	w.WriteHeader(http.StatusNoContent)
}

// totpSetup stores a new pending secret and returns it for enrollment.
// It takes effect after totpEnable checks a code from it.
func (a *api) totpSetup(w http.ResponseWriter, r *http.Request) {
	u := who(r).user
	if u.TOTPEnabled {
		a.fail(w, httpError{http.StatusConflict, "two-factor is already on; disable it first"})
		return
	}
	secret := auth.NewTOTPSecret()
	if err := a.st.SetTOTP(r.Context(), u.ID, secret, false); err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"secret": secret, "uri": auth.TOTPURI("Proxelo", u.Name, secret)})
}

func (a *api) totpEnable(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code string `json:"code"`
	}
	if err := a.decode(r, &req); err != nil {
		a.fail(w, err)
		return
	}
	u := who(r).user
	if u.TOTPSecret == "" || u.TOTPEnabled {
		a.fail(w, httpError{http.StatusConflict, "call /auth/totp/setup first"})
		return
	}
	step, ok := auth.CheckTOTP(u.TOTPSecret, req.Code, time.Now())
	if !ok {
		a.fail(w, httpError{http.StatusUnprocessableEntity, "code: does not match"})
		return
	}
	if err := a.st.SetTOTP(r.Context(), u.ID, u.TOTPSecret, true); err != nil {
		a.fail(w, err)
		return
	}
	a.st.UseTOTPStep(r.Context(), u.ID, step)
	a.audit(r, "user.totp.enable", u.ID, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (a *api) totpDisable(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
	}
	if err := a.decode(r, &req); err != nil {
		a.fail(w, err)
		return
	}
	u := who(r).user
	if !auth.CheckPassword(u.Password, req.Password) {
		a.fail(w, httpError{http.StatusForbidden, "password is wrong"})
		return
	}
	if err := a.st.SetTOTP(r.Context(), u.ID, "", false); err != nil {
		a.fail(w, err)
		return
	}
	a.audit(r, "user.totp.disable", u.ID, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (a *api) tokens(w http.ResponseWriter, r *http.Request) {
	ts, err := a.st.Tokens(r.Context(), who(r).user.ID)
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": ts})
}

// createToken issues an API token for the caller. Its role is capped at the
// caller's; the secret is shown once.
func (a *api) createToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name      string   `json:"name"`
		Role      string   `json:"role"`
		CIDRs     []string `json:"cidrs"`
		ExpiresIn string   `json:"expiresIn"`
	}
	if err := a.decode(r, &req); err != nil {
		a.fail(w, err)
		return
	}
	p := who(r)
	if p.via != "session" {
		a.fail(w, httpError{http.StatusForbidden, "tokens are created from a login session"})
		return
	}
	if !nameOK(req.Name) {
		a.fail(w, httpError{http.StatusUnprocessableEntity, "name: must be 1-64 lowercase letters, digits, '.', '_' or '-'"})
		return
	}
	role := p.role
	if req.Role != "" {
		rr, err := auth.ParseRole(req.Role)
		if err != nil {
			a.fail(w, httpError{http.StatusUnprocessableEntity, "role: " + err.Error()})
			return
		}
		role = rr.Lower(p.role)
	}
	for i, c := range req.CIDRs {
		if _, err := netip.ParsePrefix(c); err != nil {
			a.fail(w, httpError{http.StatusUnprocessableEntity, "cidrs[" + itoa(i) + "]: must be a CIDR"})
			return
		}
	}
	life := 90 * 24 * time.Hour
	if req.ExpiresIn != "" {
		d, err := time.ParseDuration(req.ExpiresIn)
		if err != nil || d <= 0 || d > maxTokenLife {
			a.fail(w, httpError{http.StatusUnprocessableEntity, "expiresIn: must be a duration up to 8784h"})
			return
		}
		life = d
	}
	key := auth.Secret(32)
	t := &store.Token{
		ID: "tok_" + auth.Secret(9), User: p.user.ID, Name: req.Name, Role: string(role), CIDRs: req.CIDRs,
		ExpiresAt: time.Now().Add(life).UTC().Truncate(time.Second), Hash: auth.Hash(key),
	}
	if err := a.st.CreateToken(r.Context(), t); err != nil {
		a.fail(w, err)
		return
	}
	a.audit(r, "token.create", t.ID, map[string]any{"name": t.Name, "role": t.Role, "cidrs": t.CIDRs, "expiresAt": t.ExpiresAt})
	writeJSON(w, http.StatusCreated, map[string]any{"token": t, "secret": t.ID + "." + key})
}

func (a *api) deleteToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := a.st.DeleteToken(r.Context(), who(r).user.ID, id); err != nil {
		a.fail(w, err)
		return
	}
	a.audit(r, "token.delete", id, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (a *api) auditLog(w http.ResponseWriter, r *http.Request) {
	after, err := uintParam(r, "after")
	if err != nil {
		a.fail(w, err)
		return
	}
	limit := 100
	if n, err := uintParam(r, "limit"); err != nil {
		a.fail(w, err)
		return
	} else if n > 0 {
		limit = int(min(n, 1000))
	}
	es, err := a.st.AuditLog(r.Context(), after, limit)
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": es})
}

func (a *api) auditVerify(w http.ResponseWriter, r *http.Request) {
	n, err := a.st.VerifyAudit(r.Context())
	if err != nil && n == 0 && !errors.Is(err, store.ErrNotFound) {
		a.fail(w, err)
		return
	}
	out := map[string]any{"entries": n, "ok": err == nil}
	if err != nil {
		out["error"] = err.Error()
	}
	writeJSON(w, http.StatusOK, out)
}
