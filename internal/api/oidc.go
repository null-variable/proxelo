package api

import (
	"cmp"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/null-variable/proxelo/internal/auth"
	"github.com/null-variable/proxelo/internal/store"
)

// OIDCKey holds the single sign-on settings in the state table.
const OIDCKey = "auth/oidc"

const (
	oidcCookie = "proxelo_oidc"
	// The browser has this long to come back from the identity provider.
	oidcWindow = 10 * time.Minute
)

// OIDCSettings configure single sign-on with an OpenID Connect provider
// (Google Workspace, Keycloak, Entra ID and others with discovery).
type OIDCSettings struct {
	Enabled bool `json:"enabled"`
	// Issuer URL; its /.well-known/openid-configuration is read.
	Issuer       string `json:"issuer"`
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret,omitempty"`
	// The console's callback URL as registered with the provider:
	// https://<admin address>/api/v1/auth/oidc/callback.
	RedirectURL string `json:"redirectUrl"`
	// Button label on the login page.
	Label string `json:"label,omitempty"`
	// Scopes besides openid; "profile email" by default.
	Scopes []string `json:"scopes,omitempty"`
	// Claim holding the account name, "preferred_username" by default
	// (then "email").
	NameClaim string `json:"nameClaim,omitempty"`
	// Claim holding the group list, "groups" by default.
	GroupsClaim string `json:"groupsClaim,omitempty"`
	// Group to role. The highest role of the groups a user is in applies.
	Mappings []OIDCMapping `json:"mappings,omitempty"`
	// Role for users in no mapped group; empty refuses them.
	DefaultRole string `json:"defaultRole,omitempty"`
	// Allowed email domains (the "hd"/email claim); empty allows any.
	Domains []string `json:"domains,omitempty"`
}

type OIDCMapping struct {
	Group string `json:"group"`
	Role  string `json:"role"`
}

func (s *OIDCSettings) validate() error {
	if !s.Enabled {
		return nil
	}
	u, err := url.Parse(s.Issuer)
	if err != nil || u.Scheme != "https" && !(u.Scheme == "http" && isLoopbackHost(u.Hostname())) || u.Host == "" {
		return fieldErr("issuer", "must be an https URL")
	}
	if s.ClientID == "" {
		return fieldErr("clientId", "is required")
	}
	r, err := url.Parse(s.RedirectURL)
	if err != nil || (r.Scheme != "https" && r.Scheme != "http") || r.Host == "" || !strings.HasSuffix(r.Path, "/api/v1/auth/oidc/callback") {
		return fieldErr("redirectUrl", "must be the URL of /api/v1/auth/oidc/callback")
	}
	for i, m := range s.Mappings {
		if m.Group == "" {
			return fieldErr("mappings["+itoa(i)+"].group", "is required")
		}
		if _, err := auth.ParseRole(m.Role); err != nil || m.Role == string(auth.Guest) {
			return fieldErr("mappings["+itoa(i)+"].role", "must be a role")
		}
	}
	if s.DefaultRole != "" {
		if _, err := auth.ParseRole(s.DefaultRole); err != nil {
			return fieldErr("defaultRole", "must be a role")
		}
	}
	if s.DefaultRole == "" && len(s.Mappings) == 0 {
		return fieldErr("mappings", "map at least one group or set defaultRole, or nobody can sign in")
	}
	return nil
}

func isLoopbackHost(h string) bool {
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

func fieldErr(path, msg string) error {
	return httpError{status: http.StatusUnprocessableEntity, msg: path + ": " + msg}
}

// oidcClient caches the provider discovered for the current settings.
type oidcClient struct {
	mu       sync.Mutex
	issuer   string
	provider *oidc.Provider
}

func (c *oidcClient) get(ctx context.Context, issuer string) (*oidc.Provider, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.provider != nil && c.issuer == issuer {
		return c.provider, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	p, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, err
	}
	c.issuer, c.provider = issuer, p
	return p, nil
}

func (a *api) oidcSettings(ctx context.Context) (*OIDCSettings, error) {
	raw, err := a.st.Value(ctx, OIDCKey)
	if errors.Is(err, store.ErrNotFound) {
		return &OIDCSettings{}, nil
	}
	if err != nil {
		return nil, err
	}
	s := &OIDCSettings{}
	if err := json.Unmarshal(raw, s); err != nil {
		return nil, err
	}
	return s, nil
}

// getOIDC returns the settings without the client secret.
func (a *api) getOIDC(w http.ResponseWriter, r *http.Request) {
	s, err := a.oidcSettings(r.Context())
	if err != nil {
		a.fail(w, err)
		return
	}
	out := *s
	out.ClientSecret = ""
	writeJSON(w, http.StatusOK, map[string]any{"settings": out, "clientSecretSet": s.ClientSecret != ""})
}

// putOIDC replaces the settings. An empty clientSecret keeps the stored
// one. Enabling checks the issuer's discovery document.
func (a *api) putOIDC(w http.ResponseWriter, r *http.Request) {
	var s OIDCSettings
	if err := a.decode(r, &s); err != nil {
		a.fail(w, err)
		return
	}
	old, err := a.oidcSettings(r.Context())
	if err != nil {
		a.fail(w, err)
		return
	}
	if s.ClientSecret == "" && s.Issuer == old.Issuer && s.ClientID == old.ClientID {
		s.ClientSecret = old.ClientSecret
	}
	if err := s.validate(); err != nil {
		a.fail(w, err)
		return
	}
	if s.Enabled {
		if _, err := a.oidc.get(r.Context(), s.Issuer); err != nil {
			a.fail(w, fieldErr("issuer", "discovery failed: "+err.Error()))
			return
		}
	}
	raw, err := json.Marshal(s)
	if err != nil {
		a.fail(w, err)
		return
	}
	if err := a.st.Put(r.Context(), OIDCKey, raw); err != nil {
		a.fail(w, err)
		return
	}
	a.audit(r, "settings.oidc", "", map[string]any{"enabled": s.Enabled, "issuer": s.Issuer, "clientId": s.ClientID, "mappings": s.Mappings, "defaultRole": s.DefaultRole})
	set := s.ClientSecret != ""
	s.ClientSecret = ""
	writeJSON(w, http.StatusOK, map[string]any{"settings": s, "clientSecretSet": set})
}

// oidcFlow is what the browser carries to the provider and back, in a
// cookie: the state, nonce and PKCE verifier.
type oidcFlow struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Expires  int64  `json:"e"`
}

func (a *api) oauth2Config(ctx context.Context, s *OIDCSettings) (*oauth2.Config, *oidc.Provider, error) {
	p, err := a.oidc.get(ctx, s.Issuer)
	if err != nil {
		return nil, nil, err
	}
	scopes := s.Scopes
	if len(scopes) == 0 {
		scopes = []string{"profile", "email"}
	}
	return &oauth2.Config{
		ClientID: s.ClientID, ClientSecret: s.ClientSecret, RedirectURL: s.RedirectURL,
		Endpoint: p.Endpoint(), Scopes: append([]string{oidc.ScopeOpenID}, scopes...),
	}, p, nil
}

// oidcStart redirects the browser to the provider.
func (a *api) oidcStart(w http.ResponseWriter, r *http.Request) {
	s, err := a.oidcSettings(r.Context())
	if err != nil {
		a.fail(w, err)
		return
	}
	if !s.Enabled {
		a.fail(w, httpError{status: http.StatusNotFound, msg: "single sign-on is off"})
		return
	}
	cfg, _, err := a.oauth2Config(r.Context(), s)
	if err != nil {
		a.log.Error("oidc discovery", "issuer", s.Issuer, "err", err)
		a.fail(w, httpError{status: http.StatusBadGateway, msg: "identity provider unreachable"})
		return
	}
	f := oidcFlow{State: auth.Secret(24), Nonce: auth.Secret(24), Verifier: oauth2.GenerateVerifier(), Expires: time.Now().Add(oidcWindow).Unix()}
	raw, _ := json.Marshal(f)
	http.SetCookie(w, &http.Cookie{
		Name: oidcCookie, Value: base64.RawURLEncoding.EncodeToString(raw), Path: "/api/v1/auth/oidc/",
		// Lax: the provider's redirect back is a cross-site navigation.
		HttpOnly: true, Secure: r.TLS != nil || a.secureCookies, SameSite: http.SameSiteLaxMode,
		MaxAge: int(oidcWindow / time.Second),
	})
	http.Redirect(w, r, cfg.AuthCodeURL(f.State, oidc.Nonce(f.Nonce), oauth2.S256ChallengeOption(f.Verifier)), http.StatusFound)
}

// oidcCallback finishes the login and sends the browser to the console.
// Failures land on the login page with ?sso_error=.
func (a *api) oidcCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	fail := func(why string, detail map[string]any) {
		if detail == nil {
			detail = map[string]any{}
		}
		detail["reason"], detail["ip"] = why, clientIP(r).String()
		a.auditAs(ctx, "anonymous", "auth.sso.failed", "", detail)
		http.Redirect(w, r, "/?sso_error="+url.QueryEscape(why), http.StatusFound)
	}
	http.SetCookie(w, &http.Cookie{Name: oidcCookie, Path: "/api/v1/auth/oidc/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	c, err := r.Cookie(oidcCookie)
	if err != nil {
		fail("sign-in expired; try again", nil)
		return
	}
	var f oidcFlow
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil || json.Unmarshal(raw, &f) != nil || time.Now().Unix() > f.Expires {
		fail("sign-in expired; try again", nil)
		return
	}
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		fail("provider refused: "+e, map[string]any{"description": q.Get("error_description")})
		return
	}
	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(f.State)) != 1 {
		fail("state mismatch", nil)
		return
	}
	s, err := a.oidcSettings(ctx)
	if err != nil || !s.Enabled {
		fail("single sign-on is off", nil)
		return
	}
	cfg, p, err := a.oauth2Config(ctx, s)
	if err != nil {
		fail("identity provider unreachable", nil)
		return
	}
	xctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	tok, err := cfg.Exchange(xctx, q.Get("code"), oauth2.VerifierOption(f.Verifier))
	if err != nil {
		fail("code exchange failed", map[string]any{"err": err.Error()})
		return
	}
	rawID, _ := tok.Extra("id_token").(string)
	if rawID == "" {
		fail("no id_token", nil)
		return
	}
	id, err := p.Verifier(&oidc.Config{ClientID: s.ClientID}).Verify(xctx, rawID)
	if err != nil {
		fail("id_token invalid", map[string]any{"err": err.Error()})
		return
	}
	if subtle.ConstantTimeCompare([]byte(id.Nonce), []byte(f.Nonce)) != 1 {
		fail("nonce mismatch", nil)
		return
	}
	var claims map[string]any
	if err := id.Claims(&claims); err != nil {
		fail("claims unreadable", nil)
		return
	}
	// Providers put groups in the userinfo response only, sometimes.
	groupsClaim := cmp.Or(s.GroupsClaim, "groups")
	if _, ok := claims[groupsClaim]; !ok {
		if ui, err := p.UserInfo(xctx, oauth2.StaticTokenSource(tok)); err == nil {
			var extra map[string]any
			if ui.Claims(&extra) == nil {
				if g, ok := extra[groupsClaim]; ok {
					claims[groupsClaim] = g
				}
			}
		}
	}
	email, _ := claims["email"].(string)
	if len(s.Domains) > 0 {
		_, domain, _ := strings.Cut(email, "@")
		if hd, _ := claims["hd"].(string); hd != "" {
			domain = hd
		}
		if !slices.Contains(s.Domains, strings.ToLower(domain)) {
			fail("email domain not allowed", map[string]any{"email": email})
			return
		}
	}
	role := oidcRole(s, stringList(claims[groupsClaim]))
	if role == "" {
		fail("no role for your groups", map[string]any{"subject": id.Subject, "email": email})
		return
	}
	name := accountName(claims, s.NameClaim, id.Subject)
	sso := id.Issuer + "|" + id.Subject
	u, created, err := a.st.SSOLogin(ctx, sso, name, string(role), true)
	if errors.Is(err, store.ErrNameTaken) {
		// A local account has the name; keep the SSO one apart.
		u, created, err = a.st.SSOLogin(ctx, sso, name+"-sso-"+shortHash(sso), string(role), true)
	}
	if err != nil {
		a.log.Error("oidc login", "err", err)
		fail("account could not be created", nil)
		return
	}
	if created {
		a.auditAs(ctx, u.Name, "user.create", u.ID, map[string]any{"name": u.Name, "role": u.Role, "sso": sso})
	}
	a.auditAs(ctx, u.Name, "auth.login", u.ID, map[string]any{"ip": clientIP(r).String(), "via": "oidc"})
	secret := auth.Secret(32)
	if err := a.st.CreateSession(ctx, auth.Hash(secret), u.ID, auth.Secret(32)); err != nil {
		a.fail(w, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: secret, Path: "/",
		HttpOnly: true, Secure: r.TLS != nil || a.secureCookies, SameSite: http.SameSiteStrictMode,
		MaxAge: int(sessionMax / time.Second),
	})
	// A SameSite=Strict cookie set on a cross-site navigation is not sent
	// on that navigation's redirects; the console page loads it from
	// /auth/me on the next same-site request.
	http.Redirect(w, r, "/", http.StatusFound)
}

// oidcRole is the highest role mapped from groups, or the default.
func oidcRole(s *OIDCSettings, groups []string) auth.Role {
	var best auth.Role
	for _, m := range s.Mappings {
		if slices.Contains(groups, m.Group) {
			if best == "" {
				best = auth.Role(m.Role)
			} else {
				best = best.Higher(auth.Role(m.Role))
			}
		}
	}
	if best == "" {
		best = auth.Role(s.DefaultRole)
	}
	return best
}

func stringList(v any) []string {
	switch x := v.(type) {
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		return strings.Fields(x)
	}
	return nil
}

// accountName makes a valid account name from the name claim.
func accountName(claims map[string]any, claim, subject string) string {
	var v string
	for _, c := range []string{claim, "preferred_username", "email"} {
		if s, ok := claims[c].(string); c != "" && ok && s != "" {
			v = s
			break
		}
	}
	if v == "" {
		v = subject
	}
	var b strings.Builder
	for _, c := range strings.ToLower(v) {
		if b.Len() >= 48 {
			break
		}
		switch {
		case c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-':
			b.WriteRune(c)
		case c == '@':
			b.WriteByte('.')
		default:
			b.WriteByte('-')
		}
	}
	if b.Len() == 0 {
		return "sso-" + shortHash(subject)
	}
	return b.String()
}

func shortHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(h[:])[:6]
}
