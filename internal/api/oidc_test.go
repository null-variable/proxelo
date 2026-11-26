package api

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// fakeIdP is an OpenID provider issuing one fixed identity.
type fakeIdP struct {
	srv    *httptest.Server
	key    *rsa.PrivateKey
	claims map[string]any
	nonce  string
}

func newIdP(t *testing.T) *fakeIdP {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &fakeIdP{key: key}
	mux := http.NewServeMux()
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer": p.srv.URL, "authorization_endpoint": p.srv.URL + "/auth", "token_endpoint": p.srv.URL + "/token",
			"jwks_uri": p.srv.URL + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		p.nonce = q.Get("nonce")
		http.Redirect(w, r, q.Get("redirect_uri")+"?code=c&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.FormValue("code_verifier") == "" {
			http.Error(w, "no PKCE", http.StatusBadRequest)
			return
		}
		claims := map[string]any{"iss": p.srv.URL, "aud": "proxelo", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "nonce": p.nonce}
		for k, v := range p.claims {
			claims[k] = v
		}
		sig, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: key, KeyID: "k"}}, nil)
		body, _ := json.Marshal(claims)
		jws, _ := sig.Sign(body)
		tok, _ := jws.CompactSerialize()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": tok})
	})
	return p
}

func TestOIDCLogin(t *testing.T) {
	c := newClient(t)
	idp := newIdP(t)
	settings := map[string]any{
		"enabled": true, "issuer": idp.srv.URL, "clientId": "proxelo", "clientSecret": "s",
		"redirectUrl": c.srv.URL + "/api/v1/auth/oidc/callback",
		"mappings":    []map[string]string{{"group": "ops", "role": "operator"}, {"group": "dev", "role": "editor"}},
	}
	wantStatus(t, c.do("PUT", "/api/v1/settings/oidc", settings, nil, nil), http.StatusOK)
	var got struct {
		Settings        OIDCSettings `json:"settings"`
		ClientSecretSet bool         `json:"clientSecretSet"`
	}
	wantStatus(t, c.do("GET", "/api/v1/settings/oidc", nil, nil, &got), http.StatusOK)
	if got.Settings.ClientSecret != "" || !got.ClientSecretSet {
		t.Errorf("secret leaked or lost: %+v", got)
	}

	login := func(claims map[string]any) (*http.Response, *client) {
		idp.claims = claims
		u := &client{t: t, srv: c.srv, http: &http.Client{Jar: newJar()}}
		resp, err := u.http.Get(c.srv.URL + "/api/v1/auth/oidc/start")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp, u
	}
	resp, u := login(map[string]any{"sub": "42", "preferred_username": "Alice@Example.com", "groups": []string{"dev", "ops"}})
	if resp.Request.URL.Path != "/" || resp.Request.URL.RawQuery != "" {
		t.Fatalf("landed on %s", resp.Request.URL)
	}
	var me struct {
		User struct{ Name, Role, SSO string }
	}
	wantStatus(t, u.do("GET", "/api/v1/auth/me", nil, nil, &me), http.StatusOK)
	if me.User.Name != "alice.example.com" || me.User.Role != "operator" || !strings.HasSuffix(me.User.SSO, "|42") {
		t.Errorf("me: %+v", me.User)
	}
	// The same subject logs into the same account; mapping changes apply.
	_, u = login(map[string]any{"sub": "42", "preferred_username": "renamed", "groups": []string{"dev"}})
	wantStatus(t, u.do("GET", "/api/v1/auth/me", nil, nil, &me), http.StatusOK)
	if me.User.Name != "alice.example.com" || me.User.Role != "editor" {
		t.Errorf("second login: %+v", me.User)
	}
	// No mapped group and no default role: refused.
	resp, _ = login(map[string]any{"sub": "43", "groups": []string{"x"}})
	if !strings.Contains(resp.Request.URL.RawQuery, "sso_error") {
		t.Errorf("unmapped user landed on %s", resp.Request.URL)
	}
	// An SSO account has no password to log in with.
	wantStatus(t, c.do("POST", "/api/v1/auth/login", map[string]any{"name": "alice.example.com", "password": ""}, nil, nil), http.StatusUnauthorized)
}

func newJar() http.CookieJar {
	j, _ := cookiejar.New(nil)
	return j
}
