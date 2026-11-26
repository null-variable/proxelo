package api

import (
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"

	"github.com/null-variable/proxelo/internal/store"
	"github.com/null-variable/proxelo/internal/topology"
)

// login creates an account with role and returns a client signed in as it.
func (c *client) login(name, role string) *client {
	c.t.Helper()
	wantStatus(c.t, c.do("POST", "/api/v1/users", map[string]any{"name": name, "password": name + "-password-1", "role": role}, nil, nil), http.StatusCreated)
	jar, _ := cookiejar.New(nil)
	u := &client{t: c.t, srv: c.srv, st: c.st, d: c.d, http: &http.Client{Jar: jar}}
	var out struct {
		CSRF string `json:"csrfToken"`
	}
	wantStatus(c.t, u.do("POST", "/api/v1/auth/login", map[string]any{"name": name, "password": name + "-password-1"}, nil, &out), http.StatusOK)
	u.csrf = out.CSRF
	return u
}

func TestGroups(t *testing.T) {
	c := newClient(t)
	var shop, pay store.Group
	wantStatus(t, c.do("POST", "/api/v1/groups", map[string]any{"name": "shop", "domains": []string{"shop.example"}}, nil, &shop), http.StatusCreated)
	// A subgroup stays inside its parent's domains.
	wantStatus(t, c.do("POST", "/api/v1/groups", map[string]any{"name": "pay", "parent": shop.ID, "domains": []string{"pay.other.example"}}, nil, nil), http.StatusUnprocessableEntity)
	wantStatus(t, c.do("POST", "/api/v1/groups", map[string]any{"name": "pay", "parent": shop.ID, "domains": []string{"pay.shop.example"}}, nil, &pay), http.StatusCreated)

	c.begin("infra")
	lst := c.create("listeners", map[string]any{"name": "http", "spec": map[string]any{"address": "0.0.0.0:8080"}})
	other := c.create("upstreams", map[string]any{"name": "other", "spec": map[string]any{"targets": []any{map[string]any{"address": "127.0.0.1:9001"}}}})
	c.apply("direct")

	// A guest with editor on shop works in pay through inheritance.
	ann := c.login("ann", "guest")
	wantStatus(t, c.do("PUT", "/api/v1/groups/"+shop.ID+"/members", map[string]any{"user": "ann", "role": "editor"}, nil, nil), http.StatusOK)
	var me struct {
		GroupRoles map[string]string `json:"groupRoles"`
	}
	wantStatus(t, ann.do("GET", "/api/v1/auth/me", nil, nil, &me), http.StatusOK)
	if me.GroupRoles[pay.ID] != "editor" {
		t.Fatalf("groupRoles = %v", me.GroupRoles)
	}

	ann.begin("pay site")
	up := ann.create("upstreams", map[string]any{"name": "pay", "group": pay.ID, "spec": map[string]any{"targets": []any{map[string]any{"address": "127.0.0.1:9000"}}}})
	site := func(host string) map[string]any {
		return map[string]any{"name": "pay", "group": pay.ID, "spec": map[string]any{"listeners": []string{lst}, "hostnames": []any{map[string]any{"type": "exact", "value": host}}}}
	}
	// Hostnames outside the group's domains are refused.
	wantStatus(t, ann.do("POST", "/api/v1/sites"+ann.q(), site("evil.example"), nil, nil), http.StatusUnprocessableEntity)
	ann.create("sites", site("pay.shop.example"))
	// Ungrouped resources need an instance role.
	wantStatus(t, ann.do("POST", "/api/v1/upstreams"+ann.q(), map[string]any{"name": "loose", "spec": map[string]any{"targets": []any{map[string]any{"address": "127.0.0.1:1"}}}}, nil, nil), http.StatusForbidden)
	// Routes cannot point at upstreams outside the member's groups.
	wantStatus(t, ann.do("POST", "/api/v1/routes"+ann.q(), map[string]any{"name": "steal", "group": pay.ID, "spec": map[string]any{
		"match": map[string]any{"path": map[string]any{"type": "prefix", "value": "/"}}, "action": map[string]any{"type": "proxy", "proxy": map[string]any{"upstream": other}},
	}}, nil, nil), http.StatusUnprocessableEntity)
	// Editors cannot apply.
	wantStatus(t, ann.do("POST", "/api/v1/changesets/"+ann.cs+"/apply", map[string]any{"mode": "direct"}, nil, nil), http.StatusForbidden)

	// Ann sees the shared listener and her group, not the other upstream.
	var ups struct {
		Items []struct{ ID string } `json:"items"`
	}
	wantStatus(t, ann.do("GET", "/api/v1/upstreams"+ann.q(), nil, nil, &ups), http.StatusOK)
	if len(ups.Items) != 1 || ups.Items[0].ID != up {
		t.Fatalf("upstreams = %+v", ups.Items)
	}
	wantStatus(t, ann.do("GET", "/api/v1/upstreams/"+other, nil, nil, nil), http.StatusNotFound)
	var g topology.Graph
	wantStatus(t, ann.do("GET", "/api/v1/topology"+ann.q(), nil, nil, &g), http.StatusOK)
	kinds := map[string]int{}
	for _, n := range g.Nodes {
		kinds[n.Kind]++
	}
	if kinds["listeners"] != 1 || kinds["sites"] != 1 || kinds["upstreams"] != 1 || kinds["targets"] != 1 {
		t.Fatalf("topology nodes = %v", kinds)
	}

	// An operator in the group applies and confirms; nobody grants above
	// their own role.
	wantStatus(t, ann.do("PUT", "/api/v1/groups/"+pay.ID+"/members", map[string]any{"user": "ann", "role": "operator"}, nil, nil), http.StatusForbidden)
	wantStatus(t, c.do("PUT", "/api/v1/groups/"+pay.ID+"/members", map[string]any{"user": "ann", "role": "operator"}, nil, nil), http.StatusOK)
	var applied applied
	wantStatus(t, ann.do("POST", "/api/v1/changesets/"+ann.cs+"/apply", map[string]any{"mode": "confirm"}, nil, &applied), http.StatusCreated)
	wantStatus(t, ann.do("POST", "/api/v1/revisions/"+itoa(int(applied.Revision.Revision))+"/confirm", nil, nil, nil), http.StatusOK)

	// A group in use cannot be deleted.
	wantStatus(t, c.do("DELETE", "/api/v1/groups/"+pay.ID, nil, nil, nil), http.StatusConflict)

	resp := c.do("GET", "/api/v1/topology?format=mermaid", nil, nil, nil)
	wantStatus(t, resp, http.StatusOK)
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/vnd.mermaid") {
		t.Fatalf("content type %q", ct)
	}
}
