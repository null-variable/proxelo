package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	snapshotv1 "github.com/null-variable/proxelo-api/gen/go/proxelo/snapshot/v1"
	"google.golang.org/protobuf/proto"

	"github.com/null-variable/proxelo/internal/auth"
	"github.com/null-variable/proxelo/internal/deploy"
	"github.com/null-variable/proxelo/internal/distrib"
	"github.com/null-variable/proxelo/internal/store"
)

type client struct {
	t    *testing.T
	srv  *httptest.Server
	d    *fakeDistributor
	st   *store.Store
	http *http.Client
	csrf string
	// Change set used by create; set by begin.
	cs string
}

// fakeDistributor records published snapshots.
type fakeDistributor struct {
	published [][]byte
}

func (f *fakeDistributor) Publish(b []byte) error {
	f.published = append(f.published, b)
	return nil
}

func (f *fakeDistributor) Nodes() []distrib.NodeStatus {
	return []distrib.NodeStatus{{NodeID: "node-a", ActiveRevision: uint64(len(f.published))}}
}

func (f *fakeDistributor) Traffic(from, to time.Time, revision uint64) distrib.Traffic {
	return distrib.Traffic{}
}

const ownerPassword = "owner-password-1"

// newClient returns a client logged in as the owner created through setup.
func newClient(t *testing.T) *client {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	d := &fakeDistributor{}
	log := slog.New(slog.DiscardHandler)
	dep := deploy.New(st, d, nil, deploy.DefaultGuard, log)
	srv := httptest.NewServer(Handler(st, d, dep, nil, Options{AdminAddr: "127.0.0.1:9443"}, log))
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	c := &client{t: t, srv: srv, d: d, st: st, http: &http.Client{Jar: jar}}

	if err := st.Put(context.Background(), SetupTokenKey, []byte("setup-token")); err != nil {
		t.Fatal(err)
	}
	var login struct {
		CSRF string `json:"csrfToken"`
	}
	wantStatus(t, c.do("POST", "/api/v1/auth/setup", map[string]any{"token": "setup-token", "name": "owner", "password": ownerPassword}, nil, &login), http.StatusOK)
	c.csrf = login.CSRF
	return c
}

func (c *client) do(method, path string, body any, header map[string]string, out any) *http.Response {
	c.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	default:
		j, err := json.Marshal(b)
		if err != nil {
			c.t.Fatal(err)
		}
		rd = bytes.NewReader(j)
	}
	req, err := http.NewRequest(method, c.srv.URL+path, rd)
	if err != nil {
		c.t.Fatal(err)
	}
	if c.csrf != "" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		c.t.Fatal(err)
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			c.t.Fatalf("%s %s: %v: %s", method, path, err, raw)
		}
	}
	return resp
}

// begin opens a change set that create, patch and remove then use.
func (c *client) begin(message string) string {
	c.t.Helper()
	var cs store.ChangeSet
	wantStatus(c.t, c.do("POST", "/api/v1/changesets", map[string]any{"message": message}, nil, &cs), http.StatusCreated)
	c.cs = cs.ID
	return cs.ID
}

func (c *client) q() string { return "?changeset=" + c.cs }

func (c *client) create(kind string, body any) string {
	c.t.Helper()
	var out struct {
		ID string `json:"id"`
	}
	resp := c.do("POST", "/api/v1/"+kind+c.q(), body, nil, &out)
	if resp.StatusCode != http.StatusCreated {
		c.t.Fatalf("create %s: status %d", kind, resp.StatusCode)
	}
	return out.ID
}

type applied struct {
	Revision store.Revision `json:"revision"`
}

func (c *client) apply(mode string) store.Revision {
	c.t.Helper()
	var out applied
	wantStatus(c.t, c.do("POST", "/api/v1/changesets/"+c.cs+"/apply", map[string]any{"mode": mode}, nil, &out), http.StatusCreated)
	return out.Revision
}

func wantStatus(t *testing.T, resp *http.Response, want int) {
	t.Helper()
	if resp.StatusCode != want {
		t.Fatalf("%s %s: status %d, want %d", resp.Request.Method, resp.Request.URL.Path, resp.StatusCode, want)
	}
}

func (c *client) basicSite() (up, rt, lst, site string) {
	up = c.create("upstreams", map[string]any{"name": "api", "spec": map[string]any{"targets": []any{map[string]any{"address": "127.0.0.1:9000"}}}})
	rt = c.create("routes", map[string]any{"name": "api", "spec": map[string]any{
		"match":  map[string]any{"path": map[string]any{"type": "prefix", "value": "/api/"}},
		"action": map[string]any{"type": "proxy", "proxy": map[string]any{"upstream": up}},
	}})
	lst = c.create("listeners", map[string]any{"name": "http", "spec": map[string]any{"address": "0.0.0.0:8080"}})
	site = c.create("sites", map[string]any{"name": "web", "spec": map[string]any{
		"listeners": []string{lst},
		"hostnames": []any{map[string]any{"type": "exact", "value": "example.com"}},
		"routes":    []string{rt},
	}})
	return
}

func TestChangeSetApply(t *testing.T) {
	c := newClient(t)
	cs := c.begin("first")
	up, rt, lst, site := c.basicSite()

	// The head does not see the change set's resources.
	var list struct {
		Items []json.RawMessage `json:"items"`
	}
	wantStatus(t, c.do("GET", "/api/v1/routes", nil, nil, &list), http.StatusOK)
	if len(list.Items) != 0 {
		t.Fatalf("head routes = %d", len(list.Items))
	}
	wantStatus(t, c.do("GET", "/api/v1/routes"+c.q(), nil, nil, &list), http.StatusOK)
	if len(list.Items) != 1 {
		t.Fatalf("change set routes = %d", len(list.Items))
	}
	// Writes need a change set.
	wantStatus(t, c.do("POST", "/api/v1/listeners", map[string]any{"name": "x", "spec": map[string]any{"address": "0.0.0.0:81"}}, nil, nil), http.StatusBadRequest)

	resp := c.do("PATCH", "/api/v1/listeners/"+lst+c.q(), map[string]any{"spec": map[string]any{"defaultSite": site}}, map[string]string{"If-Match": `"1"`}, nil)
	wantStatus(t, resp, http.StatusOK)
	if got := resp.Header.Get("ETag"); got != `"2"` {
		t.Fatalf("ETag = %s", got)
	}
	wantStatus(t, c.do("PATCH", "/api/v1/listeners/"+lst+c.q(), map[string]any{"spec": map[string]any{"backlog": 10}}, map[string]string{"If-Match": `"1"`}, nil), http.StatusPreconditionFailed)

	var v validation
	wantStatus(t, c.do("POST", "/api/v1/changesets/"+cs+"/validate", nil, nil, &v), http.StatusOK)
	if !v.Valid {
		t.Fatalf("validate = %+v", v)
	}
	var d struct {
		Resources []resourceDiff `json:"resources"`
		Effective []struct {
			Kind string `json:"kind"`
			Op   string `json:"op"`
		} `json:"effective"`
	}
	wantStatus(t, c.do("GET", "/api/v1/changesets/"+cs+"/diff", nil, nil, &d), http.StatusOK)
	if len(d.Resources) != 4 || len(d.Effective) != 4 || d.Effective[0].Op != "added" {
		t.Fatalf("diff = %+v", d)
	}

	rev := c.apply("direct")
	if rev.Revision != 1 || len(rev.Hash) != 32 || rev.Status != store.StatusConfirmed || rev.Author != "owner" {
		t.Fatalf("revision = %+v", rev)
	}
	wantStatus(t, c.do("GET", "/api/v1/changesets/"+cs, nil, nil, nil), http.StatusNotFound)

	req, _ := http.NewRequest("GET", c.srv.URL+"/api/v1/revisions/1/snapshot", nil)
	sresp, err := c.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(sresp.Body)
	sresp.Body.Close()
	var snap snapshotv1.Snapshot
	if err := proto.Unmarshal(raw, &snap); err != nil {
		t.Fatal(err)
	}
	if snap.GetRevision() != 1 || snap.GetListeners()[0].GetDefaultSite() != 0 ||
		snap.GetSites()[0].GetRoutes()[0].GetAction().GetProxy() == nil || !bytes.Equal(snap.GetHash(), rev.Hash) {
		t.Fatalf("snapshot = %v", &snap)
	}
	if len(c.d.published) != 1 || !bytes.Equal(c.d.published[0], raw) {
		t.Fatal("apply did not publish the stored snapshot")
	}

	// Deleting a referenced upstream fails at apply, at the referencing
	// field, and leaves history and the change set alone.
	c.begin("break")
	wantStatus(t, c.do("DELETE", "/api/v1/upstreams/"+up+c.q(), nil, nil, nil), http.StatusNoContent)
	var eb errorBody
	wantStatus(t, c.do("POST", "/api/v1/changesets/"+c.cs+"/apply", map[string]any{"mode": "direct"}, nil, &eb), http.StatusUnprocessableEntity)
	if len(eb.Fields) != 1 || eb.Fields[0].Path != "routes["+rt+"].spec.action.proxy.upstream" {
		t.Fatalf("apply error = %+v", eb)
	}
	var revs struct {
		Items []store.Revision `json:"items"`
	}
	wantStatus(t, c.do("GET", "/api/v1/revisions", nil, nil, &revs), http.StatusOK)
	if len(revs.Items) != 1 || len(c.d.published) != 1 {
		t.Fatalf("revisions = %d, published = %d", len(revs.Items), len(c.d.published))
	}
	wantStatus(t, c.do("GET", "/api/v1/changesets/"+c.cs, nil, nil, nil), http.StatusOK)
}

func TestConcurrentChangeSetsMerge(t *testing.T) {
	c := newClient(t)
	c.begin("base")
	up, _, _, _ := c.basicSite()
	c.apply("direct")

	a := c.begin("a")
	wantStatus(t, c.do("PATCH", "/api/v1/upstreams/"+up+c.q(), map[string]any{"spec": map[string]any{"keepalive": map[string]any{"idle": 8}}}, nil, nil), http.StatusOK)
	b := c.begin("b")
	wantStatus(t, c.do("PATCH", "/api/v1/upstreams/"+up+c.q(), map[string]any{"description": "from b"}, nil, nil), http.StatusOK)
	conflict := c.begin("conflict")
	wantStatus(t, c.do("PATCH", "/api/v1/upstreams/"+up+c.q(), map[string]any{"spec": map[string]any{"keepalive": map[string]any{"idle": 3}}}, nil, nil), http.StatusOK)

	c.cs = a
	c.apply("direct")
	// b touched other fields: both edits survive.
	c.cs = b
	var d struct {
		Resources []resourceDiff `json:"resources"`
	}
	wantStatus(t, c.do("GET", "/api/v1/changesets/"+b+"/diff", nil, nil, &d), http.StatusOK)
	if len(d.Resources) != 1 || !d.Resources[0].Drifted {
		t.Fatalf("diff = %+v", d.Resources)
	}
	c.apply("direct")
	var got struct {
		Description string `json:"description"`
		Spec        struct {
			Keepalive struct {
				Idle int `json:"idle"`
			} `json:"keepalive"`
		} `json:"spec"`
	}
	wantStatus(t, c.do("GET", "/api/v1/upstreams/"+up, nil, nil, &got), http.StatusOK)
	if got.Description != "from b" || got.Spec.Keepalive.Idle != 8 {
		t.Fatalf("merged = %+v", got)
	}
	// The same field changed on both sides is a conflict.
	var eb errorBody
	wantStatus(t, c.do("POST", "/api/v1/changesets/"+conflict+"/apply", map[string]any{"mode": "direct"}, nil, &eb), http.StatusUnprocessableEntity)
	if len(eb.Fields) != 1 || eb.Fields[0].Path != "upstreams["+up+"].spec.keepalive.idle" {
		t.Fatalf("conflict = %+v", eb.Fields)
	}
}

func TestCommitConfirmAndRollback(t *testing.T) {
	c := newClient(t)
	c.begin("one")
	c.basicSite()
	r1 := c.apply("direct")

	c.begin("two")
	c.create("listeners", map[string]any{"name": "alt", "spec": map[string]any{"address": "0.0.0.0:8081"}})
	r2 := c.apply("") // confirm is the default
	if r2.Status != store.StatusPending || r2.ConfirmBy.IsZero() {
		t.Fatalf("revision = %+v", r2)
	}
	// Nothing else applies while one is pending.
	c.begin("three")
	var eb errorBody
	wantStatus(t, c.do("POST", "/api/v1/changesets/"+c.cs+"/apply", nil, nil, &eb), http.StatusConflict)
	wantStatus(t, c.do("POST", "/api/v1/revisions/1/confirm", nil, nil, nil), http.StatusConflict)

	// Rolling back the pending revision makes revision 3 with revision 1's
	// resources and marks 2 reverted.
	var r3 store.Revision
	wantStatus(t, c.do("POST", "/api/v1/revisions/1/rollback", nil, nil, &r3), http.StatusCreated)
	if r3.Revision != 3 || r3.Status != store.StatusConfirmed || !bytes.Equal(snapHash(t, c, 3), snapHash(t, c, 1)) {
		t.Fatalf("rollback = %+v", r3)
	}
	var r2now store.Revision
	wantStatus(t, c.do("GET", "/api/v1/revisions/2", nil, nil, &r2now), http.StatusOK)
	if r2now.Status != store.StatusReverted {
		t.Fatalf("revision 2 = %s", r2now.Status)
	}
	var list struct {
		Items []json.RawMessage `json:"items"`
	}
	wantStatus(t, c.do("GET", "/api/v1/listeners", nil, nil, &list), http.StatusOK)
	if len(list.Items) != 1 {
		t.Fatalf("listeners after rollback = %d", len(list.Items))
	}

	// Confirm within the window.
	c.begin("four")
	c.create("listeners", map[string]any{"name": "alt", "spec": map[string]any{"address": "0.0.0.0:8081"}})
	r4 := c.apply("confirm")
	var conf store.Revision
	wantStatus(t, c.do("POST", "/api/v1/revisions/4/confirm", nil, nil, &conf), http.StatusOK)
	if r4.Revision != 4 || conf.Status != store.StatusConfirmed {
		t.Fatalf("confirm = %+v", conf)
	}
	_ = r1
}

// snapHash compiles nothing; it reads the stored snapshot hash without its
// revision number, which differs between revisions of the same resources.
func snapHash(t *testing.T, c *client, n uint64) []byte {
	t.Helper()
	rev, err := c.st.Revision(context.Background(), n)
	if err != nil {
		t.Fatal(err)
	}
	snap := &snapshotv1.Snapshot{}
	if err := proto.Unmarshal(rev.Snapshot, snap); err != nil {
		t.Fatal(err)
	}
	snap.Revision, snap.Hash = 0, nil
	b, _ := proto.MarshalOptions{Deterministic: true}.Marshal(snap)
	return b
}

func TestRequestErrors(t *testing.T) {
	c := newClient(t)
	c.begin("errors")
	var eb errorBody

	wantStatus(t, c.do("GET", "/api/v1/widgets", nil, nil, nil), http.StatusNotFound)
	wantStatus(t, c.do("GET", "/api/v1/routes/rt_nope", nil, nil, nil), http.StatusNotFound)
	wantStatus(t, c.do("POST", "/api/v1/listeners"+c.q(), `{"name":"x","spec":{"adress":"0.0.0.0:80"}}`, nil, nil), http.StatusBadRequest)
	wantStatus(t, c.do("POST", "/api/v1/listeners"+c.q(), `{`, nil, nil), http.StatusBadRequest)
	wantStatus(t, c.do("POST", "/api/v1/listeners?changeset=cs_nope", map[string]any{"name": "x", "spec": map[string]any{"address": "0.0.0.0:80"}}, nil, nil), http.StatusNotFound)

	wantStatus(t, c.do("POST", "/api/v1/listeners"+c.q(), map[string]any{"name": "Bad Name", "spec": map[string]any{"address": "0.0.0.0:99999"}}, nil, &eb), http.StatusUnprocessableEntity)
	paths := map[string]bool{}
	for _, f := range eb.Fields {
		paths[f.Path] = true
	}
	if !paths["name"] || !paths["spec.address"] || len(paths) != 2 {
		t.Fatalf("fields = %+v", eb.Fields)
	}

	body := map[string]any{"name": "http", "spec": map[string]any{"address": "0.0.0.0:80"}}
	id := c.create("listeners", body)
	wantStatus(t, c.do("POST", "/api/v1/listeners"+c.q(), body, nil, nil), http.StatusConflict)
	wantStatus(t, c.do("DELETE", "/api/v1/listeners/"+id+c.q(), nil, map[string]string{"If-Match": `"7"`}, nil), http.StatusPreconditionFailed)
	wantStatus(t, c.do("DELETE", "/api/v1/listeners/"+id+c.q(), nil, map[string]string{"If-Match": "x"}, nil), http.StatusBadRequest)
	wantStatus(t, c.do("DELETE", "/api/v1/listeners/"+id+c.q(), nil, map[string]string{"If-Match": `"1"`}, nil), http.StatusNoContent)
	wantStatus(t, c.do("GET", "/api/v1/revisions/1", nil, nil, nil), http.StatusNotFound)
	wantStatus(t, c.do("GET", "/api/v1/revisions/x", nil, nil, nil), http.StatusBadRequest)
}

func TestServerFieldsIgnoredOnCreate(t *testing.T) {
	c := newClient(t)
	c.begin("ids")
	var out struct {
		ID              string `json:"id"`
		ResourceVersion int64  `json:"resourceVersion"`
	}
	resp := c.do("POST", "/api/v1/listeners"+c.q(), map[string]any{"id": "lst_mine", "resourceVersion": 9, "name": "http", "spec": map[string]any{"address": "0.0.0.0:80"}}, nil, &out)
	wantStatus(t, resp, http.StatusCreated)
	if out.ID == "lst_mine" || out.ResourceVersion != 1 {
		t.Fatalf("created = %+v", out)
	}
}

func TestExportImport(t *testing.T) {
	c := newClient(t)
	c.begin("one")
	_, rt, _, _ := c.basicSite()
	c.apply("direct")

	req, _ := http.NewRequest("GET", c.srv.URL+"/api/v1/export", nil)
	resp, err := c.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	yml, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(yml), "apiVersion: proxelo/v1") || !strings.Contains(string(yml), rt) {
		t.Fatalf("export = %s", yml)
	}

	// Re-importing the export changes nothing; dropping the route deletes it.
	cs := c.begin("import")
	wantStatus(t, c.do("POST", "/api/v1/changesets/"+cs+"/import", string(yml), nil, nil), http.StatusOK)
	var d struct {
		Resources []resourceDiff `json:"resources"`
	}
	wantStatus(t, c.do("GET", "/api/v1/changesets/"+cs+"/diff", nil, nil, &d), http.StatusOK)
	for _, r := range d.Resources {
		if len(r.Changes) != 0 {
			t.Fatalf("round trip changed %s: %+v", r.ID, r.Changes)
		}
	}
	// Drop the route from the bundle (JSON is YAML too): the import deletes
	// it and the site's reference, and the diff shows both.
	var b map[string]any
	req, _ = http.NewRequest("GET", c.srv.URL+"/api/v1/export?format=json", nil)
	resp, err = c.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	json.NewDecoder(resp.Body).Decode(&b)
	resp.Body.Close()
	res := b["resources"].(map[string]any)
	delete(res, "routes")
	delete(res["sites"].([]any)[0].(map[string]any)["spec"].(map[string]any), "routes")
	wantStatus(t, c.do("POST", "/api/v1/changesets/"+cs+"/import", b, nil, nil), http.StatusOK)
	var items store.ChangeSet
	wantStatus(t, c.do("GET", "/api/v1/changesets/"+cs, nil, nil, &items), http.StatusOK)
	ops := map[string]store.Op{}
	for _, it := range items.Items {
		ops[it.Kind] = it.Op
	}
	if ops["routes"] != store.OpDelete || ops["sites"] != store.OpUpdate {
		t.Fatalf("import items = %+v", items.Items)
	}
}

func TestAuth(t *testing.T) {
	c := newClient(t)
	// Setup works once.
	wantStatus(t, c.do("POST", "/api/v1/auth/setup", map[string]any{"token": "setup-token", "name": "x", "password": ownerPassword}, nil, nil), http.StatusConflict)

	// Without the CSRF header a session cannot write.
	csrf := c.csrf
	c.csrf = ""
	wantStatus(t, c.do("POST", "/api/v1/changesets", nil, nil, nil), http.StatusForbidden)
	c.csrf = csrf

	var u store.User
	wantStatus(t, c.do("POST", "/api/v1/users", map[string]any{"name": "eve", "password": "viewer-password", "role": "viewer"}, nil, &u), http.StatusCreated)
	wantStatus(t, c.do("DELETE", "/api/v1/users/"+mustOwnerID(t, c), nil, nil, nil), http.StatusConflict)

	// A viewer reads but cannot open change sets.
	v := &client{t: t, srv: c.srv, http: &http.Client{}}
	jar, _ := cookiejar.New(nil)
	v.http.Jar = jar
	var login struct {
		CSRF string `json:"csrfToken"`
	}
	wantStatus(t, v.do("POST", "/api/v1/auth/login", map[string]any{"name": "eve", "password": "wrong-password"}, nil, nil), http.StatusUnauthorized)
	wantStatus(t, v.do("POST", "/api/v1/auth/login", map[string]any{"name": "eve", "password": "viewer-password"}, nil, &login), http.StatusOK)
	v.csrf = login.CSRF
	wantStatus(t, v.do("GET", "/api/v1/revisions", nil, nil, nil), http.StatusOK)
	wantStatus(t, v.do("POST", "/api/v1/changesets", nil, nil, nil), http.StatusForbidden)
	wantStatus(t, v.do("GET", "/api/v1/audit", nil, nil, nil), http.StatusForbidden)

	// Two-factor: enable, then a login needs the code, once.
	var setup struct {
		Secret string `json:"secret"`
	}
	wantStatus(t, v.do("POST", "/api/v1/auth/totp/setup", nil, nil, &setup), http.StatusOK)
	code, _ := auth.TOTPCode(setup.Secret, time.Now())
	wantStatus(t, v.do("POST", "/api/v1/auth/totp/enable", map[string]any{"code": code}, nil, nil), http.StatusNoContent)
	anon := &client{t: t, srv: c.srv, http: &http.Client{}}
	wantStatus(t, anon.do("POST", "/api/v1/auth/login", map[string]any{"name": "eve", "password": "viewer-password"}, nil, nil), http.StatusUnauthorized)
	// The code used for enabling cannot be replayed.
	wantStatus(t, anon.do("POST", "/api/v1/auth/login", map[string]any{"name": "eve", "password": "viewer-password", "code": code}, nil, nil), http.StatusUnauthorized)

	// Tokens are capped at the creator's role and work as bearer auth.
	var tok struct {
		Secret string `json:"secret"`
	}
	wantStatus(t, c.do("POST", "/api/v1/auth/tokens", map[string]any{"name": "ci", "role": "editor"}, nil, &tok), http.StatusCreated)
	bearer := map[string]string{"Authorization": "Bearer " + tok.Secret}
	wantStatus(t, anon.do("POST", "/api/v1/changesets", nil, bearer, nil), http.StatusCreated)
	wantStatus(t, anon.do("GET", "/api/v1/users", nil, bearer, nil), http.StatusForbidden)
	wantStatus(t, anon.do("GET", "/api/v1/revisions", nil, map[string]string{"Authorization": "Bearer " + tok.Secret + "x"}, nil), http.StatusUnauthorized)
	wantStatus(t, anon.do("GET", "/api/v1/revisions", nil, nil, nil), http.StatusUnauthorized)

	// Lockout after repeated failures, even with the right password.
	for range maxFailures {
		anon.do("POST", "/api/v1/auth/login", map[string]any{"name": "owner", "password": "nope-nope-nope"}, nil, nil)
	}
	wantStatus(t, anon.do("POST", "/api/v1/auth/login", map[string]any{"name": "owner", "password": ownerPassword}, nil, nil), http.StatusTooManyRequests)

	var audit struct {
		Items []store.AuditEntry `json:"items"`
	}
	wantStatus(t, c.do("GET", "/api/v1/audit?limit=1000", nil, nil, &audit), http.StatusOK)
	actions := map[string]bool{}
	for _, e := range audit.Items {
		actions[e.Action] = true
	}
	for _, want := range []string{"auth.setup", "user.create", "auth.login", "auth.login.failed", "user.totp.enable", "token.create"} {
		if !actions[want] {
			t.Fatalf("audit lacks %s: %v", want, actions)
		}
	}
	var ver struct {
		OK      bool   `json:"ok"`
		Entries uint64 `json:"entries"`
	}
	wantStatus(t, c.do("GET", "/api/v1/audit/verify", nil, nil, &ver), http.StatusOK)
	if !ver.OK || ver.Entries != uint64(len(audit.Items)) {
		t.Fatalf("verify = %+v", ver)
	}
}

func mustOwnerID(t *testing.T, c *client) string {
	t.Helper()
	u, err := c.st.UserByName(context.Background(), "owner")
	if err != nil {
		t.Fatal(err)
	}
	return u.ID
}

func TestMergePatch(t *testing.T) {
	var target, patch any
	json.Unmarshal([]byte(`{"a":1,"b":{"c":2,"d":3},"e":[1]}`), &target)
	json.Unmarshal([]byte(`{"a":null,"b":{"c":5},"e":[2,3],"f":"x"}`), &patch)
	got, _ := json.Marshal(mergePatch(target, patch))
	if want := `{"b":{"c":5,"d":3},"e":[2,3],"f":"x"}`; string(got) != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}
