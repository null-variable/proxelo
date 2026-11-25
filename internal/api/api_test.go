package api

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	snapshotv1 "github.com/null-variable/proxelo-api/gen/go/proxelo/snapshot/v1"
	"google.golang.org/protobuf/proto"

	"github.com/null-variable/proxelo/internal/distrib"
	"github.com/null-variable/proxelo/internal/store"
)

type client struct {
	t   *testing.T
	srv *httptest.Server
	d   *fakeDistributor
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

func newClient(t *testing.T) *client {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	d := &fakeDistributor{}
	srv := httptest.NewServer(Handler(st, d, nil, nil, slog.New(slog.DiscardHandler)))
	t.Cleanup(srv.Close)
	return &client{t: t, srv: srv, d: d}
}

// do sends body (marshalled unless it is a string) and decodes a JSON reply into out.
func (c *client) do(method, path string, body any, header map[string]string, out any) *http.Response {
	c.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = bytes.NewReader([]byte(b))
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
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
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

func (c *client) create(kind string, body any) string {
	c.t.Helper()
	var out struct {
		ID string `json:"id"`
	}
	resp := c.do("POST", "/api/v1/"+kind, body, nil, &out)
	if resp.StatusCode != http.StatusCreated {
		c.t.Fatalf("create %s: status %d", kind, resp.StatusCode)
	}
	return out.ID
}

func wantStatus(t *testing.T, resp *http.Response, want int) {
	t.Helper()
	if resp.StatusCode != want {
		t.Fatalf("%s %s: status %d, want %d", resp.Request.Method, resp.Request.URL.Path, resp.StatusCode, want)
	}
}

func TestCRUDAndApply(t *testing.T) {
	c := newClient(t)

	up := c.create("upstreams", map[string]any{"name": "api", "spec": map[string]any{"targets": []any{map[string]any{"address": "127.0.0.1:9000"}}}})
	rt := c.create("routes", map[string]any{"name": "api", "spec": map[string]any{
		"match":  map[string]any{"path": map[string]any{"type": "prefix", "value": "/api/"}},
		"action": map[string]any{"type": "proxy", "proxy": map[string]any{"upstream": up}},
	}})
	lst := c.create("listeners", map[string]any{"name": "http", "spec": map[string]any{"address": "0.0.0.0:8080"}})
	site := c.create("sites", map[string]any{"name": "web", "spec": map[string]any{
		"listeners": []string{lst},
		"hostnames": []any{map[string]any{"type": "exact", "value": "example.com"}},
		"routes":    []string{rt},
	}})

	// defaultSite set through a merge patch, guarded by If-Match.
	resp := c.do("PATCH", "/api/v1/listeners/"+lst, map[string]any{"spec": map[string]any{"defaultSite": site}}, map[string]string{"If-Match": `"1"`}, nil)
	wantStatus(t, resp, http.StatusOK)
	if got := resp.Header.Get("ETag"); got != `"2"` {
		t.Fatalf("ETag = %s", got)
	}
	resp = c.do("PATCH", "/api/v1/listeners/"+lst, map[string]any{"spec": map[string]any{"backlog": 10}}, map[string]string{"If-Match": `"1"`}, nil)
	wantStatus(t, resp, http.StatusPreconditionFailed)

	var l struct {
		Spec struct {
			Address     string `json:"address"`
			DefaultSite string `json:"defaultSite"`
		} `json:"spec"`
	}
	wantStatus(t, c.do("GET", "/api/v1/listeners/"+lst, nil, nil, &l), http.StatusOK)
	if l.Spec.Address != "0.0.0.0:8080" || l.Spec.DefaultSite != site {
		t.Fatalf("listener after patch = %+v", l.Spec)
	}

	var list struct {
		Items []json.RawMessage `json:"items"`
	}
	wantStatus(t, c.do("GET", "/api/v1/routes", nil, nil, &list), http.StatusOK)
	if len(list.Items) != 1 {
		t.Fatalf("routes = %d", len(list.Items))
	}

	var rev store.Revision
	wantStatus(t, c.do("POST", "/api/v1/apply", map[string]any{"message": "first"}, nil, &rev), http.StatusCreated)
	if rev.Revision != 1 || len(rev.Hash) != 32 {
		t.Fatalf("revision = %+v", rev)
	}

	req, _ := http.NewRequest("GET", c.srv.URL+"/api/v1/revisions/1/snapshot", nil)
	sresp, err := http.DefaultClient.Do(req)
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
	var nodes struct {
		Items []distrib.NodeStatus `json:"items"`
	}
	wantStatus(t, c.do("GET", "/api/v1/nodes", nil, nil, &nodes), http.StatusOK)
	if len(nodes.Items) != 1 || nodes.Items[0].NodeID != "node-a" || nodes.Items[0].ActiveRevision != 1 {
		t.Fatalf("nodes = %+v", nodes.Items)
	}

	// The upstream is still referenced; deleting it makes the next apply fail
	// at the referencing field and leaves the revision history unchanged.
	wantStatus(t, c.do("DELETE", "/api/v1/upstreams/"+up, nil, nil, nil), http.StatusNoContent)
	var eb errorBody
	wantStatus(t, c.do("POST", "/api/v1/apply", nil, nil, &eb), http.StatusUnprocessableEntity)
	if len(eb.Fields) != 1 || eb.Fields[0].Path != "routes["+rt+"].spec.action.proxy.upstream" {
		t.Fatalf("apply error = %+v", eb)
	}
	var revs struct {
		Items []store.Revision `json:"items"`
	}
	wantStatus(t, c.do("GET", "/api/v1/revisions", nil, nil, &revs), http.StatusOK)
	if len(revs.Items) != 1 {
		t.Fatalf("revisions = %d", len(revs.Items))
	}
	if len(c.d.published) != 1 {
		t.Fatal("failed apply published a snapshot")
	}

	var full struct {
		Config struct {
			Upstreams []json.RawMessage `json:"upstreams"`
		} `json:"config"`
	}
	wantStatus(t, c.do("GET", "/api/v1/revisions/1", nil, nil, &full), http.StatusOK)
	if len(full.Config.Upstreams) != 1 {
		t.Fatal("revision 1 must keep the deleted upstream")
	}
}

func TestRequestErrors(t *testing.T) {
	c := newClient(t)
	var eb errorBody

	wantStatus(t, c.do("GET", "/api/v1/widgets", nil, nil, nil), http.StatusNotFound)
	wantStatus(t, c.do("GET", "/api/v1/routes/rt_nope", nil, nil, nil), http.StatusNotFound)
	wantStatus(t, c.do("POST", "/api/v1/listeners", `{"name":"x","spec":{"adress":"0.0.0.0:80"}}`, nil, nil), http.StatusBadRequest)
	wantStatus(t, c.do("POST", "/api/v1/listeners", `{`, nil, nil), http.StatusBadRequest)

	wantStatus(t, c.do("POST", "/api/v1/listeners", map[string]any{"name": "Bad Name", "spec": map[string]any{"address": "0.0.0.0:99999"}}, nil, &eb), http.StatusUnprocessableEntity)
	paths := map[string]bool{}
	for _, f := range eb.Fields {
		paths[f.Path] = true
	}
	if !paths["name"] || !paths["spec.address"] || len(paths) != 2 {
		t.Fatalf("fields = %+v", eb.Fields)
	}

	body := map[string]any{"name": "http", "spec": map[string]any{"address": "0.0.0.0:80"}}
	id := c.create("listeners", body)
	wantStatus(t, c.do("POST", "/api/v1/listeners", body, nil, nil), http.StatusConflict)
	wantStatus(t, c.do("DELETE", "/api/v1/listeners/"+id, nil, map[string]string{"If-Match": `"7"`}, nil), http.StatusPreconditionFailed)
	wantStatus(t, c.do("DELETE", "/api/v1/listeners/"+id, nil, map[string]string{"If-Match": "x"}, nil), http.StatusBadRequest)
	wantStatus(t, c.do("DELETE", "/api/v1/listeners/"+id, nil, map[string]string{"If-Match": `"1"`}, nil), http.StatusNoContent)
	wantStatus(t, c.do("GET", "/api/v1/revisions/1", nil, nil, nil), http.StatusNotFound)
	wantStatus(t, c.do("GET", "/api/v1/revisions/x", nil, nil, nil), http.StatusBadRequest)
}

func TestServerFieldsIgnoredOnCreate(t *testing.T) {
	c := newClient(t)
	var out struct {
		ID              string `json:"id"`
		ResourceVersion int64  `json:"resourceVersion"`
	}
	resp := c.do("POST", "/api/v1/listeners", map[string]any{"id": "lst_mine", "resourceVersion": 9, "name": "http", "spec": map[string]any{"address": "0.0.0.0:80"}}, nil, &out)
	wantStatus(t, resp, http.StatusCreated)
	if out.ID == "lst_mine" || out.ResourceVersion != 1 {
		t.Fatalf("created = %+v", out)
	}
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
