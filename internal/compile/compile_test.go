package compile

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	snapshotv1 "github.com/null-variable/proxelo-api/gen/go/proxelo/snapshot/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/null-variable/proxelo/internal/model"
)

var update = flag.Bool("update", false, "rewrite golden files")

func meta(id, name string) model.Meta { return model.Meta{ID: id, Name: name} }

func validConfig() model.Config {
	return model.Config{
		Listeners: []*model.Listener{{Meta: meta("lst_http", "http"), Spec: model.ListenerSpec{Address: "0.0.0.0:80", DefaultSite: "site_web"}}},
		Sites: []*model.Site{{Meta: meta("site_web", "web"), Spec: model.SiteSpec{
			Listeners: []string{"lst_http"},
			Hostnames: []model.HostMatch{{Type: model.HostExact, Value: "example.com"}},
			Routes:    []string{"rt_api", "rt_root"},
		}}},
		Routes: []*model.Route{
			{Meta: meta("rt_api", "api"), Spec: model.RouteSpec{
				Match:  model.Match{Path: model.PathMatch{Type: model.PathPrefix, Value: "/api/"}},
				Action: model.Action{Type: model.ActionProxy, Proxy: &model.ProxyAction{Upstream: "up_api"}},
			}},
			{Meta: meta("rt_root", "root"), Spec: model.RouteSpec{
				Match:  model.Match{Path: model.PathMatch{Type: model.PathExact, Value: "/"}},
				Action: model.Action{Type: model.ActionStatic, Static: &model.StaticAction{Root: "/srv/www"}},
			}},
		},
		Upstreams: []*model.Upstream{{Meta: meta("up_api", "api"), Spec: model.UpstreamSpec{Targets: []model.Target{{Address: "10.0.0.1:8080"}}}}},
	}
}

func TestCompileResolvesReferences(t *testing.T) {
	snap, err := Compile(validConfig(), 3)
	if err != nil {
		t.Fatal(err)
	}
	if snap.GetRevision() != 3 {
		t.Fatalf("revision = %d", snap.GetRevision())
	}
	if got := snap.GetListeners()[0].GetDefaultSite(); got != 0 {
		t.Fatalf("default site = %d", got)
	}
	r := snap.GetSites()[0].GetRoutes()
	if r[0].GetPath().GetKind() != snapshotv1.PathMatch_KIND_PREFIX || r[0].GetAction().GetProxy().GetUpstream() != 0 {
		t.Fatalf("route 0 = %v", r[0])
	}
	if r[1].GetPath().GetKind() != snapshotv1.PathMatch_KIND_EXACT || r[1].GetAction().GetStatic().GetRoot() != "/srv/www" {
		t.Fatalf("route 1 = %v", r[1])
	}
	if w := snap.GetUpstreams()[0].GetTargets()[0].GetWeight(); w != 1 {
		t.Fatalf("default weight = %d", w)
	}
}

func TestHashCoversSnapshotWithoutHash(t *testing.T) {
	snap, err := Compile(validConfig(), 1)
	if err != nil {
		t.Fatal(err)
	}
	c := proto.Clone(snap).(*snapshotv1.Snapshot)
	c.Hash = nil
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	if !bytes.Equal(snap.GetHash(), sum[:]) {
		t.Fatal("hash does not match serialized snapshot")
	}
}

func TestOutputIndependentOfInputOrder(t *testing.T) {
	a := validConfig()
	a.Upstreams = append(a.Upstreams, &model.Upstream{Meta: meta("up_b", "b"), Spec: model.UpstreamSpec{Targets: []model.Target{{Address: "10.0.0.2:80"}}}})
	b := validConfig()
	b.Upstreams = append([]*model.Upstream{{Meta: meta("up_b", "b"), Spec: model.UpstreamSpec{Targets: []model.Target{{Address: "10.0.0.2:80"}}}}}, b.Upstreams...)
	b.Routes[0], b.Routes[1] = b.Routes[1], b.Routes[0]
	sa, err := Compile(a, 1)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := Compile(b, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sa.GetHash(), sb.GetHash()) {
		t.Fatal("hash depends on input order")
	}
}

func TestDisabledResources(t *testing.T) {
	off := false

	cfg := validConfig()
	cfg.Routes[1].Enabled = &off
	snap, err := Compile(cfg, 1)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(snap.GetSites()[0].GetRoutes()); n != 1 {
		t.Fatalf("routes = %d, want disabled route dropped", n)
	}

	cfg = validConfig()
	cfg.Upstreams[0].Enabled = &off
	_, err = Compile(cfg, 1)
	wantPaths(t, err, "routes[rt_api].spec.action.proxy.upstream")
	if !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("err = %v, want it to say the upstream is disabled", err)
	}
}

func TestCompileErrors(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*model.Config)
		paths  []string
	}{
		{"unknown default site", func(c *model.Config) { c.Listeners[0].Spec.DefaultSite = "nope" }, []string{"listeners[lst_http].spec.defaultSite"}},
		{"unknown listener", func(c *model.Config) { c.Sites[0].Spec.Listeners = []string{"nope"} }, []string{"sites[site_web].spec.listeners[0]"}},
		{"unknown route", func(c *model.Config) { c.Sites[0].Spec.Routes[1] = "nope" }, []string{"sites[site_web].spec.routes[1]"}},
		{"unknown upstream", func(c *model.Config) { c.Routes[0].Spec.Action.Proxy.Upstream = "nope" }, []string{"routes[rt_api].spec.action.proxy.upstream"}},
		{"bad path type", func(c *model.Config) { c.Routes[0].Spec.Match.Path.Type = "regex" }, []string{"routes[rt_api].spec.match.path.type"}},
		{"action type mismatch", func(c *model.Config) { c.Routes[1].Spec.Action.Type = model.ActionProxy }, []string{"routes[rt_root].spec.action.static", "routes[rt_root].spec.action.proxy"}},
		{"empty upstream", func(c *model.Config) { c.Upstreams[0].Spec.Targets = nil }, []string{"upstreams[up_api].spec.targets"}},
		{"duplicate id", func(c *model.Config) { c.Sites = append(c.Sites, c.Sites[0]) }, []string{"sites[site_web]"}},
		{"same path twice in a site", func(c *model.Config) {
			c.Routes[1].Spec.Match.Path = c.Routes[0].Spec.Match.Path
		}, []string{"sites[site_web].spec.routes[1]"}},
		{"hostname served twice on a listener", func(c *model.Config) {
			s := *c.Sites[0]
			s.Meta = meta("site_other", "other")
			s.Spec.Routes = nil
			c.Sites = append(c.Sites, &s)
		}, []string{"sites[site_web].spec.hostnames[0]"}},
		{"errors are collected", func(c *model.Config) {
			c.Listeners[0].Spec.DefaultSite = "nope"
			c.Upstreams[0].Spec.Targets[0].Address = "no-port"
		}, []string{"listeners[lst_http].spec.defaultSite", "upstreams[up_api].spec.targets[0].address"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig()
			tc.mutate(&cfg)
			_, err := Compile(cfg, 1)
			wantPaths(t, err, tc.paths...)
		})
	}
}

func wantPaths(t *testing.T, err error, paths ...string) {
	t.Helper()
	var fe model.FieldErrors
	if !errors.As(err, &fe) {
		t.Fatalf("err = %v, want model.FieldErrors", err)
	}
	got := map[string]bool{}
	for _, e := range fe {
		got[e.Path] = true
	}
	for _, p := range paths {
		if !got[p] {
			t.Fatalf("errors %v do not include path %q", fe, p)
		}
	}
	if len(got) != len(paths) {
		t.Fatalf("errors = %v, want only paths %v", fe, paths)
	}
}

// TestGolden compiles every testdata/*.json resource file and compares the
// snapshot with testdata/*.golden. Run with -update to rewrite them.
func TestGolden(t *testing.T) {
	files, err := filepath.Glob("testdata/*.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no golden inputs")
	}
	for _, in := range files {
		t.Run(filepath.Base(in), func(t *testing.T) {
			raw, err := os.ReadFile(in)
			if err != nil {
				t.Fatal(err)
			}
			var cfg model.Config
			if err := json.Unmarshal(raw, &cfg); err != nil {
				t.Fatal(err)
			}
			snap, err := Compile(cfg, 1)
			if err != nil {
				t.Fatal(err)
			}
			got := goldenText(t, snap)
			out := strings.TrimSuffix(in, ".json") + ".golden"
			if *update {
				if err := os.WriteFile(out, got, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(out)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("snapshot differs from %s (run go test -update)\ngot:\n%s", out, got)
			}
		})
	}
}

// goldenText renders snap as indented JSON. protojson output is deliberately
// unstable in whitespace, so it is re-indented with encoding/json.
func goldenText(t *testing.T, snap *snapshotv1.Snapshot) []byte {
	t.Helper()
	b, err := protojson.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, b, "", "  "); err != nil {
		t.Fatal(err)
	}
	buf.WriteByte('\n')
	return buf.Bytes()
}
