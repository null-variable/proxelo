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

func TestCompileMatchKinds(t *testing.T) {
	c := validConfig()
	c.Sites[0].Spec.Hostnames = []model.HostMatch{
		{Type: model.HostExact, Value: "example.com"},
		{Type: model.HostWildcard, Value: "*.example.com"},
		{Type: model.HostRegex, Value: `^(www\.)?example\.net$`},
	}
	c.Routes[0].Spec.Match.Path = model.PathMatch{Type: model.PathPrefixPriority, Value: "/static/"}
	c.Routes[1].Spec.Match.Path = model.PathMatch{Type: model.PathRegexCI, Value: `\.(png|jpg)$`}
	snap, err := Compile(c, 1)
	if err != nil {
		t.Fatal(err)
	}
	hosts := snap.GetSites()[0].GetHostnames()
	wantHosts := []snapshotv1.HostMatch_Kind{snapshotv1.HostMatch_KIND_EXACT, snapshotv1.HostMatch_KIND_WILDCARD, snapshotv1.HostMatch_KIND_REGEX}
	for i, k := range wantHosts {
		if hosts[i].GetKind() != k || hosts[i].GetValue() != c.Sites[0].Spec.Hostnames[i].Value {
			t.Fatalf("hostnames[%d] = %v", i, hosts[i])
		}
	}
	r := snap.GetSites()[0].GetRoutes()
	if r[0].GetPath().GetKind() != snapshotv1.PathMatch_KIND_PREFIX_PRIORITY || r[1].GetPath().GetKind() != snapshotv1.PathMatch_KIND_REGEX_CI {
		t.Fatalf("routes = %v", r)
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
		{"bad path type", func(c *model.Config) { c.Routes[0].Spec.Match.Path.Type = "glob" }, []string{"routes[rt_api].spec.match.path.type"}},
		{"empty regex", func(c *model.Config) {
			c.Routes[0].Spec.Match.Path = model.PathMatch{Type: model.PathRegex}
		}, []string{"routes[rt_api].spec.match.path.value"}},
		{"prefix priority duplicates prefix", func(c *model.Config) {
			c.Routes[1].Spec.Match.Path = c.Routes[0].Spec.Match.Path
			c.Routes[1].Spec.Match.Path.Type = model.PathPrefixPriority
		}, []string{"sites[site_web].spec.routes[1]"}},
		{"bad wildcard", func(c *model.Config) {
			c.Sites[0].Spec.Hostnames = []model.HostMatch{{Type: model.HostWildcard, Value: "a.*.com"}}
		}, []string{"sites[site_web].spec.hostnames[0].value"}},
		{"bad host type", func(c *model.Config) {
			c.Sites[0].Spec.Hostnames = []model.HostMatch{{Type: "glob", Value: "a.com"}}
		}, []string{"sites[site_web].spec.hostnames[0].type"}},
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

func TestCompileUpstreamFeatures(t *testing.T) {
	cfg := validConfig()
	cfg.Upstreams[0].Spec = model.UpstreamSpec{
		Targets: []model.Target{
			{Address: "10.0.0.1:8080", MaxConns: 10, SlowStart: "30s", Route: "a"},
			{Address: "api.internal:8080", Resolve: true, ResolveInterval: "10s", Down: true},
		},
		Balancing:   model.Balancing{Algorithm: model.HashConsistent, Key: "$request_uri"},
		HealthCheck: &model.HealthCheck{Path: "/healthz", Statuses: []string{"200", "300-399"}, Fails: 3},
		Sticky:      &model.Sticky{Type: model.StickyRoute, Route: []string{"$cookie_route"}},
		Queue:       model.Queue{Size: 50, Timeout: "5s"},
		Keepalive:   model.Keepalive{MaxAge: "10m"},
	}
	if es := model.Validate(cfg.Upstreams[0]); len(es) > 0 {
		t.Fatal(es)
	}
	snap, err := Compile(cfg, 1)
	if err != nil {
		t.Fatal(err)
	}
	u := snap.GetUpstreams()[0]
	if u.GetBalancing() != snapshotv1.Upstream_BALANCING_HASH_CONSISTENT || u.GetHashKey() != "$request_uri" {
		t.Fatalf("balancing = %v %q", u.GetBalancing(), u.GetHashKey())
	}
	if u.GetQueueSize() != 50 || u.GetQueueTimeoutMs() != 5000 || u.GetKeepaliveTimeMs() != 600_000 {
		t.Fatalf("queue/keepalive = %v", u)
	}
	h := u.GetHealthCheck()
	if h.GetKind() != snapshotv1.HealthCheck_KIND_HTTP || h.GetPath() != "/healthz" || h.GetHost() != "api" || h.GetFails() != 3 ||
		len(h.GetStatuses()) != 2 || h.GetStatuses()[1].GetFrom() != 300 || h.GetStatuses()[1].GetTo() != 399 {
		t.Fatalf("health check = %v", h)
	}
	if s := u.GetSticky(); s.GetKind() != snapshotv1.Sticky_KIND_ROUTE || s.GetRoute()[0] != "$cookie_route" {
		t.Fatalf("sticky = %v", s)
	}
	t0, t1 := u.GetTargets()[0], u.GetTargets()[1]
	if t0.GetMaxConns() != 10 || t0.GetSlowStartMs() != 30_000 || t0.GetRoute() != "a" {
		t.Fatalf("target 0 = %v", t0)
	}
	if !t1.GetResolve() || t1.GetResolveIntervalMs() != 10_000 || !t1.GetDown() {
		t.Fatalf("target 1 = %v", t1)
	}
}

func TestValidateUpstreamFeatures(t *testing.T) {
	bad := []model.UpstreamSpec{
		{Targets: []model.Target{{Address: "a:1"}}, Balancing: model.Balancing{Algorithm: model.Hash}},
		{Targets: []model.Target{{Address: "a:1"}, {Address: "b:1", Backup: true}}, Balancing: model.Balancing{Algorithm: model.IPHash}},
		{Targets: []model.Target{{Address: "a:1"}}, Queue: model.Queue{Size: 5}},
		{Targets: []model.Target{{Address: "a:1", Route: "x"}}},
		{Targets: []model.Target{{Address: "a:1"}}, Sticky: &model.Sticky{Type: model.StickyRoute, Route: []string{"$cookie_r"}}},
		{Targets: []model.Target{{Address: "a:1"}}, HealthCheck: &model.HealthCheck{Statuses: []string{"399-200"}}},
		{Targets: []model.Target{{Address: "a:1"}}, HealthCheck: &model.HealthCheck{Type: model.HealthTCP, Path: "/"}},
	}
	for i, sp := range bad {
		u := &model.Upstream{Meta: model.Meta{ID: "up_x", Name: "x"}, Spec: sp}
		if es := model.Validate(u); len(es) == 0 {
			t.Errorf("case %d: no error", i)
		}
	}
}

func TestCompileAccessPolicies(t *testing.T) {
	cfg := validConfig()
	pol := func(id string, spec model.PolicySpec) *model.Policy {
		return &model.Policy{Meta: meta(id, strings.TrimPrefix(id, "pol_")), Spec: spec}
	}
	cfg.Policies = []*model.Policy{
		pol("pol_rate", model.PolicySpec{Type: model.PolicyRateLimit, RateLimit: &model.RateLimitPolicy{Rate: "30r/m", Burst: 5, NoDelay: true, Status: 429}}),
		pol("pol_conn", model.PolicySpec{Type: model.PolicyConnLimit, ConnLimit: &model.ConnLimitPolicy{Key: "$server_name", Max: 10}}),
		pol("pol_deny", model.PolicySpec{Type: model.PolicyIPAccess, IPAccess: &model.IPAccessPolicy{Rules: []model.IPRule{
			{Action: "allow", From: "10.0.0.0/8"}, {Action: "deny", From: "all"},
		}}}),
		pol("pol_auth", model.PolicySpec{Type: model.PolicyBasicAuth, BasicAuth: &model.BasicAuthPolicy{Realm: "admin", Users: []model.BasicUser{
			{Name: "alice", Hash: "$apr1$abcdefgh$h9FWgUz3n9YxylKLlR5SQ/"},
		}}}),
		pol("pol_fwd", model.PolicySpec{Type: model.PolicyForwardAuth, ForwardAuth: &model.ForwardAuthPolicy{
			Upstream: "up_api", URI: "/check", Timeout: "2s", CopyHeaders: []string{"X-User"},
		}}),
		pol("pol_bw", model.PolicySpec{Type: model.PolicyBandwidth, Bandwidth: &model.BandwidthPolicy{Rate: "100k", After: "1m"}}),
		pol("pol_real", model.PolicySpec{Type: model.PolicyRealIP, RealIP: &model.RealIPPolicy{From: []string{"10.0.0.0/8"}, Header: "X-Forwarded-For", Recursive: true}}),
	}
	cfg.Sites[0].Spec.Policies = []string{"pol_real", "pol_rate", "pol_deny"}
	cfg.Routes[0].Spec.Policies = []string{"pol_rate", "pol_conn", "pol_auth", "pol_fwd", "pol_bw"}
	snap, err := Compile(cfg, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.GetRateZones()) != 1 || len(snap.GetConnZones()) != 1 {
		t.Fatalf("zones = %v %v", snap.GetRateZones(), snap.GetConnZones())
	}
	rz := snap.GetRateZones()[0]
	if rz.GetKey() != "$binary_remote_addr" || rz.GetRateMilli() != 500 || rz.GetBurst() != 5 || rz.GetDelay() != 5 || rz.GetStatus() != 429 {
		t.Fatalf("rate zone = %v", rz)
	}
	site := snap.GetSites()[0]
	if ri := site.GetRealIp(); ri.GetHeader() != "x-forwarded-for" || !ri.GetRecursive() || ri.GetFrom()[0] != "10.0.0.0/8" {
		t.Fatalf("real ip = %v", ri)
	}
	var api, root *snapshotv1.Route
	for _, r := range site.GetRoutes() {
		switch r.GetId() {
		case "rt_api":
			api = r
		case "rt_root":
			root = r
		}
	}
	a := api.GetAccess()
	// The site's rate limit and the route's are the same zone, listed once.
	if len(a.GetRateLimits()) != 1 || len(a.GetConnLimits()) != 1 || len(a.GetRules()) != 2 || a.GetRules()[1].GetCidr() != "" || a.GetRules()[1].GetAllow() {
		t.Fatalf("access = %v", a)
	}
	if a.GetBasicAuth().GetRealm() != "admin" || a.GetForwardAuth().GetUri() != "/check" || a.GetForwardAuth().GetTimeoutMs() != 2000 ||
		a.GetForwardAuth().GetCopyHeaders()[0] != "x-user" {
		t.Fatalf("auth = %v", a)
	}
	if b := api.GetBandwidth(); b.GetRate() != 100*1024 || b.GetAfter() != 1024*1024 {
		t.Fatalf("bandwidth = %v", b)
	}
	if ra := root.GetAccess(); len(ra.GetRules()) != 2 || ra.GetBasicAuth() != nil || root.GetBandwidth() != nil {
		t.Fatalf("root access = %v", ra)
	}

	cfg.Routes[1].Spec.Policies = []string{"pol_real"}
	_, err = Compile(cfg, 1)
	wantPaths(t, err, "routes[rt_root].spec.policies[0]")
}

func TestValidateAccessPolicies(t *testing.T) {
	bad := []model.PolicySpec{
		{Type: model.PolicyRateLimit, RateLimit: &model.RateLimitPolicy{Rate: "10r/h"}},
		{Type: model.PolicyRateLimit, RateLimit: &model.RateLimitPolicy{Rate: "10r/s", Burst: 1, Delay: 2}},
		{Type: model.PolicyConnLimit, ConnLimit: &model.ConnLimitPolicy{}},
		{Type: model.PolicyBandwidth, Bandwidth: &model.BandwidthPolicy{Rate: "0"}},
		{Type: model.PolicyIPAccess, IPAccess: &model.IPAccessPolicy{Rules: []model.IPRule{{Action: "allow", From: "10.0.0.0/33"}}}},
		{Type: model.PolicyBasicAuth, BasicAuth: &model.BasicAuthPolicy{Realm: "r", Users: []model.BasicUser{{Name: "a", Hash: "plain"}}}},
		{Type: model.PolicyForwardAuth, ForwardAuth: &model.ForwardAuthPolicy{Upstream: "up_a", URI: "check"}},
		{Type: model.PolicyRealIP, RealIP: &model.RealIPPolicy{}},
		{Type: model.PolicyRealIP, IPAccess: &model.IPAccessPolicy{}},
		{Type: "nope"},
	}
	for i, sp := range bad {
		if es := model.Validate(&model.Policy{Meta: meta("pol_x", "x"), Spec: sp}); len(es) == 0 {
			t.Errorf("case %d: no error", i)
		}
	}
	if r, err := model.ParseRate("30r/m"); err != nil || r != 500 {
		t.Errorf("ParseRate = %d %v", r, err)
	}
	if n, err := model.ParseSize("2m"); err != nil || n != 2<<20 {
		t.Errorf("ParseSize = %d %v", n, err)
	}
}

func TestCompileLookupsAndCompression(t *testing.T) {
	cfg := validConfig()
	cfg.Lookups = []*model.Lookup{
		// backend sorts before country, which it uses: the compiled order must swap them.
		{Meta: meta("lk_backend", "backend"), Spec: model.LookupSpec{Type: model.LookupMap, Source: "$country", Map: &model.MapTable{
			Entries: []model.MapEntry{{Key: "kr", Value: "seoul"}, {Match: model.MapRegexCI, Key: "^u", Value: "us-$1"}},
			Default: "any",
		}}},
		{Meta: meta("lk_country", "country"), Spec: model.LookupSpec{Type: model.LookupGeo, Geo: &model.GeoTable{
			Entries: []model.GeoEntry{{Network: "10.1.2.3/8", Value: "kr"}, {Network: "::1", Value: "lo"}},
		}}},
		{Meta: meta("lk_ab", "ab-test"), Spec: model.LookupSpec{Type: model.LookupSplit, Source: "$remote_addr", Split: &model.SplitClients{
			Buckets: []model.SplitBucket{{Percent: "0.5%", Value: "a"}, {Percent: "*", Value: "b"}},
		}}},
	}
	br := uint32(4)
	cfg.Policies = []*model.Policy{
		{Meta: meta("pol_gz", "gz"), Spec: model.PolicySpec{Type: model.PolicyCompression, Compression: &model.CompressionPolicy{
			Encodings: []string{"zstd", "gzip"}, Types: []string{"text/css"}, Proxied: []string{"any"}, Static: "on",
		}}},
		{Meta: meta("pol_br", "br"), Spec: model.PolicySpec{Type: model.PolicyCompression, Compression: &model.CompressionPolicy{
			Encodings: []string{"br"}, MinLength: "1k", BrotliLevel: &br, Vary: true,
		}}},
	}
	cfg.Sites[0].Spec.Policies = []string{"pol_gz"}
	cfg.Routes[0].Spec.Policies = []string{"pol_br"}
	for _, r := range cfg.Lookups {
		if es := model.Validate(r); len(es) > 0 {
			t.Fatalf("%s: %v", r.ID, es)
		}
	}
	snap, err := Compile(cfg, 1)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, l := range snap.GetLookups() {
		names = append(names, l.GetName())
	}
	if strings.Join(names, ",") != "ab_test,country,backend" {
		t.Fatalf("lookups = %v", names)
	}
	g := snap.GetLookups()[1]
	if g.GetSource() != "$remote_addr" || g.GetGeo().GetEntries()[0].GetCidr() != "10.0.0.0/8" || g.GetGeo().GetEntries()[1].GetCidr() != "::1/128" {
		t.Fatalf("geo = %v", g)
	}
	if e := snap.GetLookups()[2].GetMap().GetEntries(); e[0].GetKind() != snapshotv1.LookupMapEntry_KIND_EXACT || e[1].GetKind() != snapshotv1.LookupMapEntry_KIND_REGEX_CI {
		t.Fatalf("map = %v", e)
	}
	if p := snap.GetLookups()[0].GetSplit().GetParts(); p[0].GetBasisPoints() != 50 || p[1].GetBasisPoints() != 0 {
		t.Fatalf("split = %v", p)
	}
	site := snap.GetSites()[0]
	if c := site.GetCompression(); c.GetMinLength() != 20 || c.GetEncodings()[0] != snapshotv1.Compression_ENCODING_ZSTD ||
		c.GetStatic() != snapshotv1.Compression_STATIC_ON || c.GetProxied()[0] != snapshotv1.Compression_PROXIED_ANY {
		t.Fatalf("site compression = %v", c)
	}
	for _, r := range site.GetRoutes() {
		c := r.GetCompression()
		switch r.GetId() {
		case "rt_api":
			// The closest policy wins whole.
			if c.GetMinLength() != 1024 || c.GetBrotliLevel() != 4 || !c.GetVary() || c.GetStatic() != snapshotv1.Compression_STATIC_UNSPECIFIED {
				t.Fatalf("api compression = %v", c)
			}
		case "rt_root":
			if c.GetEncodings()[1] != snapshotv1.Compression_ENCODING_GZIP {
				t.Fatalf("root compression = %v", c)
			}
		}
	}

	cfg.Lookups[1].Spec.Source = "$backend"
	_, err = Compile(cfg, 1)
	wantPaths(t, err, "lookups[lk_backend].spec")
	cfg.Lookups[1].Spec.Source = ""
	cfg.Lookups[2].Spec.Variable = "country"
	_, err = Compile(cfg, 1)
	wantPaths(t, err, "lookups[lk_country].spec.variable")
}

func TestValidateLookupsAndCompression(t *testing.T) {
	bad := []model.LookupSpec{
		{Type: model.LookupMap, Map: &model.MapTable{}},
		{Type: model.LookupMap, Source: "$host", Map: &model.MapTable{Entries: []model.MapEntry{{Key: "A"}, {Key: "a"}}}},
		{Type: model.LookupMap, Source: "$host", Map: &model.MapTable{Entries: []model.MapEntry{{Match: "glob", Key: "a"}}}},
		{Type: model.LookupGeo, Geo: &model.GeoTable{Entries: []model.GeoEntry{{Network: "10.0.0.0/33"}}}},
		{Type: model.LookupSplit, Source: "$host", Split: &model.SplitClients{Buckets: []model.SplitBucket{{Percent: "*"}, {Percent: "1%"}}}},
		{Type: model.LookupSplit, Source: "$host", Split: &model.SplitClients{Buckets: []model.SplitBucket{{Percent: "60%"}, {Percent: "50%"}}}},
		{Type: model.LookupSplit, Source: "$host", Split: &model.SplitClients{Buckets: []model.SplitBucket{{Percent: "0.125%"}}}},
		{Type: model.LookupGeo, Variable: "Bad-Name", Geo: &model.GeoTable{}},
		{Type: model.LookupGeo, Map: &model.MapTable{}},
	}
	for i, sp := range bad {
		if es := model.Validate(&model.Lookup{Meta: meta("lk_x", "x"), Spec: sp}); len(es) == 0 {
			t.Errorf("lookup case %d: no error", i)
		}
	}
	big := uint32(12)
	badC := []model.CompressionPolicy{
		{},
		{Encodings: []string{"deflate"}},
		{Encodings: []string{"gzip", "gzip"}},
		{Encodings: []string{"gzip"}, GzipLevel: 10},
		{Encodings: []string{"br"}, BrotliLevel: &big},
		{Encodings: []string{"gzip"}, Proxied: []string{"sometimes"}},
		{Static: "maybe"},
		{Encodings: []string{"gzip"}, Types: []string{"html"}},
	}
	for i, c := range badC {
		sp := model.PolicySpec{Type: model.PolicyCompression, Compression: &c}
		if es := model.Validate(&model.Policy{Meta: meta("pol_x", "x"), Spec: sp}); len(es) == 0 {
			t.Errorf("compression case %d: no error", i)
		}
	}
	for s, want := range map[string]uint32{"20%": 2000, "0.5%": 50, "0.25%": 25, "100%": 10000} {
		if n, ok := model.ParsePercent(s); !ok || n != want {
			t.Errorf("ParsePercent(%q) = %d %v", s, n, ok)
		}
	}
}

func TestCompileCache(t *testing.T) {
	cfg := validConfig()
	cfg.Policies = []*model.Policy{{Meta: meta("pol_micro", "micro"), Spec: model.PolicySpec{Type: model.PolicyCache, Cache: &model.CachePolicy{
		MaxSize: "1g", Inactive: "1h", Lock: true, UseStale: []string{"updating", "http_502"}, BackgroundUpdate: true,
		Valid:  []model.CacheValid{{Time: "1s"}, {Statuses: []string{"any"}, Time: "1m"}, {Statuses: []string{"404"}, Time: "10s"}},
		Ignore: []string{"set-cookie"},
	}}}}
	cfg.Sites[0].Spec.Policies = []string{"pol_micro"}
	for _, p := range cfg.Policies {
		if es := model.Validate(p); len(es) > 0 {
			t.Fatal(es)
		}
	}
	snap, err := Compile(cfg, 1)
	if err != nil {
		t.Fatal(err)
	}
	if got := snap.GetCacheZones(); len(got) != 1 || got[0].GetPath() != "pol_micro" || got[0].GetMaxSize() != 1<<30 ||
		got[0].GetInactiveS() != 3600 || len(got[0].GetLevels()) != 2 {
		t.Fatalf("zones: %v", got)
	}
	var api, root *snapshotv1.Route
	for _, r := range snap.GetSites()[0].GetRoutes() {
		switch r.GetId() {
		case "rt_api":
			api = r
		case "rt_root":
			root = r
		}
	}
	if root.GetCache() != nil {
		t.Error("static route got a cache")
	}
	c := api.GetCache()
	want := []*snapshotv1.CacheValid{{Seconds: 1}, {Any: true, Seconds: 60}, {Statuses: []uint32{404}, Seconds: 10}}
	if !c.GetLock() || !c.GetBackgroundUpdate() || len(c.GetValid()) != 3 || len(c.GetUseStale()) != 2 ||
		c.GetIgnore()[0] != snapshotv1.Cache_IGNORE_SET_COOKIE {
		t.Fatalf("cache: %v", c)
	}
	for i, v := range c.GetValid() {
		if !proto.Equal(v, want[i]) {
			t.Errorf("valid[%d] = %v, want %v", i, v, want[i])
		}
	}
}

func TestValidateCache(t *testing.T) {
	bad := []model.CachePolicy{
		{Path: "../x"},
		{Levels: []uint32{3}},
		{MaxSize: "lots"},
		{Inactive: "500ms"},
		{Valid: []model.CacheValid{{Time: ""}}},
		{Valid: []model.CacheValid{{Statuses: []string{"any", "200"}, Time: "1m"}}},
		{Methods: []string{"get"}},
		{Bypass: "request.nope"},
		{UseStale: []string{"sometimes"}},
		{BackgroundUpdate: true},
		{Ignore: []string{"Date"}},
	}
	for i, c := range bad {
		p := &model.Policy{Meta: meta("pol_x", "x"), Spec: model.PolicySpec{Type: model.PolicyCache, Cache: &c}}
		if es := model.Validate(p); len(es) == 0 {
			t.Errorf("case %d: no error", i)
		}
	}
}

func TestCompileTokenAuth(t *testing.T) {
	cfg := validConfig()
	cfg.Policies = []*model.Policy{
		{Meta: meta("pol_jwt", "jwt"), Spec: model.PolicySpec{Type: model.PolicyJWT, JWT: &model.JWTPolicy{
			JWKSURL: "https://idp.example.com/keys", KeyCache: "10m", Audiences: []string{"api"}, Leeway: "30s",
		}}},
		{Meta: meta("pol_oidc", "oidc"), Spec: model.PolicySpec{Type: model.PolicyOIDC, OIDC: &model.OIDCPolicy{
			Issuer: "https://idp.example.com", ClientID: "app", ClientSecret: "s", SessionTimeout: "1h",
		}}},
	}
	cfg.Routes[0].Spec.Policies = []string{"pol_jwt", "pol_oidc"}
	for _, p := range cfg.Policies {
		if es := model.Validate(p); es != nil {
			t.Fatalf("%s: %v", p.ID, es)
		}
	}
	snap, err := Compile(cfg, 1)
	if err != nil {
		t.Fatal(err)
	}
	var a *snapshotv1.Access
	for _, r := range snap.GetSites()[0].GetRoutes() {
		if r.GetId() == "rt_api" {
			a = r.GetAccess()
		}
	}
	j, o := a.GetJwt(), a.GetOidc()
	if j.GetJwksUrl() != "https://idp.example.com/keys" || j.GetKeyCacheS() != 600 || j.GetLeewayS() != 30 || j.GetAudiences()[0] != "api" {
		t.Errorf("jwt = %v", j)
	}
	if o.GetIssuer() != "https://idp.example.com" || o.GetClientSecret() != "s" || o.GetSessionTimeoutS() != 3600 {
		t.Errorf("oidc = %v", o)
	}
}

func TestValidateTokenAuth(t *testing.T) {
	bad := []model.PolicySpec{
		{Type: model.PolicyJWT, JWT: &model.JWTPolicy{}},
		{Type: model.PolicyJWT, JWT: &model.JWTPolicy{JWKS: "{nope"}},
		{Type: model.PolicyJWT, JWT: &model.JWTPolicy{JWKS: `{"keys":[{}]}`}},
		{Type: model.PolicyJWT, JWT: &model.JWTPolicy{JWKSURL: "ftp://x"}},
		{Type: model.PolicyOIDC, OIDC: &model.OIDCPolicy{Issuer: "idp", ClientID: "a"}},
		{Type: model.PolicyOIDC, OIDC: &model.OIDCPolicy{Issuer: "https://idp"}},
		{Type: model.PolicyOIDC, OIDC: &model.OIDCPolicy{Issuer: "https://idp", ClientID: "a", RedirectURI: "/cb?x=1"}},
		{Type: model.PolicyOIDC, OIDC: &model.OIDCPolicy{Issuer: "https://idp", ClientID: "a", LogoutURI: "logout"}},
	}
	for i, s := range bad {
		p := &model.Policy{Meta: meta("pol_x", "x"), Spec: s}
		if es := model.Validate(p); len(es) == 0 {
			t.Errorf("case %d: no error", i)
		}
	}
}
