package compile

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"

	snapshotv1 "github.com/null-variable/proxelo-api/gen/go/proxelo/snapshot/v1"
	"google.golang.org/protobuf/proto"

	"github.com/null-variable/proxelo/internal/model"
)

func validConfig() model.Config {
	return model.Config{
		Listeners: []model.Listener{{ID: "http", Address: "0.0.0.0:80", DefaultSite: "web"}},
		Sites: []model.Site{{
			ID:        "web",
			Listeners: []string{"http"},
			Hostnames: []string{"example.com"},
			Routes: []model.Route{
				{Path: model.Path{Kind: model.PathPrefix, Value: "/api/"}, Action: model.Action{Proxy: &model.ProxyAction{Upstream: "api"}}},
				{Path: model.Path{Kind: model.PathExact, Value: "/"}, Action: model.Action{Static: &model.StaticAction{Root: "/srv/www"}}},
			},
		}},
		Upstreams: []model.Upstream{{ID: "api", Targets: []model.Target{{Address: "10.0.0.1:8080"}}}},
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
	again, _ := Compile(validConfig(), 1)
	if !bytes.Equal(snap.GetHash(), again.GetHash()) {
		t.Fatal("hash is not deterministic")
	}
}

func TestCompileErrors(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*model.Config)
		path   string
	}{
		{"unknown default site", func(c *model.Config) { c.Listeners[0].DefaultSite = "nope" }, "listeners[http].defaultSite"},
		{"unknown listener", func(c *model.Config) { c.Sites[0].Listeners = []string{"nope"} }, "sites[web].listeners"},
		{"unknown upstream", func(c *model.Config) { c.Sites[0].Routes[0].Action.Proxy.Upstream = "nope" }, "sites[web].routes[0].action.proxy.upstream"},
		{"bad path kind", func(c *model.Config) { c.Sites[0].Routes[0].Path.Kind = "regex" }, "sites[web].routes[0].path.kind"},
		{"no action", func(c *model.Config) { c.Sites[0].Routes[1].Action = model.Action{} }, "sites[web].routes[1].action"},
		{"two actions", func(c *model.Config) { c.Sites[0].Routes[0].Action.Static = &model.StaticAction{Root: "/"} }, "sites[web].routes[0].action"},
		{"empty upstream", func(c *model.Config) { c.Upstreams[0].Targets = nil }, "upstreams[api].targets"},
		{"duplicate site", func(c *model.Config) { c.Sites = append(c.Sites, c.Sites[0]) }, "sites[web]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig()
			tc.mutate(&cfg)
			_, err := Compile(cfg, 1)
			var ce *Error
			if !errors.As(err, &ce) {
				t.Fatalf("err = %v, want *Error", err)
			}
			if ce.Path != tc.path {
				t.Fatalf("path = %q, want %q", ce.Path, tc.path)
			}
		})
	}
}
