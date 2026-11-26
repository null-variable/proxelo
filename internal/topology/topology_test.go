package topology

import (
	"strings"
	"testing"

	"github.com/null-variable/proxelo/internal/model"
)

func TestBuildAndRender(t *testing.T) {
	off := false
	cfg := model.Config{
		Listeners: []*model.Listener{{Meta: model.Meta{ID: "lst_a", Name: "http"}, Spec: model.ListenerSpec{Address: "0.0.0.0:80", DefaultSite: "site_a"}}},
		Sites:     []*model.Site{{Meta: model.Meta{ID: "site_a", Name: "web", Group: "grp_x"}, Spec: model.SiteSpec{Listeners: []string{"lst_a"}, Routes: []string{"rt_a", "rt_hidden"}}}},
		Routes: []*model.Route{
			{Meta: model.Meta{ID: "rt_a", Name: "api", Enabled: &off}, Spec: model.RouteSpec{Action: model.Action{Type: "proxy", Proxy: &model.ProxyAction{Upstream: "up_a"}}}},
			{Meta: model.Meta{ID: "rt_hidden", Name: "hidden"}},
		},
		Upstreams: []*model.Upstream{{Meta: model.Meta{ID: "up_a", Name: "api"}, Spec: model.UpstreamSpec{Targets: []model.Target{{Address: "10.0.0.1:80"}, {Address: "10.0.0.2:80", Backup: true}}}}},
	}
	g := Build(cfg, func(_ string, r model.Resource) bool { return r.Common().ID != "rt_hidden" })

	var edges []string
	for _, e := range g.Edges {
		edges = append(edges, e.From+">"+e.To)
	}
	// The default-site edge and the edge to the filtered route are left out.
	want := "site_a>lst_a site_a>rt_a rt_a>up_a up_a>up_a/0 up_a>up_a/1"
	if got := strings.Join(edges, " "); got != want {
		t.Fatalf("edges = %s, want %s", got, want)
	}

	m := Mermaid(g)
	// Listener edges are drawn in request order; disabled nodes are marked.
	for _, s := range []string{"n0 --> n1", "n1 --> n2", "class n2 disabled", `n5["10.0.0.2:80<br/><small>backup</small>"]`} {
		if !strings.Contains(m, s) {
			t.Fatalf("mermaid lacks %q:\n%s", s, m)
		}
	}
	d := DOT(g)
	if !strings.Contains(d, `"lst_a" -> "site_a";`) || !strings.Contains(d, `style="rounded,dashed"`) {
		t.Fatalf("dot:\n%s", d)
	}
}
