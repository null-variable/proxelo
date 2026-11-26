// Package topology turns a configuration into the graph of how requests
// flow: listener → site → route → upstream → target, and renders it as
// Mermaid or Graphviz DOT.
package topology

import (
	"fmt"
	"strings"

	"github.com/null-variable/proxelo/internal/model"
)

// Node is a resource, or an upstream target (Kind "targets").
type Node struct {
	ID    string `json:"id"`
	Kind  string `json:"kind"`
	Name  string `json:"name"`
	Group string `json:"group,omitempty"`
	// One line describing it: an address, hostnames, a path match.
	Detail   string `json:"detail,omitempty"`
	Disabled bool   `json:"disabled,omitempty"`
	// Targets: taking no requests, marked down or reported unhealthy by a
	// proxy; Health says why.
	Down   bool   `json:"down,omitempty"`
	Health string `json:"health,omitempty"`
	// Requests over the traffic window, when asked for: for sites and
	// routes the requests they answered, for upstreams and targets the
	// attempts made to them.
	Traffic *Traffic `json:"traffic,omitempty"`
}

// Traffic is a request count and how many failed: 5xx answers, or failed
// upstream attempts.
type Traffic struct {
	Requests uint64 `json:"requests"`
	Errors   uint64 `json:"errors"`
}

// Counts are per-resource traffic counts by kind and key: "sites" by site
// ID, "routes" by site ID + "/" + route ID, "targets" by upstream ID + "/" +
// address.
type Counts func(kind, key string) (Traffic, bool)

// Edge is a reference: From uses To.
type Edge struct {
	From string `json:"from"`
	To   string `json:"to"`
	// The referencing field, for example "spec.routes".
	Field string `json:"field"`
	// Requests that took this edge over the traffic window, when asked for.
	Traffic *Traffic `json:"traffic,omitempty"`
}

// Graph is a configuration as nodes and edges in flow order. Edges point
// at nodes in the graph only.
type Graph struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}

// Build makes the graph of cfg with the resources keep admits.
func Build(cfg model.Config, keep func(kind string, r model.Resource) bool) Graph {
	g := Graph{Nodes: []Node{}, Edges: []Edge{}}
	ids := map[string]bool{}
	var rs []model.Resource
	for _, k := range []model.Kind{model.ListenerKind, model.SiteKind, model.RouteKind, model.UpstreamKind, model.CertificateKind, model.PolicyKind} {
		for _, r := range cfg.Of(k) {
			if !keep(k.Plural, r) {
				continue
			}
			m := r.Common()
			ids[m.ID] = true
			rs = append(rs, r)
			g.Nodes = append(g.Nodes, Node{ID: m.ID, Kind: k.Plural, Name: m.Name, Group: m.Group, Detail: detail(r), Disabled: !m.IsEnabled()})
		}
	}
	for _, r := range rs {
		from := r.Common().ID
		for _, ref := range model.Refs(r) {
			// A listener's default site repeats a site → listener edge.
			if ref.Field == "spec.defaultSite" || !ids[ref.ID] {
				continue
			}
			g.Edges = append(g.Edges, Edge{From: from, To: ref.ID, Field: ref.Field})
		}
		if u, ok := r.(*model.Upstream); ok {
			for i, t := range u.Spec.Targets {
				id := fmt.Sprintf("%s/%d", from, i)
				g.Nodes = append(g.Nodes, Node{ID: id, Kind: "targets", Name: t.Address, Group: u.Group, Detail: targetDetail(t), Down: t.Down})
				g.Edges = append(g.Edges, Edge{From: from, To: id, Field: "spec.targets"})
			}
		}
	}
	return g
}

var pathSign = map[model.PathMatchType]string{
	model.PathExact: "= ", model.PathPrefixPriority: "^~ ", model.PathRegex: "~ ", model.PathRegexCI: "~* ",
}

func detail(r model.Resource) string {
	switch r := r.(type) {
	case *model.Listener:
		d := r.Spec.Address
		if r.Spec.TLS != nil {
			d += " tls"
		}
		if r.Spec.HTTP2 {
			d += " h2"
		}
		return d
	case *model.Site:
		hs := make([]string, len(r.Spec.Hostnames))
		for i, h := range r.Spec.Hostnames {
			hs[i] = h.Value
		}
		if len(hs) == 0 {
			return "any host"
		}
		return strings.Join(hs, " ")
	case *model.Route:
		p := r.Spec.Match.Path
		return pathSign[p.Type] + p.Value + " → " + string(r.Spec.Action.Type)
	case *model.Upstream:
		return string(r.Spec.Balancing.Algorithm)
	case *model.Certificate:
		return strings.Join(r.Spec.Domains, " ")
	case *model.Policy:
		return string(r.Spec.Type)
	}
	return ""
}

func targetDetail(t model.Target) string {
	var parts []string
	if t.Weight > 1 {
		parts = append(parts, fmt.Sprintf("weight %d", t.Weight))
	}
	if t.Backup {
		parts = append(parts, "backup")
	}
	if t.Down {
		parts = append(parts, "down")
	}
	if t.MaxConns > 0 {
		parts = append(parts, fmt.Sprintf("max %d", t.MaxConns))
	}
	return strings.Join(parts, " ")
}

// MarkUnhealthy marks the targets for which down(upstream ID, address)
// returns a reason.
func MarkUnhealthy(g *Graph, down func(upstream, address string) (string, bool)) {
	for i := range g.Nodes {
		n := &g.Nodes[i]
		if n.Kind != "targets" {
			continue
		}
		up := n.ID[:strings.LastIndexByte(n.ID, '/')]
		if why, ok := down(up, n.Name); ok {
			n.Down = true
			n.Health = why
		}
	}
}

// Mermaid renders g as a left-to-right flowchart, one subgraph per kind.
func Mermaid(g Graph) string {
	var b strings.Builder
	b.WriteString("flowchart LR\n")
	key := mermaidKeys(g)
	for _, k := range kindOrder {
		ns := byKind(g, k)
		if len(ns) == 0 {
			continue
		}
		fmt.Fprintf(&b, "  subgraph %s[%s]\n", k, kindTitle[k])
		for _, n := range ns {
			label := n.Name
			if n.Detail != "" {
				label += "<br/><small>" + n.Detail + "</small>"
			}
			fmt.Fprintf(&b, "    %s[\"%s\"]\n", key[n.ID], mermaidText(label))
		}
		b.WriteString("  end\n")
	}
	for _, e := range g.Edges {
		arrow := "-->"
		if !flow[e.Field] {
			arrow = "-.->"
		}
		// Flow edges run listener → site → route → upstream; the stored
		// reference runs site → listener.
		from, to := e.From, e.To
		if e.Field == "spec.listeners" {
			from, to = to, from
		}
		fmt.Fprintf(&b, "  %s %s %s\n", key[from], arrow, key[to])
	}
	var disabled []string
	for _, n := range g.Nodes {
		if n.Disabled {
			disabled = append(disabled, key[n.ID])
		}
	}
	if len(disabled) > 0 {
		b.WriteString("  classDef disabled stroke-dasharray: 4 3,opacity:0.5\n")
		fmt.Fprintf(&b, "  class %s disabled\n", strings.Join(disabled, ","))
	}
	return b.String()
}

// DOT renders g for Graphviz, ranked by kind.
func DOT(g Graph) string {
	var b strings.Builder
	b.WriteString("digraph proxelo {\n  rankdir=LR;\n  node [shape=box, style=rounded, fontname=\"Helvetica\"];\n")
	for _, k := range kindOrder {
		ns := byKind(g, k)
		if len(ns) == 0 {
			continue
		}
		fmt.Fprintf(&b, "  subgraph cluster_%s {\n    label=%q;\n", k, kindTitle[k])
		for _, n := range ns {
			label := n.Name
			if n.Detail != "" {
				label += "\n" + n.Detail
			}
			attrs := fmt.Sprintf("label=%q", label)
			if n.Disabled {
				attrs += ", style=\"rounded,dashed\""
			}
			fmt.Fprintf(&b, "    %q [%s];\n", n.ID, attrs)
		}
		b.WriteString("  }\n")
	}
	for _, e := range g.Edges {
		from, to := e.From, e.To
		if e.Field == "spec.listeners" {
			from, to = to, from
		}
		attrs := ""
		if !flow[e.Field] {
			attrs = " [style=dashed]"
		}
		fmt.Fprintf(&b, "  %q -> %q%s;\n", from, to, attrs)
	}
	b.WriteString("}\n")
	return b.String()
}

var kindOrder = []string{"listeners", "sites", "routes", "upstreams", "targets", "certificates", "policies"}

var kindTitle = map[string]string{
	"listeners": "Listeners", "sites": "Sites", "routes": "Routes", "upstreams": "Upstreams",
	"targets": "Targets", "certificates": "Certificates", "policies": "Policies",
}

// flow fields carry requests; the rest attach certificates, policies and
// fallbacks.
var flow = map[string]bool{
	"spec.listeners": true, "spec.routes": true, "spec.children": true,
	"spec.action.proxy.upstream": true, "spec.action.gateway.upstream": true,
	"spec.action.memcached.upstream": true, "spec.action.grpc.upstream": true, "spec.targets": true,
}

func byKind(g Graph, kind string) []Node {
	var out []Node
	for _, n := range g.Nodes {
		if n.Kind == kind {
			out = append(out, n)
		}
	}
	return out
}

// mermaidKeys gives nodes short identifiers Mermaid accepts.
func mermaidKeys(g Graph) map[string]string {
	key := make(map[string]string, len(g.Nodes))
	for i, n := range g.Nodes {
		key[n.ID] = fmt.Sprintf("n%d", i)
	}
	return key
}

// mermaidText escapes a label for a quoted Mermaid node.
func mermaidText(s string) string {
	return strings.ReplaceAll(s, `"`, "#quot;")
}

// AddTraffic attaches the counts to g. A request is counted at the route
// that answered it, the innermost one, so:
//   - sites and targets carry their own counts;
//   - a route carries the requests it answered on every site;
//   - site → route and route → child edges carry the requests that went
//     down that branch (the route and its descendants);
//   - route → upstream edges carry the route's requests, upstream →
//     target edges the target's attempts, upstreams the sum of their
//     targets;
//   - listener → site edges carry the site's requests when the site has
//     one listener.
func AddTraffic(g *Graph, counts Counts) {
	idx := make(map[string]int, len(g.Nodes))
	var sites []string
	for i, n := range g.Nodes {
		idx[n.ID] = i
		if n.Kind == "sites" {
			sites = append(sites, n.ID)
		}
	}
	children := map[string][]string{}
	listeners := map[string]int{}
	for _, e := range g.Edges {
		switch e.Field {
		case "spec.children":
			children[e.From] = append(children[e.From], e.To)
		case "spec.listeners":
			listeners[e.From]++
		}
	}
	// subtree sums the counts of route and its descendants on site.
	var subtree func(site, route string, seen map[string]bool) Traffic
	subtree = func(site, route string, seen map[string]bool) Traffic {
		if seen[route] {
			return Traffic{}
		}
		seen[route] = true
		t, _ := counts("routes", site+"/"+route)
		for _, c := range children[route] {
			s := subtree(site, c, seen)
			t.Requests += s.Requests
			t.Errors += s.Errors
		}
		return t
	}
	set := func(t Traffic) *Traffic {
		if t.Requests == 0 {
			return nil
		}
		return &t
	}
	sum := func(a, b Traffic) Traffic { return Traffic{a.Requests + b.Requests, a.Errors + b.Errors} }
	nodeOwn := map[string]Traffic{}
	for i := range g.Nodes {
		n := &g.Nodes[i]
		switch n.Kind {
		case "sites":
			t, _ := counts("sites", n.ID)
			nodeOwn[n.ID] = t
		case "routes":
			var t Traffic
			for _, s := range sites {
				c, _ := counts("routes", s+"/"+n.ID)
				t = sum(t, c)
			}
			nodeOwn[n.ID] = t
		}
	}
	for i := range g.Edges {
		e := &g.Edges[i]
		var t Traffic
		switch e.Field {
		case "spec.routes":
			t = subtree(e.From, e.To, map[string]bool{})
		case "spec.children":
			for _, s := range sites {
				t = sum(t, subtree(s, e.To, map[string]bool{}))
			}
		case "spec.action.proxy.upstream", "spec.action.gateway.upstream",
			"spec.action.memcached.upstream", "spec.action.grpc.upstream":
			t = nodeOwn[e.From]
		case "spec.targets":
			t, _ = counts("targets", e.From+"/"+g.Nodes[idx[e.To]].Name)
			nodeOwn[e.To] = t
			nodeOwn[e.From] = sum(nodeOwn[e.From], t)
		case "spec.listeners":
			if listeners[e.From] == 1 {
				t = nodeOwn[e.From]
			}
		}
		e.Traffic = set(t)
	}
	for i := range g.Nodes {
		g.Nodes[i].Traffic = set(nodeOwn[g.Nodes[i].ID])
	}
}
