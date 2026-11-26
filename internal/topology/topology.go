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
}

// Edge is a reference: From uses To.
type Edge struct {
	From string `json:"from"`
	To   string `json:"to"`
	// The referencing field, for example "spec.routes".
	Field string `json:"field"`
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
				g.Nodes = append(g.Nodes, Node{ID: id, Kind: "targets", Name: t.Address, Group: u.Group, Detail: targetDetail(t)})
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
	return strings.Join(parts, " ")
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
	"spec.action.proxy.upstream": true, "spec.targets": true,
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
