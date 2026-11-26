package diff

import (
	"encoding/json"
	"maps"
	"slices"

	snapshotv1 "github.com/null-variable/proxelo-api/gen/go/proxelo/snapshot/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// Effective is how one compiled site or route behaves differently, with
// inherited policies, error pages and defaults resolved.
type Effective struct {
	// "listener", "site", "route" or "upstream".
	Kind    string   `json:"kind"`
	ID      string   `json:"id"`
	Op      string   `json:"op"`
	Changes []Change `json:"changes,omitempty"`
}

// node is a compiled object without its nested objects of the same tables.
type node struct {
	kind string
	doc  any
}

func flatten(s *snapshotv1.Snapshot) map[string]node {
	out := map[string]node{}
	put := func(kind, id string, m proto.Message) {
		b, err := protojson.MarshalOptions{UseProtoNames: false}.Marshal(m)
		if err != nil {
			panic(err)
		}
		var doc any
		if err := json.Unmarshal(b, &doc); err != nil {
			panic(err)
		}
		out[kind+"/"+id] = node{kind, doc}
	}
	var route func(r *snapshotv1.Route)
	route = func(r *snapshotv1.Route) {
		c := proto.CloneOf(r)
		c.Children = nil
		put("route", r.GetId(), c)
		for _, ch := range r.GetChildren() {
			route(ch)
		}
	}
	for _, l := range s.GetListeners() {
		put("listener", l.GetId(), l)
	}
	for _, site := range s.GetSites() {
		c := proto.CloneOf(site)
		c.Routes, c.NamedRoutes = nil, nil
		put("site", site.GetId(), c)
		for _, r := range site.GetRoutes() {
			route(r)
		}
		for _, r := range site.GetNamedRoutes() {
			route(r)
		}
	}
	for _, u := range s.GetUpstreams() {
		put("upstream", u.GetId(), u)
	}
	return out
}

// EffectiveDiff compares two compiled snapshots object by object. Either
// may be nil, as before the first revision.
func EffectiveDiff(a, b *snapshotv1.Snapshot) []Effective {
	fa, fb := flatten(a), flatten(b)
	keys := map[string]bool{}
	for k := range fa {
		keys[k] = true
	}
	for k := range fb {
		keys[k] = true
	}
	var out []Effective
	for _, k := range slices.Sorted(maps.Keys(keys)) {
		na, inA := fa[k]
		nb, inB := fb[k]
		switch {
		case !inA:
			out = append(out, Effective{Kind: nb.kind, ID: k[len(nb.kind)+1:], Op: "added"})
		case !inB:
			out = append(out, Effective{Kind: na.kind, ID: k[len(na.kind)+1:], Op: "removed"})
		default:
			if cs := Compare(na.doc, nb.doc); len(cs) > 0 {
				out = append(out, Effective{Kind: na.kind, ID: k[len(na.kind)+1:], Op: "changed", Changes: cs})
			}
		}
	}
	return out
}
