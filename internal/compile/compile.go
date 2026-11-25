// Package compile turns user resources into the snapshot served by proxies.
//
// The compiler is where references between resources are resolved and
// checked. It skips disabled resources and orders everything by ID so the
// same resources always produce the same snapshot bytes and hash.
package compile

import (
	"cmp"
	"crypto/sha256"
	"fmt"
	"slices"

	snapshotv1 "github.com/null-variable/proxelo-api/gen/go/proxelo/snapshot/v1"
	"google.golang.org/protobuf/proto"

	"github.com/null-variable/proxelo/internal/model"
)

// Compile resolves IDs to indexes and returns a snapshot with its hash set.
// All errors found are returned together, with paths such as
// "routes[rt_x].spec.action.proxy.upstream".
func Compile(cfg model.Config, revision uint64) (*snapshotv1.Snapshot, error) {
	c := compiler{}
	snap := c.compile(cfg, revision)
	if err := c.errs.Err(); err != nil {
		return nil, err
	}
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(snap)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	snap.Hash = sum[:]
	return snap, nil
}

type compiler struct {
	errs model.FieldErrors
}

func (c *compiler) add(path, format string, args ...any) {
	c.errs = append(c.errs, model.FieldError{Path: path, Message: fmt.Sprintf(format, args...)})
}

// index holds the enabled resources of one kind in snapshot order and
// remembers which IDs exist but are disabled.
type index[T model.Resource] struct {
	items    []T
	pos      map[string]uint32
	disabled map[string]bool
}

func newIndex[T model.Resource](c *compiler, kind string, all []T) index[T] {
	ix := index[T]{pos: map[string]uint32{}, disabled: map[string]bool{}}
	seen := map[string]bool{}
	for _, r := range all {
		m := r.Common()
		if seen[m.ID] {
			c.add(fmt.Sprintf("%s[%s]", kind, m.ID), "duplicate id")
			continue
		}
		seen[m.ID] = true
		if errs := model.Validate(r); len(errs) > 0 {
			c.errs = append(c.errs, errs.Prefixed(fmt.Sprintf("%s[%s]", kind, m.ID))...)
		}
		if !m.IsEnabled() {
			ix.disabled[m.ID] = true
			continue
		}
		ix.items = append(ix.items, r)
	}
	slices.SortFunc(ix.items, func(a, b T) int { return cmp.Compare(a.Common().ID, b.Common().ID) })
	for i, r := range ix.items {
		ix.pos[r.Common().ID] = uint32(i)
	}
	return ix
}

// resolve returns the index of id. A reference to a missing or disabled
// resource is an error.
func (ix index[T]) resolve(c *compiler, path, kind, id string) (uint32, bool) {
	if i, ok := ix.pos[id]; ok {
		return i, true
	}
	if ix.disabled[id] {
		c.add(path, "%s %q is disabled", kind, id)
	} else {
		c.add(path, "unknown %s %q", kind, id)
	}
	return 0, false
}

func (c *compiler) compile(cfg model.Config, revision uint64) *snapshotv1.Snapshot {
	listeners := newIndex(c, "listeners", cfg.Listeners)
	sites := newIndex(c, "sites", cfg.Sites)
	routes := newIndex(c, "routes", cfg.Routes)
	upstreams := newIndex(c, "upstreams", cfg.Upstreams)

	snap := &snapshotv1.Snapshot{Revision: revision}

	for _, l := range listeners.items {
		out := &snapshotv1.Listener{Address: l.Spec.Address, ReusePort: l.Spec.ReusePort, Backlog: l.Spec.Backlog}
		if id := l.Spec.DefaultSite; id != "" {
			if i, ok := sites.resolve(c, fmt.Sprintf("listeners[%s].spec.defaultSite", l.ID), "site", id); ok {
				out.DefaultSite = proto.Uint32(i)
			}
		}
		snap.Listeners = append(snap.Listeners, out)
	}

	// Hostnames must be unique per listener, as nginx server_name selection
	// would otherwise depend on declaration order.
	type hostKey struct {
		listener uint32
		host     string
	}
	hostOwner := map[hostKey]string{}

	for _, s := range sites.items {
		base := fmt.Sprintf("sites[%s].spec", s.ID)
		out := &snapshotv1.Site{}
		for i, id := range s.Spec.Listeners {
			// A disabled listener drops out of the site like a commented-out listen.
			if listeners.disabled[id] {
				continue
			}
			if li, ok := listeners.resolve(c, fmt.Sprintf("%s.listeners[%d]", base, i), "listener", id); ok {
				out.Listeners = append(out.Listeners, li)
			}
		}
		for i, h := range s.Spec.Hostnames {
			for _, li := range out.Listeners {
				k := hostKey{li, h.Value}
				if other, dup := hostOwner[k]; dup && other != s.ID {
					c.add(fmt.Sprintf("%s.hostnames[%d]", base, i), "%q is already served by site %q on listener %q",
						h.Value, other, listeners.items[li].ID)
				}
				hostOwner[k] = s.ID
			}
			out.Hostnames = append(out.Hostnames, &snapshotv1.HostMatch{Kind: snapshotv1.HostMatch_KIND_EXACT, Value: h.Value})
		}
		paths := map[pathKey]string{}
		for i, id := range s.Spec.Routes {
			if routes.disabled[id] {
				continue
			}
			ri, ok := routes.resolve(c, fmt.Sprintf("%s.routes[%d]", base, i), "route", id)
			if !ok {
				continue
			}
			r := routes.items[ri]
			k := pathKey{r.Spec.Match.Path.Type, r.Spec.Match.Path.Value}
			if other, dup := paths[k]; dup {
				c.add(fmt.Sprintf("%s.routes[%d]", base, i), "route %q has the same path match as route %q", id, other)
			}
			paths[k] = id
			if route := c.route(r, upstreams); route != nil {
				out.Routes = append(out.Routes, route)
			}
		}
		snap.Sites = append(snap.Sites, out)
	}

	for _, u := range upstreams.items {
		out := &snapshotv1.Upstream{
			Balancing:     snapshotv1.Upstream_BALANCING_ROUND_ROBIN,
			KeepaliveIdle: u.Spec.Keepalive.Idle,
		}
		for _, t := range u.Spec.Targets {
			w := t.Weight
			if w == 0 {
				w = 1
			}
			out.Targets = append(out.Targets, &snapshotv1.Target{Address: t.Address, Weight: w})
		}
		snap.Upstreams = append(snap.Upstreams, out)
	}
	return snap
}

type pathKey struct {
	kind  model.PathMatchType
	value string
}

func (c *compiler) route(r *model.Route, upstreams index[*model.Upstream]) *snapshotv1.Route {
	out := &snapshotv1.Route{Path: &snapshotv1.PathMatch{Value: r.Spec.Match.Path.Value}}
	switch r.Spec.Match.Path.Type {
	case model.PathExact:
		out.Path.Kind = snapshotv1.PathMatch_KIND_EXACT
	case model.PathPrefix:
		out.Path.Kind = snapshotv1.PathMatch_KIND_PREFIX
	default:
		return nil // reported by model.Validate
	}

	a := r.Spec.Action
	switch {
	case a.Type == model.ActionStatic && a.Static != nil:
		out.Action = &snapshotv1.Action{Kind: &snapshotv1.Action_Static{Static: &snapshotv1.StaticAction{
			Root:  a.Static.Root,
			Index: a.Static.Index,
		}}}
	case a.Type == model.ActionProxy && a.Proxy != nil:
		path := fmt.Sprintf("routes[%s].spec.action.proxy.upstream", r.ID)
		ui, ok := upstreams.resolve(c, path, "upstream", a.Proxy.Upstream)
		if !ok {
			return nil
		}
		out.Action = &snapshotv1.Action{Kind: &snapshotv1.Action_Proxy{Proxy: &snapshotv1.ProxyAction{Upstream: ui}}}
	default:
		return nil // reported by model.Validate
	}
	return out
}
