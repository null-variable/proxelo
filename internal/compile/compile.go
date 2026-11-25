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
	"strings"

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
		kind     model.HostMatchType
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
				k := hostKey{li, h.Type, h.Value}
				if other, dup := hostOwner[k]; dup && other != s.ID {
					c.add(fmt.Sprintf("%s.hostnames[%d]", base, i), "%q is already served by site %q on listener %q",
						h.Value, other, listeners.items[li].ID)
				}
				hostOwner[k] = s.ID
			}
			if kind, ok := hostKinds[h.Type]; ok {
				out.Hostnames = append(out.Hostnames, &snapshotv1.HostMatch{Kind: kind, Value: h.Value})
			}
		}
		st := &site{
			c: c, out: out, routes: routes, upstreams: upstreams,
			named: map[string]uint32{}, placed: map[string]string{},
		}
		out.Rewrites = st.rewrites(s.Spec.Rewrite)
		if r := s.Spec.Return; r != nil {
			out.Return = &snapshotv1.ReturnAction{Status: r.Status, Text: r.Text}
		}
		out.ErrorPages = st.errorPages(base+".errorPages", s.Spec.ErrorPages)
		out.Routes = st.level(base+".routes", "", s.Spec.Routes, out.ErrorPages, nil)
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

var hostKinds = map[model.HostMatchType]snapshotv1.HostMatch_Kind{
	model.HostExact:    snapshotv1.HostMatch_KIND_EXACT,
	model.HostWildcard: snapshotv1.HostMatch_KIND_WILDCARD,
	model.HostRegex:    snapshotv1.HostMatch_KIND_REGEX,
}

var pathKinds = map[model.PathMatchType]snapshotv1.PathMatch_Kind{
	model.PathExact:          snapshotv1.PathMatch_KIND_EXACT,
	model.PathPrefix:         snapshotv1.PathMatch_KIND_PREFIX,
	model.PathPrefixPriority: snapshotv1.PathMatch_KIND_PREFIX_PRIORITY,
	model.PathRegex:          snapshotv1.PathMatch_KIND_REGEX,
	model.PathRegexCI:        snapshotv1.PathMatch_KIND_REGEX_CI,
}

type pathKey struct {
	kind  model.PathMatchType
	value string
}

// site compiles the route tree of one site. Routes are referenced by ID, so
// a route can be a top-level route of several sites; within one site it may
// appear only once in the tree.
type site struct {
	c         *compiler
	out       *snapshotv1.Site
	routes    index[*model.Route]
	upstreams index[*model.Upstream]
	// Route ID to index in out.NamedRoutes.
	named map[string]uint32
	// Route ID to the path of the reference that placed it in the tree.
	placed map[string]string
}

// level compiles sibling routes. parent is the prefix of the enclosing route,
// or "" at the top level. inherited are the error pages of the enclosing
// route or site. ancestors guards against cycles.
func (st *site) level(path, parent string, ids []string, inherited []*snapshotv1.ErrorPage, ancestors []string) []*snapshotv1.Route {
	c := st.c
	var out []*snapshotv1.Route
	paths := map[pathKey]string{}
	for i, id := range ids {
		ref := fmt.Sprintf("%s[%d]", path, i)
		if st.routes.disabled[id] {
			continue
		}
		ri, ok := st.routes.resolve(c, ref, "route", id)
		if !ok {
			continue
		}
		if slices.Contains(ancestors, id) {
			c.add(ref, "route %q contains itself", id)
			continue
		}
		if other, dup := st.placed[id]; dup {
			c.add(ref, "route %q is already used at %s", id, other)
			continue
		}
		st.placed[id] = ref
		r := st.routes.items[ri]
		m := r.Spec.Match.Path
		k := pathKey{m.Type, m.Value}
		// nginx rejects "location /a" next to "location ^~ /a".
		if k.kind == model.PathPrefixPriority {
			k.kind = model.PathPrefix
		}
		if other, dup := paths[k]; dup {
			c.add(ref, "route %q has the same path match as route %q", id, other)
		}
		paths[k] = id
		// nginx: "location X is outside location Y".
		switch m.Type {
		case model.PathExact, model.PathPrefix, model.PathPrefixPriority:
			if parent != "" && !strings.HasPrefix(m.Value, parent) {
				c.add(ref, "route %q path %q is outside its parent prefix %q", id, m.Value, parent)
			}
		}
		route := st.route(r)
		if route == nil {
			continue
		}
		if len(route.ErrorPages) == 0 {
			route.ErrorPages = inherited
		}
		if len(r.Spec.Children) > 0 {
			route.Children = st.level(fmt.Sprintf("routes[%s].spec.children", id), m.Value,
				r.Spec.Children, route.ErrorPages, append(ancestors, id))
		}
		out = append(out, route)
	}
	return out
}

// namedRoute returns the index of route id in Site.named_routes, compiling it
// on first use.
func (st *site) namedRoute(path, id string) (uint32, bool) {
	if i, ok := st.named[id]; ok {
		return i, true
	}
	ri, ok := st.routes.resolve(st.c, path, "route", id)
	if !ok {
		return 0, false
	}
	i := uint32(len(st.out.NamedRoutes))
	st.named[id] = i
	// Reserve the slot first: the route may refer to itself or to other
	// named routes.
	st.out.NamedRoutes = append(st.out.NamedRoutes, nil)
	route := st.route(st.routes.items[ri])
	if route == nil {
		// Keep indexes valid; the compile fails anyway.
		route = &snapshotv1.Route{}
	} else if len(route.ErrorPages) == 0 {
		route.ErrorPages = st.out.ErrorPages
	}
	st.out.NamedRoutes[i] = route
	return i, true
}

var rewriteFlags = map[model.RewriteFlag]snapshotv1.Rewrite_Flag{
	model.RewriteNext:      snapshotv1.Rewrite_FLAG_UNSPECIFIED,
	model.RewriteLast:      snapshotv1.Rewrite_FLAG_LAST,
	model.RewriteBreak:     snapshotv1.Rewrite_FLAG_BREAK,
	model.RewriteRedirect:  snapshotv1.Rewrite_FLAG_REDIRECT,
	model.RewritePermanent: snapshotv1.Rewrite_FLAG_PERMANENT,
}

func (st *site) rewrites(rs []model.Rewrite) []*snapshotv1.Rewrite {
	var out []*snapshotv1.Rewrite
	for _, r := range rs {
		out = append(out, &snapshotv1.Rewrite{Regex: r.Regex, Replacement: r.Replacement, Flag: rewriteFlags[r.Flag]})
	}
	return out
}

func (st *site) errorPages(path string, eps []model.ErrorPage) []*snapshotv1.ErrorPage {
	var out []*snapshotv1.ErrorPage
	for i, e := range eps {
		ep := &snapshotv1.ErrorPage{Codes: e.Codes, Status: e.Status}
		switch {
		case e.URI != "":
			ep.Target = &snapshotv1.ErrorPage_Uri{Uri: e.URI}
		case e.Route != "":
			n, ok := st.namedRoute(fmt.Sprintf("%s[%d].route", path, i), e.Route)
			if !ok {
				continue
			}
			ep.Target = &snapshotv1.ErrorPage_Named{Named: n}
		default:
			continue // reported by model.Validate
		}
		out = append(out, ep)
	}
	return out
}

// route compiles r without its children.
func (st *site) route(r *model.Route) *snapshotv1.Route {
	c := st.c
	out := &snapshotv1.Route{Path: &snapshotv1.PathMatch{Value: r.Spec.Match.Path.Value}}
	kind, ok := pathKinds[r.Spec.Match.Path.Type]
	if !ok {
		return nil // reported by model.Validate
	}
	out.Path.Kind = kind
	out.Rewrites = st.rewrites(r.Spec.Rewrite)
	out.ErrorPages = st.errorPages(fmt.Sprintf("routes[%s].spec.errorPages", r.ID), r.Spec.ErrorPages)

	a := r.Spec.Action
	switch {
	case a.Type == model.ActionStatic && a.Static != nil:
		sa := &snapshotv1.StaticAction{Root: a.Static.Root, Index: a.Static.Index}
		if t := a.Static.TryFiles; t != nil {
			tf := &snapshotv1.TryFiles{Files: t.Files}
			switch {
			case t.URI != "":
				tf.Fallback = &snapshotv1.TryFiles_Uri{Uri: t.URI}
			case t.Status != 0:
				tf.Fallback = &snapshotv1.TryFiles_Status{Status: t.Status}
			case t.Route != "":
				n, ok := st.namedRoute(fmt.Sprintf("routes[%s].spec.action.static.tryFiles.route", r.ID), t.Route)
				if !ok {
					return nil
				}
				tf.Fallback = &snapshotv1.TryFiles_Named{Named: n}
			}
			sa.TryFiles = tf
		}
		out.Action = &snapshotv1.Action{Kind: &snapshotv1.Action_Static{Static: sa}}
	case a.Type == model.ActionReturn && a.Return != nil:
		out.Action = &snapshotv1.Action{Kind: &snapshotv1.Action_Return{Return: &snapshotv1.ReturnAction{
			Status: a.Return.Status, Text: a.Return.Text,
		}}}
	case a.Type == model.ActionProxy && a.Proxy != nil:
		path := fmt.Sprintf("routes[%s].spec.action.proxy.upstream", r.ID)
		ui, ok := st.upstreams.resolve(c, path, "upstream", a.Proxy.Upstream)
		if !ok {
			return nil
		}
		out.Action = &snapshotv1.Action{Kind: &snapshotv1.Action_Proxy{Proxy: &snapshotv1.ProxyAction{Upstream: ui}}}
	default:
		return nil // reported by model.Validate
	}
	return out
}
