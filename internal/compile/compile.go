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
	"strconv"
	"strings"
	"time"

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
	certs := newIndex(c, "certificates", cfg.Certificates)
	policies := newIndex(c, "policies", cfg.Policies)

	snap := &snapshotv1.Snapshot{Revision: revision}
	snap.Lookups = c.lookups(newIndex(c, "lookups", cfg.Lookups))

	// Certificates not issued yet (ACME) have no chain and are left out;
	// references to them are dropped until they are.
	certPos := map[string]uint32{}
	for _, ct := range certs.items {
		if ct.Spec.ChainPEM == "" || ct.Spec.KeyPEM == "" {
			continue
		}
		certPos[ct.ID] = uint32(len(snap.Certificates))
		snap.Certificates = append(snap.Certificates, &snapshotv1.Certificate{
			Id: ct.ID, ChainPem: ct.Spec.ChainPEM, KeyPem: ct.Spec.KeyPEM,
		})
	}
	cert := func(path, id string) (uint32, bool) {
		if _, ok := certs.resolve(c, path, "certificate", id); !ok {
			return 0, false
		}
		i, ok := certPos[id]
		return i, ok
	}

	for _, l := range listeners.items {
		base := fmt.Sprintf("listeners[%s].spec", l.ID)
		out := &snapshotv1.Listener{Id: l.ID, Address: l.Spec.Address, ReusePort: l.Spec.ReusePort, Backlog: l.Spec.Backlog, Http2: l.Spec.HTTP2, Http3: l.Spec.HTTP3}
		if id := l.Spec.DefaultSite; id != "" {
			if i, ok := sites.resolve(c, base+".defaultSite", "site", id); ok {
				out.DefaultSite = proto.Uint32(i)
			}
		}
		if t := l.Spec.TLS; t != nil {
			out.Tls = listenerTLS(t)
			if id := t.DefaultCertificate; id != "" {
				if i, ok := cert(base+".tls.defaultCertificate", id); ok {
					out.Tls.DefaultCertificate = proto.Uint32(i)
				}
			}
		}
		snap.Listeners = append(snap.Listeners, out)
	}
	logs := map[logKey]uint32{}
	zs := zones{rate: map[string]uint32{}, conn: map[string]uint32{}, cache: map[string]uint32{}, wasm: map[string]uint32{}}

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
		out := &snapshotv1.Site{Id: s.ID}
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
		for i, id := range s.Spec.Certificates {
			if ci, ok := cert(fmt.Sprintf("%s.certificates[%d]", base, i), id); ok {
				out.Certificates = append(out.Certificates, ci)
			}
		}
		out.RedirectHttps = s.Spec.RedirectHTTPToHTTPS
		st := &site{
			c: c, out: out, routes: routes, upstreams: upstreams, policies: policies,
			snap: snap, logs: logs, zones: zs,
			named: map[string]uint32{}, placed: map[string]string{},
		}
		st.sitePolicies = st.resolvePolicies(base+".policies", s.Spec.Policies)
		eff := st.effective(st.sitePolicies)
		out.ResponseHeaders = eff.response
		out.AccessLog = eff.log
		out.RealIp = realIP(st.sitePolicies)
		out.Compression = compression(st.sitePolicies)
		out.Rewrites = st.rewrites(s.Spec.Rewrite)
		if r := s.Spec.Return; r != nil {
			out.Return = &snapshotv1.ReturnAction{Status: r.Status, Text: r.Text}
		}
		out.ErrorPages = st.errorPages(base+".errorPages", s.Spec.ErrorPages)
		out.Routes = st.level(base+".routes", "", s.Spec.Routes, out.ErrorPages, nil, st.sitePolicies)
		snap.Sites = append(snap.Sites, out)
	}

	for _, u := range upstreams.items {
		sp := u.Spec
		out := &snapshotv1.Upstream{
			Id:                 u.ID,
			Balancing:          snapshotv1.Upstream_BALANCING_ROUND_ROBIN,
			KeepaliveIdle:      sp.Keepalive.Idle,
			KeepaliveTimeoutMs: millis(sp.Keepalive.Timeout),
			KeepaliveRequests:  sp.Keepalive.MaxRequests,
			// nginx proxy_pass http://<upstream name> sends the name as Host.
			Host: u.Name,
			// nginx defaults: max_fails=1 fail_timeout=10s.
			MaxFails:      1,
			FailTimeoutMs: 10_000,
		}
		if b, ok := balancing[sp.Balancing.Algorithm]; ok {
			out.Balancing = b
		}
		out.HashKey = sp.Balancing.Key
		out.KeepaliveTimeMs = millis(sp.Keepalive.MaxAge)
		out.QueueSize = sp.Queue.Size
		out.QueueTimeoutMs = millis(sp.Queue.Timeout)
		if t := sp.TLS; t != nil {
			out.Tls = &snapshotv1.UpstreamTls{
				ServerName:   t.ServerName,
				Sni:          t.SNI,
				Verify:       t.Verify,
				Ca:           t.CA,
				Depth:        t.Depth,
				MinVersion:   tlsVersions[t.MinVersion],
				MaxVersion:   tlsVersions[t.MaxVersion],
				Ciphers:      t.Ciphers,
				Ciphersuites: t.Ciphersuites,
			}
			if id := t.Certificate; id != "" {
				if i, ok := cert(fmt.Sprintf("upstreams[%s].spec.tls.certificate", u.ID), id); ok {
					out.Tls.Certificate = proto.Uint32(i)
				}
			}
		}
		if h := sp.HealthCheck; h != nil {
			hc := &snapshotv1.HealthCheck{
				Kind:       snapshotv1.HealthCheck_KIND_HTTP,
				IntervalMs: millis(h.Interval),
				TimeoutMs:  millis(h.Timeout),
				Fails:      h.Fails,
				Passes:     h.Passes,
				Path:       h.Path,
				Host:       h.Host,
				Body:       h.Body,
				Port:       h.Port,
			}
			if h.Type == model.HealthTCP {
				hc.Kind = snapshotv1.HealthCheck_KIND_TCP
			}
			if hc.Host == "" {
				hc.Host = u.Name
			}
			for _, st := range h.Statuses {
				from, to, _ := model.ParseStatusRange(st)
				hc.Statuses = append(hc.Statuses, &snapshotv1.StatusRange{From: from, To: to})
			}
			out.HealthCheck = hc
		}
		if st := sp.Sticky; st != nil {
			out.Sticky = &snapshotv1.Sticky{
				Kind:     snapshotv1.Sticky_KIND_COOKIE,
				Cookie:   st.Cookie,
				MaxAgeS:  millis(st.MaxAge) / 1000,
				Path:     st.Path,
				Domain:   st.Domain,
				HttpOnly: st.HTTPOnly,
				Secure:   st.Secure,
				SameSite: st.SameSite,
				Route:    st.Route,
			}
			if st.Type == model.StickyRoute {
				out.Sticky.Kind = snapshotv1.Sticky_KIND_ROUTE
			}
		}
		if m := sp.PassiveHealth.MaxFails; m != nil {
			out.MaxFails = *m
		}
		if v := millis(sp.PassiveHealth.FailTimeout); v != 0 {
			out.FailTimeoutMs = v
		}
		for _, t := range sp.Targets {
			w := t.Weight
			if w == 0 {
				w = 1
			}
			out.Targets = append(out.Targets, &snapshotv1.Target{
				Address: t.Address, Weight: w, Backup: t.Backup, Down: t.Down, MaxConns: t.MaxConns,
				SlowStartMs: millis(t.SlowStart), Resolve: t.Resolve,
				ResolveIntervalMs: millis(t.ResolveInterval), Route: t.Route,
			})
		}
		out.Discovered = sp.Discovery != nil
		snap.Upstreams = append(snap.Upstreams, out)
	}
	listenerAddrs := map[string]string{}
	for _, l := range listeners.items {
		listenerAddrs[l.Spec.Address] = l.ID
	}
	(&site{c: c, upstreams: upstreams, policies: policies, snap: snap, logs: logs, zones: zs}).
		streams(newIndex(c, "streams", cfg.Streams).items, listenerAddrs, cert)
	return snap
}

var tlsVersions = map[string]snapshotv1.ListenerTls_Version{
	"":    snapshotv1.ListenerTls_VERSION_UNSPECIFIED,
	"1.0": snapshotv1.ListenerTls_VERSION_TLS1_0,
	"1.1": snapshotv1.ListenerTls_VERSION_TLS1_1,
	"1.2": snapshotv1.ListenerTls_VERSION_TLS1_2,
	"1.3": snapshotv1.ListenerTls_VERSION_TLS1_3,
}

func listenerTLS(t *model.ListenerTLS) *snapshotv1.ListenerTls {
	out := &snapshotv1.ListenerTls{
		MinVersion:          tlsVersions[t.MinVersion],
		MaxVersion:          tlsVersions[t.MaxVersion],
		Ciphers:             t.Ciphers,
		Ciphersuites:        t.Ciphersuites,
		PreferServerCiphers: t.PreferServerCiphers,
		Groups:              t.Groups,
		NoSessionTickets:    t.NoSessionTickets,
		SessionCacheSize:    t.SessionCacheSize,
		DhParams:            t.DHParams,
	}
	if a := t.ClientAuth; a != nil {
		out.ClientAuth = &snapshotv1.ClientAuth{Mode: clientAuthModes[a.Mode], Ca: a.CA, Depth: a.Depth}
	}
	return out
}

var clientAuthModes = map[model.ClientAuthMode]snapshotv1.ClientAuth_Mode{
	model.ClientAuthRequire:      snapshotv1.ClientAuth_MODE_REQUIRE,
	model.ClientAuthOptional:     snapshotv1.ClientAuth_MODE_OPTIONAL,
	model.ClientAuthOptionalNoCA: snapshotv1.ClientAuth_MODE_OPTIONAL_NO_CA,
}

// millis converts a validated duration; empty is 0.
var balancing = map[model.Algorithm]snapshotv1.Upstream_Balancing{
	model.RoundRobin:     snapshotv1.Upstream_BALANCING_ROUND_ROBIN,
	model.LeastConn:      snapshotv1.Upstream_BALANCING_LEAST_CONN,
	model.IPHash:         snapshotv1.Upstream_BALANCING_IP_HASH,
	model.Hash:           snapshotv1.Upstream_BALANCING_HASH,
	model.HashConsistent: snapshotv1.Upstream_BALANCING_HASH_CONSISTENT,
	model.Random:         snapshotv1.Upstream_BALANCING_RANDOM,
	model.RandomTwo:      snapshotv1.Upstream_BALANCING_RANDOM_TWO,
}

func millis(d string) uint32 {
	if d == "" {
		return 0
	}
	v, err := time.ParseDuration(d)
	if err != nil {
		return 0 // reported by model.Validate
	}
	return uint32(v / time.Millisecond)
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
	policies  index[*model.Policy]
	snap      *snapshotv1.Snapshot
	logs      map[logKey]uint32
	zones     zones
	// The site's own policies, which every route starts from.
	sitePolicies []*model.Policy
	// Route ID to index in out.NamedRoutes.
	named map[string]uint32
	// Route ID to the path of the reference that placed it in the tree.
	placed map[string]string
}

// level compiles sibling routes. parent is the prefix of the enclosing route,
// or "" at the top level. inherited are the error pages of the enclosing
// route or site. ancestors guards against cycles.
func (st *site) level(path, parent string, ids []string, inherited []*snapshotv1.ErrorPage, ancestors []string, pols []*model.Policy) []*snapshotv1.Route {
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
		// Routes sharing a path are told apart by their conditions; only
		// one of them may have none.
		if !r.Spec.Match.HasConditions() {
			if other, dup := paths[k]; dup {
				c.add(ref, "route %q has the same path match as route %q and neither has conditions", id, other)
			}
			paths[k] = id
		}
		// nginx: "location X is outside location Y".
		switch m.Type {
		case model.PathExact, model.PathPrefix, model.PathPrefixPriority:
			if parent != "" && !strings.HasPrefix(m.Value, parent) {
				c.add(ref, "route %q path %q is outside its parent prefix %q", id, m.Value, parent)
			}
		}
		own := routePolicies(pols, st.resolvePolicies(fmt.Sprintf("routes[%s].spec.policies", id), r.Spec.Policies), r.Spec.InheritPolicies)
		route := st.route(r, own)
		if route == nil {
			continue
		}
		if len(route.ErrorPages) == 0 {
			route.ErrorPages = inherited
		}
		if len(r.Spec.Children) > 0 {
			route.Children = st.level(fmt.Sprintf("routes[%s].spec.children", id), m.Value,
				r.Spec.Children, route.ErrorPages, append(ancestors, id), own)
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
	nr := st.routes.items[ri]
	// A named route is reached from the site, so it starts from the site's
	// policies.
	route := st.route(nr, routePolicies(st.sitePolicies,
		st.resolvePolicies(fmt.Sprintf("routes[%s].spec.policies", id), nr.Spec.Policies), nr.Spec.InheritPolicies))
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

// route compiles r without its children. pols are the policies that apply to
// it, outermost first.
func (st *site) route(r *model.Route, pols []*model.Policy) *snapshotv1.Route {
	m := r.Spec.Match
	out := &snapshotv1.Route{
		Id:      r.ID,
		Path:    &snapshotv1.PathMatch{Value: m.Path.Value},
		Methods: m.Methods,
		Headers: valueMatches(m.Headers),
		Query:   valueMatches(m.Query),
		Expr:    m.Expr,
	}
	kind, ok := pathKinds[m.Path.Type]
	if !ok {
		return nil // reported by model.Validate
	}
	out.Path.Kind = kind
	out.Rewrites = st.rewrites(r.Spec.Rewrite)
	out.ErrorPages = st.errorPages(fmt.Sprintf("routes[%s].spec.errorPages", r.ID), r.Spec.ErrorPages)
	eff := st.effective(pols)
	out.ResponseHeaders, out.RequestHeaders, out.AccessLog = eff.response, eff.request, eff.log
	out.Access, out.Bandwidth = eff.access, eff.bandwidth
	out.Compression = compression(pols)

	a := r.Spec.Action
	switch {
	case a.Type == model.ActionStatic && a.Static != nil:
		sa := &snapshotv1.StaticAction{Root: a.Static.Root, Index: a.Static.Index, RandomIndex: a.Static.RandomIndex, Flv: a.Static.FLV}
		if ai := a.Static.Autoindex; ai != nil {
			sa.Autoindex = &snapshotv1.Autoindex{
				Format: map[model.AutoindexFormat]snapshotv1.Autoindex_Format{
					model.AutoindexJSON: snapshotv1.Autoindex_FORMAT_JSON, model.AutoindexJSONP: snapshotv1.Autoindex_FORMAT_JSONP, model.AutoindexXML: snapshotv1.Autoindex_FORMAT_XML,
				}[ai.Format],
				Localtime:       ai.LocalTime,
				ApproximateSize: ai.ApproximateSize,
			}
		}
		if d := a.Static.DAV; d != nil {
			access, _ := strconv.ParseUint(d.Access, 8, 32)
			sa.Dav = &snapshotv1.Dav{
				Put: slices.Contains(d.Methods, "put"), Delete: slices.Contains(d.Methods, "delete"), Mkcol: slices.Contains(d.Methods, "mkcol"),
				Copy: slices.Contains(d.Methods, "copy"), Move: slices.Contains(d.Methods, "move"),
				CreateFullPutPath: d.CreateFullPutPath, MinDeleteDepth: d.MinDeleteDepth, Access: uint32(access),
			}
		}
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
		pa := st.proxyAction(r.ID, "proxy", a.Proxy)
		if pa == nil {
			return nil
		}
		out.Action = &snapshotv1.Action{Kind: &snapshotv1.Action_Proxy{Proxy: pa}}
		out.Cache = st.cache(pols)
	case a.Type == model.ActionGrpc && a.Grpc != nil:
		pa := st.proxyAction(r.ID, "grpc", a.Grpc)
		if pa == nil {
			return nil
		}
		out.Action = &snapshotv1.Action{Kind: &snapshotv1.Action_Grpc{Grpc: &snapshotv1.GrpcAction{Proxy: pa}}}
	case a.Type == model.ActionMemcached && a.Memcached != nil:
		pa := st.proxyAction(r.ID, "memcached", &a.Memcached.ProxyAction)
		if pa == nil {
			return nil
		}
		out.Action = &snapshotv1.Action{Kind: &snapshotv1.Action_Memcached{Memcached: &snapshotv1.MemcachedAction{
			Proxy: pa, Key: a.Memcached.Key,
		}}}
	case a.Type == model.ActionGateway && a.Gateway != nil:
		pa := st.proxyAction(r.ID, "gateway", &a.Gateway.ProxyAction)
		if pa == nil {
			return nil
		}
		out.Action = &snapshotv1.Action{Kind: &snapshotv1.Action_Gateway{Gateway: gateway(a.Gateway, pa)}}
	default:
		return nil // reported by model.Validate
	}
	return out
}

// proxyAction compiles the upstream settings of an action named kind.
func (st *site) proxyAction(routeID, kind string, p *model.ProxyAction) *snapshotv1.ProxyAction {
	path := fmt.Sprintf("routes[%s].spec.action.%s.upstream", routeID, kind)
	ui, ok := st.upstreams.resolve(st.c, path, "upstream", p.Upstream)
	if !ok {
		return nil
	}
	pa := &snapshotv1.ProxyAction{
		Upstream:         ui,
		ConnectTimeoutMs: millis(p.Timeouts.Connect),
		SendTimeoutMs:    millis(p.Timeouts.Send),
		ReadTimeoutMs:    millis(p.Timeouts.Read),
	}
	if rt := p.Retry; rt != nil {
		pa.NextUpstreamTries = rt.Tries
		if len(rt.On) == 0 {
			pa.NextUpstream = []snapshotv1.NextUpstream{snapshotv1.NextUpstream_NEXT_UPSTREAM_OFF}
		}
		for _, on := range rt.On {
			pa.NextUpstream = append(pa.NextUpstream, nextUpstream[on])
		}
	}
	return pa
}

var nextUpstream = map[string]snapshotv1.NextUpstream{
	"error":          snapshotv1.NextUpstream_NEXT_UPSTREAM_ERROR,
	"timeout":        snapshotv1.NextUpstream_NEXT_UPSTREAM_TIMEOUT,
	"http_500":       snapshotv1.NextUpstream_NEXT_UPSTREAM_HTTP_500,
	"http_502":       snapshotv1.NextUpstream_NEXT_UPSTREAM_HTTP_502,
	"http_503":       snapshotv1.NextUpstream_NEXT_UPSTREAM_HTTP_503,
	"http_504":       snapshotv1.NextUpstream_NEXT_UPSTREAM_HTTP_504,
	"http_403":       snapshotv1.NextUpstream_NEXT_UPSTREAM_HTTP_403,
	"http_404":       snapshotv1.NextUpstream_NEXT_UPSTREAM_HTTP_404,
	"http_429":       snapshotv1.NextUpstream_NEXT_UPSTREAM_HTTP_429,
	"non_idempotent": snapshotv1.NextUpstream_NEXT_UPSTREAM_NON_IDEMPOTENT,
}

var matchOps = map[model.MatchOp]snapshotv1.ValueMatch_Op{
	model.OpPresent:  snapshotv1.ValueMatch_OP_PRESENT,
	model.OpAbsent:   snapshotv1.ValueMatch_OP_ABSENT,
	model.OpEquals:   snapshotv1.ValueMatch_OP_EQUALS,
	model.OpPrefix:   snapshotv1.ValueMatch_OP_PREFIX,
	model.OpSuffix:   snapshotv1.ValueMatch_OP_SUFFIX,
	model.OpContains: snapshotv1.ValueMatch_OP_CONTAINS,
	model.OpRegex:    snapshotv1.ValueMatch_OP_REGEX,
}

func valueMatches(ms []model.ValueMatch) []*snapshotv1.ValueMatch {
	var out []*snapshotv1.ValueMatch
	for _, m := range ms {
		out = append(out, &snapshotv1.ValueMatch{Name: m.Name, Op: matchOps[m.Op], Value: m.Value})
	}
	return out
}
