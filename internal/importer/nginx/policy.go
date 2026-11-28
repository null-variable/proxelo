package nginx

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/null-variable/proxelo/internal/compile"
	"github.com/null-variable/proxelo/internal/model"
)

func defaultParams(p model.GatewayProtocol) []model.GatewayParam { return compile.DefaultParams(p) }

// policy returns the ID of a policy with spec, sharing one per identical
// spec.
func (c *converter) policy(name string, spec model.PolicySpec) string {
	key := fmt.Sprintf("%#v", spec)
	if spec.Filters != nil {
		b, _ := json.Marshal(spec)
		key = string(b)
	}
	if spec.Headers != nil || spec.BasicAuth != nil || spec.Compression != nil || spec.IPAccess != nil || spec.AccessLog != nil || spec.RealIP != nil || spec.JWT != nil || spec.OIDC != nil {
		key = fmt.Sprintf("%s:%+v%+v%+v%+v%+v%+v%+v%+v", spec.Type, spec.Headers, spec.BasicAuth, spec.Compression, spec.IPAccess, spec.AccessLog, spec.RealIP, spec.JWT, spec.OIDC)
	}
	if id, ok := c.policies[key]; ok {
		return id
	}
	p := &model.Policy{Meta: meta(model.PolicyKind, c.name("policies", name)), Spec: spec}
	c.cfg.Policies = append(c.cfg.Policies, p)
	c.policies[key] = p.ID
	return p.ID
}

func (c *converter) realIPPolicy(r *model.RealIPPolicy) string {
	if r == nil || len(r.From) == 0 {
		return ""
	}
	return c.policy("real-ip", model.PolicySpec{Type: model.PolicyRealIP, RealIP: r})
}

// scopePolicies returns the policies a level adds over its parent. A route
// inherits its parent's policies, so only what changed is attached; a
// family the level resets in nginx terms (an array directive set here)
// replaces the parent's: Proxelo merges headers by name, which matches
// nginx when the level repeats what it keeps.
func (c *converter) scopePolicies(s, parent scope) []string {
	var out []string
	if s.set["add_header"] || s.set["proxy_set_header"] || s.set["proxy_hide_header"] {
		h := &model.HeadersPolicy{}
		if s.set["add_header"] {
			always := false
			for _, x := range s.addHeader {
				if h.Response.Set == nil {
					h.Response.Set = map[string]string{}
				}
				if _, dup := h.Response.Set[x.name]; dup {
					h.Response.Add = append(h.Response.Add, model.HeaderValue{Name: x.name, Value: x.value})
				} else {
					h.Response.Set[x.name] = x.value
				}
				always = always || x.always
			}
			h.Response.Always = always
		}
		if s.set["proxy_set_header"] {
			for _, x := range s.setHeader {
				if h.Request.Set == nil {
					h.Request.Set = map[string]string{}
				}
				h.Request.Set[x.name] = x.value
			}
		}
		if s.set["proxy_hide_header"] {
			h.Response.Remove = slices.Clone(s.hideHeader)
		}
		out = append(out, c.policy("headers", model.PolicySpec{Type: model.PolicyHeaders, Headers: h}))
	}
	if s.set["access"] && len(s.rules) > 0 {
		out = append(out, c.policy("ip-access", model.PolicySpec{Type: model.PolicyIPAccess, IPAccess: &model.IPAccessPolicy{Rules: s.rules}}))
	}
	if s.set["limit_req"] {
		for _, l := range s.limitReq {
			z := *c.reqZones[l.zone]
			z.Burst, z.Delay, z.NoDelay = l.burst, l.delay, l.nodelay
			z.Status, z.DryRun = s.reqStatus, s.reqDry
			out = append(out, c.policy("rate-"+l.zone, model.PolicySpec{Type: model.PolicyRateLimit, RateLimit: &z}))
		}
	}
	if s.set["limit_conn"] {
		for _, l := range s.limitConn {
			z := *c.connZones[l.zone]
			z.Max = l.max
			z.Status, z.DryRun = s.connStatus, s.connDry
			out = append(out, c.policy("conn-"+l.zone, model.PolicySpec{Type: model.PolicyConnLimit, ConnLimit: &z}))
		}
	}
	if id, ok := c.cachePolicy(s, parent); ok {
		out = append(out, id)
	}
	if s.basicRealm != "" && len(s.basicUsers) > 0 && (s.basicRealm != parent.basicRealm || !slices.Equal(s.basicUsers, parent.basicUsers)) {
		out = append(out, c.policy("basic-auth", model.PolicySpec{Type: model.PolicyBasicAuth, BasicAuth: &model.BasicAuthPolicy{Realm: s.basicRealm, Users: s.basicUsers}}))
	}
	if s.jwtRealm != "" && (s.jwt.JWKS != "" || s.jwt.JWKSURL != "") && (s.jwtRealm != parent.jwtRealm || fmt.Sprintf("%+v", s.jwt) != fmt.Sprintf("%+v", parent.jwt)) {
		j := s.jwt
		j.Realm = s.jwtRealm
		out = append(out, c.policy("jwt", model.PolicySpec{Type: model.PolicyJWT, JWT: &j}))
	}
	if s.oidc != "" && s.oidc != parent.oidc {
		o := *c.oidcProviders[s.oidc]
		out = append(out, c.policy("oidc-"+s.oidc, model.PolicySpec{Type: model.PolicyOIDC, OIDC: &o}))
	}
	if s.accessLog != nil && (parent.accessLog == nil || *s.accessLog != *parent.accessLog) {
		l := *s.accessLog
		out = append(out, c.policy("log-"+strings.Trim(l.Path, "/"), model.PolicySpec{Type: model.PolicyAccessLog, AccessLog: &l}))
	} else if s.logOff && !parent.logOff {
		off := false
		out = append(out, c.policy("log-off", model.PolicySpec{Type: model.PolicyAccessLog, AccessLog: &model.AccessLogPolicy{Path: "stdout", Enabled: &off}}))
	}
	if s.gzip != nil && (parent.gzip == nil || fmt.Sprintf("%+v", *s.gzip) != fmt.Sprintf("%+v", *parent.gzip)) {
		g := *s.gzip
		out = append(out, c.policy("compression", model.PolicySpec{Type: model.PolicyCompression, Compression: &g}))
	}
	if f, ok := filtersPolicy(s, parent); ok {
		out = append(out, c.policy("filters", model.PolicySpec{Type: model.PolicyFilters, Filters: f}))
	}
	if s.rate != "" && (s.rate != parent.rate || s.after != parent.after) && s.rate != "0" {
		out = append(out, c.policy("bandwidth", model.PolicySpec{Type: model.PolicyBandwidth, Bandwidth: &model.BandwidthPolicy{Rate: s.rate, After: s.after}}))
	}
	return out
}

// filtersPolicy is the filters a level changes over its parent: an ssi or
// addition filter set (or turned off) here.
func filtersPolicy(s, parent scope) (*model.FiltersPolicy, bool) {
	f := &model.FiltersPolicy{}
	if !same(s.sub, parent.sub) && (len(s.sub.Pairs) > 0 || len(parent.sub.Pairs) > 0) {
		sub := s.sub
		f.Sub = &sub
	}
	if !same(s.userid, parent.userid) && (s.userid.Mode != "" || parent.userid.Mode != "") {
		u := s.userid
		if u.Mode == "" {
			u.Mode = model.UseridOff
		}
		f.Userid = &u
	}
	if s.ssiOn != parent.ssiOn || s.ssiOn && !same(s.ssi, parent.ssi) {
		ssi := s.ssi
		if !s.ssiOn {
			off := false
			ssi = model.SSIFilter{Enabled: &off}
		}
		f.SSI = &ssi
	}
	if !same(s.addition, parent.addition) {
		a := s.addition
		f.Addition = &a
	}
	return f, f.Sub != nil || f.SSI != nil || f.Addition != nil || f.Userid != nil
}

// same reports whether two settings read the same, pointers by value.
func same(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

// oidcProvider reads an nginx Plus oidc_provider block.
func (c *converter) oidcProvider(d *Directive) {
	if len(d.Args) != 1 {
		c.note(d, Unsupported, "needs a name")
		return
	}
	o := &model.OIDCPolicy{}
	for _, x := range d.Block {
		a := x.Args
		v := ""
		if len(a) > 0 {
			v = a[0]
		}
		switch x.Name {
		case "issuer":
			o.Issuer = v
		case "client_id":
			o.ClientID = v
		case "client_secret":
			o.ClientSecret = v
		case "redirect_uri":
			o.RedirectURI = v
		case "scope":
			o.Scopes = slices.Clone(a)
		case "cookie_name":
			o.Cookie = v
		case "session_timeout":
			o.SessionTimeout = duration(v)
		case "logout_uri":
			o.LogoutURI = v
		case "post_logout_uri":
			o.PostLogoutURI = v
		default:
			c.note(x, Unsupported, "")
			continue
		}
		c.note(x, Converted, "")
	}
	if strings.Contains(o.ClientSecret, "$") {
		c.note(d, ConvertedWithNote, "client_secret from a variable; set it in the oidc policy")
		o.ClientSecret = ""
	} else {
		c.note(d, Converted, "")
	}
	if c.oidcProviders == nil {
		c.oidcProviders = map[string]*model.OIDCPolicy{}
	}
	c.oidcProviders[d.Args[0]] = o
}

// cachePath reads proxy_cache_path into a zone the cache policies of its
// proxy_cache directives start from.
func (c *converter) cachePath(d *Directive) {
	if len(d.Args) < 2 {
		c.note(d, Unsupported, "needs a path and keys_zone=")
		return
	}
	z := &model.CachePolicy{Path: d.Args[0]}
	name := ""
	var notes []string
	for _, x := range d.Args[1:] {
		k, v, _ := strings.Cut(x, "=")
		switch k {
		case "keys_zone":
			// The zone size is memory for keys: about 8000 per megabyte.
			n, size, _ := strings.Cut(v, ":")
			name = n
			if b, err := model.ParseSize(size); err == nil && b > 0 {
				z.MaxEntries = uint32(min(b/1024*8, 1<<31))
			}
		case "levels":
			for l := range strings.SplitSeq(v, ":") {
				z.Levels = append(z.Levels, atou(l))
			}
		case "max_size":
			z.MaxSize = v
		case "inactive":
			z.Inactive = duration(v)
		case "use_temp_path", "manager_files", "manager_sleep", "manager_threshold", "loader_files", "loader_sleep",
			"loader_threshold", "min_free":
			notes = append(notes, k+" is managed by the proxy")
		default:
			notes = append(notes, k+" not supported")
		}
	}
	if name == "" {
		c.note(d, Unsupported, "needs keys_zone=")
		return
	}
	c.cacheZones[name] = z
	c.noteOr(d, strings.Join(notes, "; "))
}

// cacheDirective reads proxy_cache and the proxy_cache_* settings into s.
func (c *converter) cacheDirective(d *Directive, s *scope) {
	a := d.Args
	k := &s.cache
	note := ""
	switch d.Name {
	case "proxy_cache":
		switch {
		case firstArg(a) == "off":
			s.cacheZone = ""
		case c.cacheZones[firstArg(a)] == nil:
			c.note(d, Unsupported, "zone "+firstArg(a)+" not defined, or named by a variable")
			return
		default:
			s.cacheZone = firstArg(a)
		}
	case "proxy_cache_key":
		k.Key = firstArg(a)
	case "proxy_cache_valid":
		v := model.CacheValid{}
		for i, x := range a {
			if i == len(a)-1 {
				v.Time = duration(x)
			} else {
				v.Statuses = append(v.Statuses, x)
			}
		}
		k.Valid = append(k.Valid, v)
	case "proxy_cache_methods":
		k.Methods = nil
		for _, m := range a {
			k.Methods = append(k.Methods, strings.ToUpper(m))
		}
		if !slices.Contains(k.Methods, "HEAD") {
			k.Methods = append(k.Methods, "HEAD")
		}
		if !slices.Contains(k.Methods, "GET") {
			k.Methods = append(k.Methods, "GET")
		}
	case "proxy_cache_min_uses":
		k.MinUses = atou(firstArg(a))
	case "proxy_cache_bypass", "proxy_no_cache":
		expr := varsExpr(a)
		if expr == "" {
			c.note(d, Unsupported, "only $arg_ and $http_ variables become conditions")
			return
		}
		if d.Name == "proxy_cache_bypass" {
			k.Bypass = expr
		} else {
			k.NoStore = expr
		}
		note = "becomes a CEL condition: set when the variables are non-empty"
	case "proxy_cache_lock":
		k.Lock = firstArg(a) == "on"
	case "proxy_cache_lock_timeout":
		k.LockTimeout = duration(firstArg(a))
	case "proxy_cache_use_stale":
		k.UseStale = nil
		for _, x := range a {
			switch {
			case x == "off":
			case x == "invalid_header":
				note = "invalid_header counts as error"
				if !slices.Contains(k.UseStale, "error") {
					k.UseStale = append(k.UseStale, "error")
				}
			case slices.Contains(model.CacheUseStale, x):
				k.UseStale = append(k.UseStale, x)
			default:
				note = x + " not supported"
			}
		}
	case "proxy_cache_background_update":
		k.BackgroundUpdate = firstArg(a) == "on"
	case "proxy_cache_revalidate":
		k.Revalidate = firstArg(a) == "on"
	case "proxy_cache_convert_head":
		k.KeepHead = firstArg(a) == "off"
	case "proxy_ignore_headers":
		k.Ignore = nil
		for _, x := range a {
			if slices.ContainsFunc(model.CacheIgnore, func(v string) bool { return strings.EqualFold(v, x) }) {
				k.Ignore = append(k.Ignore, x)
			} else {
				note = x + " not supported"
			}
		}
	}
	c.noteOr(d, note)
}

// cachePolicy is the cache policy of s when it differs from its parent's.
func (c *converter) cachePolicy(s, parent scope) (string, bool) {
	if s.cacheZone == "" {
		if parent.cacheZone == "" {
			return "", false
		}
		off := false
		return c.policy("cache-off", model.PolicySpec{Type: model.PolicyCache, Cache: &model.CachePolicy{Enabled: &off}}), true
	}
	p := cloneCache(*c.cacheZones[s.cacheZone])
	k := s.cache
	p.Key, p.Valid, p.Methods, p.MinUses, p.Bypass, p.NoStore = k.Key, k.Valid, k.Methods, k.MinUses, k.Bypass, k.NoStore
	p.Lock, p.LockTimeout, p.UseStale, p.BackgroundUpdate = k.Lock, k.LockTimeout, k.UseStale, k.BackgroundUpdate
	p.Revalidate, p.KeepHead, p.Ignore, p.Slice = k.Revalidate, k.KeepHead, k.Ignore, k.Slice
	if p.BackgroundUpdate && !slices.Contains(p.UseStale, "updating") {
		p.BackgroundUpdate = false
	}
	if s.cacheZone == parent.cacheZone && fmt.Sprintf("%+v", s.cache) == fmt.Sprintf("%+v", parent.cache) {
		return "", false
	}
	return c.policy("cache-"+s.cacheZone, model.PolicySpec{Type: model.PolicyCache, Cache: &p}), true
}

// varsExpr turns proxy_cache_bypass variables into a CEL condition that
// holds when any is non-empty and not "0", as nginx tests them.
func varsExpr(vars []string) string {
	var parts []string
	for _, v := range vars {
		name, ok := strings.CutPrefix(v, "$")
		if !ok {
			return ""
		}
		var m, k string
		switch {
		case strings.HasPrefix(name, "arg_"):
			m, k = "request.query", name[4:]
		case strings.HasPrefix(name, "http_"):
			m, k = "request.headers", strings.ReplaceAll(name[5:], "_", "-")
		default:
			return ""
		}
		parts = append(parts, fmt.Sprintf(`(%[2]q in %[1]s && %[1]s[%[2]q] != "" && %[1]s[%[2]q] != "0")`, m, k))
	}
	return strings.Join(parts, " || ")
}
