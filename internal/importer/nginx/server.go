package nginx

import (
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/null-variable/proxelo/internal/model"
)

// listen is one parsed listen directive.
type listen struct {
	addr       string
	ssl, http2 bool
	// quic is nginx's UDP listen for HTTP/3; here it is the same
	// listener's http3 flag.
	quic          bool
	defaultServer bool
	reusePort     bool
	backlog       uint32
	udp           bool
}

func parseListen(a []string) (listen, string) {
	var l listen
	if len(a) == 0 {
		return l, "needs an address"
	}
	addr := a[0]
	if strings.HasPrefix(addr, "unix:") {
		return l, "unix sockets are not supported"
	}
	switch {
	case !strings.Contains(addr, ":") && !strings.Contains(addr, "."):
		// A port alone.
		addr = "0.0.0.0:" + addr
	case strings.HasPrefix(addr, "[") && !strings.Contains(addr, "]:"):
		addr += ":80"
	case strings.Contains(addr, "."), strings.HasPrefix(addr, "*:"):
		addr = strings.Replace(hostPort(addr, "80"), "*:", "0.0.0.0:", 1)
	}
	if strings.HasPrefix(addr, "*:") {
		addr = "0.0.0.0" + addr[1:]
	}
	l.addr = addr
	var notes []string
	for _, x := range a[1:] {
		k, v, _ := strings.Cut(x, "=")
		switch k {
		case "ssl":
			l.ssl = true
		case "http2":
			l.http2 = true
		case "default_server", "default":
			l.defaultServer = true
		case "reuseport":
			l.reusePort = true
		case "backlog":
			l.backlog = atou(v)
		case "udp":
			l.udp = true
		case "quic":
			l.quic, l.ssl = true, true
		case "proxy_protocol":
			notes = append(notes, k+" is not supported")
		default:
			notes = append(notes, k+" ignored")
		}
	}
	return l, strings.Join(notes, "; ")
}

// listener returns the listener for an address, creating it. nginx sets
// socket options on one listen per address; the first one seen wins here.
func (c *converter) listener(l listen) *model.Listener {
	if x, ok := c.listeners[l.addr]; ok {
		if l.ssl && x.Spec.TLS == nil {
			x.Spec.TLS = &model.ListenerTLS{}
		}
		x.Spec.HTTP2 = x.Spec.HTTP2 || l.http2 && x.Spec.TLS != nil
		x.Spec.HTTP3 = x.Spec.HTTP3 || l.quic
		return x
	}
	x := &model.Listener{Meta: meta(model.ListenerKind, c.name("listeners", l.addr))}
	x.Spec.Address = l.addr
	x.Spec.ReusePort = l.reusePort
	x.Spec.Backlog = l.backlog
	if l.ssl {
		x.Spec.TLS = &model.ListenerTLS{}
		x.Spec.HTTP2 = l.http2
		x.Spec.HTTP3 = l.quic
	}
	c.listeners[l.addr] = x
	c.cfg.Listeners = append(c.cfg.Listeners, x)
	return x
}

// certificate makes a certificate from files in the upload.
func (c *converter) certificate(cert, key string) (string, string) {
	k := [2]string{cert, key}
	if id, ok := c.certs[k]; ok {
		return id, ""
	}
	chain, ok1 := c.lookupFile(cert)
	pk, ok2 := c.lookupFile(key)
	if !ok1 || !ok2 {
		return "", "certificate files are not in the upload; upload them to the certificate"
	}
	base := cert[strings.LastIndex(cert, "/")+1:]
	ct := &model.Certificate{Meta: meta(model.CertificateKind, c.name("certificates", strings.TrimSuffix(base, ".pem")))}
	ct.Spec = model.CertificateSpec{Source: model.CertUpload, ChainPEM: chain, KeyPEM: pk}
	c.certs[k] = ct.ID
	c.cfg.Certificates = append(c.cfg.Certificates, ct)
	return ct.ID, ""
}

// srv is the state of one server block being converted.
type srv struct {
	site *model.Site
	// Named locations by name ("@x") to route ID.
	named map[string]string
	// Routes whose error pages or try_files name a location to resolve.
	pending []func()
	// TLS settings for its listeners.
	tls       model.ListenerTLS
	tlsSet    bool
	cert, key string
}

func (c *converter) server(d *Directive, sc scope) {
	site := &model.Site{}
	s := &srv{site: site, named: map[string]string{}}
	var locations []*Directive
	var listens []listen
	names := []string{}
	for _, e := range d.Block {
		a := e.Args
		switch e.Name {
		case "listen":
			l, note := parseListen(a)
			if l.addr == "" {
				c.note(e, Unsupported, note)
				continue
			}
			listens = append(listens, l)
			c.noteOr(e, note)
		case "server_name":
			for _, n := range a {
				if n != "" && n != "_" {
					names = append(names, n)
				}
			}
			c.note(e, Converted, "")
		case "location":
			locations = append(locations, e)
		case "ssl_certificate":
			s.cert = firstArg(a)
		case "ssl_certificate_key":
			s.key = firstArg(a)
		case "ssl_protocols", "ssl_ciphers", "ssl_prefer_server_ciphers", "ssl_ecdh_curve", "ssl_session_tickets",
			"ssl_session_cache", "ssl_dhparam", "ssl_verify_client", "ssl_client_certificate", "ssl_verify_depth",
			"ssl_session_timeout", "ssl_stapling", "ssl_stapling_verify", "ssl_trusted_certificate", "ssl_conf_command":
			c.tlsDirective(e, &s.tls)
			s.tlsSet = true
		case "ssl":
			c.note(e, ConvertedWithNote, "use listen ... ssl")
			for i := range listens {
				listens[i].ssl = true
			}
		case "http2":
			if firstArg(a) == "on" {
				for i := range listens {
					listens[i].http2 = true
				}
			}
			c.note(e, Converted, "")
		case "http3":
			// On by default for quic listens; off drops HTTP/3.
			if firstArg(a) == "off" {
				for i := range listens {
					listens[i].quic = false
				}
			}
			c.note(e, Converted, "")
		case "return":
			r, ok := returnAction(a)
			if !ok {
				c.note(e, Unsupported, "")
				continue
			}
			if r.Status == 301 && strings.HasPrefix(r.Text, "https://$host$request_uri") || strings.HasPrefix(r.Text, "https://$server_name$request_uri") {
				site.Spec.RedirectHTTPToHTTPS = true
				c.note(e, Replaced, "redirectHttpToHttps")
				continue
			}
			site.Spec.Return = r
			c.note(e, Converted, "")
		case "rewrite":
			rw, ok := rewrite(a)
			if !ok {
				c.note(e, Unsupported, "")
				continue
			}
			site.Spec.Rewrite = append(site.Spec.Rewrite, rw)
			c.note(e, Converted, "")
		case "if":
			c.note(e, Replaced, "turn if blocks into route match conditions (headers, query, expr)")
			c.skipAll(e.Block, Replaced, "inside if")
		default:
			if !c.common(e, &sc) {
				c.note(e, Unsupported, "")
			}
		}
	}
	if len(listens) == 0 {
		// nginx: listen *:80 (or 8000 when not root).
		listens = []listen{{addr: "0.0.0.0:80"}}
	}
	label := "default"
	if len(names) > 0 {
		label = names[0]
	}
	site.Meta = meta(model.SiteKind, c.name("sites", label))
	if s.cert != "" {
		id, note := c.certificate(s.cert, s.key)
		if id != "" {
			site.Spec.Certificates = []string{id}
		} else {
			c.note(d, ConvertedWithNote, note)
		}
	}
	for _, l := range listens {
		lst := c.listener(l)
		if lst.Spec.TLS != nil && s.tlsSet {
			mergeTLS(lst.Spec.TLS, s.tls)
		}
		if l.defaultServer || lst.Spec.DefaultSite == "" {
			lst.Spec.DefaultSite = site.ID
		}
		if lst.Spec.TLS != nil && lst.Spec.TLS.DefaultCertificate == "" && len(site.Spec.Certificates) > 0 {
			lst.Spec.TLS.DefaultCertificate = site.Spec.Certificates[0]
		}
		site.Spec.Listeners = appendUnique(site.Spec.Listeners, lst.ID)
	}
	for _, n := range names {
		site.Spec.Hostnames = append(site.Spec.Hostnames, hostMatch(n))
	}
	site.Spec.ErrorPages = sc.errorPages
	if p := c.realIPPolicy(sc.realIP); p != "" {
		site.Spec.Policies = append(site.Spec.Policies, p)
	}
	// The site carries the server level's policies; routes add theirs.
	site.Spec.Policies = append(site.Spec.Policies, c.scopePolicies(sc, scope{})...)
	for _, l := range locations {
		if id := c.location(s, l, sc); id != "" {
			site.Spec.Routes = append(site.Spec.Routes, id)
		}
	}
	// A request no location matches is served from the server's root, so
	// without a location / one is added.
	if site.Spec.Return == nil && !slices.ContainsFunc(locations, func(l *Directive) bool {
		return len(l.Args) == 1 && l.Args[0] == "/" || len(l.Args) == 2 && l.Args[0] == "^~" && l.Args[1] == "/"
	}) {
		r := c.newRoute(fmt.Sprintf("%s-root", site.Name), model.PathMatch{Type: model.PathPrefix, Value: "/"})
		r.Spec.Action = c.staticAction(sc)
		site.Spec.Routes = append(site.Spec.Routes, r.ID)
	}
	for _, f := range s.pending {
		f()
	}
	for i := range site.Spec.ErrorPages {
		s.resolveNamed(&site.Spec.ErrorPages[i].Route)
	}
	c.cfg.Sites = append(c.cfg.Sites, site)
	c.note(d, Converted, "")
}

func (s *srv) resolveNamed(ref *string) {
	if strings.HasPrefix(*ref, "@") {
		*ref = s.named[*ref]
	}
}

func appendUnique(xs []string, x string) []string {
	for _, y := range xs {
		if y == x {
			return xs
		}
	}
	return append(xs, x)
}

func hostMatch(n string) model.HostMatch {
	n = strings.ToLower(n)
	switch {
	case strings.HasPrefix(n, "~"):
		return model.HostMatch{Type: model.HostRegex, Value: n[1:]}
	case strings.HasPrefix(n, "*.") || strings.HasSuffix(n, ".*") || strings.HasPrefix(n, "."):
		return model.HostMatch{Type: model.HostWildcard, Value: n}
	}
	return model.HostMatch{Type: model.HostExact, Value: n}
}

func (c *converter) tlsDirective(e *Directive, t *model.ListenerTLS) {
	a := e.Args
	switch e.Name {
	case "ssl_protocols":
		lo, hi := "", ""
		for _, p := range a {
			v := map[string]string{"TLSv1": "1.0", "TLSv1.1": "1.1", "TLSv1.2": "1.2", "TLSv1.3": "1.3"}[p]
			if v == "" {
				continue
			}
			if lo == "" || v < lo {
				lo = v
			}
			if v > hi {
				hi = v
			}
		}
		t.MinVersion, t.MaxVersion = lo, hi
		c.note(e, Converted, "")
	case "ssl_ciphers":
		t.Ciphers = firstArg(a)
		c.note(e, Converted, "")
	case "ssl_prefer_server_ciphers":
		t.PreferServerCiphers = firstArg(a) == "on"
		c.note(e, Converted, "")
	case "ssl_ecdh_curve":
		if v := firstArg(a); v != "auto" {
			t.Groups = v
		}
		c.note(e, Converted, "")
	case "ssl_session_tickets":
		t.NoSessionTickets = firstArg(a) == "off"
		c.note(e, Converted, "")
	case "ssl_session_cache":
		for _, x := range a {
			if v, ok := strings.CutPrefix(x, "builtin:"); ok {
				t.SessionCacheSize = atou(v)
			} else if strings.HasPrefix(x, "shared:") {
				// About 4000 sessions per megabyte, nginx's estimate.
				_, size, _ := strings.Cut(x[7:], ":")
				if b, err := model.ParseSize(size); err == nil {
					t.SessionCacheSize = uint32(b / 256)
				}
			}
		}
		c.note(e, ConvertedWithNote, "sessions are cached per worker")
	case "ssl_dhparam":
		if pem, ok := c.lookupFile(firstArg(a)); ok {
			t.DHParams = pem
			c.note(e, Converted, "")
		} else {
			c.note(e, ConvertedWithNote, "the DH file is not in the upload")
		}
	case "ssl_verify_client":
		mode := map[string]model.ClientAuthMode{"on": model.ClientAuthRequire, "optional": model.ClientAuthOptional, "optional_no_ca": model.ClientAuthOptionalNoCA}[firstArg(a)]
		if mode == "" {
			t.ClientAuth = nil
		} else {
			if t.ClientAuth == nil {
				t.ClientAuth = &model.ClientAuth{}
			}
			t.ClientAuth.Mode = mode
		}
		c.note(e, Converted, "")
	case "ssl_client_certificate", "ssl_trusted_certificate":
		pem, ok := c.lookupFile(firstArg(a))
		if !ok {
			c.note(e, ConvertedWithNote, "the CA file is not in the upload")
			return
		}
		if t.ClientAuth == nil {
			t.ClientAuth = &model.ClientAuth{Mode: model.ClientAuthRequire}
		}
		t.ClientAuth.CA = pem
		c.note(e, Converted, "")
	case "ssl_verify_depth":
		if t.ClientAuth == nil {
			t.ClientAuth = &model.ClientAuth{}
		}
		t.ClientAuth.Depth = atou(firstArg(a))
		c.note(e, Converted, "")
	case "ssl_conf_command":
		if len(a) == 2 && a[0] == "Ciphersuites" {
			t.Ciphersuites = a[1]
			c.note(e, Converted, "")
		} else {
			c.note(e, Unsupported, "only Ciphersuites is supported")
		}
	default:
		c.note(e, Unsupported, "")
	}
}

// mergeTLS copies settings a server sets onto its listener: nginx takes
// them from the default server of the address, which the first server here
// approximates.
func mergeTLS(dst *model.ListenerTLS, src model.ListenerTLS) {
	if dst.MinVersion == "" && dst.MaxVersion == "" {
		dst.MinVersion, dst.MaxVersion = src.MinVersion, src.MaxVersion
	}
	set := func(d *string, s string) {
		if *d == "" {
			*d = s
		}
	}
	set(&dst.Ciphers, src.Ciphers)
	set(&dst.Ciphersuites, src.Ciphersuites)
	set(&dst.Groups, src.Groups)
	set(&dst.DHParams, src.DHParams)
	dst.PreferServerCiphers = dst.PreferServerCiphers || src.PreferServerCiphers
	dst.NoSessionTickets = dst.NoSessionTickets || src.NoSessionTickets
	if dst.SessionCacheSize == 0 {
		dst.SessionCacheSize = src.SessionCacheSize
	}
	if dst.ClientAuth == nil && src.ClientAuth != nil {
		ca := *src.ClientAuth
		if ca.Mode == "" {
			ca.Mode = model.ClientAuthRequire
		}
		dst.ClientAuth = &ca
	}
}

func returnAction(a []string) (*model.ReturnAction, bool) {
	switch len(a) {
	case 1:
		if n, err := strconv.Atoi(a[0]); err == nil {
			return &model.ReturnAction{Status: uint32(n)}, true
		}
		// return URL: 302.
		return &model.ReturnAction{Status: 302, Text: a[0]}, true
	case 2:
		n, err := strconv.Atoi(a[0])
		if err != nil {
			return nil, false
		}
		return &model.ReturnAction{Status: uint32(n), Text: a[1]}, true
	}
	return nil, false
}

func rewrite(a []string) (model.Rewrite, bool) {
	if len(a) < 2 || len(a) > 3 {
		return model.Rewrite{}, false
	}
	rw := model.Rewrite{Regex: a[0], Replacement: a[1]}
	if len(a) == 3 {
		switch a[2] {
		case "last", "break", "redirect", "permanent":
			rw.Flag = model.RewriteFlag(a[2])
		default:
			return rw, false
		}
	}
	return rw, true
}

func (c *converter) newRoute(name string, m model.PathMatch) *model.Route {
	r := &model.Route{Meta: meta(model.RouteKind, c.name("routes", name))}
	r.Spec.Match.Path = m
	c.cfg.Routes = append(c.cfg.Routes, r)
	return r
}

func (c *converter) staticAction(sc scope) model.Action {
	root := sc.root
	if root == "" {
		root = "/usr/share/nginx/html"
	}
	return model.Action{Type: model.ActionStatic, Static: &model.StaticAction{Root: root, Index: sc.index}}
}

// pathMatch reads location's modifier and pattern.
func pathMatch(a []string) (model.PathMatch, string, bool) {
	switch len(a) {
	case 1:
		if strings.HasPrefix(a[0], "@") {
			return model.PathMatch{}, a[0], true
		}
		return model.PathMatch{Type: model.PathPrefix, Value: a[0]}, "", true
	case 2:
		switch a[0] {
		case "=":
			return model.PathMatch{Type: model.PathExact, Value: a[1]}, "", true
		case "^~":
			return model.PathMatch{Type: model.PathPrefixPriority, Value: a[1]}, "", true
		case "~":
			return model.PathMatch{Type: model.PathRegex, Value: a[1]}, "", true
		case "~*":
			return model.PathMatch{Type: model.PathRegexCI, Value: a[1]}, "", true
		}
	}
	return model.PathMatch{}, "", false
}

// location converts a location and its nested ones, returning the route ID,
// or "" for a named location.
func (c *converter) location(s *srv, d *Directive, parentScope scope) string {
	m, named, ok := pathMatch(d.Args)
	if !ok {
		c.note(d, Unsupported, "unknown location modifier")
		return ""
	}
	sc := parentScope.clone()
	label := m.Value
	if named != "" {
		label = named[1:]
	}
	r := c.newRoute(s.site.Name+"-"+label, m)
	if named != "" {
		r.Spec.Match.Path = model.PathMatch{Type: model.PathPrefix, Value: "/"}
		s.named[named] = r.ID
	}
	var children []*Directive
	var action *model.Action
	var tryFiles []string
	var proxyPass, fastcgiPass, uwsgiPass, scgiPass, grpcPass, memcachedPass *Directive
	var memcachedKey string
	for _, e := range d.Block {
		a := e.Args
		switch e.Name {
		case "location":
			children = append(children, e)
		case "proxy_pass":
			proxyPass = e
		case "fastcgi_pass":
			fastcgiPass = e
		case "uwsgi_pass":
			uwsgiPass = e
		case "scgi_pass":
			scgiPass = e
		case "grpc_pass":
			grpcPass = e
		case "memcached_pass":
			memcachedPass = e
		case "try_files":
			tryFiles = a
			c.note(e, Converted, "")
		case "return":
			rv, ok := returnAction(a)
			if !ok {
				c.note(e, Unsupported, "")
				continue
			}
			action = &model.Action{Type: model.ActionReturn, Return: rv}
			c.note(e, Converted, "")
		case "rewrite":
			rw, ok := rewrite(a)
			if !ok {
				c.note(e, Unsupported, "")
				continue
			}
			r.Spec.Rewrite = append(r.Spec.Rewrite, rw)
			c.note(e, Converted, "")
		case "internal":
			c.note(e, ConvertedWithNote, "reachable from the outside too; use a named route for internal-only targets")
		case "set":
			if len(a) == 2 {
				c.note(e, Replaced, "use a map lookup for $"+strings.TrimPrefix(a[0], "$"))
			} else {
				c.note(e, Unsupported, "")
			}
		case "if":
			c.note(e, Replaced, "turn if blocks into route match conditions (headers, query, expr)")
			c.skipAll(e.Block, Replaced, "inside if")
		case "limit_except":
			c.note(e, Replaced, "use match.methods on a route and an ipAccess policy")
			c.skipAll(e.Block, Replaced, "inside limit_except")
		case "memcached_key":
			memcachedKey = firstArg(a)
			c.note(e, Converted, "")
		case "proxy_redirect", "proxy_cookie_domain", "proxy_cookie_path", "proxy_intercept_errors", "proxy_pass_request_headers",
			"proxy_pass_request_body", "proxy_ssl_server_name", "proxy_ssl_name", "proxy_ssl_verify", "proxy_ssl_trusted_certificate",
			"proxy_ssl_protocols", "proxy_ssl_ciphers", "proxy_ssl_certificate", "proxy_ssl_certificate_key", "proxy_ssl_verify_depth":
			c.note(e, ConvertedWithNote, "set it on the upstream (tls) or the route's policies")
		case "expires":
			c.note(e, Replaced, "set Cache-Control with a headers policy")
		default:
			if !c.common(e, &sc) {
				c.note(e, Unsupported, "")
			}
		}
	}
	switch {
	case proxyPass != nil:
		action = c.proxyPass(proxyPass, sc, r)
	case fastcgiPass != nil:
		action = c.gatewayPass(fastcgiPass, model.GatewayFastCGI, sc)
	case uwsgiPass != nil:
		action = c.gatewayPass(uwsgiPass, model.GatewayUwsgi, sc)
	case scgiPass != nil:
		action = c.gatewayPass(scgiPass, model.GatewaySCGI, sc)
	case grpcPass != nil:
		if up, ok := c.passUpstream(grpcPass, "grpc://", "grpcs://"); ok {
			p := c.proxyBase(up, sc)
			action = &model.Action{Type: model.ActionGrpc, Grpc: &p}
		}
	case memcachedPass != nil:
		if up, ok := c.passUpstream(memcachedPass, ""); ok {
			action = &model.Action{Type: model.ActionMemcached, Memcached: &model.MemcachedAction{ProxyAction: c.proxyBase(up, sc), Key: memcachedKey}}
		}
	}
	if action == nil {
		a := c.staticAction(sc)
		if sc.alias != "" {
			// alias maps the location prefix to a directory: a rewrite of
			// the prefix with root at the alias directory's parent is not
			// equivalent in general, so serve from the alias with the
			// prefix stripped.
			a.Static.Root = strings.TrimSuffix(sc.alias, "/")
			if m.Type == model.PathPrefix || m.Type == model.PathPrefixPriority {
				r.Spec.Rewrite = append(r.Spec.Rewrite, model.Rewrite{Regex: "^" + regexpQuote(m.Value) + "(.*)$", Replacement: "/$1", Flag: model.RewriteBreak})
				c.note(d, ConvertedWithNote, "alias became root with a rewrite of the prefix")
			}
		}
		if tryFiles != nil {
			tf := &model.TryFiles{}
			last := tryFiles[len(tryFiles)-1]
			tf.Files = tryFiles[:len(tryFiles)-1]
			switch {
			case strings.HasPrefix(last, "="):
				tf.Status = atou(last[1:])
			case strings.HasPrefix(last, "@"):
				tf.Route = last
				s.pending = append(s.pending, func() { s.resolveNamed(&tf.Route) })
			default:
				tf.URI = last
			}
			a.Static.TryFiles = tf
		}
		action = &a
	}
	r.Spec.Action = *action
	if len(sc.errorPages) > 0 && sc.set["error_page"] {
		r.Spec.ErrorPages = sc.errorPages
		for i := range r.Spec.ErrorPages {
			ep := &r.Spec.ErrorPages[i]
			s.pending = append(s.pending, func() { s.resolveNamed(&ep.Route) })
		}
	}
	// Policies: what this location sets over its parent.
	r.Spec.Policies = c.scopePolicies(sc, parentScope)
	if f := sc.authRequest; f != "" && f != parentScope.authRequest {
		s.pending = append(s.pending, func() { c.forwardAuth(s, r, f) })
	}
	for _, ch := range children {
		if m.Type != model.PathPrefix && m.Type != model.PathPrefixPriority {
			c.note(ch, Unsupported, "nested locations only under prefix locations")
			continue
		}
		if id := c.location(s, ch, sc); id != "" {
			r.Spec.Children = append(r.Spec.Children, id)
		}
	}
	c.note(d, Converted, "")
	if named != "" {
		// Reached only from error_page and try_files.
		return ""
	}
	return r.ID
}

func regexpQuote(s string) string {
	var b strings.Builder
	for _, r := range s {
		if strings.ContainsRune(`\.+*?()|[]{}^$`, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// passUpstream finds the upstream of a *_pass target, making a one-target
// upstream for a literal address.
func (c *converter) passUpstream(d *Directive, schemes ...string) (string, bool) {
	target := firstArg(d.Args)
	tls := false
	for _, sch := range schemes {
		if sch != "" && strings.HasPrefix(target, sch) {
			tls = strings.HasSuffix(sch, "s://")
			target = strings.TrimPrefix(target, sch)
		}
	}
	if strings.Contains(target, "$") {
		c.note(d, Unsupported, "a target with variables needs a fixed upstream")
		return "", false
	}
	if strings.HasPrefix(target, "unix:") {
		c.note(d, Unsupported, "unix sockets are not supported")
		return "", false
	}
	host := target
	if i := strings.Index(host, "/"); i >= 0 {
		host = host[:i]
	}
	if id, ok := c.upstreams[host]; ok {
		if tls {
			c.upstreamTLS(id)
		}
		c.note(d, Converted, "")
		return id, true
	}
	port := "80"
	if tls {
		port = "443"
	}
	addr := hostPort(host, port)
	u := &model.Upstream{Meta: meta(model.UpstreamKind, c.name("upstreams", host))}
	u.Spec.Targets = []model.Target{{Address: addr}}
	if tls {
		u.Spec.TLS = &model.UpstreamTLS{ServerName: strings.Split(host, ":")[0]}
	}
	c.upstreams[host] = u.ID
	c.cfg.Upstreams = append(c.cfg.Upstreams, u)
	c.note(d, Converted, "")
	return u.ID, true
}

func (c *converter) upstreamTLS(id string) {
	for _, u := range c.cfg.Upstreams {
		if u.ID == id && u.Spec.TLS == nil {
			u.Spec.TLS = &model.UpstreamTLS{}
		}
	}
}

func (c *converter) proxyBase(up string, sc scope) model.ProxyAction {
	p := model.ProxyAction{Upstream: up, Timeouts: sc.timeouts}
	if len(sc.nextUpstream) > 0 {
		on := []string{}
		for _, x := range sc.nextUpstream {
			if x != "off" && x != "invalid_header" {
				on = append(on, x)
			}
		}
		p.Retry = &model.Retry{On: on, Tries: sc.nextTries}
	}
	return p
}

// proxyPass converts proxy_pass. A URI part replaces the location prefix,
// which becomes a rewrite.
func (c *converter) proxyPass(d *Directive, sc scope, r *model.Route) *model.Action {
	target := firstArg(d.Args)
	up, ok := c.passUpstream(d, "http://", "https://")
	if !ok {
		return nil
	}
	rest := strings.TrimPrefix(strings.TrimPrefix(target, "https://"), "http://")
	if i := strings.Index(rest, "/"); i >= 0 {
		uri := rest[i:]
		m := r.Spec.Match.Path
		if m.Type == model.PathPrefix || m.Type == model.PathPrefixPriority || m.Type == model.PathExact {
			if u, err := url.PathUnescape(uri); err == nil {
				uri = u
			}
			r.Spec.Rewrite = append(r.Spec.Rewrite, model.Rewrite{Regex: "^" + regexpQuote(m.Value) + "(.*)$", Replacement: uri + "$1", Flag: model.RewriteBreak})
			c.note(d, ConvertedWithNote, "the URI part became a rewrite of the location prefix")
		} else {
			c.note(d, Unsupported, "a URI part in a regex location is not allowed")
		}
	}
	p := c.proxyBase(up, sc)
	return &model.Action{Type: model.ActionProxy, Proxy: &p}
}

func (c *converter) gatewayPass(d *Directive, proto model.GatewayProtocol, sc scope) *model.Action {
	up, ok := c.passUpstream(d, "")
	if !ok {
		return nil
	}
	g := &model.GatewayAction{Protocol: proto, ProxyAction: c.proxyBase(up, sc), DocumentRoot: sc.root}
	if proto == model.GatewayFastCGI {
		g.Index, g.SplitPathInfo = sc.gatewayIndex, sc.splitPath
	}
	// The standard params are included by default; listed params that
	// repeat a standard value are dropped so overrides stand out.
	std := map[string]string{}
	for _, p := range defaultParams(proto) {
		std[p.Name] = p.Value
	}
	for _, p := range sc.fastcgi {
		if v, ok := std[p.Name]; ok && v == p.Value {
			continue
		}
		g.Params = append(g.Params, p)
	}
	return &model.Action{Type: model.ActionGateway, Gateway: g}
}

// forwardAuth makes the forwardAuth policy of auth_request uri: the
// location serving uri must proxy to an upstream.
func (c *converter) forwardAuth(s *srv, r *model.Route, uri string) {
	var check *model.Route
	for _, x := range c.cfg.Routes {
		if p := x.Spec.Match.Path; (p.Type == model.PathExact || p.Type == model.PathPrefix) && p.Value == uri && x.Spec.Action.Proxy != nil {
			check = x
		}
	}
	if check == nil {
		return
	}
	// The subrequest goes upstream with the URI the check location's
	// proxy_pass gives it.
	target := uri
	for _, rw := range check.Spec.Rewrite {
		if re, err := regexp.Compile(rw.Regex); err == nil && re.MatchString(target) {
			target = re.ReplaceAllString(target, strings.ReplaceAll(rw.Replacement, "$1", "${1}"))
		}
	}
	key := "fa:" + check.ID
	id, ok := c.policies[key]
	if !ok {
		p := &model.Policy{Meta: meta(model.PolicyKind, c.name("policies", "auth-"+strings.Trim(uri, "/")))}
		p.Spec = model.PolicySpec{Type: model.PolicyForwardAuth, ForwardAuth: &model.ForwardAuthPolicy{Upstream: check.Spec.Action.Proxy.Upstream, URI: target}}
		c.cfg.Policies = append(c.cfg.Policies, p)
		id = p.ID
		c.policies[key] = id
	}
	r.Spec.Policies = append(r.Spec.Policies, id)
}
