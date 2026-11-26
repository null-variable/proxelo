package nginx

import (
	"strings"

	"github.com/null-variable/proxelo/internal/model"
)

// stream converts a stream block: upstreams, maps and servers.
func (c *converter) stream(st *Directive) {
	c.note(st, Converted, "")
	var log *model.AccessLogPolicy
	var rules []model.IPRule
	var servers []*Directive
	// map $ssl_preread_server_name $x { name upstream; ... } is how nginx
	// routes by SNI; such maps become stream routes.
	sniMaps := map[string]*Directive{}
	for _, d := range st.Block {
		switch d.Name {
		case "upstream":
			c.upstream(d)
		case "log_format":
			c.logFormat(d)
		case "limit_conn_zone":
			c.limitConnZone(d)
		case "map":
			if len(d.Args) == 2 && d.Args[0] == "$ssl_preread_server_name" {
				sniMaps[d.Args[1]] = d
				continue
			}
			c.lookup(d)
		case "geo", "split_clients":
			c.lookup(d)
		}
	}
	for _, d := range st.Block {
		switch d.Name {
		case "upstream", "log_format", "limit_conn_zone", "map", "geo", "split_clients":
		case "server":
			servers = append(servers, d)
		case "access_log":
			if firstArg(d.Args) != "off" {
				log = c.streamLog(d)
			}
			c.note(d, Converted, "")
		case "allow", "deny":
			rules = append(rules, model.IPRule{Action: d.Name, From: firstArg(d.Args)})
			c.note(d, Converted, "")
		case "proxy_timeout", "proxy_connect_timeout", "preread_timeout", "resolver", "tcp_nodelay", "proxy_buffer_size":
			c.note(d, ConvertedWithNote, "set it on each stream")
		default:
			c.note(d, Unsupported, "")
		}
	}
	for _, d := range servers {
		c.streamServer(d, log, rules, sniMaps)
	}
	for _, m := range sniMaps {
		c.note(m, Replaced, "routes of the streams that use it")
	}
}

func (c *converter) streamLog(d *Directive) *model.AccessLogPolicy {
	l := &model.AccessLogPolicy{Path: firstArg(d.Args)}
	if len(d.Args) > 1 {
		if f, ok := c.formats[d.Args[1]]; ok {
			l.Format, l.EscapeJSON = f.format, f.json
		}
	}
	return l
}

func (c *converter) streamServer(d *Directive, log *model.AccessLogPolicy, rules []model.IPRule, sniMaps map[string]*Directive) {
	var listens []listen
	sp := model.StreamSpec{}
	var tls model.ListenerTLS
	cert, key := "", ""
	var limits []limitConn
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
		case "proxy_pass":
			target := firstArg(a)
			if m, ok := sniMaps[target]; ok {
				c.sniRoutes(m, &sp)
				c.note(e, Converted, "")
				continue
			}
			if strings.Contains(target, "$") {
				c.note(e, Unsupported, "a target with variables needs a fixed upstream")
				continue
			}
			if up, ok := c.passUpstream(e, ""); ok {
				sp.Routes = append(sp.Routes, model.StreamRoute{Upstream: up})
			}
		case "ssl_preread":
			sp.SSLPreread = firstArg(a) == "on"
			c.note(e, Converted, "")
		case "proxy_protocol":
			sp.ProxyProtocol = firstArg(a) == "on"
			c.note(e, Converted, "")
		case "proxy_timeout":
			sp.Timeout = duration(firstArg(a))
			c.note(e, Converted, "")
		case "proxy_connect_timeout":
			sp.ConnectTimeout = duration(firstArg(a))
			c.note(e, Converted, "")
		case "proxy_responses":
			n := atou(firstArg(a))
			sp.Responses = &n
			c.note(e, Converted, "")
		case "proxy_next_upstream":
			sp.NoNextUpstream = firstArg(a) == "off"
			c.note(e, Converted, "")
		case "proxy_next_upstream_tries":
			sp.Tries = atou(firstArg(a))
			c.note(e, Converted, "")
		case "allow", "deny":
			rules = append(rules[:len(rules):len(rules)], model.IPRule{Action: e.Name, From: firstArg(a)})
			c.note(e, Converted, "")
		case "limit_conn":
			if _, ok := c.connZones[firstArg(a)]; !ok {
				c.note(e, Unsupported, "zone is not defined")
				continue
			}
			limits = append(limits, limitConn{firstArg(a), atou(a[len(a)-1])})
			c.note(e, Converted, "")
		case "access_log":
			if firstArg(a) == "off" {
				log = nil
			} else {
				log = c.streamLog(e)
			}
			c.note(e, Converted, "")
		case "ssl_certificate":
			cert = firstArg(a)
			c.note(e, Converted, "")
		case "ssl_certificate_key":
			key = firstArg(a)
			c.note(e, Converted, "")
		case "ssl_protocols", "ssl_ciphers", "ssl_prefer_server_ciphers", "ssl_ecdh_curve", "ssl_session_tickets",
			"ssl_session_cache", "ssl_dhparam", "ssl_verify_client", "ssl_client_certificate", "ssl_verify_depth", "ssl_conf_command":
			c.tlsDirective(e, &tls)
		case "proxy_ssl":
			c.note(e, ConvertedWithNote, "set tls on the upstream")
		case "tcp_nodelay", "proxy_buffer_size", "preread_buffer_size", "preread_timeout", "resolver":
			c.note(e, Replaced, "fixed in the proxy")
		default:
			c.note(e, Unsupported, "")
		}
	}
	label := "stream"
	if len(listens) > 0 {
		label = listens[0].addr
	}
	for _, l := range listens {
		s := &model.Stream{Meta: meta(model.StreamKind, c.name("streams", label)), Spec: sp}
		s.Spec.Address = l.addr
		s.Spec.ReusePort, s.Spec.Backlog = l.reusePort, l.backlog
		if l.udp {
			s.Spec.Protocol = model.StreamUDP
		} else if s.Spec.Responses != nil {
			s.Spec.Responses = nil
		}
		if l.ssl {
			t := tls
			if id, note := c.certificate(cert, key); id != "" {
				t.DefaultCertificate = id
			} else {
				c.note(d, ConvertedWithNote, note)
			}
			s.Spec.TLS = &t
		}
		if len(rules) > 0 {
			s.Spec.Policies = append(s.Spec.Policies, c.policy("ip-access", model.PolicySpec{Type: model.PolicyIPAccess, IPAccess: &model.IPAccessPolicy{Rules: rules}}))
		}
		for _, lc := range limits {
			z := *c.connZones[lc.zone]
			z.Max = lc.max
			s.Spec.Policies = append(s.Spec.Policies, c.policy("conn-"+lc.zone, model.PolicySpec{Type: model.PolicyConnLimit, ConnLimit: &z}))
		}
		if log != nil {
			l := *log
			s.Spec.Policies = append(s.Spec.Policies, c.policy("log-"+strings.Trim(l.Path, "/"), model.PolicySpec{Type: model.PolicyAccessLog, AccessLog: &l}))
		}
		c.cfg.Streams = append(c.cfg.Streams, s)
	}
	c.note(d, Converted, "")
}

// sniRoutes turns map $ssl_preread_server_name $x { name upstream; }
// into stream routes; "default" is the catch-all, last.
func (c *converter) sniRoutes(m *Directive, sp *model.StreamSpec) {
	var def string
	hostnames := false
	for _, e := range m.Block {
		if e.Name == "hostnames" {
			hostnames = true
		}
	}
	for _, e := range m.Block {
		if len(e.Args) != 1 {
			continue
		}
		up, ok := c.upstreams[e.Args[0]]
		if !ok {
			c.note(e, Unsupported, "map value "+e.Args[0]+" is not an upstream")
			continue
		}
		if e.Name == "default" {
			def = up
			continue
		}
		var h model.HostMatch
		switch {
		case strings.HasPrefix(e.Name, "~"):
			h = model.HostMatch{Type: model.HostRegex, Value: strings.TrimPrefix(strings.TrimPrefix(e.Name, "~*"), "~")}
		case hostnames:
			h = hostMatch(e.Name)
		default:
			h = model.HostMatch{Type: model.HostExact, Value: strings.ToLower(e.Name)}
		}
		sp.Routes = append(sp.Routes, model.StreamRoute{ServerNames: []model.HostMatch{h}, Upstream: up})
	}
	if def != "" {
		sp.Routes = append(sp.Routes, model.StreamRoute{Upstream: def})
	}
}
