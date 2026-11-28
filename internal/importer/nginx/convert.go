package nginx

import (
	"fmt"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/null-variable/proxelo/internal/model"
)

// Class is how a directive was carried over.
type Class string

const (
	// Same meaning in Proxelo.
	Converted Class = "converted"
	// Converted; the operator should check something.
	ConvertedWithNote Class = "convertedWithNote"
	// Expressed another way, or replaced by Proxelo's own mechanism.
	Replaced Class = "replaced"
	// Not carried over; the configuration behaves differently without it.
	Unsupported Class = "unsupported"
)

// Entry is one line of the conversion report.
type Entry struct {
	File      string `json:"file"`
	Line      int    `json:"line"`
	Directive string `json:"directive"`
	Class     Class  `json:"class"`
	Note      string `json:"note,omitempty"`
}

// Report lists every directive by class, in file order.
type Report struct {
	Entries []Entry       `json:"entries"`
	Counts  map[Class]int `json:"counts"`
}

// converter holds what one conversion has made so far. Files the
// configuration names (certificates, user files) are read from the upload.
type converter struct {
	files  Files
	cfg    model.Config
	report Report
	// Upstream name to ID.
	upstreams map[string]string
	// Listener address to ID.
	listeners map[string]*model.Listener
	// Certificate (cert, key path) to ID.
	certs map[[2]string]string
	// Names taken per kind, for unique resource names.
	names map[string]map[string]bool
	// Zones by name (limit_req_zone, limit_conn_zone).
	reqZones  map[string]*model.RateLimitPolicy
	connZones map[string]*model.ConnLimitPolicy
	// proxy_cache_path zones by name.
	cacheZones map[string]*model.CachePolicy
	// oidc_provider blocks by name.
	oidcProviders map[string]*model.OIDCPolicy
	// Policies made per zone and settings, to share one per zone.
	policies map[string]string
	// Log formats by name.
	formats map[string]logFormat
	// charset_map blocks.
	charsetMaps []*model.CharsetMap
}

type logFormat struct {
	format string
	json   bool
}

// Convert turns a parsed configuration into resources. Resources get fresh
// IDs. The report classifies every directive; a nil error with Unsupported
// entries means the conversion is partial.
func Convert(tree []*Directive, files Files) (model.Config, Report) {
	c := &converter{
		files:      files,
		upstreams:  map[string]string{},
		listeners:  map[string]*model.Listener{},
		certs:      map[[2]string]string{},
		names:      map[string]map[string]bool{},
		reqZones:   map[string]*model.RateLimitPolicy{},
		connZones:  map[string]*model.ConnLimitPolicy{},
		cacheZones: map[string]*model.CachePolicy{},
		policies:   map[string]string{},
		formats:    map[string]logFormat{},
	}
	c.report.Counts = map[Class]int{}
	for _, d := range tree {
		switch d.Name {
		case "http":
			c.http(d)
		case "stream":
			c.stream(d)
		case "events":
			c.note(d, Replaced, "the proxy sizes its event loop itself")
			c.skipAll(d.Block, Replaced, "the proxy sizes its event loop itself")
		case "load_module":
			c.note(d, Unsupported, "third-party C modules are not loaded; port the logic to a WASM plugin")
		case "worker_processes", "worker_cpu_affinity", "worker_rlimit_nofile", "worker_priority",
			"worker_shutdown_timeout", "user", "pid", "daemon", "master_process", "lock_file",
			"working_directory", "env", "thread_pool", "pcre_jit", "timer_resolution", "ssl_engine",
			"worker_rlimit_core", "debug_points":
			c.note(d, Replaced, "process settings belong to the proxelo up service and the systemd unit")
		case "error_log":
			c.note(d, Replaced, "the proxy logs errors to stderr")
		case "mail":
			c.note(d, Unsupported, "mail proxying is not available")
			c.skipAll(d.Block, Unsupported, "inside mail")
		default:
			c.note(d, Unsupported, "")
		}
	}
	return c.cfg, c.report
}

func (c *converter) note(d *Directive, class Class, note string) {
	c.report.Entries = append(c.report.Entries, Entry{File: d.File, Line: d.Line, Directive: d.Name, Class: class, Note: note})
	c.report.Counts[class]++
}

func (c *converter) skipAll(ds []*Directive, class Class, note string) {
	for _, d := range ds {
		c.note(d, class, note)
		c.skipAll(d.Block, class, note)
	}
}

// name returns a unique resource name for kind based on s.
func (c *converter) name(kind, s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	dash := false
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z' || r >= '0' && r <= '9':
			b.WriteRune(r)
			dash = false
		default:
			if b.Len() > 0 && !dash {
				b.WriteByte('-')
				dash = true
			}
		}
	}
	n := strings.Trim(b.String(), "-")
	if len(n) > 55 {
		n = strings.Trim(n[:55], "-")
	}
	if n == "" {
		n = kind
	}
	taken := c.names[kind]
	if taken == nil {
		taken = map[string]bool{}
		c.names[kind] = taken
	}
	out := n
	for i := 2; taken[out]; i++ {
		out = fmt.Sprintf("%s-%d", n, i)
	}
	taken[out] = true
	return out
}

func meta(k model.Kind, name string) model.Meta {
	return model.Meta{ID: k.NewID(), Name: name}
}

// scope is the inherited settings of an http, server or location block.
// nginx array directives (add_header, proxy_set_header, error_page,
// allow/deny, limit_req, ...) are inherited only when a level sets none
// of its own; each family is a list that replaces the parent's.
type scope struct {
	root, alias string
	index       []string
	// Content handlers of static locations.
	autoindexOn bool
	autoindex   model.Autoindex
	randomIndex bool
	dav         *model.DAV
	flv         bool
	// ssi on|off and the ssi_* settings; add_before_body, add_after_body
	// and addition_types; mirror (nil: off) and mirror_request_body off.
	ssiOn  bool
	ssi    model.SSIFilter
	sub    model.SubFilter
	userid model.UseridFilter
	// charset, source_charset, override_charset and charset_types.
	charset      model.CharsetFilter
	addition     model.AdditionFilter
	mirror       []string
	mirrorNoBody bool
	addHeader    []header
	setHeader    []header
	hideHeader   []string
	errorPages   []model.ErrorPage
	rules        []model.IPRule
	limitReq     []limitReq
	limitConn    []limitConn
	// limit_req_status, limit_req_dry_run and the limit_conn twins.
	reqStatus, connStatus uint32
	reqDry, connDry       bool
	basicRealm            string
	basicUsers            []model.BasicUser
	// auth_jwt: realm "" for off; jwt the auth_jwt_* settings.
	jwtRealm string
	jwt      model.JWTPolicy
	// auth_oidc: the provider name, "" for off.
	oidc        string
	authRequest string
	accessLog   *model.AccessLogPolicy
	logOff      bool
	gzip        *model.CompressionPolicy
	// proxy_cache: the zone name, "" for off; cache the proxy_cache_*
	// settings, which apply only with a zone.
	cacheZone    string
	cache        model.CachePolicy
	rate, after  string
	timeouts     model.ProxyTimeouts
	nextUpstream []string
	nextTries    uint32
	// proxy_redirect, nil when unset; proxy_cookie_*; *_intercept_errors.
	redirects *model.Redirects
	cookies   model.CookieEdits
	intercept bool
	// *_pass_header, *_limit_rate, *_bind; proxy_method, proxy_set_body,
	// proxy_pass_request_headers and proxy_pass_request_body.
	passHeaders  []string
	limitRate    string
	bind         string
	request      model.UpstreamRequest
	fastcgi      []model.GatewayParam
	gatewayIndex string
	splitPath    string
	realIP       *model.RealIPPolicy
	// Array families this level set, so the first of each drops the
	// inherited list.
	set map[string]bool
}

type header struct {
	name, value string
	always      bool
}

type limitReq struct {
	zone         string
	burst, delay uint32
	nodelay      bool
}

type limitConn struct {
	zone string
	max  uint32
}

func (s scope) clone() scope {
	out := s
	out.set = map[string]bool{}
	if s.gzip != nil {
		g := *s.gzip
		out.gzip = &g
	}
	out.cache = cloneCache(s.cache)
	if s.dav != nil {
		d := *s.dav
		d.Methods = slices.Clone(d.Methods)
		out.dav = &d
	}
	out.jwt.Audiences = slices.Clone(s.jwt.Audiences)
	out.ssi.Types = slices.Clone(s.ssi.Types)
	out.sub.Types = slices.Clone(s.sub.Types)
	out.charset.Types = slices.Clone(s.charset.Types)
	out.sub.Pairs = slices.Clone(s.sub.Pairs)
	if v := s.userid.Service; v != nil {
		n := *v
		out.userid.Service = &n
	}
	out.addition.Types = slices.Clone(s.addition.Types)
	out.mirror = slices.Clone(s.mirror)
	return out
}

func cloneCache(c model.CachePolicy) model.CachePolicy {
	c.Levels = slices.Clone(c.Levels)
	c.Valid = slices.Clone(c.Valid)
	c.Methods = slices.Clone(c.Methods)
	c.UseStale = slices.Clone(c.UseStale)
	c.Ignore = slices.Clone(c.Ignore)
	return c
}

func (c *converter) http(h *Directive) {
	c.note(h, Converted, "")
	top := scope{set: map[string]bool{}}
	var servers []*Directive
	// Zones, formats and upstreams first: servers refer to them.
	for _, d := range h.Block {
		switch d.Name {
		case "upstream":
			c.upstream(d)
		case "log_format":
			c.logFormat(d)
		case "limit_req_zone":
			c.limitReqZone(d)
		case "limit_conn_zone":
			c.limitConnZone(d)
		case "proxy_cache_path":
			c.cachePath(d)
		case "oidc_provider":
			c.oidcProvider(d)
		case "charset_map":
			c.charsetMap(d)
		case "map", "geo", "split_clients":
			c.lookup(d)
		}
	}
	for _, d := range h.Block {
		switch d.Name {
		case "upstream", "log_format", "limit_req_zone", "limit_conn_zone", "proxy_cache_path", "oidc_provider", "charset_map", "map", "geo", "split_clients":
		case "server":
			servers = append(servers, d)
		default:
			c.common(d, &top)
		}
	}
	// nginx picks the first server of a listen socket as its default unless
	// one says default_server; the converter does the same.
	for _, s := range servers {
		c.server(s, top.clone())
	}
}

// common handles directives valid in http, server and location. It reports
// the directive and returns whether it knew it.
func (c *converter) common(d *Directive, s *scope) bool {
	a := d.Args
	arg := func(i int) string {
		if i < len(a) {
			return a[i]
		}
		return ""
	}
	switch d.Name {
	case "root":
		s.root, s.alias = arg(0), ""
	case "alias":
		s.alias = arg(0)
	case "index":
		s.index = slices.Clone(a)
	case "autoindex", "autoindex_format", "autoindex_localtime", "autoindex_exact_size":
		ai := &s.autoindex
		switch d.Name {
		case "autoindex":
			s.autoindexOn = arg(0) == "on"
		case "autoindex_format":
			ai.Format = model.AutoindexFormat(arg(0))
			if ai.Format == model.AutoindexHTML {
				ai.Format = ""
			}
		case "autoindex_localtime":
			ai.LocalTime = arg(0) == "on"
		case "autoindex_exact_size":
			ai.ApproximateSize = arg(0) == "off"
		}
	case "ssi":
		s.ssiOn = arg(0) == "on"
	case "ssi_silent_errors":
		s.ssi.SilentErrors = arg(0) == "on"
	case "ssi_types":
		s.ssi.Types = mediaTypes(a)
	case "ssi_value_length":
		s.ssi.ValueLength = atou(arg(0))
	case "ssi_last_modified":
		s.ssi.LastModified = arg(0) == "on"
	case "ssi_min_file_chunk", "ssi_ignore_recycled_buffers":
		c.note(d, Replaced, "buffers are handled by the proxy")
		return true
	case "charset", "source_charset":
		if strings.Contains(arg(0), "$") {
			c.note(d, Unsupported, "a charset from a variable")
			return true
		}
		if d.Name == "charset" {
			s.charset.Charset = arg(0)
		} else {
			s.charset.Source = arg(0)
		}
	case "override_charset":
		s.charset.Override = arg(0) == "on"
	case "charset_types":
		// Unlike the other *_types, an empty list means nginx's default
		// here, so text/html stays when it is the only type.
		s.charset.Types = mediaTypes(a)
		if len(s.charset.Types) == 0 {
			s.charset.Types = []string{"text/html"}
		}
	case "sub_filter":
		s.sub.Pairs = append(slices.Clip(fresh(s, "sub_filter", s.sub.Pairs)), model.SubPair{Match: arg(0), Replacement: arg(1)})
	case "sub_filter_once":
		s.sub.All = arg(0) == "off"
	case "sub_filter_types":
		s.sub.Types = mediaTypes(a)
	case "sub_filter_last_modified":
		s.sub.LastModified = arg(0) == "on"
	case "userid":
		s.userid.Mode = model.UseridMode(arg(0))
	case "userid_name":
		s.userid.Name = arg(0)
	case "userid_domain":
		s.userid.Domain = noneEmpty(arg(0))
	case "userid_path":
		s.userid.Path = arg(0)
	case "userid_p3p":
		s.userid.P3P = noneEmpty(arg(0))
	case "userid_expires":
		switch arg(0) {
		case "off":
			s.userid.Expires = ""
		case "max":
			s.userid.Expires = "max"
		default:
			s.userid.Expires = duration(arg(0))
		}
	case "userid_service":
		n := atou(arg(0))
		s.userid.Service = &n
	case "userid_mark":
		s.userid.Mark = arg(0)
		if s.userid.Mark == "off" {
			s.userid.Mark = ""
		}
	case "userid_flags":
		u := &s.userid
		u.Secure, u.HTTPOnly, u.SameSite = false, false, ""
		for _, f := range a {
			switch {
			case f == "secure":
				u.Secure = true
			case f == "httponly":
				u.HTTPOnly = true
			case strings.HasPrefix(f, "samesite="):
				u.SameSite = f[len("samesite="):]
			}
		}
	case "add_before_body":
		s.addition.Before = arg(0)
	case "add_after_body":
		s.addition.After = arg(0)
	case "addition_types":
		s.addition.Types = mediaTypes(a)
	case "mirror":
		if arg(0) == "off" {
			s.mirror = nil
		} else {
			s.mirror = append(slices.Clip(fresh(s, "mirror", s.mirror)), arg(0))
		}
	case "mirror_request_body":
		s.mirrorNoBody = arg(0) == "off"
	case "random_index":
		s.randomIndex = arg(0) == "on"
	case "flv":
		s.flv = true
	case "dav_methods", "create_full_put_path", "min_delete_depth", "dav_access":
		if s.dav == nil {
			s.dav = &model.DAV{}
		}
		dv := s.dav
		switch d.Name {
		case "dav_methods":
			dv.Methods = nil
			if arg(0) != "off" {
				for _, m := range a {
					dv.Methods = append(dv.Methods, strings.ToLower(m))
				}
			}
		case "create_full_put_path":
			dv.CreateFullPutPath = arg(0) == "on"
		case "min_delete_depth":
			dv.MinDeleteDepth = atou(arg(0))
		case "dav_access":
			acc, ok := davAccess(a)
			if !ok {
				c.note(d, Unsupported, "could not read the permissions")
				return true
			}
			dv.Access = acc
		}
	case "add_header":
		s.addHeader = append(slices.Clip(fresh(s, "add_header", s.addHeader)), header{arg(0), arg(1), arg(2) == "always"})
	case "proxy_set_header":
		if slices.Contains(model.ReservedHeaders, strings.ToLower(arg(0))) {
			c.note(d, Replaced, arg(0)+" is set by the proxy")
			return true
		}
		s.setHeader = append(slices.Clip(fresh(s, "proxy_set_header", s.setHeader)), header{name: arg(0), value: arg(1)})
	case "proxy_hide_header":
		s.hideHeader = append(slices.Clip(fresh(s, "proxy_hide_header", s.hideHeader)), arg(0))
	case "error_page":
		ep, ok := errorPage(a)
		if !ok {
			c.note(d, Unsupported, "could not read the codes and target")
			return true
		}
		s.errorPages = append(slices.Clip(fresh(s, "error_page", s.errorPages)), ep)
	case "allow", "deny":
		s.rules = append(slices.Clip(fresh(s, "access", s.rules)), model.IPRule{Action: d.Name, From: arg(0)})
	case "limit_req":
		lr := limitReq{}
		for _, x := range a {
			switch {
			case strings.HasPrefix(x, "zone="):
				lr.zone = x[5:]
			case strings.HasPrefix(x, "burst="):
				lr.burst = atou(x[6:])
			case strings.HasPrefix(x, "delay="):
				lr.delay = atou(x[6:])
			case x == "nodelay":
				lr.nodelay = true
			}
		}
		if _, ok := c.reqZones[lr.zone]; !ok {
			c.note(d, Unsupported, "zone "+lr.zone+" is not defined")
			return true
		}
		s.limitReq = append(slices.Clip(fresh(s, "limit_req", s.limitReq)), lr)
	case "limit_conn":
		if _, ok := c.connZones[arg(0)]; !ok {
			c.note(d, Unsupported, "zone "+arg(0)+" is not defined")
			return true
		}
		s.limitConn = append(slices.Clip(fresh(s, "limit_conn", s.limitConn)), limitConn{arg(0), atou(arg(1))})
	case "limit_req_status":
		s.reqStatus = atou(arg(0))
		c.limitNote(d, s, "limit_req")
		return true
	case "limit_conn_status":
		s.connStatus = atou(arg(0))
		c.limitNote(d, s, "limit_conn")
		return true
	case "limit_req_dry_run":
		s.reqDry = arg(0) == "on"
		c.limitNote(d, s, "limit_req")
		return true
	case "limit_conn_dry_run":
		s.connDry = arg(0) == "on"
		c.limitNote(d, s, "limit_conn")
		return true
	case "limit_req_log_level", "limit_conn_log_level":
		c.note(d, Replaced, "rejections are logged at warn")
		return true
	case "auth_basic":
		if arg(0) == "off" {
			s.basicRealm, s.basicUsers = "", nil
		} else {
			s.basicRealm = arg(0)
		}
	case "auth_basic_user_file":
		users, err := c.htpasswd(arg(0))
		if err != "" {
			c.note(d, ConvertedWithNote, err+"; add the users to the basicAuth policy")
			return true
		}
		s.basicUsers = users
	case "auth_jwt":
		if arg(0) == "off" {
			s.jwtRealm = ""
		} else {
			s.jwtRealm = arg(0)
			if arg(1) != "" {
				tok, ok := strings.CutPrefix(arg(1), "token=")
				if !ok {
					c.note(d, Unsupported, "expected token=$variable")
					return true
				}
				s.jwt.Token = tok
			}
		}
	case "auth_jwt_key_file":
		src, ok := c.lookupFile(arg(0))
		if !ok {
			c.note(d, ConvertedWithNote, "key file "+arg(0)+" is not in the upload; add the keys to the jwt policy")
			return true
		}
		s.jwt.JWKS = src
	case "auth_jwt_key_request":
		c.note(d, ConvertedWithNote, "set jwt.jwksUrl to the URL the location fetches")
		return true
	case "auth_jwt_key_cache":
		s.jwt.KeyCache = duration(arg(0))
	case "auth_jwt_leeway":
		s.jwt.Leeway = duration(arg(0))
	case "auth_jwt_require", "auth_jwt_claim_set", "auth_jwt_header_set":
		c.note(d, Replaced, "claims are variables $jwt_claim_<name>; issuer and audiences are jwt policy settings")
		return true
	case "auth_jwt_type":
		if arg(0) != "" && arg(0) != "signed" {
			c.note(d, Unsupported, "only signed tokens (JWS) are verified")
			return true
		}
	case "auth_oidc":
		if arg(0) == "off" {
			s.oidc = ""
		} else if _, ok := c.oidcProviders[arg(0)]; ok {
			s.oidc = arg(0)
		} else {
			c.note(d, Unsupported, "oidc_provider "+arg(0)+" is not defined")
			return true
		}
	case "auth_request":
		if arg(0) == "off" {
			s.authRequest = ""
		} else {
			s.authRequest = arg(0)
		}
		c.note(d, ConvertedWithNote, "the check location's proxy_pass becomes a forwardAuth policy")
		return true
	case "auth_request_set":
		c.note(d, Replaced, "copied response headers are available as $auth_resp_<name>; list them in forwardAuth.copyHeaders")
		return true
	case "access_log":
		if arg(0) == "off" {
			s.logOff, s.accessLog = true, nil
			break
		}
		l := &model.AccessLogPolicy{Path: arg(0)}
		if f, ok := c.formats[arg(1)]; ok {
			l.Format, l.EscapeJSON = f.format, f.json
		} else if arg(1) != "" && arg(1) != "combined" {
			c.note(d, ConvertedWithNote, "log format "+arg(1)+" is not defined; combined is used")
			s.accessLog, s.logOff = l, false
			return true
		}
		if !strings.HasPrefix(l.Path, "/") && l.Path != "stdout" && l.Path != "stderr" {
			l.Path = "/var/log/nginx/" + l.Path
			s.accessLog, s.logOff = l, false
			c.note(d, ConvertedWithNote, "relative path resolved against /var/log/nginx")
			return true
		}
		if len(a) > 2 {
			s.accessLog, s.logOff = l, false
			c.note(d, ConvertedWithNote, "buffer, flush, gzip and if= are not carried over")
			return true
		}
		s.accessLog, s.logOff = l, false
	case "gzip":
		if arg(0) == "on" {
			if s.gzip == nil {
				s.gzip = &model.CompressionPolicy{}
			}
			if !slices.Contains(s.gzip.Encodings, "gzip") {
				s.gzip.Encodings = append(s.gzip.Encodings, "gzip")
			}
		} else if s.gzip != nil {
			s.gzip.Encodings = slices.DeleteFunc(slices.Clone(s.gzip.Encodings), func(e string) bool { return e == "gzip" })
		}
	case "gzip_types", "gzip_min_length", "gzip_comp_level", "gzip_proxied", "gzip_vary", "gzip_static", "gunzip", "gzip_http_version", "gzip_disable":
		if s.gzip == nil {
			s.gzip = &model.CompressionPolicy{}
		}
		g := s.gzip
		switch d.Name {
		case "gzip_types":
			g.Types = slices.Clone(a)
		case "gzip_min_length":
			g.MinLength = arg(0)
		case "gzip_comp_level":
			g.GzipLevel = atou(arg(0))
		case "gzip_proxied":
			g.Proxied = slices.DeleteFunc(slices.Clone(a), func(x string) bool { return x == "off" })
		case "gzip_vary":
			g.Vary = arg(0) == "on"
		case "gzip_static":
			g.Static = map[string]string{"on": "on", "always": "always"}[arg(0)]
		case "gunzip":
			g.Gunzip = arg(0) == "on"
		case "gzip_http_version":
			g.HTTP10 = arg(0) == "1.0"
		case "gzip_disable":
			g.Disable = strings.Join(a, "|")
			if arg(0) == "msie6" {
				g.Disable = `MSIE [4-6]\.`
			}
		}
	case "gzip_buffers", "gzip_window", "gzip_hash":
		c.note(d, Replaced, "buffers are sized by the proxy")
		return true
	case "proxy_cache", "proxy_cache_key", "proxy_cache_valid", "proxy_cache_methods", "proxy_cache_min_uses",
		"proxy_cache_bypass", "proxy_no_cache", "proxy_cache_lock", "proxy_cache_lock_timeout", "proxy_cache_use_stale",
		"proxy_cache_background_update", "proxy_cache_revalidate", "proxy_cache_convert_head", "proxy_ignore_headers":
		c.cacheDirective(d, s)
		return true
	case "slice":
		if arg(0) == "0" {
			s.cache.Slice = ""
		} else {
			s.cache.Slice = arg(0)
		}
		c.note(d, Converted, "")
		return true
	case "proxy_cache_lock_age", "proxy_cache_max_range_offset":
		c.note(d, Replaced, "the lock lasts as long as the request that holds it; ranges are served from whole entries")
		return true
	case "limit_rate":
		s.rate = arg(0)
	case "limit_rate_after":
		s.after = arg(0)
	case "proxy_connect_timeout":
		s.timeouts.Connect = duration(arg(0))
	case "proxy_send_timeout":
		s.timeouts.Send = duration(arg(0))
	case "proxy_read_timeout":
		s.timeouts.Read = duration(arg(0))
	case "proxy_next_upstream":
		s.nextUpstream = slices.Clone(a)
	case "proxy_next_upstream_tries":
		s.nextTries = atou(arg(0))
	case "proxy_intercept_errors", "fastcgi_intercept_errors", "uwsgi_intercept_errors", "scgi_intercept_errors",
		"grpc_intercept_errors":
		s.intercept = arg(0) == "on"
	case "proxy_pass_header", "fastcgi_pass_header", "uwsgi_pass_header", "scgi_pass_header", "grpc_pass_header":
		s.passHeaders = append(slices.Clip(fresh(s, "pass_header", s.passHeaders)), arg(0))
	case "proxy_limit_rate", "fastcgi_limit_rate", "uwsgi_limit_rate", "scgi_limit_rate":
		if arg(0) == "0" {
			s.limitRate = ""
		} else {
			s.limitRate = arg(0)
		}
	case "grpc_bind":
		c.note(d, Unsupported, "grpc upstream connections are shared by requests")
		return true
	case "proxy_bind", "fastcgi_bind", "uwsgi_bind", "scgi_bind", "memcached_bind":
		switch {
		case len(a) > 1:
			c.note(d, Unsupported, "transparent binding is not supported")
			return true
		case arg(0) == "off":
			s.bind = ""
		default:
			s.bind = arg(0)
		}
	case "proxy_method":
		s.request.Method = arg(0)
	case "proxy_set_body":
		b := arg(0)
		s.request.Body = &b
	case "proxy_pass_request_headers":
		s.request.NoHeaders = arg(0) == "off"
	case "proxy_pass_request_body":
		s.request.NoBody = arg(0) == "off"
	case "proxy_redirect":
		r := s.redirects
		if r == nil || !s.set["proxy_redirect"] {
			r = &model.Redirects{}
		}
		s.set["proxy_redirect"] = true
		r = &model.Redirects{Off: r.Off, Default: r.Default, Rules: slices.Clip(r.Rules)}
		switch {
		case len(a) == 1 && a[0] == "off":
			r.Off = true
		case len(a) == 1 && a[0] == "default":
			r.Default = true
		case len(a) == 2:
			r.Rules = append(r.Rules, headerRewrite(a[0], a[1], true))
		default:
			c.note(d, Unsupported, "")
			return true
		}
		// Rules without "default" drop the default rule, as in nginx.
		s.redirects = r
	case "proxy_cookie_domain", "proxy_cookie_path":
		list := &s.cookies.Domains
		if d.Name == "proxy_cookie_path" {
			list = &s.cookies.Paths
		}
		*list = slices.Clip(fresh(s, d.Name, *list))
		switch {
		case len(a) == 1 && a[0] == "off":
			*list = nil
		case len(a) == 2:
			// A domain regex is ~ only, caseless.
			*list = append(*list, headerRewrite(a[0], a[1], d.Name == "proxy_cookie_path"))
		default:
			c.note(d, Unsupported, "")
			return true
		}
	case "proxy_cookie_flags":
		s.cookies.Flags = slices.Clip(fresh(s, d.Name, s.cookies.Flags))
		switch {
		case len(a) == 1 && a[0] == "off":
			s.cookies.Flags = nil
		case len(a) >= 2:
			f := model.CookieFlags{Cookie: a[0], Flags: a[1:]}
			if strings.HasPrefix(a[0], "~") {
				f.Cookie, f.Regex = a[0][1:], true
			}
			s.cookies.Flags = append(s.cookies.Flags, f)
		default:
			c.note(d, Unsupported, "")
			return true
		}
	case "fastcgi_param", "uwsgi_param", "scgi_param":
		p := model.GatewayParam{Name: arg(0), Value: arg(1), IfNotEmpty: arg(2) == "if_not_empty"}
		s.fastcgi = append(slices.Clip(fresh(s, "param", s.fastcgi)), p)
	case "fastcgi_index":
		s.gatewayIndex = arg(0)
	case "fastcgi_split_path_info":
		s.splitPath = arg(0)
	case "set_real_ip_from":
		if s.realIP == nil {
			s.realIP = &model.RealIPPolicy{}
		}
		r := *s.realIP
		r.From = append(slices.Clip(r.From), arg(0))
		s.realIP = &r
	case "real_ip_header":
		if s.realIP == nil {
			s.realIP = &model.RealIPPolicy{}
		}
		r := *s.realIP
		r.Header = arg(0)
		s.realIP = &r
	case "real_ip_recursive":
		if s.realIP == nil {
			s.realIP = &model.RealIPPolicy{}
		}
		r := *s.realIP
		r.Recursive = arg(0) == "on"
		s.realIP = &r
	case "sendfile", "tcp_nopush", "tcp_nodelay", "keepalive_timeout", "keepalive_requests", "client_body_buffer_size",
		"client_header_buffer_size", "large_client_header_buffers", "client_body_timeout", "client_header_timeout",
		"send_timeout", "server_tokens", "types_hash_max_size", "types_hash_bucket_size", "server_names_hash_bucket_size",
		"server_names_hash_max_size", "proxy_buffering", "proxy_buffer_size", "proxy_buffers", "proxy_busy_buffers_size",
		"open_file_cache", "open_file_cache_valid", "open_file_cache_min_uses", "open_file_cache_errors", "reset_timedout_connection",
		"output_buffers", "postpone_output", "fastcgi_buffers", "fastcgi_buffer_size", "proxy_temp_path", "client_body_temp_path",
		"fastcgi_temp_path", "uwsgi_temp_path", "scgi_temp_path", "proxy_max_temp_file_size", "aio", "directio",
		"ssl_buffer_size", "variables_hash_max_size", "variables_hash_bucket_size", "map_hash_bucket_size", "map_hash_max_size",
		"log_not_found", "log_subrequest", "msie_padding", "lingering_close", "lingering_time", "lingering_timeout",
		"proxy_http_version", "chunked_transfer_encoding", "absolute_redirect", "port_in_redirect", "server_name_in_redirect",
		"resolver", "resolver_timeout":
		c.note(d, Replaced, "the proxy uses fixed buffers, timeouts and HTTP/1.1 upstream connections")
		return true
	case "include":
		if strings.HasSuffix(firstArg(a), "mime.types") {
			c.note(d, Replaced, "the proxy has nginx's mime.types built in")
		} else {
			c.note(d, Unsupported, "include target not in the upload")
		}
		return true
	case "default_type", "types":
		c.note(d, Replaced, "the proxy has nginx's mime.types built in")
		return true
	case "client_max_body_size":
		c.note(d, ConvertedWithNote, "the proxy limits request bodies to 1m, nginx's default")
		return true
	default:
		return false
	}
	c.note(d, Converted, "")
	return true
}

// headerRewrite reads a proxy_redirect or proxy_cookie_* pattern: "~" is a
// regex, "~*" (when caseCI) a caseless one.
func headerRewrite(pattern, replacement string, caseCI bool) model.HeaderRewrite {
	r := model.HeaderRewrite{Pattern: pattern, Replacement: replacement}
	switch {
	case caseCI && strings.HasPrefix(pattern, "~*"):
		r.Match, r.Pattern = model.RewriteRegexCI, pattern[2:]
	case strings.HasPrefix(pattern, "~"):
		r.Match, r.Pattern = model.RewriteRegex, pattern[1:]
	}
	return r
}

// fresh returns cur, or nil on the level's first directive of family: a
// level that sets any directive of an array family replaces the inherited
// list, as in nginx.
func fresh[T any](s *scope, family string, cur []T) []T {
	if s.set[family] {
		return cur
	}
	s.set[family] = true
	return nil
}

// davAccess reads nginx dav_access ("user:rw group:r all:r") as octal
// permission bits.
func davAccess(a []string) (string, bool) {
	var mode uint32
	for _, x := range a {
		who, perm, ok := strings.Cut(x, ":")
		if !ok {
			return "", false
		}
		var bits uint32
		switch perm {
		case "r":
			bits = 4
		case "w":
			bits = 2
		case "rw":
			bits = 6
		default:
			return "", false
		}
		switch who {
		case "user":
			mode |= bits << 6
		case "group":
			mode |= bits << 3
		case "all":
			mode |= bits
		default:
			return "", false
		}
	}
	return fmt.Sprintf("0%o", mode), true
}

// charsetMap reads an nginx charset_map block.
func (c *converter) charsetMap(d *Directive) {
	if len(d.Args) != 2 {
		c.note(d, Unsupported, "needs two charsets")
		return
	}
	m := &model.CharsetMap{From: d.Args[0], To: d.Args[1], Bytes: map[string]string{}}
	for _, e := range d.Block {
		if len(e.Args) != 1 {
			c.note(e, Unsupported, "needs a byte and its value")
			continue
		}
		m.Bytes[strings.ToUpper(e.Name)] = strings.ToUpper(e.Args[0])
	}
	c.charsetMaps = append(c.charsetMaps, m)
	c.note(d, Converted, "")
}

// charsetFilter is the charset filter of s with the charset_map it needs.
func (c *converter) charsetFilter(s scope) model.CharsetFilter {
	f := s.charset
	if f.Charset == "" {
		f.Charset = "off"
	}
	if f.Source == "" || f.Charset == "off" || strings.EqualFold(f.Source, f.Charset) {
		return f
	}
	for _, m := range c.charsetMaps {
		if strings.EqualFold(m.From, f.Source) && strings.EqualFold(m.To, f.Charset) || strings.EqualFold(m.From, f.Charset) && strings.EqualFold(m.To, f.Source) {
			f.Map = m
		}
	}
	return f
}

// noneEmpty reads nginx's "none" as unset.
func noneEmpty(v string) string {
	if v == "none" {
		return ""
	}
	return v
}

// mediaTypes reads a *_types list; nginx always adds text/html, so it is
// dropped here, and "*" stands alone.
func mediaTypes(a []string) []string {
	if slices.Contains(a, "*") {
		return []string{"*"}
	}
	var out []string
	for _, t := range a {
		if t = strings.ToLower(t); t != "text/html" && !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	return out
}

func atou(s string) uint32 {
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0
	}
	return uint32(n)
}

// duration converts an nginx time ("60", "30s", "1m", "500ms", "1h") to a Go
// duration string. Unreadable values are returned as is for validation to
// report.
func duration(v string) string {
	if v == "" {
		return ""
	}
	if _, err := strconv.Atoi(v); err == nil {
		return v + "s"
	}
	units := map[string]string{"ms": "ms", "s": "s", "m": "m", "h": "h", "d": "h", "w": "h"}
	var b strings.Builder
	rest := v
	for rest != "" {
		i := 0
		for i < len(rest) && rest[i] >= '0' && rest[i] <= '9' {
			i++
		}
		j := i
		for j < len(rest) && (rest[j] < '0' || rest[j] > '9') {
			j++
		}
		n, u := rest[:i], rest[i:j]
		rest = rest[j:]
		gu, ok := units[u]
		if !ok || n == "" {
			return v
		}
		switch u {
		case "d":
			x, _ := strconv.Atoi(n)
			n = strconv.Itoa(x * 24)
		case "w":
			x, _ := strconv.Atoi(n)
			n = strconv.Itoa(x * 24 * 7)
		}
		b.WriteString(n + gu)
	}
	return b.String()
}

// errorPage reads "error_page code ... [=[response]] uri".
func errorPage(a []string) (model.ErrorPage, bool) {
	if len(a) < 2 {
		return model.ErrorPage{}, false
	}
	var ep model.ErrorPage
	target := a[len(a)-1]
	for _, x := range a[:len(a)-1] {
		if strings.HasPrefix(x, "=") {
			n := uint32(0)
			if x != "=" {
				n = atou(x[1:])
				if n == 0 {
					return ep, false
				}
			}
			ep.Status = &n
			continue
		}
		code := atou(x)
		if code < 300 || code > 599 {
			return ep, false
		}
		ep.Codes = append(ep.Codes, code)
	}
	if len(ep.Codes) == 0 {
		return ep, false
	}
	if strings.HasPrefix(target, "@") {
		// Resolved to the named route's ID by the server.
		ep.Route = target
	} else {
		ep.URI = target
	}
	return ep, true
}

func (c *converter) htpasswd(file string) ([]model.BasicUser, string) {
	src, ok := c.lookupFile(file)
	if !ok {
		return nil, "user file " + file + " is not in the upload"
	}
	var out []model.BasicUser
	for line := range strings.SplitSeq(src, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, hash, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		// Comment fields after a second colon are not part of the hash.
		if h, _, ok := strings.Cut(hash, ":"); ok {
			hash = h
		}
		out = append(out, model.BasicUser{Name: name, Hash: hash})
	}
	return out, ""
}

// lookupFile finds a file the configuration names, by its path or, for an
// upload rooted elsewhere, by its name relative to a common suffix.
func (c *converter) lookupFile(name string) (string, bool) {
	if s, ok := c.files[name]; ok {
		return s, true
	}
	for n, s := range c.files {
		if strings.HasSuffix(name, "/"+n) || strings.HasSuffix(n, "/"+strings.TrimPrefix(name, "/")) {
			return s, true
		}
	}
	return "", false
}

func (c *converter) logFormat(d *Directive) {
	if len(d.Args) < 2 {
		c.note(d, Unsupported, "needs a name and a format")
		return
	}
	f := logFormat{}
	parts := d.Args[1:]
	if strings.HasPrefix(parts[0], "escape=") {
		f.json = parts[0] == "escape=json"
		if parts[0] == "escape=none" {
			c.note(d, ConvertedWithNote, "escape=none logs with default escaping")
		}
		parts = parts[1:]
	}
	f.format = strings.Join(parts, "")
	c.formats[d.Args[0]] = f
	c.note(d, Converted, "")
}

func (c *converter) limitReqZone(d *Directive) {
	z := &model.RateLimitPolicy{}
	var name string
	for i, x := range d.Args {
		switch {
		case i == 0:
			z.Key = x
		case strings.HasPrefix(x, "zone="):
			name, _, _ = strings.Cut(x[5:], ":")
		case strings.HasPrefix(x, "rate="):
			z.Rate = x[5:]
		}
	}
	if name == "" || z.Rate == "" {
		c.note(d, Unsupported, "needs zone= and rate=")
		return
	}
	c.reqZones[name] = z
	c.note(d, ConvertedWithNote, "becomes a rateLimit policy per limit_req; the zone size is a key count (maxKeys)")
}

func (c *converter) limitConnZone(d *Directive) {
	if len(d.Args) < 2 || !strings.HasPrefix(d.Args[1], "zone=") {
		c.note(d, Unsupported, "needs a key and zone=")
		return
	}
	name, _, _ := strings.Cut(d.Args[1][5:], ":")
	c.connZones[name] = &model.ConnLimitPolicy{Key: d.Args[0]}
	c.note(d, ConvertedWithNote, "becomes a connLimit policy per limit_conn; the zone size is a key count (maxKeys)")
}

var mapVar = regexp.MustCompile(`^\$[a-z0-9_]+$`)

func (c *converter) lookup(d *Directive) {
	add := func(spec model.LookupSpec, variable string) {
		v := strings.TrimPrefix(variable, "$")
		l := &model.Lookup{Meta: meta(model.LookupKind, c.name("lookups", v)), Spec: spec}
		if strings.ReplaceAll(l.Name, "-", "_") != v {
			l.Spec.Variable = v
		}
		c.cfg.Lookups = append(c.cfg.Lookups, l)
	}
	switch d.Name {
	case "map":
		if len(d.Args) != 2 || !mapVar.MatchString(d.Args[1]) {
			c.note(d, Unsupported, "needs a source and a $variable")
			return
		}
		t := &model.MapTable{}
		note := ""
		for _, e := range d.Block {
			key := e.Name
			if len(e.Args) != 1 {
				switch key {
				case "hostnames":
					t.Hostnames = true
					continue
				case "volatile":
					continue
				}
				note = "entries with other than one value were skipped"
				continue
			}
			val := e.Args[0]
			switch {
			case key == "default":
				t.Default = val
			case key == "include":
				note = "include inside map is not followed"
			case strings.HasPrefix(key, "~*"):
				t.Entries = append(t.Entries, model.MapEntry{Match: model.MapRegexCI, Key: key[2:], Value: val})
			case strings.HasPrefix(key, "~"):
				t.Entries = append(t.Entries, model.MapEntry{Match: model.MapRegex, Key: key[1:], Value: val})
			default:
				t.Entries = append(t.Entries, model.MapEntry{Key: strings.TrimPrefix(key, "\\"), Value: val})
			}
		}
		add(model.LookupSpec{Type: model.LookupMap, Source: d.Args[0], Map: t}, d.Args[1])
		c.noteOr(d, note)
	case "geo":
		src, v := "", ""
		switch len(d.Args) {
		case 1:
			v = d.Args[0]
		case 2:
			src, v = d.Args[0], d.Args[1]
		}
		if !mapVar.MatchString(v) {
			c.note(d, Unsupported, "needs a $variable")
			return
		}
		t := &model.GeoTable{}
		note := ""
		for _, e := range d.Block {
			if len(e.Args) != 1 {
				if e.Name != "ranges" && e.Name != "proxy_recursive" {
					note = "entries with other than one value were skipped"
				} else {
					note = e.Name + " is not supported"
				}
				continue
			}
			switch e.Name {
			case "default":
				t.Default = e.Args[0]
			case "proxy", "include", "delete":
				note = e.Name + " inside geo is not supported"
			default:
				t.Entries = append(t.Entries, model.GeoEntry{Network: e.Name, Value: e.Args[0]})
			}
		}
		add(model.LookupSpec{Type: model.LookupGeo, Source: src, Geo: t}, v)
		c.noteOr(d, note)
	case "split_clients":
		if len(d.Args) != 2 || !mapVar.MatchString(d.Args[1]) {
			c.note(d, Unsupported, "needs a source and a $variable")
			return
		}
		t := &model.SplitClients{}
		for _, e := range d.Block {
			v := ""
			if len(e.Args) > 0 {
				v = e.Args[0]
			}
			t.Buckets = append(t.Buckets, model.SplitBucket{Percent: e.Name, Value: v})
		}
		add(model.LookupSpec{Type: model.LookupSplit, Source: d.Args[0], Split: t}, d.Args[1])
		c.note(d, Converted, "")
	}
}

func (c *converter) noteOr(d *Directive, note string) {
	if note != "" {
		c.note(d, ConvertedWithNote, note)
	} else {
		c.note(d, Converted, "")
	}
}

// upstream converts an upstream block. Servers are host:port; a unix: socket
// is not supported.
func (c *converter) upstream(d *Directive) {
	if len(d.Args) != 1 {
		c.note(d, Unsupported, "needs a name")
		return
	}
	u := &model.Upstream{Meta: meta(model.UpstreamKind, c.name("upstreams", d.Args[0]))}
	sp := &u.Spec
	notes := []string{}
	for _, e := range d.Block {
		a := e.Args
		switch e.Name {
		case "server":
			if len(a) == 0 || strings.HasPrefix(a[0], "unix:") {
				c.note(e, Unsupported, "unix sockets are not supported")
				continue
			}
			t := model.Target{Address: hostPort(a[0], "80")}
			for _, x := range a[1:] {
				k, v, _ := strings.Cut(x, "=")
				switch k {
				case "weight":
					t.Weight = atou(v)
				case "max_conns":
					t.MaxConns = atou(v)
				case "backup":
					t.Backup = true
				case "down":
					t.Down = true
				case "slow_start":
					t.SlowStart = duration(v)
				case "resolve":
					t.Resolve = true
				case "route":
					t.Route = v
				case "max_fails":
					n := atou(v)
					sp.PassiveHealth.MaxFails = &n
				case "fail_timeout":
					sp.PassiveHealth.FailTimeout = duration(v)
				default:
					notes = append(notes, "server parameter "+k+" ignored")
				}
			}
			sp.Targets = append(sp.Targets, t)
			c.note(e, Converted, "")
		case "least_conn":
			sp.Balancing.Algorithm = model.LeastConn
			c.note(e, Converted, "")
		case "ip_hash":
			sp.Balancing.Algorithm = model.IPHash
			c.note(e, Converted, "")
		case "hash":
			sp.Balancing = model.Balancing{Algorithm: model.Hash, Key: firstArg(a)}
			if len(a) > 1 && a[1] == "consistent" {
				sp.Balancing.Algorithm = model.HashConsistent
			}
			c.note(e, Converted, "")
		case "random":
			sp.Balancing.Algorithm = model.Random
			if len(a) > 0 && a[0] == "two" {
				sp.Balancing.Algorithm = model.RandomTwo
			}
			c.note(e, Converted, "")
		case "keepalive":
			sp.Keepalive.Idle = atou(firstArg(a))
			c.note(e, Converted, "")
		case "keepalive_timeout":
			sp.Keepalive.Timeout = duration(firstArg(a))
			c.note(e, Converted, "")
		case "keepalive_requests":
			sp.Keepalive.MaxRequests = atou(firstArg(a))
			c.note(e, Converted, "")
		case "keepalive_time":
			sp.Keepalive.MaxAge = duration(firstArg(a))
			c.note(e, Converted, "")
		case "queue":
			sp.Queue.Size = atou(firstArg(a))
			for _, x := range a[1:] {
				if v, ok := strings.CutPrefix(x, "timeout="); ok {
					sp.Queue.Timeout = duration(v)
				}
			}
			c.note(e, Converted, "")
		case "zone", "resolver", "resolver_timeout":
			c.note(e, Replaced, "upstream state is kept by the proxy")
		case "sticky":
			st, note := sticky(a)
			if st == nil {
				c.note(e, Unsupported, note)
				continue
			}
			sp.Sticky = st
			c.noteOr(e, note)
		default:
			c.note(e, Unsupported, "")
		}
	}
	c.upstreams[d.Args[0]] = u.ID
	c.cfg.Upstreams = append(c.cfg.Upstreams, u)
	if len(notes) > 0 {
		c.note(d, ConvertedWithNote, strings.Join(notes, "; "))
	} else {
		c.note(d, Converted, "")
	}
}

func firstArg(a []string) string {
	if len(a) == 0 {
		return ""
	}
	return a[0]
}

func sticky(a []string) (*model.Sticky, string) {
	if len(a) == 0 {
		return nil, "needs a method"
	}
	switch a[0] {
	case "cookie":
		if len(a) < 2 {
			return nil, "needs a cookie name"
		}
		st := &model.Sticky{Type: model.StickyCookie, Cookie: a[1]}
		for _, x := range a[2:] {
			k, v, _ := strings.Cut(x, "=")
			switch k {
			case "expires":
				if v != "max" {
					st.MaxAge = duration(v)
				}
			case "path":
				st.Path = v
			case "domain":
				st.Domain = v
			case "httponly":
				st.HTTPOnly = true
			case "secure":
				st.Secure = true
			case "samesite":
				st.SameSite = v
			}
		}
		return st, ""
	case "route":
		return &model.Sticky{Type: model.StickyRoute, Route: a[1:]}, ""
	}
	return nil, "sticky " + a[0] + " is not supported"
}

// hostPort adds the default port to an address without one.
func hostPort(addr, port string) string {
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	if strings.Count(addr, ":") > 1 && !strings.HasPrefix(addr, "[") {
		return "[" + addr + "]:" + port
	}
	return net.JoinHostPort(strings.Trim(addr, "[]"), port)
}

// limitNote reports a limit_*_status or _dry_run: it reaches the policies of
// the limits this level declares (or later, nested ones), not inherited ones.
func (c *converter) limitNote(d *Directive, s *scope, family string) {
	if s.set[family] {
		c.note(d, Converted, "")
	} else {
		c.note(d, ConvertedWithNote, "applies to "+family+" in this block and nested ones; repeat "+family+" here for the inherited limits")
	}
}
