package model

import (
	"fmt"
	"maps"
	"math"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// FieldError points at the field that is invalid, for example
// "spec.match.path.value".
type FieldError struct {
	Path    string `json:"path"`
	Message string `json:"message"`
}

func (e FieldError) Error() string { return e.Path + ": " + e.Message }

// FieldErrors is a non-empty list of field errors.
type FieldErrors []FieldError

func (es FieldErrors) Error() string {
	msgs := make([]string, len(es))
	for i, e := range es {
		msgs[i] = e.Error()
	}
	return strings.Join(msgs, "; ")
}

// Err returns nil for an empty list so callers can return it as an error.
func (es FieldErrors) Err() error {
	if len(es) == 0 {
		return nil
	}
	return es
}

func (es *FieldErrors) add(path, format string, args ...any) {
	*es = append(*es, FieldError{Path: path, Message: fmt.Sprintf(format, args...)})
}

// Prefixed returns es with prefix + "." prepended to every path.
func (es FieldErrors) Prefixed(prefix string) FieldErrors {
	out := make(FieldErrors, len(es))
	for i, e := range es {
		out[i] = FieldError{Path: prefix + "." + e.Path, Message: e.Message}
	}
	return out
}

var nameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// Validate checks the fields of r on their own. References between resources
// are checked when the configuration is compiled.
func Validate(r Resource) FieldErrors {
	var es FieldErrors
	m := r.Common()
	if !nameRE.MatchString(m.Name) {
		es.add("name", "must be 1-63 lowercase letters, digits or '-', starting and ending with a letter or digit")
	}
	for k := range m.Labels {
		if k == "" {
			es.add("labels", "keys must not be empty")
		}
	}
	switch r := r.(type) {
	case *Listener:
		r.Spec.validate(&es)
	case *Site:
		r.Spec.validate(&es)
	case *Route:
		r.Spec.validate(&es)
	case *Upstream:
		r.Spec.validate(&es)
	case *Certificate:
		r.Spec.validate(&es)
	case *Policy:
		r.Spec.validate(&es)
	}
	return es
}

// TLSVersions maps ListenerTLS.MinVersion values.
var TLSVersions = []string{"1.0", "1.1", "1.2", "1.3"}

func (s *ListenerSpec) validate(es *FieldErrors) {
	if err := checkHostPort(s.Address); err != "" {
		es.add("spec.address", "%s", err)
	}
	if t := s.TLS; t != nil {
		if t.MinVersion != "" && !slices.Contains(TLSVersions, t.MinVersion) {
			es.add("spec.tls.minVersion", "must be one of %s", strings.Join(TLSVersions, ", "))
		}
	}
	if s.HTTP2 && s.TLS == nil {
		es.add("spec.http2", "requires tls")
	}
}

func checkDuration(es *FieldErrors, path, v string) {
	if v == "" {
		return
	}
	d, err := time.ParseDuration(v)
	switch {
	case err != nil:
		es.add(path, "must be a duration such as \"5s\"")
	case d <= 0 || d%time.Millisecond != 0:
		es.add(path, "must be a positive whole number of milliseconds")
	case d > time.Duration(math.MaxUint32)*time.Millisecond:
		es.add(path, "is too long")
	}
}

func (s *CertificateSpec) validate(es *FieldErrors) {
	switch s.Source {
	case "", CertUpload:
		if s.ChainPEM == "" {
			es.add("spec.chainPem", "is required")
		}
		if s.KeyPEM == "" {
			es.add("spec.keyPem", "is required")
		}
		if len(s.Domains) > 0 {
			es.add("spec.domains", "only for source %q", CertACME)
		}
		if s.ChainPEM != "" && s.KeyPEM != "" {
			if _, err := ParseCertificate(s.ChainPEM, s.KeyPEM); err != nil {
				es.add("spec.chainPem", "%v", err)
			}
		}
	case CertACME:
		if len(s.Domains) == 0 {
			es.add("spec.domains", "at least one domain is required")
		}
		for i, d := range s.Domains {
			if !isHostname(d) || strings.HasPrefix(d, ".") {
				es.add(fmt.Sprintf("spec.domains[%d]", i), "must be a lowercase hostname")
			}
		}
	default:
		es.add("spec.source", "must be %q or %q", CertUpload, CertACME)
	}
}

func (s *PolicySpec) validate(es *FieldErrors) {
	for _, o := range []struct {
		t   PolicyType
		set bool
	}{{PolicyHeaders, s.Headers != nil}, {PolicyAccessLog, s.AccessLog != nil}} {
		if o.set && o.t != s.Type {
			es.add("spec."+string(o.t), "must be empty when type is %q", s.Type)
		}
	}
	switch s.Type {
	case PolicyHeaders:
		if s.Headers == nil {
			es.add("spec.headers", "is required when type is %q", s.Type)
			return
		}
		s.Headers.Response.validate(es, "spec.headers.response")
		s.Headers.Request.validate(es, "spec.headers.request")
		if s.Headers.Request.Always {
			es.add("spec.headers.request.always", "applies to responses only")
		}
	case PolicyAccessLog:
		l := s.AccessLog
		if l == nil {
			es.add("spec.accessLog", "is required when type is %q", s.Type)
			return
		}
		if l.Path != "stdout" && l.Path != "stderr" && !strings.HasPrefix(l.Path, "/") {
			es.add("spec.accessLog.path", "must be stdout, stderr or an absolute path")
		}
		if strings.Contains(l.Format, "\n") {
			es.add("spec.accessLog.format", "must be one line")
		}
	default:
		es.add("spec.type", "must be %q or %q", PolicyHeaders, PolicyAccessLog)
	}
}

var headerNameRE = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")

// Headers a policy may not change: framing and connection management are the
// proxy's.
var reservedHeaders = []string{"connection", "content-length", "transfer-encoding", "keep-alive", "upgrade", "te", "trailer", "proxy-connection"}

func checkHeaderName(es *FieldErrors, path, name string) {
	switch {
	case !headerNameRE.MatchString(name):
		es.add(path, "must be a header name")
	case slices.Contains(reservedHeaders, strings.ToLower(name)):
		es.add(path, "%q is managed by the proxy", name)
	}
}

func checkHeaderValue(es *FieldErrors, path, v string) {
	if strings.ContainsAny(v, "\r\n\x00") {
		es.add(path, "must not contain CR, LF or NUL")
	}
}

func (o *HeaderOps) validate(es *FieldErrors, path string) {
	for _, name := range slices.Sorted(maps.Keys(o.Set)) {
		p := fmt.Sprintf("%s.set[%s]", path, name)
		checkHeaderName(es, p, name)
		checkHeaderValue(es, p, o.Set[name])
	}
	for i, h := range o.Add {
		p := fmt.Sprintf("%s.add[%d]", path, i)
		checkHeaderName(es, p+".name", h.Name)
		checkHeaderValue(es, p+".value", h.Value)
	}
	for i, n := range o.Remove {
		checkHeaderName(es, fmt.Sprintf("%s.remove[%d]", path, i), n)
	}
}

func (s *SiteSpec) validate(es *FieldErrors) {
	if len(s.Listeners) == 0 {
		es.add("spec.listeners", "at least one listener is required")
	}
	checkIDs(es, "spec.listeners", s.Listeners)
	for i, h := range s.Hostnames {
		p := fmt.Sprintf("spec.hostnames[%d]", i)
		switch h.Type {
		case HostExact:
			if !isHostname(h.Value) {
				es.add(p+".value", "must be a lowercase hostname")
			}
		case HostWildcard:
			if !isWildcard(h.Value) {
				es.add(p+".value", `must be "*.name", "name.*" or ".name" with a lowercase hostname`)
			}
		case HostRegex:
			// The pattern grammar is PCRE2's; the proxy checks it when it
			// loads the snapshot.
			if h.Value == "" {
				es.add(p+".value", "must not be empty")
			}
		default:
			es.add(p+".type", "must be %q, %q or %q", HostExact, HostWildcard, HostRegex)
		}
	}
	checkIDs(es, "spec.routes", s.Routes)
	checkRewrites(es, "spec.rewrite", s.Rewrite)
	if s.Return != nil {
		s.Return.validate(es, "spec.return")
	}
	checkErrorPages(es, "spec.errorPages", s.ErrorPages)
	checkIDs(es, "spec.certificates", s.Certificates)
	checkIDs(es, "spec.policies", s.Policies)
}

func checkRewrites(es *FieldErrors, path string, rs []Rewrite) {
	for i, r := range rs {
		p := fmt.Sprintf("%s[%d]", path, i)
		// PCRE2 grammar is checked by the proxy when it loads the snapshot.
		if r.Regex == "" {
			es.add(p+".regex", "must not be empty")
		}
		if r.Replacement == "" {
			es.add(p+".replacement", "must not be empty")
		}
		switch r.Flag {
		case RewriteNext, RewriteLast, RewriteBreak, RewriteRedirect, RewritePermanent:
		default:
			es.add(p+".flag", "must be empty, %q, %q, %q or %q", RewriteLast, RewriteBreak, RewriteRedirect, RewritePermanent)
		}
	}
}

func checkErrorPages(es *FieldErrors, path string, eps []ErrorPage) {
	for i, e := range eps {
		p := fmt.Sprintf("%s[%d]", path, i)
		if len(e.Codes) == 0 {
			es.add(p+".codes", "at least one code is required")
		}
		for j, c := range e.Codes {
			// nginx error_page accepts 300-599.
			if c < 300 || c > 599 {
				es.add(fmt.Sprintf("%s.codes[%d]", p, j), "must be 300-599")
			}
		}
		switch {
		case (e.URI == "") == (e.Route == ""):
			es.add(p, "exactly one of uri and route is required")
		case e.URI != "" && !isTarget(e.URI):
			es.add(p+".uri", "must start with '/', '$', \"http://\" or \"https://\"")
		}
		if e.Status != nil && *e.Status != 0 && (*e.Status < 100 || *e.Status > 999) {
			es.add(p+".status", "must be 0 or 100-999")
		}
	}
}

// isTarget accepts a path, an absolute http(s) URL, or a template whose
// first variable supplies either.
func isTarget(s string) bool {
	return strings.HasPrefix(s, "/") || strings.HasPrefix(s, "$") ||
		strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

func (r *ReturnAction) validate(es *FieldErrors, path string) {
	if r.Status > 999 {
		es.add(path+".status", "must be 0-999")
	}
	if isRedirect(r.Status) && r.Text == "" {
		es.add(path+".text", "is required for a redirect")
	}
}

func isRedirect(status uint32) bool {
	switch status {
	case 301, 302, 303, 307, 308:
		return true
	}
	return false
}

func checkIDs(es *FieldErrors, path string, ids []string) {
	seen := make(map[string]bool, len(ids))
	for i, id := range ids {
		switch {
		case id == "":
			es.add(fmt.Sprintf("%s[%d]", path, i), "must not be empty")
		case seen[id]:
			es.add(fmt.Sprintf("%s[%d]", path, i), "duplicate %q", id)
		}
		seen[id] = true
	}
}

func (s *RouteSpec) validate(es *FieldErrors) {
	p := s.Match.Path
	switch p.Type {
	case PathExact, PathPrefix, PathPrefixPriority:
		if !strings.HasPrefix(p.Value, "/") {
			es.add("spec.match.path.value", "must start with '/'")
		}
	case PathRegex, PathRegexCI:
		// PCRE2 grammar is checked by the proxy when it loads the snapshot.
		if p.Value == "" {
			es.add("spec.match.path.value", "must not be empty")
		}
	default:
		es.add("spec.match.path.type", "must be one of %q, %q, %q, %q, %q",
			PathExact, PathPrefix, PathPrefixPriority, PathRegex, PathRegexCI)
	}

	s.Match.validateConditions(es)
	checkRewrites(es, "spec.rewrite", s.Rewrite)
	checkIDs(es, "spec.children", s.Children)
	if len(s.Children) > 0 && p.Type != PathPrefix && p.Type != PathPrefixPriority {
		es.add("spec.children", "only prefix and prefixPriority routes can have children")
	}
	checkErrorPages(es, "spec.errorPages", s.ErrorPages)
	checkIDs(es, "spec.policies", s.Policies)

	a := s.Action
	for _, o := range []struct {
		t   ActionType
		set bool
	}{{ActionStatic, a.Static != nil}, {ActionProxy, a.Proxy != nil}, {ActionReturn, a.Return != nil}} {
		if o.set && o.t != a.Type {
			es.add("spec.action."+string(o.t), "must be empty when type is %q", a.Type)
		}
	}
	switch a.Type {
	case ActionStatic:
		if a.Static == nil {
			es.add("spec.action.static", "is required when type is %q", a.Type)
			return
		}
		if !strings.HasPrefix(a.Static.Root, "/") {
			es.add("spec.action.static.root", "must be an absolute path")
		}
		for i, idx := range a.Static.Index {
			if idx == "" || strings.Contains(idx, "/") {
				es.add(fmt.Sprintf("spec.action.static.index[%d]", i), "must be a file name")
			}
		}
		if t := a.Static.TryFiles; t != nil {
			t.validate(es, "spec.action.static.tryFiles")
		}
	case ActionProxy:
		if a.Proxy == nil {
			es.add("spec.action.proxy", "is required when type is %q", a.Type)
			return
		}
		if a.Proxy.Upstream == "" {
			es.add("spec.action.proxy.upstream", "is required")
		}
		t := a.Proxy.Timeouts
		checkDuration(es, "spec.action.proxy.timeouts.connect", t.Connect)
		checkDuration(es, "spec.action.proxy.timeouts.send", t.Send)
		checkDuration(es, "spec.action.proxy.timeouts.read", t.Read)
		if r := a.Proxy.Retry; r != nil {
			for i, on := range r.On {
				if _, ok := RetryConditions[on]; !ok {
					es.add(fmt.Sprintf("spec.action.proxy.retry.on[%d]", i), "unknown condition %q", on)
				}
			}
		}
	case ActionReturn:
		if a.Return == nil {
			es.add("spec.action.return", "is required when type is %q", a.Type)
			return
		}
		a.Return.validate(es, "spec.action.return")
	default:
		es.add("spec.action.type", "must be %q, %q or %q", ActionStatic, ActionProxy, ActionReturn)
	}
}

func (t *TryFiles) validate(es *FieldErrors, path string) {
	if len(t.Files) == 0 {
		es.add(path+".files", "at least one file is required")
	}
	for i, f := range t.Files {
		if f == "" {
			es.add(fmt.Sprintf("%s.files[%d]", path, i), "must not be empty")
		}
	}
	n := 0
	for _, ok := range []bool{t.URI != "", t.Status != 0, t.Route != ""} {
		if ok {
			n++
		}
	}
	switch {
	case n != 1:
		es.add(path, "exactly one of uri, status and route is required")
	case t.URI != "" && !strings.HasPrefix(t.URI, "/") && !strings.HasPrefix(t.URI, "$"):
		es.add(path+".uri", "must start with '/' or '$'")
	case t.Status != 0 && (t.Status < 100 || t.Status > 999):
		es.add(path+".status", "must be 100-999")
	}
}

func (s *UpstreamSpec) validate(es *FieldErrors) {
	if len(s.Targets) == 0 {
		es.add("spec.targets", "at least one target is required")
	}
	primary := 0
	for i, t := range s.Targets {
		if err := checkHostPort(t.Address); err != "" {
			es.add(fmt.Sprintf("spec.targets[%d].address", i), "%s", err)
		}
		if !t.Backup {
			primary++
		}
	}
	if len(s.Targets) > 0 && primary == 0 {
		es.add("spec.targets", "at least one target must not be a backup")
	}
	switch s.Balancing.Algorithm {
	case "", RoundRobin, LeastConn:
	default:
		es.add("spec.balancing.algorithm", "must be %q or %q", RoundRobin, LeastConn)
	}
	checkDuration(es, "spec.passiveHealth.failTimeout", s.PassiveHealth.FailTimeout)
	checkDuration(es, "spec.keepalive.timeout", s.Keepalive.Timeout)
}

// checkHostPort returns a message if addr is not host:port with a numeric port.
func checkHostPort(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "must be host:port"
	}
	if host == "" {
		return "host must not be empty"
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return "port must be 1-65535"
	}
	return ""
}

func isHostname(s string) bool {
	return s != "" && s == strings.ToLower(s) && !strings.ContainsAny(s, " \t/:*")
}

// isWildcard accepts the nginx server_name wildcard forms: one "*" as the
// whole first or last label, or a leading dot.
func isWildcard(s string) bool {
	switch {
	case strings.HasPrefix(s, "*."):
		return isHostname(s[2:])
	case strings.HasSuffix(s, ".*"):
		return isHostname(s[:len(s)-2])
	case strings.HasPrefix(s, "."):
		return isHostname(s[1:])
	}
	return false
}

var methodRE = regexp.MustCompile(`^[A-Z]+$`)

func (m *Match) validateConditions(es *FieldErrors) {
	for i, method := range m.Methods {
		if !methodRE.MatchString(method) {
			es.add(fmt.Sprintf("spec.match.methods[%d]", i), "must be an uppercase method name")
		}
	}
	checkValueMatches(es, "spec.match.headers", m.Headers)
	checkValueMatches(es, "spec.match.query", m.Query)
	if m.Expr != "" {
		if err := CheckExpr(m.Expr); err != nil {
			es.add("spec.match.expr", "%v", err)
		}
	}
}

func checkValueMatches(es *FieldErrors, path string, ms []ValueMatch) {
	for i, v := range ms {
		p := fmt.Sprintf("%s[%d]", path, i)
		if v.Name == "" {
			es.add(p+".name", "is required")
		}
		switch v.Op {
		case OpPresent, OpAbsent:
			if v.Value != "" {
				es.add(p+".value", "must be empty for op %q", v.Op)
			}
		case OpEquals, OpPrefix, OpSuffix, OpContains:
		case OpRegex:
			if v.Value == "" {
				es.add(p+".value", "must not be empty")
			}
		default:
			es.add(p+".op", "must be one of %q, %q, %q, %q, %q, %q, %q",
				OpPresent, OpAbsent, OpEquals, OpPrefix, OpSuffix, OpContains, OpRegex)
		}
	}
}
