package model

import (
	"encoding/pem"
	"fmt"
	"maps"
	"math"
	"net"
	"net/netip"
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
	if m.Group != "" && !strings.HasPrefix(m.Group, "grp_") {
		es.add("group", "must be a group ID")
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
	case *Lookup:
		r.Spec.validate(&es, r.VariableName())
	case *Stream:
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
		checkTLSVersions(es, "spec.tls", t.MinVersion, t.MaxVersion)
		if t.DHParams != "" {
			checkPEM(es, "spec.tls.dhParams", t.DHParams, "DH PARAMETERS")
		}
		if a := t.ClientAuth; a != nil {
			switch a.Mode {
			case ClientAuthRequire, ClientAuthOptional:
				if a.CA == "" {
					es.add("spec.tls.clientAuth.ca", "required unless mode is optional_no_ca")
				}
			case ClientAuthOptionalNoCA:
			default:
				es.add("spec.tls.clientAuth.mode", "must be require, optional or optional_no_ca")
			}
			if a.CA != "" {
				checkPEM(es, "spec.tls.clientAuth.ca", a.CA, "CERTIFICATE")
			}
		}
	}
	if s.HTTP2 && s.TLS == nil {
		es.add("spec.http2", "requires tls")
	}
}

func (s *StreamSpec) validate(es *FieldErrors) {
	if err := checkHostPort(s.Address); err != "" {
		es.add("spec.address", "%s", err)
	}
	switch s.Protocol {
	case "", StreamTCP:
	case StreamUDP:
		if s.TLS != nil || s.SSLPreread || s.ProxyProtocol {
			es.add("spec.protocol", "tls, sslPreread and proxyProtocol need tcp")
		}
	default:
		es.add("spec.protocol", "must be tcp or udp")
	}
	if s.Protocol != StreamUDP && s.Responses != nil {
		es.add("spec.responses", "only for udp")
	}
	if t := s.TLS; t != nil {
		if t.DefaultCertificate == "" {
			es.add("spec.tls.defaultCertificate", "required")
		}
		if s.SSLPreread {
			es.add("spec.sslPreread", "conflicts with tls")
		}
		(&ListenerSpec{Address: s.Address, TLS: t}).validate(es)
	}
	if len(s.Routes) == 0 {
		es.add("spec.routes", "at least one route is required")
	}
	for i, r := range s.Routes {
		if r.Upstream == "" {
			es.add(fmt.Sprintf("spec.routes[%d].upstream", i), "required")
		}
		for j, h := range r.ServerNames {
			h.validate(es, fmt.Sprintf("spec.routes[%d].serverNames[%d]", i, j))
		}
		if len(r.ServerNames) > 0 && s.TLS == nil && !s.SSLPreread {
			es.add(fmt.Sprintf("spec.routes[%d].serverNames", i), "need tls or sslPreread")
		}
	}
	checkDuration(es, "spec.connectTimeout", s.ConnectTimeout)
	checkDuration(es, "spec.timeout", s.Timeout)
}

func checkTLSVersions(es *FieldErrors, path, lo, hi string) {
	for _, v := range [][2]string{{"minVersion", lo}, {"maxVersion", hi}} {
		if v[1] != "" && !slices.Contains(TLSVersions, v[1]) {
			es.add(path+"."+v[0], "must be one of %s", strings.Join(TLSVersions, ", "))
		}
	}
	if lo != "" && hi != "" && slices.Index(TLSVersions, lo) > slices.Index(TLSVersions, hi) {
		es.add(path+".maxVersion", "must not be below minVersion")
	}
}

// checkPEM requires at least one PEM block, all of type kind.
func checkPEM(es *FieldErrors, path, v, kind string) {
	rest := []byte(v)
	n := 0
	for {
		b, r := pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != kind {
			es.add(path, "has a %s block; want %s", b.Type, kind)
			return
		}
		n++
		rest = r
	}
	if n == 0 || strings.TrimSpace(string(rest)) != "" {
		es.add(path, "must be PEM %s blocks", kind)
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
			if !IsHostname(d) || strings.HasPrefix(d, ".") {
				es.add(fmt.Sprintf("spec.domains[%d]", i), "must be a lowercase hostname")
			}
		}
	default:
		es.add("spec.source", "must be %q or %q", CertUpload, CertACME)
	}
}

func (s *PolicySpec) validate(es *FieldErrors) {
	set := map[PolicyType]bool{
		PolicyHeaders:     s.Headers != nil,
		PolicyAccessLog:   s.AccessLog != nil,
		PolicyRateLimit:   s.RateLimit != nil,
		PolicyConnLimit:   s.ConnLimit != nil,
		PolicyBandwidth:   s.Bandwidth != nil,
		PolicyIPAccess:    s.IPAccess != nil,
		PolicyBasicAuth:   s.BasicAuth != nil,
		PolicyForwardAuth: s.ForwardAuth != nil,
		PolicyRealIP:      s.RealIP != nil,
		PolicyCompression: s.Compression != nil,
		PolicyCache:       s.Cache != nil,
	}
	for _, t := range slices.Sorted(maps.Keys(set)) {
		if set[t] && t != s.Type {
			es.add("spec."+string(t), "must be empty when type is %q", s.Type)
		}
	}
	if _, known := set[s.Type]; !known {
		es.add("spec.type", "must be one of %s", quotedList(slices.Sorted(maps.Keys(set))))
		return
	}
	if !set[s.Type] {
		es.add("spec."+string(s.Type), "is required when type is %q", s.Type)
		return
	}
	switch s.Type {
	case PolicyHeaders:
		s.Headers.Response.validate(es, "spec.headers.response")
		s.Headers.Request.validate(es, "spec.headers.request")
		if s.Headers.Request.Always {
			es.add("spec.headers.request.always", "applies to responses only")
		}
	case PolicyAccessLog:
		l := s.AccessLog
		if l.Path != "stdout" && l.Path != "stderr" && !strings.HasPrefix(l.Path, "/") {
			es.add("spec.accessLog.path", "must be stdout, stderr or an absolute path")
		}
		if strings.Contains(l.Format, "\n") {
			es.add("spec.accessLog.format", "must be one line")
		}
	case PolicyRateLimit:
		r := s.RateLimit
		if _, err := ParseRate(r.Rate); err != nil {
			es.add("spec.rateLimit.rate", "%s", err)
		}
		if r.NoDelay && r.Delay != 0 {
			es.add("spec.rateLimit.delay", "must be empty with noDelay")
		}
		if r.Delay > r.Burst {
			es.add("spec.rateLimit.delay", "must not exceed burst")
		}
		checkLimitStatus(es, "spec.rateLimit.status", r.Status)
		checkOneLine(es, "spec.rateLimit.key", r.Key)
	case PolicyConnLimit:
		c := s.ConnLimit
		if c.Max == 0 {
			es.add("spec.connLimit.max", "must be positive")
		}
		checkLimitStatus(es, "spec.connLimit.status", c.Status)
		checkOneLine(es, "spec.connLimit.key", c.Key)
	case PolicyBandwidth:
		b := s.Bandwidth
		if n, err := ParseSize(b.Rate); err != nil || n == 0 {
			es.add("spec.bandwidth.rate", "must be a positive size such as \"100k\"")
		}
		if b.After != "" {
			if _, err := ParseSize(b.After); err != nil {
				es.add("spec.bandwidth.after", "must be a size such as \"500k\"")
			}
		}
	case PolicyIPAccess:
		if len(s.IPAccess.Rules) == 0 {
			es.add("spec.ipAccess.rules", "at least one rule is required")
		}
		for i, r := range s.IPAccess.Rules {
			p := fmt.Sprintf("spec.ipAccess.rules[%d]", i)
			if r.Action != "allow" && r.Action != "deny" {
				es.add(p+".action", "must be \"allow\" or \"deny\"")
			}
			if r.From != "all" && !validCIDR(r.From) {
				es.add(p+".from", "must be a CIDR, an address or \"all\"")
			}
		}
	case PolicyBasicAuth:
		b := s.BasicAuth
		if b.Realm == "" {
			es.add("spec.basicAuth.realm", "is required")
		}
		checkOneLine(es, "spec.basicAuth.realm", b.Realm)
		if len(b.Users) == 0 {
			es.add("spec.basicAuth.users", "at least one user is required")
		}
		seen := map[string]bool{}
		for i, u := range b.Users {
			p := fmt.Sprintf("spec.basicAuth.users[%d]", i)
			if u.Name == "" || strings.ContainsAny(u.Name, ":\r\n") {
				es.add(p+".name", "must be non-empty without a colon")
			}
			if seen[u.Name] {
				es.add(p+".name", "duplicate user %q", u.Name)
			}
			seen[u.Name] = true
			if !knownPasswordHash(u.Hash) {
				es.add(p+".hash", "must be a bcrypt, $apr1$, $1$, $5$, $6$, {SHA} or {SSHA} hash")
			}
		}
	case PolicyForwardAuth:
		f := s.ForwardAuth
		if f.Upstream == "" {
			es.add("spec.forwardAuth.upstream", "is required")
		}
		if f.URI != "" && !strings.HasPrefix(f.URI, "/") {
			es.add("spec.forwardAuth.uri", "must start with /")
		}
		checkOneLine(es, "spec.forwardAuth.uri", f.URI)
		checkDuration(es, "spec.forwardAuth.timeout", f.Timeout)
		for i, h := range f.CopyHeaders {
			checkHeaderName(es, fmt.Sprintf("spec.forwardAuth.copyHeaders[%d]", i), h)
		}
	case PolicyRealIP:
		r := s.RealIP
		if len(r.From) == 0 {
			es.add("spec.realIp.from", "at least one trusted address is required")
		}
		for i, f := range r.From {
			if !validCIDR(f) {
				es.add(fmt.Sprintf("spec.realIp.from[%d]", i), "must be a CIDR or an address")
			}
		}
		if r.Header != "" && !headerNameRE.MatchString(r.Header) {
			es.add("spec.realIp.header", "must be a header name")
		}
	case PolicyCompression:
		s.Compression.validate(es)
	case PolicyCache:
		s.Cache.validate(es)
	}
}

func (c *CachePolicy) validate(es *FieldErrors) {
	for _, part := range strings.Split(c.Path, "/") {
		if part == "." || part == ".." {
			es.add("spec.cache.path", "must not have . or .. parts")
			break
		}
	}
	if strings.ContainsAny(c.Path, "\x00\n") {
		es.add("spec.cache.path", "must be one line")
	}
	if len(c.Levels) > 3 {
		es.add("spec.cache.levels", "at most three levels")
	}
	for i, l := range c.Levels {
		if l != 1 && l != 2 {
			es.add(fmt.Sprintf("spec.cache.levels[%d]", i), "must be 1 or 2")
		}
	}
	if c.MaxSize != "" {
		if _, err := ParseSize(c.MaxSize); err != nil {
			es.add("spec.cache.maxSize", "must be a size such as \"1g\"")
		}
	}
	checkSeconds(es, "spec.cache.inactive", c.Inactive)
	if c.Slice != "" {
		if n, err := ParseSize(c.Slice); err != nil || n == 0 {
			es.add("spec.cache.slice", "must be a positive size such as \"1m\"")
		} else if c.Key != "" && !strings.Contains(c.Key, "$slice_range") {
			es.add("spec.cache.key", "must include $slice_range with slice")
		}
	}
	checkOneLine(es, "spec.cache.key", c.Key)
	for i, v := range c.Valid {
		p := fmt.Sprintf("spec.cache.valid[%d]", i)
		if v.Time == "" {
			es.add(p+".time", "is required")
		}
		checkSeconds(es, p+".time", v.Time)
		for j, s := range v.Statuses {
			if s == "any" && len(v.Statuses) == 1 {
				continue
			}
			if n, err := strconv.Atoi(s); err != nil || n < 100 || n > 599 {
				es.add(fmt.Sprintf("%s.statuses[%d]", p, j), "must be a status 100-599, or \"any\" alone")
			}
		}
	}
	for i, m := range c.Methods {
		if m == "" || strings.ToUpper(m) != m || strings.ContainsAny(m, " \t\r\n") {
			es.add(fmt.Sprintf("spec.cache.methods[%d]", i), "must be an uppercase method")
		}
	}
	for _, e := range []struct{ path, src string }{{"spec.cache.bypass", c.Bypass}, {"spec.cache.noStore", c.NoStore}} {
		if e.src == "" {
			continue
		}
		if err := CheckExpr(e.src); err != nil {
			es.add(e.path, "%s", err)
		}
	}
	checkDuration(es, "spec.cache.lockTimeout", c.LockTimeout)
	for i, u := range c.UseStale {
		if !slices.Contains(CacheUseStale, u) {
			es.add(fmt.Sprintf("spec.cache.useStale[%d]", i), "must be one of %s", strings.Join(CacheUseStale, ", "))
		}
	}
	if c.BackgroundUpdate && !slices.Contains(c.UseStale, "updating") {
		es.add("spec.cache.backgroundUpdate", "needs useStale \"updating\"")
	}
	for i, h := range c.Ignore {
		if !slices.ContainsFunc(CacheIgnore, func(v string) bool { return strings.EqualFold(v, h) }) {
			es.add(fmt.Sprintf("spec.cache.ignore[%d]", i), "must be one of %s", strings.Join(CacheIgnore, ", "))
		}
	}
}

// checkSeconds reports v unless it is empty or a positive whole number of
// seconds that fits 32 bits.
func checkSeconds(es *FieldErrors, path, v string) {
	if v == "" {
		return
	}
	d, err := time.ParseDuration(v)
	switch {
	case err != nil:
		es.add(path, "must be a duration such as \"10m\"")
	case d <= 0 || d%time.Second != 0:
		es.add(path, "must be a positive whole number of seconds")
	case d > time.Duration(math.MaxUint32)*time.Second:
		es.add(path, "is too long")
	}
}

// CompressionEncodings are the dynamic encodings by token.
var CompressionEncodings = []string{"gzip", "br", "zstd"}

// CompressionProxied are the gzip_proxied flags.
var CompressionProxied = []string{"expired", "no-cache", "no-store", "private", "no_last_modified", "no_etag", "auth", "any"}

func (c *CompressionPolicy) validate(es *FieldErrors) {
	seen := map[string]bool{}
	for i, e := range c.Encodings {
		p := fmt.Sprintf("spec.compression.encodings[%d]", i)
		if !slices.Contains(CompressionEncodings, e) {
			es.add(p, "must be one of %s", strings.Join(CompressionEncodings, ", "))
		}
		if seen[e] {
			es.add(p, "duplicate encoding %q", e)
		}
		seen[e] = true
	}
	for i, t := range c.Types {
		if t != "*" && (!strings.Contains(t, "/") || strings.ContainsAny(t, " ;,\r\n")) {
			es.add(fmt.Sprintf("spec.compression.types[%d]", i), "must be a media type such as \"text/css\" or \"*\"")
		}
	}
	if c.MinLength != "" {
		if n, err := ParseSize(c.MinLength); err != nil || n > math.MaxUint32 {
			es.add("spec.compression.minLength", "must be a size such as \"1k\"")
		}
	}
	if c.GzipLevel > 9 {
		es.add("spec.compression.gzipLevel", "must be 1-9")
	}
	if c.BrotliLevel != nil && *c.BrotliLevel > 11 {
		es.add("spec.compression.brotliLevel", "must be 0-11")
	}
	if c.ZstdLevel > 22 {
		es.add("spec.compression.zstdLevel", "must be 1-22")
	}
	for i, f := range c.Proxied {
		if !slices.Contains(CompressionProxied, f) {
			es.add(fmt.Sprintf("spec.compression.proxied[%d]", i), "must be one of %s", strings.Join(CompressionProxied, ", "))
		}
	}
	switch c.Static {
	case "", "on", "always":
	default:
		es.add("spec.compression.static", "must be \"on\" or \"always\"")
	}
	checkOneLine(es, "spec.compression.disable", c.Disable)
	if len(c.Encodings) == 0 && c.Static == "" && !c.Gunzip {
		es.add("spec.compression", "needs encodings, static or gunzip")
	}
}

var variableRE = regexp.MustCompile(`^[a-z0-9_]{1,63}$`)

func (s *LookupSpec) validate(es *FieldErrors, variable string) {
	if !variableRE.MatchString(variable) {
		es.add("spec.variable", "must be 1-63 lowercase letters, digits or '_'")
	}
	checkOneLine(es, "spec.source", s.Source)
	set := map[LookupType]bool{LookupMap: s.Map != nil, LookupGeo: s.Geo != nil, LookupSplit: s.Split != nil}
	for _, t := range []LookupType{LookupMap, LookupGeo, LookupSplit} {
		if set[t] && t != s.Type {
			es.add("spec."+string(t), "must be empty when type is %q", s.Type)
		}
	}
	if _, known := set[s.Type]; !known {
		es.add("spec.type", "must be %q, %q or %q", LookupMap, LookupGeo, LookupSplit)
		return
	}
	if !set[s.Type] {
		es.add("spec."+string(s.Type), "is required when type is %q", s.Type)
		return
	}
	if s.Type != LookupGeo && s.Source == "" {
		es.add("spec.source", "is required for %s", s.Type)
	}
	switch s.Type {
	case LookupMap:
		checkOneLine(es, "spec.map.default", s.Map.Default)
		exact := map[string]bool{}
		for i, e := range s.Map.Entries {
			p := fmt.Sprintf("spec.map.entries[%d]", i)
			switch e.Match {
			case "", MapExact:
				k := strings.ToLower(e.Key)
				if exact[k] {
					es.add(p+".key", "duplicate key %q", e.Key)
				}
				exact[k] = true
			case MapRegex, MapRegexCI:
				if e.Key == "" {
					es.add(p+".key", "must not be empty")
				}
			default:
				es.add(p+".match", "must be %q, %q or %q", MapExact, MapRegex, MapRegexCI)
			}
			checkOneLine(es, p+".key", e.Key)
			checkOneLine(es, p+".value", e.Value)
		}
	case LookupGeo:
		checkOneLine(es, "spec.geo.default", s.Geo.Default)
		seen := map[netip.Prefix]bool{}
		for i, e := range s.Geo.Entries {
			p := fmt.Sprintf("spec.geo.entries[%d]", i)
			n, ok := ParseNetwork(e.Network)
			if !ok {
				es.add(p+".network", "must be a CIDR or an address")
			} else if seen[n] {
				es.add(p+".network", "duplicate network %s", n)
			}
			seen[n] = true
			checkOneLine(es, p+".value", e.Value)
		}
	case LookupSplit:
		if len(s.Split.Buckets) == 0 {
			es.add("spec.split.buckets", "at least one bucket is required")
		}
		var sum uint64
		for i, b := range s.Split.Buckets {
			p := fmt.Sprintf("spec.split.buckets[%d]", i)
			if b.Percent == "*" {
				if i != len(s.Split.Buckets)-1 {
					es.add(p+".percent", "\"*\" must be the last bucket")
				}
			} else if n, ok := ParsePercent(b.Percent); !ok || n == 0 {
				es.add(p+".percent", "must be a percentage such as \"20%%\" or \"0.5%%\", or \"*\"")
			} else {
				sum += uint64(n)
			}
			checkOneLine(es, p+".value", b.Value)
		}
		if sum > 10000 {
			es.add("spec.split.buckets", "percentages must not exceed 100%%")
		}
	}
}

// ParseNetwork parses a CIDR or a single address, masked.
func ParseNetwork(s string) (netip.Prefix, bool) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), true
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(a, a.BitLen()), true
}

// ParsePercent parses "20%" or "0.25%" into basis points, two decimals as
// nginx split_clients.
func ParsePercent(s string) (uint32, bool) {
	n, ok := strings.CutSuffix(s, "%")
	if !ok || n == "" {
		return 0, false
	}
	whole, frac, _ := strings.Cut(n, ".")
	if len(frac) > 2 || whole == "" {
		return 0, false
	}
	frac += strings.Repeat("0", 2-len(frac))
	w, err1 := strconv.ParseUint(whole, 10, 32)
	f, err2 := strconv.ParseUint(frac, 10, 32)
	if err1 != nil || err2 != nil || w > 100 {
		return 0, false
	}
	return uint32(w*100 + f), true
}

func quotedList(ts []PolicyType) string {
	q := make([]string, len(ts))
	for i, t := range ts {
		q[i] = strconv.Quote(string(t))
	}
	return strings.Join(q, ", ")
}

func checkLimitStatus(es *FieldErrors, path string, s uint32) {
	if s != 0 && (s < 400 || s > 599) {
		es.add(path, "must be 400-599")
	}
}

func checkOneLine(es *FieldErrors, path, v string) {
	if strings.ContainsAny(v, "\r\n\x00") {
		es.add(path, "must be one line")
	}
}

func validCIDR(s string) bool {
	if _, err := netip.ParsePrefix(s); err == nil {
		return true
	}
	_, err := netip.ParseAddr(s)
	return err == nil
}

func knownPasswordHash(h string) bool {
	for _, p := range []string{"$2a$", "$2b$", "$2y$", "$apr1$", "$1$", "$5$", "$6$", "{SHA}", "{SSHA}", "{PLAIN}"} {
		if strings.HasPrefix(h, p) && len(h) > len(p) {
			return true
		}
	}
	return false
}

// ParseRate parses an nginx rate, "Nr/s" or "Nr/m", into requests per 1000
// seconds.
func ParseRate(s string) (uint64, error) {
	n, unit, ok := strings.Cut(s, "r/")
	v, err := strconv.ParseUint(n, 10, 32)
	if !ok || err != nil || v == 0 {
		return 0, fmt.Errorf("must be a rate such as \"10r/s\" or \"30r/m\"")
	}
	switch unit {
	case "s":
		return v * 1000, nil
	case "m":
		return v * 1000 / 60, nil
	}
	return 0, fmt.Errorf("must be a rate such as \"10r/s\" or \"30r/m\"")
}

// ParseSize parses an nginx size: bytes, or with a k or m suffix.
func ParseSize(s string) (uint64, error) {
	mult := uint64(1)
	switch {
	case strings.HasSuffix(s, "k"), strings.HasSuffix(s, "K"):
		mult, s = 1024, s[:len(s)-1]
	case strings.HasSuffix(s, "m"), strings.HasSuffix(s, "M"):
		mult, s = 1024*1024, s[:len(s)-1]
	case strings.HasSuffix(s, "g"), strings.HasSuffix(s, "G"):
		mult, s = 1024*1024*1024, s[:len(s)-1]
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil || v > math.MaxUint64/mult {
		return 0, fmt.Errorf("bad size %q", s)
	}
	return v * mult, nil
}

var headerNameRE = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")

// Headers a policy may not change: framing and connection management are the
// proxy's.
// ReservedHeaders are hop-by-hop and framing headers the proxy sets itself.
var ReservedHeaders = []string{"connection", "content-length", "transfer-encoding", "keep-alive", "upgrade", "te", "trailer", "proxy-connection"}

func checkHeaderName(es *FieldErrors, path, name string) {
	switch {
	case !headerNameRE.MatchString(name):
		es.add(path, "must be a header name")
	case slices.Contains(ReservedHeaders, strings.ToLower(name)):
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

func (h HostMatch) validate(es *FieldErrors, p string) {
	switch h.Type {
	case HostExact:
		if !IsHostname(h.Value) {
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

func (s *SiteSpec) validate(es *FieldErrors) {
	if len(s.Listeners) == 0 {
		es.add("spec.listeners", "at least one listener is required")
	}
	checkIDs(es, "spec.listeners", s.Listeners)
	for i, h := range s.Hostnames {
		h.validate(es, fmt.Sprintf("spec.hostnames[%d]", i))
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
	}{
		{ActionStatic, a.Static != nil}, {ActionProxy, a.Proxy != nil}, {ActionReturn, a.Return != nil},
		{ActionGateway, a.Gateway != nil}, {ActionMemcached, a.Memcached != nil}, {ActionGrpc, a.Grpc != nil},
	} {
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
		a.Proxy.validate(es, "spec.action.proxy")
	case ActionGrpc:
		if a.Grpc == nil {
			es.add("spec.action.grpc", "is required when type is %q", a.Type)
			return
		}
		a.Grpc.validate(es, "spec.action.grpc")
	case ActionMemcached:
		if a.Memcached == nil {
			es.add("spec.action.memcached", "is required when type is %q", a.Type)
			return
		}
		a.Memcached.ProxyAction.validate(es, "spec.action.memcached")
	case ActionGateway:
		if a.Gateway == nil {
			es.add("spec.action.gateway", "is required when type is %q", a.Type)
			return
		}
		a.Gateway.validate(es, "spec.action.gateway")
	case ActionReturn:
		if a.Return == nil {
			es.add("spec.action.return", "is required when type is %q", a.Type)
			return
		}
		a.Return.validate(es, "spec.action.return")
	default:
		es.add("spec.action.type", "must be one of %q, %q, %q, %q, %q, %q",
			ActionStatic, ActionProxy, ActionReturn, ActionGateway, ActionMemcached, ActionGrpc)
	}
}

func (p *ProxyAction) validate(es *FieldErrors, path string) {
	if p.Upstream == "" {
		es.add(path+".upstream", "is required")
	}
	t := p.Timeouts
	checkDuration(es, path+".timeouts.connect", t.Connect)
	checkDuration(es, path+".timeouts.send", t.Send)
	checkDuration(es, path+".timeouts.read", t.Read)
	if r := p.Retry; r != nil {
		for i, on := range r.On {
			if _, ok := RetryConditions[on]; !ok {
				es.add(fmt.Sprintf("%s.retry.on[%d]", path, i), "unknown condition %q", on)
			}
		}
	}
}

// gatewayParamRE is a CGI-style param name.
var gatewayParamRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,255}$`)

func (g *GatewayAction) validate(es *FieldErrors, path string) {
	switch g.Protocol {
	case GatewayFastCGI, GatewayUwsgi, GatewaySCGI:
	default:
		es.add(path+".protocol", "must be one of %q, %q, %q", GatewayFastCGI, GatewayUwsgi, GatewaySCGI)
	}
	g.ProxyAction.validate(es, path)
	for i, p := range g.Params {
		if !gatewayParamRE.MatchString(p.Name) {
			es.add(fmt.Sprintf("%s.params[%d].name", path, i), "must be letters, digits, '_', '.' or '-'")
		}
	}
	if g.DocumentRoot != "" && !strings.HasPrefix(g.DocumentRoot, "/") {
		es.add(path+".documentRoot", "must be an absolute path")
	}
	if strings.Contains(g.Index, "/") {
		es.add(path+".index", "must be a file name")
	}
	if g.SplitPathInfo != "" && strings.Count(g.SplitPathInfo, "(")-strings.Count(g.SplitPathInfo, `\(`) < 2 {
		es.add(path+".splitPathInfo", "needs two groups: the script name and the path info")
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
	if t := s.TLS; t != nil {
		checkTLSVersions(es, "spec.tls", t.MinVersion, t.MaxVersion)
		if t.CA != "" {
			checkPEM(es, "spec.tls.ca", t.CA, "CERTIFICATE")
		}
		if t.ServerName != "" && strings.ContainsAny(t.ServerName, " /:") {
			es.add("spec.tls.serverName", "must be a host name")
		}
	}
	primary := 0
	for i, t := range s.Targets {
		p := fmt.Sprintf("spec.targets[%d]", i)
		if err := checkHostPort(t.Address); err != "" {
			es.add(p+".address", "%s", err)
		}
		if !t.Backup {
			primary++
		}
		if t.Backup && hashing(s.Balancing.Algorithm) {
			// nginx: hash, ip_hash and random do not take backup servers.
			es.add(p+".backup", "is not supported with %s balancing", s.Balancing.Algorithm)
		}
		checkDuration(es, p+".slowStart", t.SlowStart)
		checkDuration(es, p+".resolveInterval", t.ResolveInterval)
		if t.ResolveInterval != "" && !t.Resolve {
			es.add(p+".resolveInterval", "requires resolve")
		}
		if t.Route != "" && (s.Sticky == nil || s.Sticky.Type != StickyRoute) {
			es.add(p+".route", "requires route sticky sessions")
		}
	}
	if len(s.Targets) > 0 && primary == 0 {
		es.add("spec.targets", "at least one target must not be a backup")
	}
	switch s.Balancing.Algorithm {
	case "", RoundRobin, LeastConn, IPHash, Random, RandomTwo:
		if s.Balancing.Key != "" {
			es.add("spec.balancing.key", "is only used by hash and hash_consistent")
		}
	case Hash, HashConsistent:
		if s.Balancing.Key == "" {
			es.add("spec.balancing.key", "is required for %s", s.Balancing.Algorithm)
		}
	default:
		es.add("spec.balancing.algorithm", "must be one of %s", strings.Join([]string{
			string(RoundRobin), string(LeastConn), string(IPHash), string(Hash),
			string(HashConsistent), string(Random), string(RandomTwo)}, ", "))
	}
	checkDuration(es, "spec.passiveHealth.failTimeout", s.PassiveHealth.FailTimeout)
	checkDuration(es, "spec.keepalive.timeout", s.Keepalive.Timeout)
	checkDuration(es, "spec.keepalive.maxAge", s.Keepalive.MaxAge)
	checkDuration(es, "spec.queue.timeout", s.Queue.Timeout)
	if s.Queue.Timeout != "" && s.Queue.Size == 0 {
		es.add("spec.queue.timeout", "requires size")
	}
	if s.Queue.Size > 0 && !slices.ContainsFunc(s.Targets, func(t Target) bool { return t.MaxConns > 0 }) {
		es.add("spec.queue.size", "requires a target with maxConns")
	}
	if h := s.HealthCheck; h != nil {
		switch h.Type {
		case "", HealthHTTP:
		case HealthTCP:
			if h.Path != "" || h.Host != "" || len(h.Statuses) > 0 || h.Body != "" {
				es.add("spec.healthCheck", "path, host, statuses and body apply to http checks")
			}
		default:
			es.add("spec.healthCheck.type", "must be %q or %q", HealthHTTP, HealthTCP)
		}
		checkDuration(es, "spec.healthCheck.interval", h.Interval)
		checkDuration(es, "spec.healthCheck.timeout", h.Timeout)
		if h.Path != "" && !strings.HasPrefix(h.Path, "/") {
			es.add("spec.healthCheck.path", "must start with /")
		}
		for i, st := range h.Statuses {
			if _, _, ok := ParseStatusRange(st); !ok {
				es.add(fmt.Sprintf("spec.healthCheck.statuses[%d]", i), "must be a status such as 200 or a range such as 200-399")
			}
		}
		if h.Port > 65535 {
			es.add("spec.healthCheck.port", "must be 1-65535")
		}
	}
	if st := s.Sticky; st != nil {
		switch st.Type {
		case StickyCookie:
			if st.Cookie != "" && !headerNameRE.MatchString(st.Cookie) {
				es.add("spec.sticky.cookie", "must be a cookie name")
			}
			checkDuration(es, "spec.sticky.maxAge", st.MaxAge)
			switch st.SameSite {
			case "", "strict", "lax", "none":
			default:
				es.add("spec.sticky.sameSite", "must be strict, lax or none")
			}
			if len(st.Route) > 0 {
				es.add("spec.sticky.route", "applies to route sticky sessions")
			}
		case StickyRoute:
			if len(st.Route) == 0 {
				es.add("spec.sticky.route", "at least one variable is required")
			}
			if !slices.ContainsFunc(s.Targets, func(t Target) bool { return t.Route != "" }) {
				es.add("spec.targets", "route sticky sessions need a target with a route")
			}
		default:
			es.add("spec.sticky.type", "must be %q or %q", StickyCookie, StickyRoute)
		}
	}
}

func hashing(a Algorithm) bool {
	switch a {
	case IPHash, Hash, HashConsistent, Random, RandomTwo:
		return true
	}
	return false
}

// ParseStatusRange parses "200" or "200-399".
func ParseStatusRange(s string) (from, to uint32, ok bool) {
	a, b, isRange := strings.Cut(s, "-")
	if !isRange {
		b = a
	}
	x, err1 := strconv.ParseUint(a, 10, 32)
	y, err2 := strconv.ParseUint(b, 10, 32)
	if err1 != nil || err2 != nil || x < 100 || y > 999 || x > y {
		return 0, 0, false
	}
	return uint32(x), uint32(y), true
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

// IsHostname reports whether s is a lowercase DNS name.
func IsHostname(s string) bool {
	return s != "" && s == strings.ToLower(s) && !strings.ContainsAny(s, " \t/:*")
}

// isWildcard accepts the nginx server_name wildcard forms: one "*" as the
// whole first or last label, or a leading dot.
func isWildcard(s string) bool {
	switch {
	case strings.HasPrefix(s, "*."):
		return IsHostname(s[2:])
	case strings.HasSuffix(s, ".*"):
		return IsHostname(s[:len(s)-2])
	case strings.HasPrefix(s, "."):
		return IsHostname(s[1:])
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
