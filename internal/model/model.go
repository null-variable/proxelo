// Package model defines the resources users edit through the API and UI.
//
// Resources reference each other by ID. The compile package resolves those
// references into the snapshot served by proxies.
package model

import (
	"time"

	"github.com/oklog/ulid/v2"
)

// Meta holds the fields every resource has.
type Meta struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Labels      map[string]string `json:"labels,omitempty"`
	Description string            `json:"description,omitempty"`
	// Enabled false keeps the resource stored but leaves it out of snapshots.
	// Nil means enabled.
	Enabled         *bool     `json:"enabled,omitempty"`
	ResourceVersion int64     `json:"resourceVersion"`
	CreatedAt       time.Time `json:"createdAt"`
	UpdatedAt       time.Time `json:"updatedAt"`
}

// Common returns the shared fields. It lets every resource satisfy Resource.
func (m *Meta) Common() *Meta { return m }

// IsEnabled reports whether the resource takes part in compilation.
func (m *Meta) IsEnabled() bool { return m.Enabled == nil || *m.Enabled }

// Resource is implemented by pointers to every resource type.
type Resource interface {
	Common() *Meta
}

// Kind describes one resource type as it appears in the API.
type Kind struct {
	// Plural is the collection name used in URLs, for example "routes".
	Plural   string
	IDPrefix string
	New      func() Resource
}

// NewID returns a new immutable resource ID such as "rt_01JD8X...".
func (k Kind) NewID() string { return k.IDPrefix + "_" + ulid.Make().String() }

var (
	ListenerKind    = Kind{Plural: "listeners", IDPrefix: "lst", New: func() Resource { return &Listener{} }}
	SiteKind        = Kind{Plural: "sites", IDPrefix: "site", New: func() Resource { return &Site{} }}
	RouteKind       = Kind{Plural: "routes", IDPrefix: "rt", New: func() Resource { return &Route{} }}
	UpstreamKind    = Kind{Plural: "upstreams", IDPrefix: "up", New: func() Resource { return &Upstream{} }}
	CertificateKind = Kind{Plural: "certificates", IDPrefix: "cert", New: func() Resource { return &Certificate{} }}
	PolicyKind      = Kind{Plural: "policies", IDPrefix: "pol", New: func() Resource { return &Policy{} }}
)

// Kinds lists every resource kind in a fixed order.
var Kinds = []Kind{ListenerKind, SiteKind, RouteKind, UpstreamKind, CertificateKind, PolicyKind}

// KindByPlural finds a kind by its collection name.
func KindByPlural(plural string) (Kind, bool) {
	for _, k := range Kinds {
		if k.Plural == plural {
			return k, true
		}
	}
	return Kind{}, false
}

// Listener is a socket the proxy accepts connections on (nginx listen).
type Listener struct {
	Meta
	Spec ListenerSpec `json:"spec"`
}

type ListenerSpec struct {
	// host:port, for example "0.0.0.0:443".
	Address   string `json:"address"`
	ReusePort bool   `json:"reusePort,omitempty"`
	Backlog   uint32 `json:"backlog,omitempty"`
	// Site ID served when no hostname matches (nginx default_server).
	DefaultSite string `json:"defaultSite,omitempty"`
	// TLS termination. Nil: plain TCP.
	TLS *ListenerTLS `json:"tls,omitempty"`
	// Offer HTTP/2 through ALPN; requires TLS.
	HTTP2 bool `json:"http2,omitempty"`
}

type ListenerTLS struct {
	// Certificate ID for handshakes without SNI or whose name selects a site
	// without certificates. Empty: those handshakes fail.
	DefaultCertificate string `json:"defaultCertificate,omitempty"`
	// "1.0", "1.1", "1.2" or "1.3". Empty: "1.2" (nginx ssl_protocols
	// TLSv1.2 TLSv1.3).
	MinVersion string `json:"minVersion,omitempty"`
	// OpenSSL cipher list for TLS 1.2 and below (nginx ssl_ciphers). Empty:
	// "HIGH:!aNULL:!MD5".
	Ciphers string `json:"ciphers,omitempty"`
}

// Site groups routes served for a set of hostnames (nginx server).
type Site struct {
	Meta
	Spec SiteSpec `json:"spec"`
}

type SiteSpec struct {
	// Listener IDs.
	Listeners []string    `json:"listeners"`
	Hostnames []HostMatch `json:"hostnames,omitempty"`
	// Route IDs in display order. Matching priority does not depend on it.
	Routes []string `json:"routes,omitempty"`
	// Server-level rewrites, run before a route is chosen.
	Rewrite []Rewrite `json:"rewrite,omitempty"`
	// Server-level return, after Rewrite.
	Return *ReturnAction `json:"return,omitempty"`
	// Inherited by routes that set none of their own, as in nginx.
	ErrorPages []ErrorPage `json:"errorPages,omitempty"`
	// Certificate IDs offered on TLS listeners, at most one per key type.
	Certificates []string `json:"certificates,omitempty"`
	// On plain listeners, answer every request with a 301 to https.
	RedirectHTTPToHTTPS bool `json:"redirectHttpToHttps,omitempty"`
	// Policy IDs applied to every route of the site.
	Policies []string `json:"policies,omitempty"`
}

// Template strings (Rewrite.Replacement, ReturnAction.Text, TryFiles.Files,
// TryFiles.URI, ErrorPage.URI) use nginx variables: $uri, $args, $host, $1
// and so on. The proxy rejects unknown variables when it loads the snapshot.

type RewriteFlag string

const (
	// No flag: continue with the next rewrite.
	RewriteNext      RewriteFlag = ""
	RewriteLast      RewriteFlag = "last"
	RewriteBreak     RewriteFlag = "break"
	RewriteRedirect  RewriteFlag = "redirect"
	RewritePermanent RewriteFlag = "permanent"
)

// Rewrite is nginx rewrite.
type Rewrite struct {
	// PCRE2 pattern matched against the path.
	Regex       string      `json:"regex"`
	Replacement string      `json:"replacement"`
	Flag        RewriteFlag `json:"flag,omitempty"`
}

// ErrorPage is nginx error_page. Exactly one of URI and Route is set.
type ErrorPage struct {
	Codes []uint32 `json:"codes"`
	// Path for an internal redirect, or an absolute http(s) URL for a
	// redirect.
	URI string `json:"uri,omitempty"`
	// Route ID handling the error like an nginx named location (@name); its
	// path match is not used.
	Route string `json:"route,omitempty"`
	// Nil keeps the original code, 0 takes the redirected request's status
	// (nginx "error_page 404 = /x"), anything else replaces the code.
	Status *uint32 `json:"status,omitempty"`
}

type HostMatchType string

// Host match types, in nginx server_name order.
const (
	HostExact HostMatchType = "exact"
	// "*.example.com", "mail.*", or ".example.com" for example.com and every
	// name under it.
	HostWildcard HostMatchType = "wildcard"
	// PCRE2 pattern matched against the lowercase host, without nginx's "~".
	HostRegex HostMatchType = "regex"
)

type HostMatch struct {
	Type  HostMatchType `json:"type"`
	Value string        `json:"value"`
}

// Route maps matching requests to an action (nginx location).
type Route struct {
	Meta
	Spec RouteSpec `json:"spec"`
}

type RouteSpec struct {
	Match   Match     `json:"match"`
	Rewrite []Rewrite `json:"rewrite,omitempty"`
	Action  Action    `json:"action"`
	// Nested route IDs (nginx location inside a prefix location). Their paths
	// must lie inside this route's prefix.
	Children []string `json:"children,omitempty"`
	// Empty inherits the parent route's, then the site's.
	ErrorPages []ErrorPage `json:"errorPages,omitempty"`
	// Policy IDs added to those of the parent route and the site.
	Policies []string `json:"policies,omitempty"`
	// False drops the policies of the parent route and the site.
	InheritPolicies *bool `json:"inheritPolicies,omitempty"`
}

// Match selects requests by path (nginx location) and, optionally, by
// conditions checked after the path. Routes with the same path in one block
// are tried in order with their conditions, then the one without.
type Match struct {
	Path PathMatch `json:"path"`
	// Uppercase methods; empty allows any.
	Methods []string `json:"methods,omitempty"`
	// Header conditions; names are case-insensitive.
	Headers []ValueMatch `json:"headers,omitempty"`
	// Query argument conditions; names are case-sensitive.
	Query []ValueMatch `json:"query,omitempty"`
	// CEL expression over `request` (see proxelo.expr.v1.Request) that must
	// be a bool, with the standard library and the network extension.
	Expr string `json:"expr,omitempty"`
}

// HasConditions reports whether anything beyond the path is matched.
func (m *Match) HasConditions() bool {
	return len(m.Methods) > 0 || len(m.Headers) > 0 || len(m.Query) > 0 || m.Expr != ""
}

type MatchOp string

const (
	OpPresent  MatchOp = "present"
	OpAbsent   MatchOp = "absent"
	OpEquals   MatchOp = "equals"
	OpPrefix   MatchOp = "prefix"
	OpSuffix   MatchOp = "suffix"
	OpContains MatchOp = "contains"
	// PCRE2, checked by the proxy when it loads the snapshot.
	OpRegex MatchOp = "regex"
)

// ValueMatch is one condition on a header or query argument, compared with
// the raw value as sent.
type ValueMatch struct {
	Name  string  `json:"name"`
	Op    MatchOp `json:"op"`
	Value string  `json:"value,omitempty"`
}

type PathMatchType string

const (
	// location = /path
	PathExact PathMatchType = "exact"
	// location /path
	PathPrefix PathMatchType = "prefix"
	// location ^~ /path
	PathPrefixPriority PathMatchType = "prefixPriority"
	// location ~ pattern (PCRE2)
	PathRegex PathMatchType = "regex"
	// location ~* pattern (PCRE2, caseless)
	PathRegexCI PathMatchType = "regexCI"
)

type PathMatch struct {
	Type  PathMatchType `json:"type"`
	Value string        `json:"value"`
}

type ActionType string

const (
	ActionStatic ActionType = "static"
	ActionProxy  ActionType = "proxy"
	ActionReturn ActionType = "return"
)

// Action carries the settings for Type and nothing else.
type Action struct {
	Type   ActionType    `json:"type"`
	Static *StaticAction `json:"static,omitempty"`
	Proxy  *ProxyAction  `json:"proxy,omitempty"`
	Return *ReturnAction `json:"return,omitempty"`
}

type StaticAction struct {
	// Absolute directory path.
	Root     string    `json:"root"`
	Index    []string  `json:"index,omitempty"`
	TryFiles *TryFiles `json:"tryFiles,omitempty"`
}

// TryFiles is nginx try_files. Exactly one of URI, Status and Route is the
// fallback.
type TryFiles struct {
	// Paths under Root; a trailing "/" matches a directory.
	Files []string `json:"files"`
	// Internal redirect, for example "/index.html".
	URI string `json:"uri,omitempty"`
	// Answer with this code, nginx "=404".
	Status uint32 `json:"status,omitempty"`
	// Route ID, like an nginx named location (@name).
	Route string `json:"route,omitempty"`
}

// ReturnAction is nginx return.
type ReturnAction struct {
	// 0-999. 444 closes the connection without a response.
	Status uint32 `json:"status"`
	// Location for 301, 302, 303, 307 and 308, otherwise the body.
	Text string `json:"text,omitempty"`
}

type ProxyAction struct {
	// Upstream ID.
	Upstream string        `json:"upstream"`
	Timeouts ProxyTimeouts `json:"timeouts,omitzero"`
	Retry    *Retry        `json:"retry,omitempty"`
}

// ProxyTimeouts are Go durations such as "5s". Empty: 60s, the nginx
// defaults.
type ProxyTimeouts struct {
	Connect string `json:"connect,omitempty"`
	Send    string `json:"send,omitempty"`
	Read    string `json:"read,omitempty"`
}

// Retry is nginx proxy_next_upstream. Nil: on error and timeout.
type Retry struct {
	// "error", "timeout", "http_500", "http_502", "http_503", "http_504",
	// "http_403", "http_404", "http_429", "non_idempotent"; empty: never.
	On []string `json:"on"`
	// Zero: no limit.
	Tries uint32 `json:"tries,omitempty"`
}

// Upstream is a pool of backend targets (nginx upstream).
type Upstream struct {
	Meta
	Spec UpstreamSpec `json:"spec"`
}

type UpstreamSpec struct {
	Targets       []Target      `json:"targets"`
	Balancing     Balancing     `json:"balancing,omitzero"`
	PassiveHealth PassiveHealth `json:"passiveHealth,omitzero"`
	Keepalive     Keepalive     `json:"keepalive"`
}

type Target struct {
	// host:port
	Address string `json:"address"`
	// Zero means 1.
	Weight uint32 `json:"weight,omitempty"`
	// Used only when no other target is available.
	Backup bool `json:"backup,omitempty"`
}

type Algorithm string

const (
	RoundRobin Algorithm = "round_robin"
	LeastConn  Algorithm = "least_conn"
)

type Balancing struct {
	// Empty: round_robin.
	Algorithm Algorithm `json:"algorithm,omitempty"`
}

// PassiveHealth is nginx max_fails and fail_timeout.
type PassiveHealth struct {
	// Nil: 1. Zero disables it.
	MaxFails *uint32 `json:"maxFails,omitempty"`
	// Empty: "10s".
	FailTimeout string `json:"failTimeout,omitempty"`
}

type Keepalive struct {
	// Idle connections kept per worker (nginx keepalive).
	Idle uint32 `json:"idle,omitempty"`
	// Empty: "60s".
	Timeout string `json:"timeout,omitempty"`
	// Zero: 1000.
	MaxRequests uint32 `json:"maxRequests,omitempty"`
}

// Certificate is a TLS certificate chain and its private key (nginx
// ssl_certificate and ssl_certificate_key).
type Certificate struct {
	Meta
	Spec CertificateSpec `json:"spec"`
}

type CertificateSpec struct {
	// "upload" (default) or "acme".
	Source CertSource `json:"source,omitempty"`
	// PEM, leaf first. For acme, filled in when issued.
	ChainPEM string `json:"chainPem,omitempty"`
	// PEM private key. Never returned by the API.
	KeyPEM string `json:"keyPem,omitempty"`
	// For acme: the names to issue for.
	Domains []string `json:"domains,omitempty"`
	// Set by the control plane.
	Status CertStatus `json:"status,omitzero"`
}

type CertSource string

const (
	CertUpload CertSource = "upload"
	CertACME   CertSource = "acme"
)

// CertStatus is what the control plane read from the chain, or the last
// issuance error.
type CertStatus struct {
	Subject  string    `json:"subject,omitempty"`
	DNSNames []string  `json:"dnsNames,omitempty"`
	NotAfter time.Time `json:"notAfter,omitzero"`
	Error    string    `json:"error,omitempty"`
}

// Policy is a reusable setting attached to sites and routes.
type Policy struct {
	Meta
	Spec PolicySpec `json:"spec"`
}

type PolicyType string

const (
	PolicyHeaders   PolicyType = "headers"
	PolicyAccessLog PolicyType = "accessLog"
)

// PolicySpec carries the settings for Type and nothing else.
type PolicySpec struct {
	Type      PolicyType       `json:"type"`
	Headers   *HeadersPolicy   `json:"headers,omitempty"`
	AccessLog *AccessLogPolicy `json:"accessLog,omitempty"`
}

// HeadersPolicy replaces nginx add_header, proxy_set_header and
// proxy_hide_header. Several headers policies merge by header name, the
// closer one winning.
type HeadersPolicy struct {
	Response HeaderOps `json:"response,omitzero"`
	// Headers of the request sent upstream.
	Request HeaderOps `json:"request,omitzero"`
}

type HeaderOps struct {
	// Header name to value template; replaces headers with that name. On
	// responses, sent only with success and redirect statuses unless Always.
	Set map[string]string `json:"set,omitempty"`
	// Added alongside existing headers of the same name.
	Add []HeaderValue `json:"add,omitempty"`
	// Names to drop.
	Remove []string `json:"remove,omitempty"`
	// Response headers only: send with every status (nginx always).
	Always bool `json:"always,omitempty"`
}

type HeaderValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// AccessLogPolicy is nginx access_log with log_format. One applies: the
// closest to the route.
type AccessLogPolicy struct {
	// "stdout", "stderr" or an absolute file path.
	Path string `json:"path"`
	// "combined" (default), "main", "json", or a template with nginx
	// variables.
	Format string `json:"format,omitempty"`
	// Escape values for JSON; implied by format "json".
	EscapeJSON bool `json:"escapeJson,omitempty"`
	// False turns logging off for the routes it applies to.
	Enabled *bool `json:"enabled,omitempty"`
}

// Config is the full set of resources compiled into one snapshot.
type Config struct {
	Listeners    []*Listener    `json:"listeners,omitempty"`
	Sites        []*Site        `json:"sites,omitempty"`
	Routes       []*Route       `json:"routes,omitempty"`
	Upstreams    []*Upstream    `json:"upstreams,omitempty"`
	Certificates []*Certificate `json:"certificates,omitempty"`
	Policies     []*Policy      `json:"policies,omitempty"`
}

// Add appends r to the list for its type.
func (c *Config) Add(r Resource) {
	switch r := r.(type) {
	case *Listener:
		c.Listeners = append(c.Listeners, r)
	case *Site:
		c.Sites = append(c.Sites, r)
	case *Route:
		c.Routes = append(c.Routes, r)
	case *Upstream:
		c.Upstreams = append(c.Upstreams, r)
	case *Certificate:
		c.Certificates = append(c.Certificates, r)
	case *Policy:
		c.Policies = append(c.Policies, r)
	default:
		panic("model: unknown resource type")
	}
}
