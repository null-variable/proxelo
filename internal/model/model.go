// Package model defines the resources users edit through the API and UI.
//
// Resources reference each other by ID. The compile package resolves those
// references into the snapshot served by proxies.
package model

//go:generate go run schemagen.go

import (
	"fmt"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"
)

// Meta holds the fields every resource has.
type Meta struct {
	ID     string            `json:"id"`
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels,omitempty"`
	// Group ID; members of the group and its ancestors get their group
	// role on the resource. Empty: only instance roles apply.
	Group       string `json:"group,omitempty"`
	Description string `json:"description,omitempty"`
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
	LookupKind      = Kind{Plural: "lookups", IDPrefix: "lk", New: func() Resource { return &Lookup{} }}
	StreamKind      = Kind{Plural: "streams", IDPrefix: "st", New: func() Resource { return &Stream{} }}
)

// Kinds lists every resource kind in a fixed order.
var Kinds = []Kind{ListenerKind, SiteKind, RouteKind, UpstreamKind, CertificateKind, PolicyKind, LookupKind, StreamKind}

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
	// HTTP3 also serves HTTP/3 over QUIC on the same UDP address
	// (TLS 1.3, the same certificates) and advertises it with Alt-Svc.
	HTTP3 bool `json:"http3,omitempty"`
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
	// Highest version, like minVersion. Empty: "1.3".
	MaxVersion string `json:"maxVersion,omitempty"`
	// TLS 1.3 suites, e.g. "TLS_AES_128_GCM_SHA256" (nginx ssl_conf_command
	// Ciphersuites). Empty: OpenSSL's.
	Ciphersuites string `json:"ciphersuites,omitempty"`
	// Server cipher order over the client's (nginx ssl_prefer_server_ciphers).
	PreferServerCiphers bool `json:"preferServerCiphers,omitempty"`
	// Key exchange groups, e.g. "X25519:prime256v1" (nginx ssl_ecdh_curve).
	// Empty: OpenSSL's.
	Groups string `json:"groups,omitempty"`
	// Refuse session tickets (nginx ssl_session_tickets off).
	NoSessionTickets bool `json:"noSessionTickets,omitempty"`
	// Sessions kept for resumption by ID, per worker (nginx ssl_session_cache
	// builtin:N). Zero: no cache.
	SessionCacheSize uint32 `json:"sessionCacheSize,omitempty"`
	// PEM DH parameters for DHE suites (nginx ssl_dhparam). Empty: none.
	DHParams string `json:"dhParams,omitempty"`
	// Client certificate check (nginx ssl_verify_client). Nil: none.
	ClientAuth *ClientAuth `json:"clientAuth,omitempty"`
}

type ClientAuthMode string

const (
	ClientAuthRequire      ClientAuthMode = "require"
	ClientAuthOptional     ClientAuthMode = "optional"
	ClientAuthOptionalNoCA ClientAuthMode = "optional_no_ca"
)

// ClientAuth asks for a client certificate. A missing (require) or invalid one
// answers 400; the result is in $ssl_client_verify.
type ClientAuth struct {
	Mode ClientAuthMode `json:"mode"`
	// PEM CA certificates that sign client certificates (nginx
	// ssl_client_certificate). Required unless mode is optional_no_ca.
	CA string `json:"ca,omitempty"`
	// Chain length at most (nginx ssl_verify_depth). Zero: 1.
	Depth uint32 `json:"depth,omitempty"`
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
	// FastCGI, uwsgi or SCGI application server.
	ActionGateway   ActionType = "gateway"
	ActionMemcached ActionType = "memcached"
	ActionGrpc      ActionType = "grpc"
)

// Action carries the settings for Type and nothing else.
type Action struct {
	Type   ActionType    `json:"type"`
	Static *StaticAction `json:"static,omitempty"`
	Proxy  *ProxyAction  `json:"proxy,omitempty"`
	Return *ReturnAction `json:"return,omitempty"`
	// FastCGI, uwsgi or SCGI.
	Gateway   *GatewayAction   `json:"gateway,omitempty"`
	Memcached *MemcachedAction `json:"memcached,omitempty"`
	Grpc      *ProxyAction     `json:"grpc,omitempty"`
}

// Upstream returns the upstream ID the action sends requests to, if any.
func (a *Action) Upstream() (string, string) {
	switch {
	case a.Proxy != nil:
		return a.Proxy.Upstream, "spec.action.proxy.upstream"
	case a.Gateway != nil:
		return a.Gateway.Upstream, "spec.action.gateway.upstream"
	case a.Memcached != nil:
		return a.Memcached.Upstream, "spec.action.memcached.upstream"
	case a.Grpc != nil:
		return a.Grpc.Upstream, "spec.action.grpc.upstream"
	}
	return "", ""
}

type GatewayProtocol string

const (
	GatewayFastCGI GatewayProtocol = "fastcgi"
	GatewayUwsgi   GatewayProtocol = "uwsgi"
	GatewaySCGI    GatewayProtocol = "scgi"
)

// GatewayAction passes requests to an application server (nginx
// fastcgi_pass, uwsgi_pass, scgi_pass). The request body is read in full
// first.
type GatewayAction struct {
	Protocol GatewayProtocol `json:"protocol"`
	ProxyAction
	// Added after the standard set of the protocol (nginx fastcgi_params,
	// uwsgi_params, scgi_params); a param of the same name replaces the
	// standard one. Values are templates.
	Params []GatewayParam `json:"params,omitempty"`
	// Leave out the standard set.
	NoDefaultParams bool `json:"noDefaultParams,omitempty"`
	// Do not send request headers as HTTP_* params.
	NoRequestHeaders bool `json:"noRequestHeaders,omitempty"`
	// $document_root, an absolute path; SCRIPT_FILENAME of FastCGI is
	// $document_root$fastcgi_script_name.
	DocumentRoot string `json:"documentRoot,omitempty"`
	// Appended to $fastcgi_script_name for a URI ending in "/", for example
	// "index.php" (fastcgi_index).
	Index string `json:"index,omitempty"`
	// PCRE2 with two groups over $uri, the script name and the path info,
	// for example "^(.+\.php)(/.+)$" (fastcgi_split_path_info).
	SplitPathInfo string `json:"splitPathInfo,omitempty"`
}

type GatewayParam struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	// Skip the param when the value expands to nothing.
	IfNotEmpty bool `json:"ifNotEmpty,omitempty"`
}

// MemcachedAction answers GET and HEAD with the value stored under the key
// (nginx memcached_pass); a missing key is 404.
type MemcachedAction struct {
	ProxyAction
	// Template; empty: $uri.
	Key string `json:"key,omitempty"`
}

type StaticAction struct {
	// Absolute directory path.
	Root     string    `json:"root"`
	Index    []string  `json:"index,omitempty"`
	TryFiles *TryFiles `json:"tryFiles,omitempty"`
	// List directories without an index file (nginx autoindex). Nil: off.
	Autoindex *Autoindex `json:"autoindex,omitempty"`
	// Send a request for a directory to a random file in it (nginx
	// random_index).
	RandomIndex bool `json:"randomIndex,omitempty"`
	// WebDAV methods on the files under Root (nginx dav_methods). Nil: off.
	DAV *DAV `json:"dav,omitempty"`
	// Serve .flv files from ?start=N (nginx flv).
	FLV bool `json:"flv,omitempty"`
}

type AutoindexFormat string

const (
	AutoindexHTML  AutoindexFormat = "html"
	AutoindexJSON  AutoindexFormat = "json"
	AutoindexJSONP AutoindexFormat = "jsonp"
	AutoindexXML   AutoindexFormat = "xml"
)

// Autoindex is nginx autoindex and its settings.
type Autoindex struct {
	// "html" (default), "json", "jsonp" (with ?callback=) or "xml".
	Format AutoindexFormat `json:"format,omitempty"`
	// HTML times in the proxy's local time zone instead of UTC.
	LocalTime bool `json:"localTime,omitempty"`
	// HTML sizes rounded to K, M and G (autoindex_exact_size off).
	ApproximateSize bool `json:"approximateSize,omitempty"`
}

// DAV is nginx dav_methods with create_full_put_path, min_delete_depth and
// dav_access.
type DAV struct {
	// Any of "put", "delete", "mkcol", "copy", "move".
	Methods []string `json:"methods"`
	// PUT creates missing parent directories.
	CreateFullPutPath bool `json:"createFullPutPath,omitempty"`
	// DELETE needs at least this many path segments.
	MinDeleteDepth uint32 `json:"minDeleteDepth,omitempty"`
	// Permission bits of created files as octal, "0644". Directories also
	// get x where r is set. Default "0600".
	Access string `json:"access,omitempty"`
}

// DAVMethods are the methods DAV.Methods takes.
var DAVMethods = []string{"put", "delete", "mkcol", "copy", "move"}

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
	// Active health checks (probes from every node). Nil: none.
	HealthCheck *HealthCheck `json:"healthCheck,omitempty"`
	// Session affinity (nginx sticky). Nil: none.
	Sticky *Sticky `json:"sticky,omitempty"`
	// Requests waiting when every target is at maxConns (nginx queue).
	Queue     Queue     `json:"queue,omitzero"`
	Keepalive Keepalive `json:"keepalive"`
	// TLS to the targets (nginx proxy_pass https:// and proxy_ssl_*). Nil:
	// plain TCP.
	TLS *UpstreamTLS `json:"tls,omitempty"`
	// Targets found at run time and added to Targets, which may then be
	// empty. Nil: only Targets.
	Discovery *Discovery `json:"discovery,omitempty"`
}

type DiscoveryProvider string

const (
	DiscoveryDocker     DiscoveryProvider = "docker"
	DiscoveryKubernetes DiscoveryProvider = "kubernetes"
	DiscoveryConsul     DiscoveryProvider = "consul"
)

// Discovery finds an upstream's targets with a service registry. The
// control plane polls it and sends what it finds to every proxy; the rest
// of the upstream (balancing, health checks, keepalive) applies to them as
// to configured targets. When the registry cannot be read the last targets
// found stay.
type Discovery struct {
	// "docker", "kubernetes" or "consul".
	Provider DiscoveryProvider `json:"provider"`
	// docker: the Engine API, "unix:///var/run/docker.sock" by default or
	// "http://host:port". kubernetes: the API server, by default the
	// in-cluster one (KUBERNETES_SERVICE_HOST, service account token and
	// CA). consul: the agent, "http://127.0.0.1:8500" by default.
	Endpoint string `json:"endpoint,omitempty"`
	// docker: running containers with every one of these labels
	// ("key=value" or "key"). kubernetes: the Service whose
	// EndpointSlices give the targets, as "namespace/name". consul: the
	// service name.
	Selector []string `json:"selector,omitempty"`
	// Port on the targets. docker: the container port, used with the
	// container's address on network; kubernetes: the port name or number
	// of the EndpointSlice; consul: overrides the service port.
	Port string `json:"port,omitempty"`
	// docker: the network whose container address is used. Empty: the
	// first one.
	Network string `json:"network,omitempty"`
	// consul: only services with this tag; kubernetes and consul: a token
	// for the API (kubernetes default: the service account's).
	Tag   string `json:"tag,omitempty"`
	Token string `json:"token,omitempty"`
	// How often the registry is read. Default "10s".
	Interval string `json:"interval,omitempty"`
}

// UpstreamTLS configures connections to an upstream's targets.
type UpstreamTLS struct {
	// Name for SNI and certificate verification (nginx proxy_ssl_name).
	// Empty: the upstream name.
	ServerName string `json:"serverName,omitempty"`
	// Send SNI (nginx proxy_ssl_server_name).
	SNI bool `json:"sni,omitempty"`
	// Check the target's chain and name (nginx proxy_ssl_verify).
	Verify bool `json:"verify,omitempty"`
	// PEM CA certificates to trust (nginx proxy_ssl_trusted_certificate).
	// Empty: the system store.
	CA string `json:"ca,omitempty"`
	// Chain length at most (nginx proxy_ssl_verify_depth). Zero: 1.
	Depth uint32 `json:"depth,omitempty"`
	// Certificate ID presented to targets (nginx proxy_ssl_certificate).
	Certificate string `json:"certificate,omitempty"`
	// "1.0" to "1.3". Empty: "1.2" and "1.3" (nginx proxy_ssl_protocols).
	MinVersion string `json:"minVersion,omitempty"`
	MaxVersion string `json:"maxVersion,omitempty"`
	// OpenSSL cipher list (nginx proxy_ssl_ciphers). Empty: "DEFAULT".
	Ciphers string `json:"ciphers,omitempty"`
	// TLS 1.3 suites. Empty: OpenSSL's.
	Ciphersuites string `json:"ciphersuites,omitempty"`
}

type Target struct {
	// host:port
	Address string `json:"address"`
	// Zero means 1.
	Weight uint32 `json:"weight,omitempty"`
	// Used only when no other target is available.
	Backup bool `json:"backup,omitempty"`
	// Takes no requests (nginx down).
	Down bool `json:"down,omitempty"`
	// Requests in progress at most; zero: no limit (nginx max_conns).
	MaxConns uint32 `json:"maxConns,omitempty"`
	// After recovering, the weight grows from 1 over this time, e.g. "30s"
	// (nginx slow_start).
	SlowStart string `json:"slowStart,omitempty"`
	// Re-resolve the host name while running (nginx resolve).
	Resolve bool `json:"resolve,omitempty"`
	// How often a resolve target is looked up again. Empty: "30s".
	ResolveInterval string `json:"resolveInterval,omitempty"`
	// Sticky route value naming this target (nginx server route=).
	Route string `json:"route,omitempty"`
}

type HealthCheckType string

const (
	HealthHTTP HealthCheckType = "http"
	HealthTCP  HealthCheckType = "tcp"
)

// HealthCheck probes every target; a target failing `fails` probes in a row
// takes no requests until it passes `passes` in a row.
type HealthCheck struct {
	// Empty: http.
	Type HealthCheckType `json:"type,omitempty"`
	// Empty: "5s".
	Interval string `json:"interval,omitempty"`
	// Per probe. Empty: "1s".
	Timeout string `json:"timeout,omitempty"`
	// Zero: 1.
	Fails uint32 `json:"fails,omitempty"`
	// Zero: 1.
	Passes uint32 `json:"passes,omitempty"`
	// HTTP request path. Empty: "/".
	Path string `json:"path,omitempty"`
	// HTTP Host header. Empty: the upstream's name.
	Host string `json:"host,omitempty"`
	// Passing statuses such as "200-399" or "204". Empty: 200-399.
	Statuses []string `json:"statuses,omitempty"`
	// PCRE2 pattern the response body must match.
	Body string `json:"body,omitempty"`
	// Probe this port instead of the target's.
	Port uint32 `json:"port,omitempty"`
}

type StickyType string

const (
	StickyCookie StickyType = "cookie"
	StickyRoute  StickyType = "route"
)

// Sticky keeps a client on one target.
type Sticky struct {
	Type StickyType `json:"type"`
	// cookie: cookie name. Empty: "route".
	Cookie string `json:"cookie,omitempty"`
	// cookie: lifetime such as "1h". Empty: a session cookie.
	MaxAge string `json:"maxAge,omitempty"`
	// cookie: Path attribute. Empty: "/".
	Path string `json:"path,omitempty"`
	// cookie: Domain attribute.
	Domain   string `json:"domain,omitempty"`
	HTTPOnly bool   `json:"httpOnly,omitempty"`
	Secure   bool   `json:"secure,omitempty"`
	// cookie: "strict", "lax" or "none".
	SameSite string `json:"sameSite,omitempty"`
	// route: variables tried in order, such as "$cookie_jsessionid"; the
	// first non-empty one is matched against target routes.
	Route []string `json:"route,omitempty"`
}

type Queue struct {
	// Zero: no queue; a request finding every target full fails with 502.
	Size uint32 `json:"size,omitempty"`
	// Empty: "60s".
	Timeout string `json:"timeout,omitempty"`
}

type Algorithm string

const (
	RoundRobin     Algorithm = "round_robin"
	LeastConn      Algorithm = "least_conn"
	IPHash         Algorithm = "ip_hash"
	Hash           Algorithm = "hash"
	HashConsistent Algorithm = "hash_consistent"
	Random         Algorithm = "random"
	RandomTwo      Algorithm = "random_two"
)

type Balancing struct {
	// Empty: round_robin.
	Algorithm Algorithm `json:"algorithm,omitempty"`
	// hash and hash_consistent: the key, with variables, such as
	// "$request_uri".
	Key string `json:"key,omitempty"`
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
	// A connection closes after being open this long (nginx keepalive_time).
	// Empty: "1h".
	MaxAge string `json:"maxAge,omitempty"`
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
	PolicyHeaders     PolicyType = "headers"
	PolicyAccessLog   PolicyType = "accessLog"
	PolicyRateLimit   PolicyType = "rateLimit"
	PolicyConnLimit   PolicyType = "connLimit"
	PolicyBandwidth   PolicyType = "bandwidth"
	PolicyIPAccess    PolicyType = "ipAccess"
	PolicyBasicAuth   PolicyType = "basicAuth"
	PolicyForwardAuth PolicyType = "forwardAuth"
	PolicyJWT         PolicyType = "jwt"
	PolicyOIDC        PolicyType = "oidc"
	PolicyRealIP      PolicyType = "realIp"
	PolicyCompression PolicyType = "compression"
	PolicyCache       PolicyType = "cache"
	PolicyWasm        PolicyType = "wasm"
	PolicyWAF         PolicyType = "waf"
)

// PolicySpec carries the settings for Type and nothing else.
type PolicySpec struct {
	Type        PolicyType         `json:"type"`
	Headers     *HeadersPolicy     `json:"headers,omitempty"`
	AccessLog   *AccessLogPolicy   `json:"accessLog,omitempty"`
	RateLimit   *RateLimitPolicy   `json:"rateLimit,omitempty"`
	ConnLimit   *ConnLimitPolicy   `json:"connLimit,omitempty"`
	Bandwidth   *BandwidthPolicy   `json:"bandwidth,omitempty"`
	IPAccess    *IPAccessPolicy    `json:"ipAccess,omitempty"`
	BasicAuth   *BasicAuthPolicy   `json:"basicAuth,omitempty"`
	ForwardAuth *ForwardAuthPolicy `json:"forwardAuth,omitempty"`
	JWT         *JWTPolicy         `json:"jwt,omitempty"`
	OIDC        *OIDCPolicy        `json:"oidc,omitempty"`
	RealIP      *RealIPPolicy      `json:"realIp,omitempty"`
	Compression *CompressionPolicy `json:"compression,omitempty"`
	Cache       *CachePolicy       `json:"cache,omitempty"`
	Wasm        *WasmPolicy        `json:"wasm,omitempty"`
	WAF         *WAFPolicy         `json:"waf,omitempty"`
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

// RateLimitPolicy is nginx limit_req_zone with limit_req: a leaky bucket
// per key. Each policy is one zone; every route it applies to shares the
// zone's counters. All rate limits that apply are checked.
type RateLimitPolicy struct {
	// Template for the key, "$binary_remote_addr" by default. Requests whose
	// key is empty are not limited.
	Key string `json:"key,omitempty"`
	// Such as "10r/s" or "30r/m".
	Rate string `json:"rate"`
	// Requests over the rate that wait (or pass, up to Delay) instead of
	// being rejected.
	Burst uint32 `json:"burst,omitempty"`
	// Excess requests passed without waiting (nginx delay). NoDelay passes
	// the whole burst.
	Delay   uint32 `json:"delay,omitempty"`
	NoDelay bool   `json:"noDelay,omitempty"`
	// Status for rejected requests, 503 by default.
	Status uint32 `json:"status,omitempty"`
	// Count and log, but never delay or reject.
	DryRun bool `json:"dryRun,omitempty"`
	// Keys kept per proxy; when full, idle keys are dropped. Default 16384.
	MaxKeys uint32 `json:"maxKeys,omitempty"`
}

// ConnLimitPolicy is nginx limit_conn_zone with limit_conn: requests in
// progress per key.
type ConnLimitPolicy struct {
	// Template for the key, "$binary_remote_addr" by default.
	Key string `json:"key,omitempty"`
	Max uint32 `json:"max"`
	// Status for rejected requests, 503 by default.
	Status  uint32 `json:"status,omitempty"`
	DryRun  bool   `json:"dryRun,omitempty"`
	MaxKeys uint32 `json:"maxKeys,omitempty"`
}

// BandwidthPolicy is nginx limit_rate and limit_rate_after: the response
// body rate of each request. The closest policy applies.
type BandwidthPolicy struct {
	// Such as "100k" or "1m" bytes per second.
	Rate string `json:"rate"`
	// Sent at full speed first, such as "500k".
	After string `json:"after,omitempty"`
}

// IPAccessPolicy is nginx allow and deny. Rules of all policies that apply
// are checked in order, outermost first; the first match decides and no
// match allows. A denied request gets 403.
type IPAccessPolicy struct {
	Rules []IPRule `json:"rules"`
}

type IPRule struct {
	// "allow" or "deny".
	Action string `json:"action"`
	// CIDR, address, or "all".
	From string `json:"from"`
}

// BasicAuthPolicy is nginx auth_basic with the users inline. The closest
// policy applies.
type BasicAuthPolicy struct {
	Realm string      `json:"realm"`
	Users []BasicUser `json:"users"`
}

type BasicUser struct {
	Name string `json:"name"`
	// A hash as htpasswd or openssl passwd makes: bcrypt, $apr1$, $1$, $5$,
	// $6$, {SHA} or {SSHA}.
	Hash string `json:"hash"`
}

// ForwardAuthPolicy is nginx auth_request: an upstream decides whether to
// serve each request. It gets a GET with the request headers and
// X-Forwarded-Method, -Proto, -Host and -Uri; 2xx allows, 401 and 403 are
// sent to the client, anything else is a 500. The closest policy applies.
type ForwardAuthPolicy struct {
	Upstream string `json:"upstream"`
	// Path and query of the check, a template. Default "/".
	URI string `json:"uri,omitempty"`
	// Default 60s.
	Timeout string `json:"timeout,omitempty"`
	// Response headers of a successful check added to the request sent
	// upstream; also variables $auth_resp_<name>.
	CopyHeaders []string `json:"copyHeaders,omitempty"`
}

// JWTPolicy is nginx auth_jwt: requests need a JSON Web Token signed by
// one of the keys, unexpired and, when set, from the issuer for one of the
// audiences. Others get 401 with WWW-Authenticate: Bearer. The claims are
// variables $jwt_claim_<name> and the token header $jwt_header_<name>.
// The closest policy applies.
type JWTPolicy struct {
	// Realm of the challenge. Default "proxelo".
	Realm string `json:"realm,omitempty"`
	// A template giving the token, for example "$cookie_token". Default:
	// the Bearer credentials of the Authorization header.
	Token string `json:"token,omitempty"`
	// A JSON Web Key Set (RFC 7517) with the signing keys.
	JWKS string `json:"jwks,omitempty"`
	// Or where to fetch it; both may be set.
	JWKSURL string `json:"jwksUrl,omitempty"`
	// How long fetched keys are kept. Default 1h.
	KeyCache string `json:"keyCache,omitempty"`
	Issuer   string `json:"issuer,omitempty"`
	// The aud claim must hold one of these.
	Audiences []string `json:"audiences,omitempty"`
	// Clock skew allowed for exp and nbf.
	Leeway string `json:"leeway,omitempty"`
}

// OIDCPolicy signs users in with an OpenID Connect provider before their
// requests are served: the authorization code flow with PKCE, then a
// signed session cookie. The user's sub and email are variables $oidc_sub
// and $oidc_email. The closest policy applies.
type OIDCPolicy struct {
	// The provider, found through <issuer>/.well-known/openid-configuration.
	Issuer   string `json:"issuer"`
	ClientID string `json:"clientId"`
	// Never returned by the API; empty on update keeps the stored one.
	ClientSecret string `json:"clientSecret,omitempty"`
	// Where the provider sends users back, a path on the site or a URL
	// whose path reaches a route with this policy. Default "/oidc_callback".
	RedirectURI string `json:"redirectUri,omitempty"`
	// Default ["openid"]; "openid" is always asked for.
	Scopes []string `json:"scopes,omitempty"`
	// Session cookie name. Default "proxelo_oidc".
	Cookie string `json:"cookie,omitempty"`
	// Default 8h.
	SessionTimeout string `json:"sessionTimeout,omitempty"`
	// A path that signs the user out, then goes to the provider's logout
	// or to PostLogoutURI.
	LogoutURI     string `json:"logoutUri,omitempty"`
	PostLogoutURI string `json:"postLogoutUri,omitempty"`
}

// RealIPPolicy is nginx set_real_ip_from, real_ip_header and
// real_ip_recursive: the client address is taken from a header that
// trusted proxies set. It applies to the whole site, before the route is
// chosen, so only site policies may be realIp.
type RealIPPolicy struct {
	// Trusted proxies, as CIDRs or addresses.
	From []string `json:"from"`
	// Default "X-Real-IP"; "X-Forwarded-For" is read from the right.
	Header string `json:"header,omitempty"`
	// Skip trusted addresses from the right of the header.
	Recursive bool `json:"recursive,omitempty"`
}

// CompressionPolicy is nginx gzip, gzip_static and gunzip, plus brotli and
// zstd. The closest policy applies.
type CompressionPolicy struct {
	// Dynamic encodings in order of preference: "gzip", "br", "zstd". The
	// first one the client accepts is used. Empty: none, only static and
	// gunzip apply.
	Encodings []string `json:"encodings,omitempty"`
	// Media types encoded besides text/html, or "*" for any (nginx
	// gzip_types).
	Types []string `json:"types,omitempty"`
	// Responses shorter than this are sent as is, such as "1k" (nginx
	// gzip_min_length). Empty: 20 bytes.
	MinLength string `json:"minLength,omitempty"`
	// gzip 1-9 (default 1), br 0-11 (default 6), zstd 1-22 (default 3).
	GzipLevel   uint32  `json:"gzipLevel,omitempty"`
	BrotliLevel *uint32 `json:"brotliLevel,omitempty"`
	ZstdLevel   uint32  `json:"zstdLevel,omitempty"`
	// Encode responses to requests with Via when one of these holds (nginx
	// gzip_proxied): "expired", "no-cache", "no-store", "private",
	// "no_last_modified", "no_etag", "auth", "any". Empty: never.
	Proxied []string `json:"proxied,omitempty"`
	// Send Vary: Accept-Encoding (nginx gzip_vary).
	Vary bool `json:"vary,omitempty"`
	// Serve file.gz next to a static file: "on" to clients that accept
	// gzip, "always" to all (nginx gzip_static).
	Static string `json:"static,omitempty"`
	// Decode gzip responses for clients that do not accept gzip (nginx
	// gunzip).
	Gunzip bool `json:"gunzip,omitempty"`
	// Also encode for HTTP/1.0 clients (nginx gzip_http_version 1.0).
	HTTP10 bool `json:"http10,omitempty"`
	// PCRE2 pattern; clients whose User-Agent matches get plain responses
	// (nginx gzip_disable).
	Disable string `json:"disable,omitempty"`
}

// CachePolicy is nginx proxy_cache_path with proxy_cache and the
// proxy_cache_* directives. Each policy is one cache zone shared by every
// proxy route it applies to; the closest policy applies. Other routes
// ignore it.
type CachePolicy struct {
	// Directory of the entries. Relative or empty: under the proxy data
	// directory in proxy/cache, named after the policy ID by default.
	Path string `json:"path,omitempty"`
	// Subdirectory name lengths, each 1 or 2, at most three (nginx
	// levels=1:2). Default [1, 2].
	Levels []uint32 `json:"levels,omitempty"`
	// Disk size at most, such as "1g"; least recently used entries go
	// first. Empty: unlimited.
	MaxSize string `json:"maxSize,omitempty"`
	// Entries kept at most (keys_zone). Default 100000.
	MaxEntries uint32 `json:"maxEntries,omitempty"`
	// Entries not used for this long are removed. Default "10m".
	Inactive string `json:"inactive,omitempty"`
	// Template. Default "$scheme$proxy_host$request_uri".
	Key string `json:"key,omitempty"`
	// Freshness by status when the upstream does not say
	// (proxy_cache_valid). Responses without either are not stored.
	Valid []CacheValid `json:"valid,omitempty"`
	// Methods cached. Default GET and HEAD.
	Methods []string `json:"methods,omitempty"`
	// Requests for a key before its response is stored. Default 1.
	MinUses uint32 `json:"minUses,omitempty"`
	// CEL expressions over request, as route matches. Bypass answers from
	// the upstream and still stores (proxy_cache_bypass); noStore does not
	// store (proxy_no_cache).
	Bypass  string `json:"bypass,omitempty"`
	NoStore string `json:"noStore,omitempty"`
	// One request per key goes upstream; the others wait up to lockTimeout
	// (default "5s") for its response.
	Lock        bool   `json:"lock,omitempty"`
	LockTimeout string `json:"lockTimeout,omitempty"`
	// When an expired entry answers instead (proxy_cache_use_stale):
	// "error", "timeout", "updating", "http_500", "http_502", "http_503",
	// "http_504", "http_403", "http_404", "http_429".
	UseStale []string `json:"useStale,omitempty"`
	// Answer expired entries at once and refresh after; needs useStale
	// "updating".
	BackgroundUpdate bool `json:"backgroundUpdate,omitempty"`
	// Refresh expired entries with conditional requests.
	Revalidate bool `json:"revalidate,omitempty"`
	// Upstream headers whose caching instructions are ignored:
	// "X-Accel-Expires", "Expires", "Cache-Control", "Set-Cookie", "Vary".
	Ignore []string `json:"ignore,omitempty"`
	// HEAD goes upstream as HEAD, not GET (proxy_cache_convert_head off).
	KeepHead bool `json:"keepHead,omitempty"`
	// Fetch and store ranges of this size apart, such as "1m" (nginx
	// slice); the key gets $slice_range when it is the default. Valid times
	// should include 206.
	Slice string `json:"slice,omitempty"`
	// False turns caching off for the routes it applies to (proxy_cache
	// off); the other settings are then unused.
	Enabled *bool `json:"enabled,omitempty"`
}

// WasmPolicy runs a proxy-wasm (ABI 0.2) plugin in the access phase of the
// routes it applies to: it sees the request headers and, with requestBody,
// the body, then the response headers, and may answer itself. Every wasm
// and waf policy that applies runs, outermost first.
type WasmPolicy struct {
	// SHA-256 of an uploaded module, lowercase hex.
	Module string `json:"module"`
	// Plugin name, its root ID. Default the policy name.
	PluginName string `json:"pluginName,omitempty"`
	// Plugin configuration, often JSON.
	Configuration string `json:"configuration,omitempty"`
	// VM configuration.
	VMConfiguration string `json:"vmConfiguration,omitempty"`
	// Buffer the request body for the plugin, up to maxBody (default "1m").
	RequestBody bool   `json:"requestBody,omitempty"`
	MaxBody     string `json:"maxBody,omitempty"`
	// Memory of one instance at most. Default "256m".
	MaxMemory string `json:"maxMemory,omitempty"`
	// Time one callback may run. Default "1s".
	Timeout string `json:"timeout,omitempty"`
	// When the plugin fails, pass the request on instead of answering 500.
	FailOpen bool `json:"failOpen,omitempty"`
}

// WAFPolicy filters requests with the Coraza web application firewall,
// ModSecurity rules with the OWASP Core Rule Set, run as a proxy-wasm
// plugin. In detect mode matches are only logged; block answers 403.
type WAFPolicy struct {
	// SHA-256 of an uploaded coraza-proxy-wasm module, lowercase hex.
	Module string `json:"module"`
	// "detect" (default) or "block".
	Mode string `json:"mode,omitempty"`
	// Leave out the OWASP Core Rule Set; only rules apply.
	NoCRS bool `json:"noCrs,omitempty"`
	// CRS paranoia level 1 (default) to 4.
	Paranoia uint32 `json:"paranoia,omitempty"`
	// Inbound anomaly score that blocks. Default 5.
	AnomalyThreshold uint32 `json:"anomalyThreshold,omitempty"`
	// More ModSecurity directives (SecLang), one per entry, after the CRS.
	Rules []string `json:"rules,omitempty"`
	// Rules turned off, everywhere or under a path.
	Exceptions []WAFException `json:"exceptions,omitempty"`
	// Inspect the request body, up to maxBody (default "1m").
	RequestBody bool   `json:"requestBody,omitempty"`
	MaxBody     string `json:"maxBody,omitempty"`
	// When the firewall fails, pass the request on instead of answering 500.
	FailOpen bool `json:"failOpen,omitempty"`
}

// WAFException turns off one rule, for requests whose path starts with
// Path when set.
type WAFException struct {
	Rule uint32 `json:"rule"`
	Path string `json:"path,omitempty"`
	// Why, for whoever reads the policy later.
	Note string `json:"note,omitempty"`
}

// CacheValid is one proxy_cache_valid line.
type CacheValid struct {
	// Empty: 200, 301 and 302. "any" alone: every status.
	Statuses []string `json:"statuses,omitempty"`
	// Such as "10m".
	Time string `json:"time"`
}

// CacheUseStale and CacheIgnore are the accepted values of
// CachePolicy.UseStale and CachePolicy.Ignore.
var (
	CacheUseStale = []string{"error", "timeout", "updating", "http_500", "http_502", "http_503", "http_504", "http_403", "http_404", "http_429"}
	CacheIgnore   = []string{"X-Accel-Expires", "Expires", "Cache-Control", "Set-Cookie", "Vary"}
)

// Stream is an L4 proxy (nginx stream server): TCP connections or UDP
// datagrams on an address are relayed to an upstream.
type Stream struct {
	Meta
	Spec StreamSpec `json:"spec"`
}

type StreamProtocol string

const (
	StreamTCP StreamProtocol = "tcp"
	StreamUDP StreamProtocol = "udp"
)

type StreamSpec struct {
	// host:port. A TCP stream must not share it with a listener.
	Address string `json:"address"`
	// "tcp" (default) or "udp" (nginx listen udp).
	Protocol  StreamProtocol `json:"protocol,omitempty"`
	ReusePort bool           `json:"reusePort,omitempty"`
	Backlog   uint32         `json:"backlog,omitempty"`
	// TLS termination (nginx listen ssl); defaultCertificate is required.
	// TCP only.
	TLS *ListenerTLS `json:"tls,omitempty"`
	// Read the SNI name and ALPN from the ClientHello without terminating
	// TLS (nginx ssl_preread), for routing by serverNames. TCP only.
	SSLPreread bool `json:"sslPreread,omitempty"`
	// The first route whose serverNames match the session's SNI name serves
	// it; a route without names matches every session.
	Routes []StreamRoute `json:"routes"`
	// Policy IDs: ipAccess, connLimit and accessLog apply (nginx allow,
	// deny, limit_conn and access_log in a stream server).
	Policies []string `json:"policies,omitempty"`
	// Send a PROXY protocol v1 header to the upstream (nginx
	// proxy_protocol on). TCP only.
	ProxyProtocol bool `json:"proxyProtocol,omitempty"`
	// nginx proxy_connect_timeout. Empty: "60s".
	ConnectTimeout string `json:"connectTimeout,omitempty"`
	// Idle time after which the session ends (nginx proxy_timeout). Empty:
	// "10m".
	Timeout string `json:"timeout,omitempty"`
	// UDP: responses expected per datagram; the session ends after them
	// (nginx proxy_responses). Nil: until the timeout.
	Responses *uint32 `json:"responses,omitempty"`
	// Do not try another target when connecting fails (nginx
	// proxy_next_upstream off).
	NoNextUpstream bool `json:"noNextUpstream,omitempty"`
	// Targets tried at most. Zero: all (nginx proxy_next_upstream_tries).
	Tries uint32 `json:"tries,omitempty"`
}

type StreamRoute struct {
	// SNI names, like a site's hostnames (nginx map $ssl_preread_server_name
	// or server_name in a stream server). Empty: every session.
	ServerNames []HostMatch `json:"serverNames,omitempty"`
	// Upstream ID.
	Upstream string `json:"upstream"`
}

// Lookup defines a variable computed from others: nginx map, geo or
// split_clients. Its name is the variable, usable as $name in every template
// of the configuration.
type Lookup struct {
	Meta
	Spec LookupSpec `json:"spec"`
}

type LookupType string

const (
	LookupMap   LookupType = "map"
	LookupGeo   LookupType = "geo"
	LookupSplit LookupType = "split"
)

// LookupSpec carries the table for Type and nothing else.
type LookupSpec struct {
	Type LookupType `json:"type"`
	// Variable name without '$': lowercase letters, digits and '_'. Empty:
	// the resource name with '-' as '_'.
	Variable string `json:"variable,omitempty"`
	// Template looked up, such as "$http_user_agent". geo: an address,
	// $remote_addr when empty.
	Source string        `json:"source,omitempty"`
	Map    *MapTable     `json:"map,omitempty"`
	Geo    *GeoTable     `json:"geo,omitempty"`
	Split  *SplitClients `json:"split,omitempty"`
}

// MapTable is nginx map. Exact keys compare case-insensitively and win;
// regexes are then tried in order.
type MapTable struct {
	Entries []MapEntry `json:"entries"`
	// Value when nothing matches, a template. Empty: an empty value.
	Default string `json:"default,omitempty"`
	// Keys may be "*.example.com", ".example.com" or "www.example.*" (nginx
	// map hostnames).
	Hostnames bool `json:"hostnames,omitempty"`
}

type MapMatch string

const (
	MapExact   MapMatch = "exact"
	MapRegex   MapMatch = "regex"
	MapRegexCI MapMatch = "regexCI"
)

type MapEntry struct {
	// Empty: exact.
	Match MapMatch `json:"match,omitempty"`
	Key   string   `json:"key"`
	// A template; a regex's groups are $1..$9.
	Value string `json:"value"`
}

// GeoTable is nginx geo: the longest network that contains the address wins.
type GeoTable struct {
	Entries []GeoEntry `json:"entries"`
	Default string     `json:"default,omitempty"`
}

type GeoEntry struct {
	// CIDR or address.
	Network string `json:"network"`
	Value   string `json:"value"`
}

// SplitClients is nginx split_clients: the source's hash picks a bucket by
// percentage.
type SplitClients struct {
	Buckets []SplitBucket `json:"buckets"`
}

type SplitBucket struct {
	// Such as "0.5%" or "20%"; "*" takes the rest and must come last.
	Percent string `json:"percent"`
	Value   string `json:"value"`
}

// VariableName is the variable a lookup defines.
func (l *Lookup) VariableName() string {
	if l.Spec.Variable != "" {
		return l.Spec.Variable
	}
	return strings.ReplaceAll(l.Name, "-", "_")
}

// Config is the full set of resources compiled into one snapshot.
type Config struct {
	Listeners    []*Listener    `json:"listeners,omitempty"`
	Sites        []*Site        `json:"sites,omitempty"`
	Routes       []*Route       `json:"routes,omitempty"`
	Upstreams    []*Upstream    `json:"upstreams,omitempty"`
	Certificates []*Certificate `json:"certificates,omitempty"`
	Policies     []*Policy      `json:"policies,omitempty"`
	Lookups      []*Lookup      `json:"lookups,omitempty"`
	Streams      []*Stream      `json:"streams,omitempty"`
}

// Of returns the resources of kind.
func (c *Config) Of(kind Kind) []Resource {
	var out []Resource
	add := func(n int, at func(int) Resource) {
		for i := range n {
			out = append(out, at(i))
		}
	}
	switch kind.Plural {
	case ListenerKind.Plural:
		add(len(c.Listeners), func(i int) Resource { return c.Listeners[i] })
	case SiteKind.Plural:
		add(len(c.Sites), func(i int) Resource { return c.Sites[i] })
	case RouteKind.Plural:
		add(len(c.Routes), func(i int) Resource { return c.Routes[i] })
	case UpstreamKind.Plural:
		add(len(c.Upstreams), func(i int) Resource { return c.Upstreams[i] })
	case CertificateKind.Plural:
		add(len(c.Certificates), func(i int) Resource { return c.Certificates[i] })
	case PolicyKind.Plural:
		add(len(c.Policies), func(i int) Resource { return c.Policies[i] })
	case LookupKind.Plural:
		add(len(c.Lookups), func(i int) Resource { return c.Lookups[i] })
	case StreamKind.Plural:
		add(len(c.Streams), func(i int) Resource { return c.Streams[i] })
	}
	return out
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
	case *Lookup:
		c.Lookups = append(c.Lookups, r)
	case *Stream:
		c.Streams = append(c.Streams, r)
	default:
		panic("model: unknown resource type")
	}
}

// Ref is a reference from one resource to another by ID.
type Ref struct {
	Kind string
	ID   string
	// The field that holds it, for example "spec.listeners".
	Field string
}

// Refs lists the references r makes, in field order.
func Refs(r Resource) []Ref {
	var out []Ref
	add := func(k Kind, field string, ids ...string) {
		for _, id := range ids {
			if id != "" {
				out = append(out, Ref{Kind: k.Plural, ID: id, Field: field})
			}
		}
	}
	pages := func(field string, eps []ErrorPage) {
		for _, ep := range eps {
			add(RouteKind, field, ep.Route)
		}
	}
	switch r := r.(type) {
	case *Listener:
		add(SiteKind, "spec.defaultSite", r.Spec.DefaultSite)
		if r.Spec.TLS != nil {
			add(CertificateKind, "spec.tls.defaultCertificate", r.Spec.TLS.DefaultCertificate)
		}
	case *Site:
		add(ListenerKind, "spec.listeners", r.Spec.Listeners...)
		add(RouteKind, "spec.routes", r.Spec.Routes...)
		add(CertificateKind, "spec.certificates", r.Spec.Certificates...)
		add(PolicyKind, "spec.policies", r.Spec.Policies...)
		pages("spec.errorPages", r.Spec.ErrorPages)
	case *Route:
		add(RouteKind, "spec.children", r.Spec.Children...)
		add(PolicyKind, "spec.policies", r.Spec.Policies...)
		pages("spec.errorPages", r.Spec.ErrorPages)
		if id, field := r.Spec.Action.Upstream(); id != "" {
			add(UpstreamKind, field, id)
		}
		if s := r.Spec.Action.Static; s != nil && s.TryFiles != nil {
			add(RouteKind, "spec.action.static.tryFiles.route", s.TryFiles.Route)
		}
	case *Upstream:
		if t := r.Spec.TLS; t != nil {
			add(CertificateKind, "spec.tls.certificate", t.Certificate)
		}
	case *Stream:
		if t := r.Spec.TLS; t != nil {
			add(CertificateKind, "spec.tls.defaultCertificate", t.DefaultCertificate)
		}
		for i, rt := range r.Spec.Routes {
			add(UpstreamKind, fmt.Sprintf("spec.routes[%d].upstream", i), rt.Upstream)
		}
		add(PolicyKind, "spec.policies", r.Spec.Policies...)
	case *Policy:
		if f := r.Spec.ForwardAuth; f != nil {
			add(UpstreamKind, "spec.forwardAuth.upstream", f.Upstream)
		}
	}
	return out
}
