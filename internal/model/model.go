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
	ListenerKind = Kind{Plural: "listeners", IDPrefix: "lst", New: func() Resource { return &Listener{} }}
	SiteKind     = Kind{Plural: "sites", IDPrefix: "site", New: func() Resource { return &Site{} }}
	RouteKind    = Kind{Plural: "routes", IDPrefix: "rt", New: func() Resource { return &Route{} }}
	UpstreamKind = Kind{Plural: "upstreams", IDPrefix: "up", New: func() Resource { return &Upstream{} }}
)

// Kinds lists every resource kind in a fixed order.
var Kinds = []Kind{ListenerKind, SiteKind, RouteKind, UpstreamKind}

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
}

type Match struct {
	Path PathMatch `json:"path"`
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
	Upstream string `json:"upstream"`
}

// Upstream is a pool of backend targets (nginx upstream).
type Upstream struct {
	Meta
	Spec UpstreamSpec `json:"spec"`
}

type UpstreamSpec struct {
	Targets   []Target  `json:"targets"`
	Keepalive Keepalive `json:"keepalive"`
}

type Target struct {
	// host:port
	Address string `json:"address"`
	// Zero means 1.
	Weight uint32 `json:"weight,omitempty"`
}

type Keepalive struct {
	// Idle connections kept per worker (nginx keepalive).
	Idle uint32 `json:"idle,omitempty"`
}

// Config is the full set of resources compiled into one snapshot.
type Config struct {
	Listeners []*Listener `json:"listeners,omitempty"`
	Sites     []*Site     `json:"sites,omitempty"`
	Routes    []*Route    `json:"routes,omitempty"`
	Upstreams []*Upstream `json:"upstreams,omitempty"`
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
	default:
		panic("model: unknown resource type")
	}
}
