// Package model defines the resources users edit through the API and UI.
package model

// Listener is a socket the proxy accepts connections on.
type Listener struct {
	ID          string `json:"id"`
	Address     string `json:"address"`
	ReusePort   bool   `json:"reusePort"`
	Backlog     uint32 `json:"backlog"`
	DefaultSite string `json:"defaultSite,omitempty"`
}

// Site groups routes served for a set of hostnames.
type Site struct {
	ID        string   `json:"id"`
	Listeners []string `json:"listeners"`
	Hostnames []string `json:"hostnames"`
	Routes    []Route  `json:"routes"`
}

// PathKind selects how a route path is compared with the request path.
type PathKind string

const (
	PathExact  PathKind = "exact"
	PathPrefix PathKind = "prefix"
)

// Route maps a request path to an action.
type Route struct {
	Path   Path   `json:"path"`
	Action Action `json:"action"`
}

type Path struct {
	Kind  PathKind `json:"kind"`
	Value string   `json:"value"`
}

// Action is exactly one of Static or Proxy.
type Action struct {
	Static *StaticAction `json:"static,omitempty"`
	Proxy  *ProxyAction  `json:"proxy,omitempty"`
}

type StaticAction struct {
	Root  string   `json:"root"`
	Index []string `json:"index,omitempty"`
}

type ProxyAction struct {
	Upstream string `json:"upstream"`
}

// Upstream is a pool of backend targets.
type Upstream struct {
	ID            string   `json:"id"`
	Targets       []Target `json:"targets"`
	KeepaliveIdle uint32   `json:"keepaliveIdle"`
}

type Target struct {
	Address string `json:"address"`
	Weight  uint32 `json:"weight"`
}

// Config is the full set of resources compiled into one snapshot.
type Config struct {
	Listeners []Listener `json:"listeners"`
	Sites     []Site     `json:"sites"`
	Upstreams []Upstream `json:"upstreams"`
}
