package model

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
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
	}
	return es
}

func (s *ListenerSpec) validate(es *FieldErrors) {
	if err := checkHostPort(s.Address); err != "" {
		es.add("spec.address", "%s", err)
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

	a := s.Action
	switch a.Type {
	case ActionStatic:
		if a.Proxy != nil {
			es.add("spec.action.proxy", "must be empty when type is %q", a.Type)
		}
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
	case ActionProxy:
		if a.Static != nil {
			es.add("spec.action.static", "must be empty when type is %q", a.Type)
		}
		if a.Proxy == nil {
			es.add("spec.action.proxy", "is required when type is %q", a.Type)
			return
		}
		if a.Proxy.Upstream == "" {
			es.add("spec.action.proxy.upstream", "is required")
		}
	default:
		es.add("spec.action.type", "must be %q or %q", ActionStatic, ActionProxy)
	}
}

func (s *UpstreamSpec) validate(es *FieldErrors) {
	if len(s.Targets) == 0 {
		es.add("spec.targets", "at least one target is required")
	}
	for i, t := range s.Targets {
		if err := checkHostPort(t.Address); err != "" {
			es.add(fmt.Sprintf("spec.targets[%d].address", i), "%s", err)
		}
	}
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
