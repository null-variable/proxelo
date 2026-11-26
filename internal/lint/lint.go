// Package lint finds configurations that compile but are probably wrong,
// and checks that could lock out the admin. Findings never block an apply.
package lint

import (
	"fmt"
	"net"
	"strings"

	"github.com/null-variable/proxelo/internal/model"
)

// Finding is one warning at a field path.
type Finding struct {
	Path    string `json:"path"`
	Message string `json:"message"`
	// "warning", or "safety" for changes that may cut off admin access.
	Level string `json:"level"`
}

// Check returns the findings for cfg. adminAddr is the admin API address.
func Check(cfg model.Config, adminAddr string) []Finding {
	var out []Finding
	warn := func(path, format string, args ...any) {
		out = append(out, Finding{Path: path, Message: fmt.Sprintf(format, args...), Level: "warning"})
	}

	routes := map[string]*model.Route{}
	for _, r := range cfg.Routes {
		routes[r.ID] = r
	}
	policies := map[string]*model.Policy{}
	for _, p := range cfg.Policies {
		policies[p.ID] = p
	}
	certs := map[string]*model.Certificate{}
	for _, c := range cfg.Certificates {
		certs[c.ID] = c
	}
	listeners := map[string]*model.Listener{}
	for _, l := range cfg.Listeners {
		listeners[l.ID] = l
	}

	used := map[string]bool{}
	var walk func(path string, ids []string)
	walk = func(path string, ids []string) {
		// Regex routes are tried in order; an identical earlier one without
		// conditions takes every request.
		seen := map[model.PathMatch]string{}
		for i, id := range ids {
			r := routes[id]
			if r == nil || used[id] {
				continue
			}
			used[id] = true
			m := r.Spec.Match.Path
			if m.Type == model.PathRegex || m.Type == model.PathRegexCI {
				if other, ok := seen[m]; ok {
					warn(fmt.Sprintf("%s[%d]", path, i), "route %q is unreachable: route %q has the same pattern and no conditions", id, other)
				} else if !r.Spec.Match.HasConditions() {
					seen[m] = id
				}
			}
			markRefs(used, r.Spec.ErrorPages, r.Spec.Action)
			walk(fmt.Sprintf("routes[%s].spec.children", id), r.Spec.Children)
		}
	}
	for _, s := range cfg.Sites {
		if !s.IsEnabled() {
			continue
		}
		markRefs(used, s.Spec.ErrorPages, model.Action{})
		walk(fmt.Sprintf("sites[%s].spec.routes", s.ID), s.Spec.Routes)

		base := fmt.Sprintf("sites[%s].spec", s.ID)
		tls := false
		for _, id := range s.Spec.Listeners {
			if l := listeners[id]; l != nil && l.IsEnabled() && l.Spec.TLS != nil {
				tls = true
			}
		}
		if tls && !setsHeader(policies, s.Spec.Policies, "strict-transport-security", false) {
			warn(base+".policies", "served over HTTPS without a Strict-Transport-Security header")
		}
		if tls && len(s.Spec.Certificates) == 0 {
			warn(base+".certificates", "served over HTTPS without a certificate: handshakes use the listener default")
		}
		for i, id := range s.Spec.Certificates {
			c := certs[id]
			if c == nil {
				continue
			}
			p := fmt.Sprintf("%s.certificates[%d]", base, i)
			switch {
			case c.Spec.ChainPEM == "":
				warn(p, "certificate %q is not issued yet and is left out", id)
			case c.Spec.Status.Error != "":
				warn(p, "certificate %q: %s", id, c.Spec.Status.Error)
			}
			for j, h := range s.Spec.Hostnames {
				if h.Type == model.HostExact && c.Spec.Status.Subject != "" && !covers(c.Spec.Status.DNSNames, h.Value) {
					warn(fmt.Sprintf("%s.hostnames[%d]", base, j), "%q is not covered by certificate %q", h.Value, id)
				}
			}
		}
	}
	for _, r := range cfg.Routes {
		if r.IsEnabled() && !used[r.ID] {
			warn(fmt.Sprintf("routes[%s]", r.ID), "route is not used by any site")
		}
		if p := r.Spec.Action.Proxy; p != nil && setsHeader(policies, r.Spec.Policies, "authorization", true) {
			warn(fmt.Sprintf("routes[%s].spec.policies", r.ID), "sends credentials to upstream %q over plain HTTP", p.Upstream)
		}
	}

	if _, adminPort, err := net.SplitHostPort(adminAddr); err == nil {
		for _, l := range cfg.Listeners {
			if _, port, err := net.SplitHostPort(l.Spec.Address); err == nil && port == adminPort && l.IsEnabled() {
				out = append(out, Finding{
					Path:    fmt.Sprintf("listeners[%s].spec.address", l.ID),
					Message: fmt.Sprintf("uses the admin API port %s; binding fails or takes over admin access", port),
					Level:   "safety",
				})
			}
		}
	}
	return out
}

func markRefs(used map[string]bool, eps []model.ErrorPage, a model.Action) {
	for _, ep := range eps {
		if ep.Route != "" {
			used[ep.Route] = true
		}
	}
	if s := a.Static; s != nil && s.TryFiles != nil && s.TryFiles.Route != "" {
		used[s.TryFiles.Route] = true
	}
}

// setsHeader reports whether a headers policy sets name on responses, or on
// requests sent upstream.
func setsHeader(policies map[string]*model.Policy, ids []string, name string, request bool) bool {
	for _, id := range ids {
		p := policies[id]
		if p == nil || p.Spec.Headers == nil {
			continue
		}
		ops := p.Spec.Headers.Response
		if request {
			ops = p.Spec.Headers.Request
		}
		{
			for k := range ops.Set {
				if strings.EqualFold(k, name) {
					return true
				}
			}
			for _, h := range ops.Add {
				if strings.EqualFold(h.Name, name) {
					return true
				}
			}
		}
	}
	return false
}

func covers(names []string, host string) bool {
	for _, n := range names {
		n = strings.ToLower(n)
		if n == host {
			return true
		}
		if rest, ok := strings.CutPrefix(n, "*."); ok {
			if i := strings.IndexByte(host, '.'); i > 0 && host[i+1:] == rest {
				return true
			}
		}
	}
	return false
}
