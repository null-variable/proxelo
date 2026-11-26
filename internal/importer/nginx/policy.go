package nginx

import (
	"fmt"
	"slices"
	"strings"

	"github.com/null-variable/proxelo/internal/compile"
	"github.com/null-variable/proxelo/internal/model"
)

func defaultParams(p model.GatewayProtocol) []model.GatewayParam { return compile.DefaultParams(p) }

// policy returns the ID of a policy with spec, sharing one per identical
// spec.
func (c *converter) policy(name string, spec model.PolicySpec) string {
	key := fmt.Sprintf("%#v", spec)
	if spec.Headers != nil || spec.BasicAuth != nil || spec.Compression != nil || spec.IPAccess != nil || spec.AccessLog != nil || spec.RealIP != nil {
		key = fmt.Sprintf("%s:%+v%+v%+v%+v%+v%+v", spec.Type, spec.Headers, spec.BasicAuth, spec.Compression, spec.IPAccess, spec.AccessLog, spec.RealIP)
	}
	if id, ok := c.policies[key]; ok {
		return id
	}
	p := &model.Policy{Meta: meta(model.PolicyKind, c.name("policies", name)), Spec: spec}
	c.cfg.Policies = append(c.cfg.Policies, p)
	c.policies[key] = p.ID
	return p.ID
}

func (c *converter) realIPPolicy(r *model.RealIPPolicy) string {
	if r == nil || len(r.From) == 0 {
		return ""
	}
	return c.policy("real-ip", model.PolicySpec{Type: model.PolicyRealIP, RealIP: r})
}

// scopePolicies returns the policies a level adds over its parent. A route
// inherits its parent's policies, so only what changed is attached; a
// family the level resets in nginx terms (an array directive set here)
// replaces the parent's: Proxelo merges headers by name, which matches
// nginx when the level repeats what it keeps.
func (c *converter) scopePolicies(s, parent scope) []string {
	var out []string
	if s.set["add_header"] || s.set["proxy_set_header"] || s.set["proxy_hide_header"] {
		h := &model.HeadersPolicy{}
		if s.set["add_header"] {
			always := false
			for _, x := range s.addHeader {
				if h.Response.Set == nil {
					h.Response.Set = map[string]string{}
				}
				if _, dup := h.Response.Set[x.name]; dup {
					h.Response.Add = append(h.Response.Add, model.HeaderValue{Name: x.name, Value: x.value})
				} else {
					h.Response.Set[x.name] = x.value
				}
				always = always || x.always
			}
			h.Response.Always = always
		}
		if s.set["proxy_set_header"] {
			for _, x := range s.setHeader {
				if h.Request.Set == nil {
					h.Request.Set = map[string]string{}
				}
				h.Request.Set[x.name] = x.value
			}
		}
		if s.set["proxy_hide_header"] {
			h.Response.Remove = slices.Clone(s.hideHeader)
		}
		out = append(out, c.policy("headers", model.PolicySpec{Type: model.PolicyHeaders, Headers: h}))
	}
	if s.set["access"] && len(s.rules) > 0 {
		out = append(out, c.policy("ip-access", model.PolicySpec{Type: model.PolicyIPAccess, IPAccess: &model.IPAccessPolicy{Rules: s.rules}}))
	}
	if s.set["limit_req"] {
		for _, l := range s.limitReq {
			z := *c.reqZones[l.zone]
			z.Burst, z.Delay, z.NoDelay = l.burst, l.delay, l.nodelay
			z.Status, z.DryRun = s.reqStatus, s.reqDry
			out = append(out, c.policy("rate-"+l.zone, model.PolicySpec{Type: model.PolicyRateLimit, RateLimit: &z}))
		}
	}
	if s.set["limit_conn"] {
		for _, l := range s.limitConn {
			z := *c.connZones[l.zone]
			z.Max = l.max
			z.Status, z.DryRun = s.connStatus, s.connDry
			out = append(out, c.policy("conn-"+l.zone, model.PolicySpec{Type: model.PolicyConnLimit, ConnLimit: &z}))
		}
	}
	if s.basicRealm != "" && len(s.basicUsers) > 0 && (s.basicRealm != parent.basicRealm || !slices.Equal(s.basicUsers, parent.basicUsers)) {
		out = append(out, c.policy("basic-auth", model.PolicySpec{Type: model.PolicyBasicAuth, BasicAuth: &model.BasicAuthPolicy{Realm: s.basicRealm, Users: s.basicUsers}}))
	}
	if s.accessLog != nil && (parent.accessLog == nil || *s.accessLog != *parent.accessLog) {
		l := *s.accessLog
		out = append(out, c.policy("log-"+strings.Trim(l.Path, "/"), model.PolicySpec{Type: model.PolicyAccessLog, AccessLog: &l}))
	} else if s.logOff && !parent.logOff {
		off := false
		out = append(out, c.policy("log-off", model.PolicySpec{Type: model.PolicyAccessLog, AccessLog: &model.AccessLogPolicy{Path: "stdout", Enabled: &off}}))
	}
	if s.gzip != nil && (parent.gzip == nil || fmt.Sprintf("%+v", *s.gzip) != fmt.Sprintf("%+v", *parent.gzip)) {
		g := *s.gzip
		out = append(out, c.policy("compression", model.PolicySpec{Type: model.PolicyCompression, Compression: &g}))
	}
	if s.rate != "" && (s.rate != parent.rate || s.after != parent.after) && s.rate != "0" {
		out = append(out, c.policy("bandwidth", model.PolicySpec{Type: model.PolicyBandwidth, Bandwidth: &model.BandwidthPolicy{Rate: s.rate, After: s.after}}))
	}
	return out
}
