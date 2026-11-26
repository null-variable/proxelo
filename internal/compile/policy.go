package compile

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
	"strings"

	snapshotv1 "github.com/null-variable/proxelo-api/gen/go/proxelo/snapshot/v1"
	"google.golang.org/protobuf/proto"

	"github.com/null-variable/proxelo/internal/model"
)

// Policy inheritance: the site's policies apply to every
// route, a route adds its own to its parent's, and inheritPolicies: false
// starts over. Headers policies merge by header name with the closest one
// winning; one accessLog policy applies, the closest. The proxy receives the
// result per route and knows nothing of policies.

// Built-in log formats (nginx log_format). "main" is the format nginx ships
// in its default nginx.conf.
var logFormats = map[string]string{
	"":         `$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"`,
	"combined": `$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"`,
	"main":     `$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" "$http_x_forwarded_for"`,
	"json": `{"time":"$time_iso8601","remote_addr":"$remote_addr","request_id":"$request_id","method":"$request_method",` +
		`"uri":"$request_uri","protocol":"$server_protocol","status":$status,"bytes_sent":$bytes_sent,` +
		`"request_time":$request_time,"host":"$host","referer":"$http_referer","user_agent":"$http_user_agent",` +
		`"upstream_addr":"$upstream_addr","upstream_status":"$upstream_status","upstream_response_time":"$upstream_response_time"}`,
}

type logKey struct {
	path, format string
	json         bool
}

// resolvePolicies returns the enabled policies listed at path, in order.
// realIp policies apply before the route is chosen, so only a site may list
// them.
func (st *site) resolvePolicies(path string, ids []string) []*model.Policy {
	var out []*model.Policy
	route := strings.HasPrefix(path, "routes[")
	for i, id := range ids {
		at := fmt.Sprintf("%s[%d]", path, i)
		if pi, ok := st.policies.resolve(st.c, at, "policy", id); ok {
			p := st.policies.items[pi]
			if route && p.Spec.Type == model.PolicyRealIP {
				st.c.add(at, "realIp policy %q applies to sites only", id)
				continue
			}
			out = append(out, p)
		}
	}
	return out
}

// effect is what a list of policies, outermost first, comes to.
type effect struct {
	response  *snapshotv1.HeaderOps
	request   *snapshotv1.HeaderOps
	log       *uint32
	access    *snapshotv1.Access
	bandwidth *snapshotv1.Bandwidth
}

// zones are the limit zones of the snapshot, one per policy, by policy ID.
type zones struct {
	rate map[string]uint32
	conn map[string]uint32
}

// The default key of limit policies, nginx's usual $binary_remote_addr.
const defaultLimitKey = "$binary_remote_addr"

// headerSet merges header operations by lowercase name; later wins.
type headerSet struct {
	// By lowercase name.
	set    map[string]headerEntry
	add    []*snapshotv1.HeaderValue
	remove map[string]bool
}

type headerEntry struct {
	name   string
	value  string
	always bool
}

func newHeaderSet() *headerSet {
	return &headerSet{set: map[string]headerEntry{}, remove: map[string]bool{}}
}

func (h *headerSet) apply(o model.HeaderOps) {
	for _, name := range slices.Sorted(maps.Keys(o.Set)) {
		k := strings.ToLower(name)
		delete(h.remove, k)
		h.add = slices.DeleteFunc(h.add, func(v *snapshotv1.HeaderValue) bool { return strings.ToLower(v.Name) == k })
		h.set[k] = headerEntry{name, o.Set[name], o.Always}
	}
	for _, name := range o.Remove {
		k := strings.ToLower(name)
		delete(h.set, k)
		h.add = slices.DeleteFunc(h.add, func(v *snapshotv1.HeaderValue) bool { return strings.ToLower(v.Name) == k })
		h.remove[k] = true
	}
	for _, a := range o.Add {
		h.add = append(h.add, &snapshotv1.HeaderValue{Name: a.Name, Value: a.Value, Always: o.Always})
	}
}

func (h *headerSet) ops() *snapshotv1.HeaderOps {
	if len(h.set) == 0 && len(h.add) == 0 && len(h.remove) == 0 {
		return nil
	}
	out := &snapshotv1.HeaderOps{Add: h.add}
	for _, k := range slices.Sorted(maps.Keys(h.set)) {
		e := h.set[k]
		out.Set = append(out.Set, &snapshotv1.HeaderValue{Name: e.name, Value: e.value, Always: e.always})
	}
	// A set header replaces the original anyway; a removal is only needed
	// for names that are not set.
	for _, k := range slices.Sorted(maps.Keys(h.remove)) {
		out.Remove = append(out.Remove, k)
	}
	return out
}

// effective folds a full policy list, outermost first.
func (st *site) effective(all []*model.Policy) effect {
	resp, req := newHeaderSet(), newHeaderSet()
	var e effect
	var log *model.AccessLogPolicy
	a := &snapshotv1.Access{}
	for _, p := range all {
		switch p.Spec.Type {
		case model.PolicyHeaders:
			if h := p.Spec.Headers; h != nil {
				resp.apply(h.Response)
				req.apply(h.Request)
			}
		case model.PolicyAccessLog:
			log = p.Spec.AccessLog
		case model.PolicyRateLimit:
			if i, ok := st.rateZone(p); ok && !slices.Contains(a.RateLimits, i) {
				a.RateLimits = append(a.RateLimits, i)
			}
		case model.PolicyConnLimit:
			if i, ok := st.connZone(p); ok && !slices.Contains(a.ConnLimits, i) {
				a.ConnLimits = append(a.ConnLimits, i)
			}
		case model.PolicyBandwidth:
			if b := p.Spec.Bandwidth; b != nil {
				rate, _ := model.ParseSize(b.Rate)
				after, _ := model.ParseSize(b.After)
				e.bandwidth = &snapshotv1.Bandwidth{Rate: rate, After: after}
			}
		case model.PolicyIPAccess:
			a.Rules = append(a.Rules, accessRules(p.Spec.IPAccess)...)
		case model.PolicyBasicAuth:
			if b := p.Spec.BasicAuth; b != nil {
				ba := &snapshotv1.BasicAuth{Realm: b.Realm}
				for _, u := range b.Users {
					ba.Users = append(ba.Users, &snapshotv1.BasicUser{Name: u.Name, Hash: u.Hash})
				}
				a.BasicAuth = ba
			}
		case model.PolicyForwardAuth:
			a.ForwardAuth = st.forwardAuth(p)
		}
	}
	if len(a.RateLimits) > 0 || len(a.ConnLimits) > 0 || len(a.Rules) > 0 || a.BasicAuth != nil || a.ForwardAuth != nil {
		e.access = a
	}
	e.response, e.request = resp.ops(), req.ops()
	if log != nil && (log.Enabled == nil || *log.Enabled) {
		e.log = proto.Uint32(st.accessLog(log))
	}
	return e
}

// rateZone returns the index of p's rate zone, adding it on first use.
func (st *site) rateZone(p *model.Policy) (uint32, bool) {
	r := p.Spec.RateLimit
	if r == nil {
		return 0, false
	}
	if i, ok := st.zones.rate[p.ID]; ok {
		return i, true
	}
	rate, err := model.ParseRate(r.Rate)
	if err != nil {
		return 0, false // reported by model.Validate
	}
	z := &snapshotv1.RateZone{
		Id: p.ID, Key: cmp.Or(r.Key, defaultLimitKey), RateMilli: rate, Burst: r.Burst, Delay: r.Delay,
		Status: r.Status, DryRun: r.DryRun, MaxKeys: r.MaxKeys,
	}
	if r.NoDelay {
		z.Delay = r.Burst
	}
	i := uint32(len(st.snap.RateZones))
	st.snap.RateZones = append(st.snap.RateZones, z)
	st.zones.rate[p.ID] = i
	return i, true
}

// connZone returns the index of p's connection zone, adding it on first use.
func (st *site) connZone(p *model.Policy) (uint32, bool) {
	c := p.Spec.ConnLimit
	if c == nil {
		return 0, false
	}
	if i, ok := st.zones.conn[p.ID]; ok {
		return i, true
	}
	i := uint32(len(st.snap.ConnZones))
	st.snap.ConnZones = append(st.snap.ConnZones, &snapshotv1.ConnZone{
		Id: p.ID, Key: cmp.Or(c.Key, defaultLimitKey), Max: c.Max, Status: c.Status, DryRun: c.DryRun, MaxKeys: c.MaxKeys,
	})
	st.zones.conn[p.ID] = i
	return i, true
}

func (st *site) forwardAuth(p *model.Policy) *snapshotv1.ForwardAuth {
	f := p.Spec.ForwardAuth
	if f == nil {
		return nil
	}
	ui, ok := st.upstreams.resolve(st.c, fmt.Sprintf("policies[%s].spec.forwardAuth.upstream", p.ID), "upstream", f.Upstream)
	if !ok {
		return nil
	}
	out := &snapshotv1.ForwardAuth{Upstream: ui, Uri: cmp.Or(f.URI, "/"), TimeoutMs: millis(f.Timeout)}
	for _, h := range f.CopyHeaders {
		out.CopyHeaders = append(out.CopyHeaders, strings.ToLower(h))
	}
	return out
}

// realIP returns the realIp setting of the site's policies: the last one.
func realIP(pols []*model.Policy) *snapshotv1.RealIp {
	var out *snapshotv1.RealIp
	for _, p := range pols {
		if r := p.Spec.RealIP; p.Spec.Type == model.PolicyRealIP && r != nil {
			out = &snapshotv1.RealIp{From: r.From, Header: strings.ToLower(cmp.Or(r.Header, "X-Real-IP")), Recursive: r.Recursive}
		}
	}
	return out
}

// accessLog returns the index of the snapshot access log for l, adding it on
// first use.
func (st *site) accessLog(l *model.AccessLogPolicy) uint32 {
	format, builtin := logFormats[l.Format]
	if !builtin {
		format = l.Format
	}
	k := logKey{l.Path, format, l.EscapeJSON || l.Format == "json"}
	if i, ok := st.logs[k]; ok {
		return i
	}
	i := uint32(len(st.snap.AccessLogs))
	st.snap.AccessLogs = append(st.snap.AccessLogs, &snapshotv1.AccessLog{Path: k.path, Format: k.format, EscapeJson: k.json})
	st.logs[k] = i
	return i
}

// routePolicies is the policy list a route sees: its parent's plus its own,
// or only its own when it does not inherit.
func routePolicies(parent []*model.Policy, own []*model.Policy, inherit *bool) []*model.Policy {
	if inherit != nil && !*inherit {
		return own
	}
	return append(slices.Clip(parent), own...)
}
