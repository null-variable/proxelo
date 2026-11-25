package compile

import (
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
func (st *site) resolvePolicies(path string, ids []string) []*model.Policy {
	var out []*model.Policy
	for i, id := range ids {
		if pi, ok := st.policies.resolve(st.c, fmt.Sprintf("%s[%d]", path, i), "policy", id); ok {
			out = append(out, st.policies.items[pi])
		}
	}
	return out
}

// effect is what a list of policies, outermost first, comes to.
type effect struct {
	response *snapshotv1.HeaderOps
	request  *snapshotv1.HeaderOps
	log      *uint32
}

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
	for _, p := range all {
		switch p.Spec.Type {
		case model.PolicyHeaders:
			if h := p.Spec.Headers; h != nil {
				resp.apply(h.Response)
				req.apply(h.Request)
			}
		case model.PolicyAccessLog:
			log = p.Spec.AccessLog
		}
	}
	e.response, e.request = resp.ops(), req.ops()
	if log != nil && (log.Enabled == nil || *log.Enabled) {
		e.log = proto.Uint32(st.accessLog(log))
	}
	return e
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
