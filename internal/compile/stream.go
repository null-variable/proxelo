package compile

import (
	"fmt"
	"slices"

	snapshotv1 "github.com/null-variable/proxelo-api/gen/go/proxelo/snapshot/v1"
	"google.golang.org/protobuf/proto"

	"github.com/null-variable/proxelo/internal/model"
)

// Default log line of a stream session, nginx's usual stream log_format.
const streamLogFormat = `$remote_addr [$time_local] $protocol $status $bytes_sent $bytes_received $session_time "$upstream_addr" "$upstream_bytes_sent" "$upstream_bytes_received" "$upstream_connect_time"`

// streams compiles the L4 proxies. st carries the snapshot's shared zones,
// logs and indexes; its site fields are unused.
func (st *site) streams(items []*model.Stream, listenerAddrs map[string]string, cert func(path, id string) (uint32, bool)) {
	for _, s := range items {
		base := fmt.Sprintf("streams[%s].spec", s.ID)
		sp := s.Spec
		udp := sp.Protocol == model.StreamUDP
		if !udp {
			if l, ok := listenerAddrs[sp.Address]; ok {
				st.c.add(base+".address", "listener %q is bound to %s", l, sp.Address)
			}
		}
		out := &snapshotv1.Stream{
			Id: s.ID, Address: sp.Address, Udp: udp, ReusePort: sp.ReusePort, Backlog: sp.Backlog,
			SslPreread: sp.SSLPreread, ProxyProtocol: sp.ProxyProtocol,
			ConnectTimeoutMs: millis(sp.ConnectTimeout), TimeoutMs: millis(sp.Timeout),
			NoNextUpstream: sp.NoNextUpstream, Tries: sp.Tries,
		}
		if sp.Responses != nil {
			out.Responses = proto.Uint32(*sp.Responses)
		}
		if t := sp.TLS; t != nil {
			out.Tls = listenerTLS(t)
			if i, ok := cert(base+".tls.defaultCertificate", t.DefaultCertificate); ok {
				out.Tls.DefaultCertificate = proto.Uint32(i)
			}
		}
		for i, r := range sp.Routes {
			ui, ok := st.upstreams.resolve(st.c, fmt.Sprintf("%s.routes[%d].upstream", base, i), "upstream", r.Upstream)
			if !ok {
				continue
			}
			sr := &snapshotv1.StreamRoute{Upstream: ui}
			for _, h := range r.ServerNames {
				if kind, ok := hostKinds[h.Type]; ok {
					sr.ServerNames = append(sr.ServerNames, &snapshotv1.HostMatch{Kind: kind, Value: h.Value})
				}
			}
			out.Routes = append(out.Routes, sr)
		}
		var log *model.AccessLogPolicy
		for i, id := range sp.Policies {
			at := fmt.Sprintf("%s.policies[%d]", base, i)
			pi, ok := st.policies.resolve(st.c, at, "policy", id)
			if !ok {
				continue
			}
			p := st.policies.items[pi]
			switch p.Spec.Type {
			case model.PolicyIPAccess:
				out.Rules = append(out.Rules, accessRules(p.Spec.IPAccess)...)
			case model.PolicyConnLimit:
				if zi, ok := st.connZone(p); ok && !slices.Contains(out.ConnLimits, zi) {
					out.ConnLimits = append(out.ConnLimits, zi)
				}
			case model.PolicyAccessLog:
				log = p.Spec.AccessLog
			default:
				st.c.add(at, "%s policy %q does not apply to streams", p.Spec.Type, id)
			}
		}
		if log != nil && (log.Enabled == nil || *log.Enabled) {
			l := *log
			if l.Format == "" || l.Format == "combined" {
				l.Format = streamLogFormat
			}
			out.AccessLog = proto.Uint32(st.accessLog(&l))
		}
		st.snap.Streams = append(st.snap.Streams, out)
	}
}

// accessRules converts nginx allow and deny rules.
func accessRules(ip *model.IPAccessPolicy) []*snapshotv1.AccessRule {
	if ip == nil {
		return nil
	}
	var out []*snapshotv1.AccessRule
	for _, r := range ip.Rules {
		cidr := r.From
		if cidr == "all" {
			cidr = ""
		}
		out = append(out, &snapshotv1.AccessRule{Allow: r.Action == "allow", Cidr: cidr})
	}
	return out
}
