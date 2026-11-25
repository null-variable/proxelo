// Package compile turns user resources into the snapshot served by proxies.
package compile

import (
	"crypto/sha256"
	"fmt"

	snapshotv1 "github.com/null-variable/proxelo-api/gen/go/proxelo/snapshot/v1"
	"google.golang.org/protobuf/proto"

	"github.com/null-variable/proxelo/internal/model"
)

// Error points at the resource field that failed to compile.
type Error struct {
	Path string
	Msg  string
}

func (e *Error) Error() string { return e.Path + ": " + e.Msg }

func errf(path, format string, args ...any) error {
	return &Error{Path: path, Msg: fmt.Sprintf(format, args...)}
}

// Compile resolves IDs to indexes and returns a snapshot with its hash set.
func Compile(cfg model.Config, revision uint64) (*snapshotv1.Snapshot, error) {
	listenerIdx := make(map[string]uint32, len(cfg.Listeners))
	for i, l := range cfg.Listeners {
		if _, dup := listenerIdx[l.ID]; dup {
			return nil, errf(fmt.Sprintf("listeners[%s]", l.ID), "duplicate id")
		}
		listenerIdx[l.ID] = uint32(i)
	}
	siteIdx := make(map[string]uint32, len(cfg.Sites))
	for i, s := range cfg.Sites {
		if _, dup := siteIdx[s.ID]; dup {
			return nil, errf(fmt.Sprintf("sites[%s]", s.ID), "duplicate id")
		}
		siteIdx[s.ID] = uint32(i)
	}
	upstreamIdx := make(map[string]uint32, len(cfg.Upstreams))
	for i, u := range cfg.Upstreams {
		if _, dup := upstreamIdx[u.ID]; dup {
			return nil, errf(fmt.Sprintf("upstreams[%s]", u.ID), "duplicate id")
		}
		upstreamIdx[u.ID] = uint32(i)
	}

	snap := &snapshotv1.Snapshot{Revision: revision}

	for _, l := range cfg.Listeners {
		out := &snapshotv1.Listener{Address: l.Address, ReusePort: l.ReusePort, Backlog: l.Backlog}
		if l.DefaultSite != "" {
			idx, ok := siteIdx[l.DefaultSite]
			if !ok {
				return nil, errf(fmt.Sprintf("listeners[%s].defaultSite", l.ID), "unknown site %q", l.DefaultSite)
			}
			out.DefaultSite = proto.Uint32(idx)
		}
		snap.Listeners = append(snap.Listeners, out)
	}

	for _, s := range cfg.Sites {
		base := fmt.Sprintf("sites[%s]", s.ID)
		out := &snapshotv1.Site{}
		for _, lid := range s.Listeners {
			idx, ok := listenerIdx[lid]
			if !ok {
				return nil, errf(base+".listeners", "unknown listener %q", lid)
			}
			out.Listeners = append(out.Listeners, idx)
		}
		for _, h := range s.Hostnames {
			out.Hostnames = append(out.Hostnames, &snapshotv1.HostMatch{
				Kind:  snapshotv1.HostMatch_KIND_EXACT,
				Value: h,
			})
		}
		for i, r := range s.Routes {
			route, err := compileRoute(fmt.Sprintf("%s.routes[%d]", base, i), r, upstreamIdx)
			if err != nil {
				return nil, err
			}
			out.Routes = append(out.Routes, route)
		}
		snap.Sites = append(snap.Sites, out)
	}

	for _, u := range cfg.Upstreams {
		if len(u.Targets) == 0 {
			return nil, errf(fmt.Sprintf("upstreams[%s].targets", u.ID), "at least one target is required")
		}
		out := &snapshotv1.Upstream{
			Balancing:     snapshotv1.Upstream_BALANCING_ROUND_ROBIN,
			KeepaliveIdle: u.KeepaliveIdle,
		}
		for _, t := range u.Targets {
			w := t.Weight
			if w == 0 {
				w = 1
			}
			out.Targets = append(out.Targets, &snapshotv1.Target{Address: t.Address, Weight: w})
		}
		snap.Upstreams = append(snap.Upstreams, out)
	}

	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(snap)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	snap.Hash = sum[:]
	return snap, nil
}

func compileRoute(path string, r model.Route, upstreams map[string]uint32) (*snapshotv1.Route, error) {
	out := &snapshotv1.Route{Path: &snapshotv1.PathMatch{Value: r.Path.Value}}
	switch r.Path.Kind {
	case model.PathExact:
		out.Path.Kind = snapshotv1.PathMatch_KIND_EXACT
	case model.PathPrefix:
		out.Path.Kind = snapshotv1.PathMatch_KIND_PREFIX
	default:
		return nil, errf(path+".path.kind", "must be %q or %q", model.PathExact, model.PathPrefix)
	}

	switch {
	case r.Action.Static != nil && r.Action.Proxy != nil:
		return nil, errf(path+".action", "set exactly one of static or proxy")
	case r.Action.Static != nil:
		out.Action = &snapshotv1.Action{Kind: &snapshotv1.Action_Static{Static: &snapshotv1.StaticAction{
			Root:  r.Action.Static.Root,
			Index: r.Action.Static.Index,
		}}}
	case r.Action.Proxy != nil:
		idx, ok := upstreams[r.Action.Proxy.Upstream]
		if !ok {
			return nil, errf(path+".action.proxy.upstream", "unknown upstream %q", r.Action.Proxy.Upstream)
		}
		out.Action = &snapshotv1.Action{Kind: &snapshotv1.Action_Proxy{Proxy: &snapshotv1.ProxyAction{Upstream: idx}}}
	default:
		return nil, errf(path+".action", "set exactly one of static or proxy")
	}
	return out, nil
}
