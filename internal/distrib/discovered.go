package distrib

import distribv1 "github.com/null-variable/proxelo-api/gen/go/proxelo/distrib/v1"

type discoveredSet struct {
	addresses []string
	version   uint64
}

// SetDiscovered replaces the targets discovery found for an upstream and
// sends them to every proxy; each one that connects later gets them too.
// nil clears them.
func (d *Distributor) SetDiscovered(upstreamID string, addresses []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.discovered == nil {
		d.discovered = map[string]discoveredSet{}
	}
	d.discVersion++
	d.discovered[upstreamID] = discoveredSet{addresses: addresses, version: d.discVersion}
	for _, n := range d.nodes {
		select {
		case n.wake <- struct{}{}:
		default:
		}
	}
}

// takeDiscovered returns the discovered targets n has not been sent and
// marks them sent. Callers hold d.mu.
func (n *node) takeDiscovered(all map[string]discoveredSet) []*distribv1.DiscoveredTargets {
	var out []*distribv1.DiscoveredTargets
	for id, s := range all {
		if n.sentDiscovered[id] == s.version {
			continue
		}
		n.sentDiscovered[id] = s.version
		out = append(out, &distribv1.DiscoveredTargets{UpstreamId: id, Addresses: s.addresses})
	}
	return out
}
