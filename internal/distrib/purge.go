package distrib

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"maps"
	"slices"
	"strings"

	distribv1 "github.com/null-variable/proxelo-api/gen/go/proxelo/distrib/v1"
)

// PurgeResult is one node's answer to a purge.
type PurgeResult struct {
	NodeID  string `json:"nodeId"`
	Removed uint64 `json:"removed"`
	Error   string `json:"error,omitempty"`
}

// ErrNoNodes means no proxy is connected to purge.
var ErrNoNodes = errors.New("no proxy connected")

// purges are the purges sent to nodes and not answered yet.
type purges struct {
	// By purge ID: the answers, one per node, buffered for every node.
	waiting map[string]chan *distribv1.PurgeDone
}

// Purge removes cached responses on every connected proxy and waits for
// their answers until ctx ends. Nodes that did not answer are reported with
// the context's error.
func (d *Distributor) Purge(ctx context.Context, p *distribv1.Purge) ([]PurgeResult, error) {
	var b [8]byte
	_, _ = rand.Read(b[:])
	p.Id = "purge-" + hex.EncodeToString(b[:])
	d.mu.Lock()
	if len(d.nodes) == 0 {
		d.mu.Unlock()
		return nil, ErrNoNodes
	}
	answers := make(chan *distribv1.PurgeDone, len(d.nodes))
	if d.purges.waiting == nil {
		d.purges.waiting = map[string]chan *distribv1.PurgeDone{}
	}
	d.purges.waiting[p.Id] = answers
	pending := map[string]bool{}
	for id, n := range d.nodes {
		n.purges = append(n.purges, p)
		pending[id] = true
		select {
		case n.wake <- struct{}{}:
		default:
		}
	}
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		delete(d.purges.waiting, p.Id)
		d.mu.Unlock()
	}()

	var out []PurgeResult
	for len(pending) > 0 {
		select {
		case done := <-answers:
			// purgeDone puts the node ID in Id.
			node := done.GetId()
			if !pending[node] {
				continue
			}
			delete(pending, node)
			out = append(out, PurgeResult{NodeID: node, Removed: done.GetRemoved(), Error: done.GetError()})
		case <-ctx.Done():
			for _, id := range slices.Sorted(maps.Keys(pending)) {
				out = append(out, PurgeResult{NodeID: id, Error: ctx.Err().Error()})
			}
			pending = nil
		}
	}
	slices.SortFunc(out, func(a, b PurgeResult) int { return strings.Compare(a.NodeID, b.NodeID) })
	return out, nil
}

// purgeDone hands a node's answer to the waiting Purge, if any.
func (d *Distributor) purgeDone(n *node, done *distribv1.PurgeDone) {
	d.mu.Lock()
	ch := d.purges.waiting[done.GetId()]
	d.mu.Unlock()
	if ch == nil {
		return
	}
	select {
	case ch <- &distribv1.PurgeDone{Id: n.status.NodeID, Removed: done.GetRemoved(), Error: done.GetError()}:
	default:
	}
}

// takePurges returns and clears the purges queued for n. Callers hold d.mu.
func (n *node) takePurges() []*distribv1.Purge {
	out := n.purges
	n.purges = nil
	return out
}
