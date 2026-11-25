// Package distrib pushes snapshots to proxies over the DistributionService
// gRPC stream.
//
// Proxies dial in, say Hello and keep the stream open. The control plane sends
// the latest snapshot as soon as a proxy connects and again whenever a newer
// revision is applied; a proxy that is already serving the same snapshot
// (same hash) acknowledges it without swapping. Each Ack updates the node's
// reported state.
package distrib

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	distribv1 "github.com/null-variable/proxelo-api/gen/go/proxelo/distrib/v1"
	snapshotv1 "github.com/null-variable/proxelo-api/gen/go/proxelo/snapshot/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// NodeStatus is what the control plane knows about one connected proxy.
type NodeStatus struct {
	NodeID       string    `json:"nodeId"`
	ProxyVersion string    `json:"proxyVersion"`
	ConnectedAt  time.Time `json:"connectedAt"`
	// Revision the proxy serves: from Hello, then from every applied Ack.
	ActiveRevision uint64 `json:"activeRevision"`
	// Latest revision sent on this connection, 0 if none.
	SentRevision uint64 `json:"sentRevision"`
	// Set when the proxy rejected a snapshot; cleared by the next applied Ack.
	FailedRevision uint64 `json:"failedRevision,omitempty"`
	Error          string `json:"error,omitempty"`
}

// Distributor implements DistributionService. It is safe for concurrent use.
type Distributor struct {
	distribv1.UnimplementedDistributionServiceServer

	log *slog.Logger

	mu     sync.Mutex
	latest *published
	// challenges is the ACME challenge set; version counts replacements.
	challenges *distribv1.Challenges
	chVersion  uint64
	nodes      map[string]*node
}

// published is a snapshot as sent: the exact bytes the hash covers.
type published struct {
	revision uint64
	data     []byte
}

type node struct {
	status NodeStatus
	// wake has room for one signal: a newer snapshot may be available.
	wake chan struct{}
	// Challenge set version last sent on this connection.
	sentChallenges uint64
	// replaced is closed when a newer connection takes over the node ID.
	replaced chan struct{}
}

func New(log *slog.Logger) *Distributor {
	return &Distributor{log: log, nodes: map[string]*node{}}
}

// Publish makes the serialized snapshot the one served to every proxy, unless
// a newer revision is already published.
func (d *Distributor) Publish(b []byte) error {
	snap := &snapshotv1.Snapshot{}
	if err := proto.Unmarshal(b, snap); err != nil {
		return fmt.Errorf("publish: %w", err)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.latest != nil && d.latest.revision >= snap.GetRevision() {
		return nil
	}
	d.latest = &published{revision: snap.GetRevision(), data: slices.Clone(b)}
	d.wakeAll()
	return nil
}

// SetChallenges replaces the ACME challenges every proxy answers.
func (d *Distributor) SetChallenges(c *distribv1.Challenges) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.challenges = c
	d.chVersion++
	d.wakeAll()
}

func (d *Distributor) wakeAll() {
	for _, n := range d.nodes {
		select {
		case n.wake <- struct{}{}:
		default:
		}
	}
}

// Nodes returns the connected proxies ordered by node ID.
func (d *Distributor) Nodes() []NodeStatus {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]NodeStatus, 0, len(d.nodes))
	for _, n := range d.nodes {
		out = append(out, n.status)
	}
	slices.SortFunc(out, func(a, b NodeStatus) int { return strings.Compare(a.NodeID, b.NodeID) })
	return out
}

// Sync serves one proxy connection.
func (d *Distributor) Sync(stream distribv1.DistributionService_SyncServer) error {
	req, err := stream.Recv()
	if err != nil {
		return err
	}
	hello := req.GetHello()
	if hello == nil {
		return status.Error(codes.InvalidArgument, "the first message must be hello")
	}
	if hello.GetNodeId() == "" {
		return status.Error(codes.InvalidArgument, "hello.node_id is required")
	}
	n := d.register(hello)
	defer d.unregister(n)
	d.log.Info("proxy connected", "node", hello.GetNodeId(), "version", hello.GetProxyVersion(), "activeRevision", hello.GetActiveRevision())

	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()
	// Recv runs on its own goroutine; Send stays on this one, as gRPC
	// requires one sender per stream. Recv returns once the handler does.
	recvErr := make(chan error, 1)
	go func() {
		err := d.recvLoop(stream, n)
		recvErr <- err
		cancel()
	}()

	err = d.sendLoop(ctx, stream, n)
	select {
	case rerr := <-recvErr:
		if rerr != nil {
			err = rerr
		} else {
			err = nil // the proxy closed the stream
		}
	default:
	}
	d.log.Info("proxy disconnected", "node", hello.GetNodeId(), "err", err)
	return err
}

func (d *Distributor) register(hello *distribv1.Hello) *node {
	n := &node{
		status: NodeStatus{
			NodeID:         hello.GetNodeId(),
			ProxyVersion:   hello.GetProxyVersion(),
			ConnectedAt:    time.Now().UTC(),
			ActiveRevision: hello.GetActiveRevision(),
		},
		wake:     make(chan struct{}, 1),
		replaced: make(chan struct{}),
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if old, ok := d.nodes[n.status.NodeID]; ok {
		close(old.replaced)
	}
	d.nodes[n.status.NodeID] = n
	return n
}

func (d *Distributor) unregister(n *node) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.nodes[n.status.NodeID] == n {
		delete(d.nodes, n.status.NodeID)
	}
}

// sendLoop sends the latest snapshot whenever it is newer than the last one
// sent on this connection, starting with the one current at connect time.
func (d *Distributor) sendLoop(ctx context.Context, stream distribv1.DistributionService_SyncServer, n *node) error {
	for {
		d.mu.Lock()
		snap := d.latest
		if snap != nil && snap.revision == n.status.SentRevision {
			snap = nil
		}
		var ch *distribv1.Challenges
		chVersion := d.chVersion
		if chVersion != n.sentChallenges {
			ch = d.challenges
			if ch == nil {
				ch = &distribv1.Challenges{}
			}
		}
		d.mu.Unlock()

		// Challenges go first: a snapshot may add a site whose certificate
		// is being issued.
		if ch != nil {
			resp := &distribv1.SyncResponse{Kind: &distribv1.SyncResponse_Challenges{Challenges: ch}}
			if err := stream.Send(resp); err != nil {
				return err
			}
			d.mu.Lock()
			n.sentChallenges = chVersion
			d.mu.Unlock()
		}
		if snap != nil {
			resp := &distribv1.SyncResponse{Kind: &distribv1.SyncResponse_SnapshotData{SnapshotData: snap.data}}
			if err := stream.Send(resp); err != nil {
				return err
			}
			d.mu.Lock()
			n.status.SentRevision = snap.revision
			d.mu.Unlock()
			d.log.Info("snapshot sent", "node", n.status.NodeID, "revision", snap.revision)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-n.replaced:
			return status.Error(codes.Aborted, "replaced by a newer connection from the same node")
		case <-n.wake:
		}
	}
}

func (d *Distributor) recvLoop(stream distribv1.DistributionService_SyncServer, n *node) error {
	for {
		req, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		ack := req.GetAck()
		if ack == nil {
			return status.Error(codes.InvalidArgument, "expected ack")
		}
		d.mu.Lock()
		if ack.GetApplied() {
			n.status.ActiveRevision = ack.GetRevision()
			n.status.FailedRevision, n.status.Error = 0, ""
		} else {
			n.status.FailedRevision, n.status.Error = ack.GetRevision(), ack.GetError()
		}
		d.mu.Unlock()
		if ack.GetApplied() {
			d.log.Info("snapshot applied", "node", n.status.NodeID, "revision", ack.GetRevision())
		} else {
			d.log.Warn("snapshot rejected", "node", n.status.NodeID, "revision", ack.GetRevision(), "error", ack.GetError())
		}
	}
}

// Listen opens the Unix socket proxies dial. Access is controlled by file
// permissions: the socket is created 0660 in a 0750 directory.
// A stale socket from a previous run is replaced.
func Listen(path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o660); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

// NewServer returns a gRPC server with d registered.
func NewServer(d *Distributor) *grpc.Server {
	s := grpc.NewServer()
	distribv1.RegisterDistributionServiceServer(s, d)
	return s
}
