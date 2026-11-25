package distrib

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	distribv1 "github.com/null-variable/proxelo-api/gen/go/proxelo/distrib/v1"
	snapshotv1 "github.com/null-variable/proxelo-api/gen/go/proxelo/snapshot/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func snap(t *testing.T, rev uint64) []byte {
	t.Helper()
	b, err := proto.Marshal(&snapshotv1.Snapshot{Revision: rev})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// serve starts d on a Unix socket in a temporary directory.
func serve(t *testing.T, d *Distributor) string {
	t.Helper()
	// Unix socket paths are limited to ~100 bytes; t.TempDir can be longer.
	dir, err := os.MkdirTemp("", "distrib")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "run", "control.sock")
	ln, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(d)
	go s.Serve(ln)
	t.Cleanup(s.Stop)
	return path
}

type proxy struct {
	t      *testing.T
	stream grpc.BidiStreamingClient[distribv1.SyncRequest, distribv1.SyncResponse]
	cancel context.CancelFunc
}

func dial(t *testing.T, path, node string, active uint64) *proxy {
	t.Helper()
	conn, err := grpc.NewClient("unix://"+path, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	stream, err := distribv1.NewDistributionServiceClient(conn).Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	p := &proxy{t: t, stream: stream, cancel: cancel}
	p.send(&distribv1.SyncRequest{Kind: &distribv1.SyncRequest_Hello{Hello: &distribv1.Hello{NodeId: node, ProxyVersion: "test", ActiveRevision: active}}})
	return p
}

func (p *proxy) send(req *distribv1.SyncRequest) {
	p.t.Helper()
	if err := p.stream.Send(req); err != nil {
		p.t.Fatal(err)
	}
}

func (p *proxy) ack(rev uint64, applied bool, msg string) {
	p.t.Helper()
	p.send(&distribv1.SyncRequest{Kind: &distribv1.SyncRequest_Ack{Ack: &distribv1.Ack{Revision: rev, Applied: applied, Error: msg}}})
}

// recv waits for the next snapshot and returns its revision.
func (p *proxy) recv() uint64 {
	p.t.Helper()
	type result struct {
		resp *distribv1.SyncResponse
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		resp, err := p.stream.Recv()
		ch <- result{resp, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			p.t.Fatal(r.err)
		}
		snap := &snapshotv1.Snapshot{}
		if err := proto.Unmarshal(r.resp.GetSnapshotData(), snap); err != nil {
			p.t.Fatalf("snapshot_data: %v", err)
		}
		return snap.GetRevision()
	case <-time.After(5 * time.Second):
		p.t.Fatal("no snapshot within 5s")
		return 0
	}
}

func waitFor(t *testing.T, d *Distributor, cond func([]NodeStatus) bool) []NodeStatus {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		nodes := d.Nodes()
		if cond(nodes) {
			return nodes
		}
		if time.Now().After(deadline) {
			t.Fatalf("condition not met; nodes = %+v", nodes)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestPushOnConnectAndOnPublish(t *testing.T) {
	d := New(slog.New(slog.DiscardHandler))
	if err := d.Publish(snap(t, 1)); err != nil {
		t.Fatal(err)
	}
	path := serve(t, d)

	p := dial(t, path, "node-a", 0)
	if got := p.recv(); got != 1 {
		t.Fatalf("snapshot on connect = %d, want 1", got)
	}
	p.ack(1, true, "")
	waitFor(t, d, func(n []NodeStatus) bool { return len(n) == 1 && n[0].ActiveRevision == 1 })

	if err := d.Publish(snap(t, 2)); err != nil {
		t.Fatal(err)
	}
	if got := p.recv(); got != 2 {
		t.Fatalf("pushed snapshot = %d, want 2", got)
	}
	p.ack(2, false, "bind 0.0.0.0:80: permission denied")
	nodes := waitFor(t, d, func(n []NodeStatus) bool { return len(n) == 1 && n[0].FailedRevision == 2 })
	if nodes[0].ActiveRevision != 1 || nodes[0].Error == "" || nodes[0].SentRevision != 2 || nodes[0].ProxyVersion != "test" {
		t.Fatalf("status after rejected snapshot = %+v", nodes[0])
	}

	// An older revision never replaces a newer one.
	if err := d.Publish(snap(t, 1)); err != nil {
		t.Fatal(err)
	}
	if err := d.Publish(snap(t, 3)); err != nil {
		t.Fatal(err)
	}
	if got := p.recv(); got != 3 {
		t.Fatalf("snapshot after stale publish = %d, want 3", got)
	}
	p.ack(3, true, "")
	nodes = waitFor(t, d, func(n []NodeStatus) bool { return len(n) == 1 && n[0].ActiveRevision == 3 })
	if nodes[0].FailedRevision != 0 || nodes[0].Error != "" {
		t.Fatalf("applied ack did not clear the failure: %+v", nodes[0])
	}

	p.cancel()
	waitFor(t, d, func(n []NodeStatus) bool { return len(n) == 0 })
}

func TestNoSnapshotUntilPublished(t *testing.T) {
	d := New(slog.New(slog.DiscardHandler))
	path := serve(t, d)
	p := dial(t, path, "node-a", 7)
	nodes := waitFor(t, d, func(n []NodeStatus) bool { return len(n) == 1 })
	if nodes[0].ActiveRevision != 7 || nodes[0].SentRevision != 0 {
		t.Fatalf("status = %+v", nodes[0])
	}
	if err := d.Publish(snap(t, 8)); err != nil {
		t.Fatal(err)
	}
	if got := p.recv(); got != 8 {
		t.Fatalf("snapshot = %d, want 8", got)
	}
}

func TestSameNodeReconnectReplacesOldStream(t *testing.T) {
	d := New(slog.New(slog.DiscardHandler))
	if err := d.Publish(snap(t, 1)); err != nil {
		t.Fatal(err)
	}
	path := serve(t, d)
	old := dial(t, path, "node-a", 0)
	old.recv()
	fresh := dial(t, path, "node-a", 1)
	if got := fresh.recv(); got != 1 {
		t.Fatalf("snapshot on reconnect = %d", got)
	}
	_, err := old.stream.Recv()
	if status.Code(err) != codes.Aborted {
		t.Fatalf("old stream ended with %v, want Aborted", err)
	}
	nodes := waitFor(t, d, func(n []NodeStatus) bool { return len(n) == 1 })
	if nodes[0].ActiveRevision != 1 {
		t.Fatalf("node = %+v", nodes[0])
	}
}

func TestHelloRequired(t *testing.T) {
	d := New(slog.New(slog.DiscardHandler))
	path := serve(t, d)
	conn, err := grpc.NewClient("unix://"+path, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for _, first := range []*distribv1.SyncRequest{
		{Kind: &distribv1.SyncRequest_Ack{Ack: &distribv1.Ack{Revision: 1}}},
		{Kind: &distribv1.SyncRequest_Hello{Hello: &distribv1.Hello{}}},
	} {
		stream, err := distribv1.NewDistributionServiceClient(conn).Sync(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if err := stream.Send(first); err != nil {
			t.Fatal(err)
		}
		if _, err := stream.Recv(); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("first message %v: err = %v, want InvalidArgument", first, err)
		}
	}
	if n := d.Nodes(); len(n) != 0 {
		t.Fatalf("nodes = %+v", n)
	}
}

func TestListenReplacesStaleSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "distrib")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "control.sock")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ln, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSocket == 0 || fi.Mode().Perm() != 0o660 {
		t.Fatalf("socket mode = %v", fi.Mode())
	}
}
