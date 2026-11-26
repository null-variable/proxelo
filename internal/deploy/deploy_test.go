package deploy

import (
	"context"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/null-variable/proxelo/internal/distrib"
	"github.com/null-variable/proxelo/internal/model"
	"github.com/null-variable/proxelo/internal/store"
)

type fakePub struct {
	published int
	before    distrib.Traffic
	after     distrib.Traffic
}

func (f *fakePub) Publish([]byte) error { f.published++; return nil }

func (f *fakePub) Traffic(from, to time.Time, revision uint64) distrib.Traffic {
	if revision == 0 {
		return f.before
	}
	return f.after
}

func setup(t *testing.T, g Guard) (*Manager, *store.Store, *fakePub) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	pub := &fakePub{}
	return New(st, pub, nil, g, slog.New(slog.DiscardHandler)), st, pub
}

func listenerChange(t *testing.T, st *store.Store, name, addr string) string {
	t.Helper()
	ctx := context.Background()
	cs, err := st.CreateChangeSet(ctx, "t", name)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Create(ctx, cs.ID, model.ListenerKind, &model.Listener{Meta: model.Meta{Name: name}, Spec: model.ListenerSpec{Address: addr}}); err != nil {
		t.Fatal(err)
	}
	return cs.ID
}

func TestTimeoutReverts(t *testing.T) {
	m, st, pub := setup(t, DefaultGuard)
	ctx := context.Background()
	if _, err := m.Apply(ctx, listenerChange(t, st, "a", "0.0.0.0:80"), "t", 0); err != nil {
		t.Fatal(err)
	}
	rev, err := m.Apply(ctx, listenerChange(t, st, "b", "0.0.0.0:81"), "t", time.Minute)
	if err != nil || rev.Status != store.StatusPending {
		t.Fatalf("apply = %+v, %v", rev, err)
	}
	m.check(ctx) // within the window: nothing
	if _, err := st.Pending(ctx); err != nil {
		t.Fatal("pending revision went away early")
	}
	m.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	m.check(ctx)
	if _, err := st.Pending(ctx); err == nil {
		t.Fatal("still pending after the window")
	}
	latest, _ := st.Latest(ctx)
	if latest.Revision != 3 || len(latest.Config.Listeners) != 1 || latest.Config.Listeners[0].Name != "a" || pub.published != 3 {
		t.Fatalf("after revert: revision %d, listeners %+v, published %d", latest.Revision, latest.Config.Listeners, pub.published)
	}
	if r2, _ := st.Revision(ctx, 2); r2.Status != store.StatusReverted {
		t.Fatalf("revision 2 = %s", r2.Status)
	}
	es, _ := st.AuditLog(ctx, 0, 10)
	if len(es) != 1 || es[0].Action != "revision.revert" {
		t.Fatalf("audit = %+v", es)
	}
}

func TestGuard(t *testing.T) {
	g := DefaultGuard
	g.Rollback = true
	m, st, pub := setup(t, g)
	ctx := context.Background()
	if _, err := m.Apply(ctx, listenerChange(t, st, "a", "0.0.0.0:80"), "t", time.Minute); err != nil {
		t.Fatal(err)
	}
	pub.before = distrib.Traffic{Requests: 1000, ServerErrors: 10}
	pub.after = distrib.Traffic{Requests: 10, ServerErrors: 9}
	m.check(ctx) // too few requests to judge
	if _, err := st.Pending(ctx); err != nil {
		t.Fatal("judged on too little traffic")
	}
	pub.after = distrib.Traffic{Requests: 100, ServerErrors: 50}
	m.check(ctx)
	r1, _ := st.Revision(ctx, 1)
	if r1.Status != store.StatusReverted || r1.Guard == "" {
		t.Fatalf("revision 1 = %+v", r1)
	}
	// Nothing was confirmed before: the rollback empties the configuration.
	latest, _ := st.Latest(ctx)
	if latest.Revision != 2 || len(latest.Config.Listeners) != 0 {
		t.Fatalf("latest = %d %+v", latest.Revision, latest.Config.Listeners)
	}
}

func TestIssuedCertificateWaitsForPending(t *testing.T) {
	m, st, pub := setup(t, DefaultGuard)
	ctx := context.Background()
	cs, _ := st.CreateChangeSet(ctx, "t", "cert")
	cert := &model.Certificate{Meta: model.Meta{Name: "c"}, Spec: model.CertificateSpec{Source: model.CertACME, Domains: []string{"example.com"}}}
	if err := st.Create(ctx, cs.ID, model.CertificateKind, cert); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Apply(ctx, cs.ID, "t", time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SetCertificate(ctx, cert.ID, "chain", "key", model.CertStatus{}); err != nil {
		t.Fatal(err)
	}
	if err := m.ApplyHead(ctx); err != nil || pub.published != 1 {
		t.Fatalf("applied while pending: %v, %d", err, pub.published)
	}
	if _, err := m.Confirm(ctx, 1, "t"); err != nil {
		t.Fatal(err)
	}
	latest, _ := st.Latest(ctx)
	if latest.Revision != 2 || latest.Config.Certificates[0].Spec.ChainPEM != "chain" || pub.published != 2 {
		t.Fatalf("latest = %d, published %d", latest.Revision, pub.published)
	}
	// Nothing new: no revision.
	if err := m.ApplyHead(ctx); err != nil || pub.published != 2 {
		t.Fatalf("empty apply: %v, %d", err, pub.published)
	}
}
