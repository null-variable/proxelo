// Package deploy turns change sets into running revisions: apply with
// commit-confirm, confirm, rollback, the confirm timer and the traffic
// guard. The API, ACME and break-glass all go through it.
package deploy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/null-variable/proxelo/internal/distrib"
	"github.com/null-variable/proxelo/internal/store"
)

// DefaultConfirmTimeout is the commit-confirm window when none is given.
const DefaultConfirmTimeout = 120 * time.Second

// MaxConfirmTimeout bounds the window.
const MaxConfirmTimeout = time.Hour

// Publisher delivers snapshots and reports what proxies handled.
type Publisher interface {
	Publish(snapshot []byte) error
	Traffic(from, to time.Time, revision uint64) distrib.Traffic
}

// Guard thresholds: a pending revision is flagged when its
// error rate exceeds the rate before it by more than the margin, once
// enough traffic was seen to judge.
type Guard struct {
	// Compared window before the apply.
	Baseline time.Duration
	// Minimum requests (upstream attempts) before judging.
	MinRequests uint64
	// Allowed increase of the 5xx share of requests.
	ServerErrorMargin float64
	// Allowed increase of the failed share of upstream attempts.
	UpstreamFailureMargin float64
	// Roll back instead of only flagging.
	Rollback bool
}

// DefaultGuard flags; it rolls back only when configured to.
var DefaultGuard = Guard{Baseline: 5 * time.Minute, MinRequests: 20, ServerErrorMargin: 0.05, UpstreamFailureMargin: 0.05}

// Manager is safe for concurrent use.
type Manager struct {
	st     *store.Store
	pub    Publisher
	verify store.Verify
	guard  Guard
	log    *slog.Logger
	now    func() time.Time

	// wake asks Run to look at the pending revision again.
	wake chan struct{}
	mu   sync.Mutex
}

// New returns a manager. verify dry-loads snapshots; nil skips it.
func New(st *store.Store, pub Publisher, verify store.Verify, guard Guard, log *slog.Logger) *Manager {
	return &Manager{st: st, pub: pub, verify: verify, guard: guard, log: log, now: time.Now, wake: make(chan struct{}, 1)}
}

func (m *Manager) kick() {
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

func (m *Manager) publish(rev *store.Revision) {
	// The revision is stored; proxies that miss this push get it when they
	// reconnect, so a publish failure is logged rather than undone.
	if err := m.pub.Publish(rev.Snapshot); err != nil {
		m.log.Error("publishing snapshot", "revision", rev.Revision, "err", err)
	}
}

// Apply makes change set cs the next revision. A zero confirm applies it
// confirmed; otherwise it rolls back unless confirmed within confirm.
func (m *Manager) Apply(ctx context.Context, cs, actor string, confirm time.Duration) (*store.Revision, error) {
	var by time.Time
	if confirm > 0 {
		by = m.now().Add(confirm)
	}
	rev, err := m.st.ApplyChangeSet(ctx, cs, actor, by, m.verify)
	if err != nil {
		return nil, err
	}
	m.log.Info("applied", "revision", rev.Revision, "status", rev.Status, "author", actor, "hash", fmt.Sprintf("%x", rev.Hash))
	m.publish(rev)
	m.kick()
	return rev, nil
}

// Confirm ends the commit-confirm window of revision n.
func (m *Manager) Confirm(ctx context.Context, n uint64, actor string) (*store.Revision, error) {
	rev, err := m.st.Confirm(ctx, n)
	if err != nil {
		return nil, err
	}
	m.log.Info("confirmed", "revision", n, "by", actor)
	m.kick()
	// Certificates issued while it was pending wait for this.
	m.ApplyHead(ctx)
	return rev, nil
}

// Rollback makes the resources of revision to (0: none) the next revision.
func (m *Manager) Rollback(ctx context.Context, to uint64, actor, message string, confirm time.Duration) (*store.Revision, error) {
	var by time.Time
	if confirm > 0 {
		by = m.now().Add(confirm)
	}
	if message == "" {
		message = fmt.Sprintf("rollback to revision %d", to)
	}
	rev, err := m.st.Rollback(ctx, to, actor, message, by, m.verify)
	if err != nil {
		return nil, err
	}
	m.log.Warn("rolled back", "to", to, "revision", rev.Revision, "by", actor)
	m.publish(rev)
	m.kick()
	return rev, nil
}

// RollbackToConfirmed rolls back to the newest confirmed revision, or to no
// resources when none was ever confirmed.
func (m *Manager) RollbackToConfirmed(ctx context.Context, actor, message string) (*store.Revision, error) {
	var to uint64
	switch last, err := m.st.LastConfirmed(ctx); {
	case errors.Is(err, store.ErrNotFound):
	case err != nil:
		return nil, err
	default:
		to = last.Revision
	}
	return m.Rollback(ctx, to, actor, message, 0)
}

// ApplyHead applies changes the control plane made to the head itself,
// such as issued certificates. While a revision is pending they wait for it
// to be confirmed or rolled back.
func (m *Manager) ApplyHead(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rev, err := m.st.ApplyHead(ctx, "proxelo", "certificates issued", m.verify)
	if errors.Is(err, store.ErrPending) {
		return nil
	}
	if err != nil || rev == nil {
		return err
	}
	m.log.Info("applied", "revision", rev.Revision, "status", rev.Status, "author", "proxelo")
	m.publish(rev)
	return nil
}

// Run reverts a pending revision whose window ends and watches its
// traffic, until ctx ends. It also picks up a revision left pending by a
// previous run.
func (m *Manager) Run(ctx context.Context) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		m.check(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-m.wake:
		}
	}
}

func (m *Manager) check(ctx context.Context) {
	rev, err := m.st.Pending(ctx)
	if errors.Is(err, store.ErrNotFound) {
		return
	}
	if err != nil {
		m.log.Error("commit-confirm", "err", err)
		return
	}
	now := m.now()
	if !now.Before(rev.ConfirmBy) {
		m.revert(ctx, rev, "not confirmed in time")
		return
	}
	finding := m.judge(rev, now)
	if finding == "" || finding == rev.Guard {
		return
	}
	if err := m.st.SetGuard(ctx, rev.Revision, finding); err != nil {
		m.log.Error("guard", "err", err)
	}
	m.st.Audit(ctx, "proxelo", "revision.guard", fmt.Sprint(rev.Revision), map[string]any{"finding": finding, "rollback": m.guard.Rollback})
	m.log.Warn("guard", "revision", rev.Revision, "finding", finding)
	if m.guard.Rollback {
		m.revert(ctx, rev, finding)
	}
}

func (m *Manager) revert(ctx context.Context, rev *store.Revision, why string) {
	out, err := m.RollbackToConfirmed(ctx, "proxelo", fmt.Sprintf("revert revision %d: %s", rev.Revision, why))
	if err != nil {
		m.log.Error("reverting", "revision", rev.Revision, "err", err)
		return
	}
	m.st.Audit(ctx, "proxelo", "revision.revert", fmt.Sprint(rev.Revision), map[string]any{"reason": why, "revision": out.Revision})
}

// judge compares the traffic since rev was applied with the traffic before.
func (m *Manager) judge(rev *store.Revision, now time.Time) string {
	g := m.guard
	before := m.pub.Traffic(rev.CreatedAt.Add(-g.Baseline), rev.CreatedAt, 0)
	after := m.pub.Traffic(rev.CreatedAt, now, rev.Revision)
	rate := func(n, d uint64) float64 {
		if d == 0 {
			return 0
		}
		return float64(n) / float64(d)
	}
	if after.Requests >= g.MinRequests {
		b, a := rate(before.ServerErrors, before.Requests), rate(after.ServerErrors, after.Requests)
		if a > b+g.ServerErrorMargin {
			return fmt.Sprintf("5xx rate %.1f%%, was %.1f%%", a*100, b*100)
		}
	}
	if after.UpstreamAttempts >= g.MinRequests {
		b, a := rate(before.UpstreamFailures, before.UpstreamAttempts), rate(after.UpstreamFailures, after.UpstreamAttempts)
		if a > b+g.UpstreamFailureMargin {
			return fmt.Sprintf("upstream failure rate %.1f%%, was %.1f%%", a*100, b*100)
		}
	}
	return ""
}
