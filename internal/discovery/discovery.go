// Package discovery finds upstream targets in service registries: Docker
// container labels, Kubernetes EndpointSlices and the Consul catalog. A
// Manager polls the registry of every upstream with discovery in the head
// and hands what it finds to a Sink, which sends it to the proxies.
package discovery

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/null-variable/proxelo/internal/model"
)

// DefaultInterval is how often a registry is read when the upstream does
// not say.
const DefaultInterval = 10 * time.Second

// requestTimeout bounds one registry read.
const requestTimeout = 10 * time.Second

// Sink receives the targets found for an upstream: host:port addresses,
// sorted. nil forgets the upstream.
type Sink interface {
	SetDiscovered(upstreamID string, addresses []string)
}

// Source gives the upstreams of the head.
type Source func(ctx context.Context) ([]*model.Upstream, error)

// Status is what the last read of one upstream's registry found.
type Status struct {
	UpstreamID string    `json:"upstreamId"`
	Provider   string    `json:"provider"`
	Addresses  []string  `json:"addresses"`
	CheckedAt  time.Time `json:"checkedAt"`
	Error      string    `json:"error,omitempty"`
}

// provider reads one registry.
type provider interface {
	targets(ctx context.Context) ([]string, error)
}

// Manager is safe for concurrent use.
type Manager struct {
	src  Source
	sink Sink
	log  *slog.Logger

	mu      sync.Mutex
	watches map[string]*watch
	wake    chan struct{}
}

type watch struct {
	// The settings it runs with; a change restarts it.
	spec   model.Discovery
	cancel context.CancelFunc
	status Status
}

func New(src Source, sink Sink, log *slog.Logger) *Manager {
	return &Manager{src: src, sink: sink, log: log, watches: map[string]*watch{}, wake: make(chan struct{}, 1)}
}

// Kick makes Run look at the head again, after a revision is applied.
func (m *Manager) Kick() {
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

// Statuses returns the last result of every watched upstream.
func (m *Manager) Statuses() []Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Status, 0, len(m.watches))
	for _, w := range m.watches {
		out = append(out, w.status)
	}
	slices.SortFunc(out, func(a, b Status) int { return cmp.Compare(a.UpstreamID, b.UpstreamID) })
	return out
}

// Run keeps one watch per upstream with discovery until ctx ends.
func (m *Manager) Run(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		m.sync(ctx)
		select {
		case <-ctx.Done():
			m.mu.Lock()
			for _, w := range m.watches {
				w.cancel()
			}
			m.mu.Unlock()
			return
		case <-t.C:
		case <-m.wake:
		}
	}
}

// sync starts, restarts and stops watches to match the head.
func (m *Manager) sync(ctx context.Context) {
	ups, err := m.src(ctx)
	if err != nil {
		m.log.Error("discovery", "err", err)
		return
	}
	want := map[string]model.Discovery{}
	for _, u := range ups {
		if d := u.Spec.Discovery; d != nil && u.IsEnabled() {
			want[u.ID] = *d
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, w := range m.watches {
		if d, ok := want[id]; !ok || !sameSpec(d, w.spec) {
			w.cancel()
			delete(m.watches, id)
			if !ok {
				m.sink.SetDiscovered(id, nil)
			}
		}
	}
	for id, d := range want {
		if _, ok := m.watches[id]; ok {
			continue
		}
		p, err := newProvider(d)
		wctx, cancel := context.WithCancel(ctx)
		w := &watch{spec: d, cancel: cancel, status: Status{UpstreamID: id, Provider: string(d.Provider)}}
		m.watches[id] = w
		if err != nil {
			w.status.Error = err.Error()
			cancel()
			continue
		}
		go m.poll(wctx, id, w, p, interval(d))
	}
}

func sameSpec(a, b model.Discovery) bool {
	return a.Provider == b.Provider && a.Endpoint == b.Endpoint && slices.Equal(a.Selector, b.Selector) &&
		a.Port == b.Port && a.Network == b.Network && a.Tag == b.Tag && a.Token == b.Token && a.Interval == b.Interval
}

func interval(d model.Discovery) time.Duration {
	if v, err := time.ParseDuration(d.Interval); err == nil && v > 0 {
		return v
	}
	return DefaultInterval
}

// poll reads the registry every period; a failed read keeps the last
// targets.
func (m *Manager) poll(ctx context.Context, id string, w *watch, p provider, period time.Duration) {
	var last []string
	sent := false
	t := time.NewTicker(period)
	defer t.Stop()
	for {
		rctx, cancel := context.WithTimeout(ctx, requestTimeout)
		addrs, err := p.targets(rctx)
		cancel()
		if ctx.Err() != nil {
			return
		}
		m.mu.Lock()
		w.status.CheckedAt = time.Now().UTC()
		if err != nil {
			if w.status.Error != err.Error() {
				m.log.Warn("discovery", "upstream", id, "provider", w.spec.Provider, "err", err)
			}
			w.status.Error = err.Error()
		} else {
			slices.Sort(addrs)
			addrs = slices.Compact(addrs)
			w.status.Error = ""
			w.status.Addresses = addrs
		}
		m.mu.Unlock()
		if err == nil && (!sent || !slices.Equal(addrs, last)) {
			m.log.Info("discovered targets", "upstream", id, "count", len(addrs))
			m.sink.SetDiscovered(id, addrs)
			last, sent = addrs, true
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func newProvider(d model.Discovery) (provider, error) {
	switch d.Provider {
	case model.DiscoveryDocker:
		return newDocker(d)
	case model.DiscoveryKubernetes:
		return newKubernetes(d)
	case model.DiscoveryConsul:
		return newConsul(d)
	}
	return nil, fmt.Errorf("unknown provider %q", d.Provider)
}

// hostPort joins an address and a port, bracketing IPv6.
func hostPort(ip string, port int) string {
	return net.JoinHostPort(ip, strconv.Itoa(port))
}

// getJSON GETs url with c into v.
func getJSON(ctx context.Context, c *http.Client, url string, header http.Header, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	for k, vs := range header {
		req.Header[k] = vs
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", url, resp.Status)
	}
	return decodeLimited(resp, v)
}
