package discovery

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/null-variable/proxelo/internal/model"
)

func registry(t *testing.T, routes map[string]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := routes[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("X-Consul-Index", "7")
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestProviders(t *testing.T) {
	srv := registry(t, map[string]string{
		"/containers/json": `[
			{"NetworkSettings":{"Networks":{"b":{"IPAddress":"10.0.1.2"},"a":{"IPAddress":"10.0.0.2"}}}},
			{"NetworkSettings":{"Networks":{"b":{"IPAddress":"10.0.1.3"}}}}]`,
		"/apis/discovery.k8s.io/v1/namespaces/shop/endpointslices": `{"items":[{
			"ports":[{"name":"metrics","port":9100},{"name":"http","port":8080}],
			"endpoints":[{"addresses":["10.1.0.5"]},{"addresses":["10.1.0.6"],"conditions":{"ready":false}},{"addresses":["fd00::7"],"conditions":{"ready":true}}]}]}`,
		"/v1/health/service/web": `[{"Node":{"Address":"10.2.0.1"},"Service":{"Address":"","Port":80}},{"Node":{"Address":"10.2.0.1"},"Service":{"Address":"10.2.0.9","Port":81}}]`,
	})
	cases := []struct {
		d    model.Discovery
		want []string
	}{
		{model.Discovery{Provider: model.DiscoveryDocker, Endpoint: srv.URL, Selector: []string{"app=web"}, Port: "80"}, []string{"10.0.0.2:80", "10.0.1.3:80"}},
		{model.Discovery{Provider: model.DiscoveryDocker, Endpoint: srv.URL, Selector: []string{"app"}, Port: "80", Network: "b"}, []string{"10.0.1.2:80", "10.0.1.3:80"}},
		{model.Discovery{Provider: model.DiscoveryKubernetes, Endpoint: srv.URL, Selector: []string{"shop/web"}, Port: "http"}, []string{"10.1.0.5:8080", "[fd00::7]:8080"}},
		{model.Discovery{Provider: model.DiscoveryKubernetes, Endpoint: srv.URL, Selector: []string{"shop/web"}}, []string{"10.1.0.5:9100", "[fd00::7]:9100"}},
		{model.Discovery{Provider: model.DiscoveryConsul, Endpoint: srv.URL, Selector: []string{"web"}}, []string{"10.2.0.1:80", "10.2.0.9:81"}},
	}
	for _, c := range cases {
		p, err := newProvider(c.d)
		if err != nil {
			t.Fatal(err)
		}
		got, err := p.targets(context.Background())
		if err != nil {
			t.Fatalf("%s: %v", c.d.Provider, err)
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("%s %v: got %v, want %v", c.d.Provider, c.d.Selector, got, c.want)
		}
	}
	if _, err := newProvider(model.Discovery{Provider: model.DiscoveryKubernetes, Selector: []string{"a/b"}}); err == nil || !strings.Contains(err.Error(), "not running in a cluster") {
		t.Errorf("kubernetes outside a cluster: %v", err)
	}
}

type sink struct {
	mu  sync.Mutex
	got map[string][]string
}

func (s *sink) SetDiscovered(id string, addrs []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.got[id] = addrs
}

func (s *sink) get(id string) ([]string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.got[id]
	return v, ok
}

func TestManager(t *testing.T) {
	srv := registry(t, map[string]string{"/v1/health/service/web": `[{"Node":{"Address":"10.2.0.1"},"Service":{"Port":80}}]`})
	up := &model.Upstream{Meta: model.Meta{ID: "up_1"}, Spec: model.UpstreamSpec{Discovery: &model.Discovery{
		Provider: model.DiscoveryConsul, Endpoint: srv.URL, Selector: []string{"web"}, Interval: "50ms",
	}}}
	var mu sync.Mutex
	ups := []*model.Upstream{up}
	s := &sink{got: map[string][]string{}}
	m := New(func(context.Context) ([]*model.Upstream, error) {
		mu.Lock()
		defer mu.Unlock()
		return ups, nil
	}, s, slog.New(slog.DiscardHandler))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)
	waitFor(t, func() bool { v, _ := s.get("up_1"); return slices.Equal(v, []string{"10.2.0.1:80"}) })
	if st := m.Statuses(); len(st) != 1 || st[0].Error != "" || len(st[0].Addresses) != 1 {
		t.Errorf("statuses %+v", st)
	}
	// Removing discovery forgets the upstream.
	mu.Lock()
	ups = nil
	mu.Unlock()
	m.Kick()
	waitFor(t, func() bool { v, ok := s.get("up_1"); return ok && v == nil })
}

func waitFor(t *testing.T, f func() bool) {
	t.Helper()
	for range 200 {
		if f() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out")
}
