// Package admin runs the admin API listener. It can move to
// another address while running, for break-glass, and refuses clients
// outside an allowlist, which a non-loopback address requires.
package admin

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"
)

// Server is safe for concurrent use.
type Server struct {
	handler http.Handler
	allow   []netip.Prefix
	log     *slog.Logger

	mu   sync.Mutex
	srv  *http.Server
	addr string
	errc chan error
}

// New returns a server for handler. allow lists the client networks
// accepted; empty accepts any client but only on loopback addresses.
func New(handler http.Handler, allow []netip.Prefix, log *slog.Logger) *Server {
	return &Server{handler: handler, allow: allow, log: log, errc: make(chan error, 1)}
}

// ParseAllow parses comma-separated CIDRs or addresses.
func ParseAllow(list []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range list {
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("allow %q: must be an address or CIDR", s)
		}
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

func loopbackOnly(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

// Bind starts serving on addr and then stops the previous listener, so a
// failed bind keeps the old one.
func (s *Server) Bind(addr string) error {
	if !loopbackOnly(addr) && len(s.allow) == 0 {
		return fmt.Errorf("admin address %s is not loopback: set an allowlist (-admin-allow)", addr)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: s.filter(s.handler), ReadHeaderTimeout: 10 * time.Second}
	s.mu.Lock()
	old := s.srv
	s.srv, s.addr = srv, addr
	s.mu.Unlock()
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			select {
			case s.errc <- err:
			default:
			}
		}
	}()
	if old != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		old.Shutdown(ctx)
	}
	s.log.Info("admin API listening", "addr", addr)
	return nil
}

// Addr is the current address.
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.addr
}

// Err receives a serve failure.
func (s *Server) Err() <-chan error { return s.errc }

// Shutdown stops the listener.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	srv := s.srv
	s.mu.Unlock()
	if srv == nil {
		return nil
	}
	return srv.Shutdown(ctx)
}

func (s *Server) filter(h http.Handler) http.Handler {
	if len(s.allow) == 0 {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		ip, perr := netip.ParseAddr(host)
		if err != nil || perr != nil || !s.allowed(ip.Unmap()) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func (s *Server) allowed(ip netip.Addr) bool {
	if ip.IsLoopback() {
		return true
	}
	for _, p := range s.allow {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}
