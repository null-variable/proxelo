// Command proxelo runs the Proxelo control plane.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/null-variable/proxelo/internal/acme"
	"github.com/null-variable/proxelo/internal/api"
	"github.com/null-variable/proxelo/internal/compile"
	"github.com/null-variable/proxelo/internal/distrib"
	"github.com/null-variable/proxelo/internal/model"
	"github.com/null-variable/proxelo/internal/simulate"
	"github.com/null-variable/proxelo/internal/store"
)

var version = "dev"

const usage = `usage: proxelo <command>

commands:
  control [-data dir] [-listen addr] [-socket path] [-proxy path]
                                       run the control plane API and snapshot distribution
  up [-data dir] [-listen addr] [-socket path] [-proxy path] [-- proxy options]
                                       run the control plane and proxelo-proxy together
  compile <config.json> <out.bin>      compile resources into a snapshot
  version                              print the version`

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, usage)
		return 2
	}
	var err error
	switch {
	case args[0] == "version" && len(args) == 1:
		fmt.Println("proxelo", version)
		return 0
	case args[0] == "compile" && len(args) == 3:
		err = compileFile(args[1], args[2])
	case args[0] == "control":
		err = control(args[1:])
	case args[0] == "up":
		err = up(args[1:])
	default:
		fmt.Fprintln(os.Stderr, usage)
		return 2
	}
	if errors.Is(err, flag.ErrHelp) {
		return 2
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func control(args []string) error {
	fs := flag.NewFlagSet("control", flag.ContinueOnError)
	dataDir := fs.String("data", envOr("PROXELO_DATA", "/var/lib/proxelo"), "data directory (env PROXELO_DATA)")
	listen := fs.String("listen", envOr("PROXELO_ADMIN_LISTEN", "127.0.0.1:9443"), "admin API address (env PROXELO_ADMIN_LISTEN)")
	socket := fs.String("socket", envOr("PROXELO_CONTROL_SOCKET", "/run/proxelo/control.sock"), "Unix socket proxies connect to (env PROXELO_CONTROL_SOCKET)")
	proxyBin := fs.String("proxy", envOr("PROXELO_PROXY", ""), "proxelo-proxy binary for dry-loads and simulation (env PROXELO_PROXY; default: next to this binary, then $PATH)")
	acmeDir := fs.String("acme-directory", envOr("PROXELO_ACME_DIRECTORY", acme.LetsEncrypt), "ACME directory URL (env PROXELO_ACME_DIRECTORY)")
	acmeEmail := fs.String("acme-email", envOr("PROXELO_ACME_EMAIL", ""), "ACME account contact email (env PROXELO_ACME_EMAIL)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("control: unexpected argument %q", fs.Arg(0))
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	// Without the proxy binary, applies skip the engine dry-load and the
	// simulator is off; proxies still reject what they cannot load.
	bin, err := findProxy(*proxyBin)
	if err != nil {
		log.Warn("simulator disabled", "err", err)
		bin = ""
	}
	sim := simulate.New(bin, log)
	defer sim.Close()
	dir := filepath.Join(*dataDir, "control")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	st, err := store.Open(filepath.Join(dir, "proxelo.db"))
	if err != nil {
		return err
	}
	defer st.Close()

	dist := distrib.New(log)
	switch rev, err := st.Latest(context.Background()); {
	case errors.Is(err, store.ErrNotFound):
	case err != nil:
		return err
	default:
		if err := dist.Publish(rev.Snapshot); err != nil {
			return err
		}
	}

	certs := acme.New(acme.Config{
		Directory: *acmeDir,
		Email:     *acmeEmail,
		// A renewed certificate replaces only itself in the latest applied
		// revision; edits not applied yet stay unapplied.
		Apply: func(ctx context.Context, c *model.Certificate) error {
			rev, err := st.ApplyChange(ctx, "certificate "+c.ID+" issued", sim.DryLoad, func(cfg *model.Config) {
				for i, old := range cfg.Certificates {
					if old.ID == c.ID {
						cfg.Certificates[i] = c
					}
				}
			})
			if errors.Is(err, store.ErrNotFound) {
				return nil // nothing applied yet; the next apply includes it
			}
			if err != nil {
				return err
			}
			return dist.Publish(rev.Snapshot)
		},
	}, st, dist, log)

	ln, err := distrib.Listen(*socket)
	if err != nil {
		return fmt.Errorf("control socket: %w", err)
	}
	grpcSrv := distrib.NewServer(dist)
	srv := &http.Server{
		Addr:              *listen,
		Handler:           api.Handler(st, dist, sim, certs.Kick, log),
		ReadHeaderTimeout: 10 * time.Second,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go certs.Run(ctx)
	errc := make(chan error, 2)
	go func() { errc <- fmt.Errorf("control socket: %w", grpcSrv.Serve(ln)) }()
	go func() { errc <- srv.ListenAndServe() }()
	log.Info("control plane listening", "addr", *listen, "socket", *socket, "data", *dataDir)

	var runErr error
	select {
	case runErr = <-errc:
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Proxy streams never end on their own; Stop closes them.
	grpcSrv.Stop()
	if err := srv.Shutdown(shutdownCtx); err != nil && runErr == nil {
		runErr = err
	}
	return runErr
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func compileFile(in, out string) error {
	raw, err := os.ReadFile(in)
	if err != nil {
		return err
	}
	var cfg model.Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("%s: %w", in, err)
	}
	snap, err := compile.Compile(cfg, 1)
	if err != nil {
		return fmt.Errorf("%s: %w", in, err)
	}
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(snap)
	if err != nil {
		return err
	}
	return os.WriteFile(out, b, 0o644)
}
