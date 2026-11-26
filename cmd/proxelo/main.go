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
	"strings"
	"syscall"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/null-variable/proxelo/internal/acme"
	"github.com/null-variable/proxelo/internal/admin"
	"github.com/null-variable/proxelo/internal/api"
	"github.com/null-variable/proxelo/internal/auth"
	"github.com/null-variable/proxelo/internal/breakglass"
	"github.com/null-variable/proxelo/internal/compile"
	"github.com/null-variable/proxelo/internal/deploy"
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
  admin [-socket path] reset-password --user <name>
  admin [-socket path] rollback --to <revision|last-confirmed>
  admin [-socket path] bind <addr>     break-glass recovery over the local socket
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
	case args[0] == "admin":
		err = adminCmd(args[1:])
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
	breakGlass := fs.String("break-glass", envOr("PROXELO_BREAK_GLASS_SOCKET", ""), "break-glass Unix socket (env PROXELO_BREAK_GLASS_SOCKET; default <data>/run/admin.sock)")
	allow := fs.String("admin-allow", envOr("PROXELO_ADMIN_ALLOW", ""), "comma-separated client networks the admin API accepts besides loopback; required for a non-loopback -listen (env PROXELO_ADMIN_ALLOW)")
	secureCookies := fs.Bool("secure-cookies", envOr("PROXELO_SECURE_COOKIES", "") == "1", "mark session cookies Secure on plain HTTP, behind a TLS front (env PROXELO_SECURE_COOKIES=1)")
	guardRollback := fs.Bool("guard-rollback", envOr("PROXELO_GUARD_ROLLBACK", "") == "1", "roll back pending revisions whose error rates rise instead of only flagging them (env PROXELO_GUARD_ROLLBACK=1)")
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
	guard := deploy.DefaultGuard
	guard.Rollback = *guardRollback
	dep := deploy.New(st, dist, sim.DryLoad, guard, log)

	certs := acme.New(acme.Config{
		Directory: *acmeDir,
		Email:     *acmeEmail,
		// Issued certificates go into the head and out as the next revision;
		// open change sets stay unapplied.
		Apply: func(ctx context.Context, _ *model.Certificate) error { return dep.ApplyHead(ctx) },
	}, st, dist, log)

	if err := printSetupToken(st, *listen); err != nil {
		return err
	}
	allowList, err := admin.ParseAllow(splitList(*allow))
	if err != nil {
		return err
	}
	if v, err := st.Value(context.Background(), breakglass.ListenKey); err == nil {
		log.Info("admin address set by break-glass", "addr", string(v))
		*listen = string(v)
	}
	adm := admin.New(api.Handler(st, dist, dep, sim, api.Options{CertsChanged: certs.Kick, AdminAddr: *listen, SecureCookies: *secureCookies}, log), allowList, log)
	if err := adm.Bind(*listen); err != nil {
		return fmt.Errorf("admin API: %w", err)
	}

	ln, err := distrib.Listen(*socket)
	if err != nil {
		return fmt.Errorf("control socket: %w", err)
	}
	grpcSrv := distrib.NewServer(dist)
	if *breakGlass == "" {
		*breakGlass = filepath.Join(*dataDir, "run", "admin.sock")
	}
	bgLn, err := breakglass.Listen(*breakGlass)
	if err != nil {
		return fmt.Errorf("break-glass socket: %w", err)
	}
	bgSrv := &http.Server{Handler: breakglass.Handler(st, dep, adm), ReadHeaderTimeout: 10 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go certs.Run(ctx)
	go dep.Run(ctx)
	errc := make(chan error, 3)
	go func() { errc <- fmt.Errorf("control socket: %w", grpcSrv.Serve(ln)) }()
	go func() { errc <- fmt.Errorf("break-glass socket: %w", bgSrv.Serve(bgLn)) }()
	log.Info("control plane running", "socket", *socket, "breakGlass", *breakGlass, "data", *dataDir)

	var runErr error
	select {
	case runErr = <-errc:
	case err := <-adm.Err():
		runErr = fmt.Errorf("admin API: %w", err)
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Proxy streams never end on their own; Stop closes them.
	grpcSrv.Stop()
	bgSrv.Shutdown(shutdownCtx)
	if err := adm.Shutdown(shutdownCtx); err != nil && runErr == nil {
		runErr = err
	}
	return runErr
}

// printSetupToken makes and prints the one-time token that creates the
// first owner, while no account exists.
func printSetupToken(st *store.Store, listen string) error {
	ctx := context.Background()
	n, err := st.CountUsers(ctx)
	if err != nil || n > 0 {
		return err
	}
	tok, err := st.Value(ctx, api.SetupTokenKey)
	if errors.Is(err, store.ErrNotFound) {
		tok = []byte(auth.Secret(24))
		err = st.Put(ctx, api.SetupTokenKey, tok)
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "\nNo admin account yet. Create the owner with this one-time setup token:\n\n  %s\n\n  curl -X POST http://%s/api/v1/auth/setup -d '{\"token\":\"%s\",\"name\":\"owner\",\"password\":\"...\"}'\n\n", tok, listen, tok)
	return nil
}

func splitList(s string) []string {
	var out []string
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
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
