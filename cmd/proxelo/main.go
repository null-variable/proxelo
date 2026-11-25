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

	"github.com/null-variable/proxelo/internal/api"
	"github.com/null-variable/proxelo/internal/compile"
	"github.com/null-variable/proxelo/internal/model"
	"github.com/null-variable/proxelo/internal/store"
)

var version = "dev"

const usage = `usage: proxelo <command>

commands:
  control [-data dir] [-listen addr]   run the control plane API
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
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("control: unexpected argument %q", fs.Arg(0))
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	dir := filepath.Join(*dataDir, "control")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	st, err := store.Open(filepath.Join(dir, "proxelo.db"))
	if err != nil {
		return err
	}
	defer st.Close()

	srv := &http.Server{
		Addr:              *listen,
		Handler:           api.Handler(st, log),
		ReadHeaderTimeout: 10 * time.Second,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	log.Info("control plane listening", "addr", *listen, "data", *dataDir)

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
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
