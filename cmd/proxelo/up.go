package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// up runs the control plane and proxelo-proxy as children of this process
// and restarts whichever exits (for development and home labs; in
// production each runs as its own systemd unit). The two still talk only over
// the control socket, so up behaves like the two-unit setup.
func up(args []string) error {
	fs := flag.NewFlagSet("up", flag.ContinueOnError)
	dataDir := fs.String("data", envOr("PROXELO_DATA", "/var/lib/proxelo"), "data directory (env PROXELO_DATA)")
	listen := fs.String("listen", envOr("PROXELO_ADMIN_LISTEN", "127.0.0.1:9443"), "admin API address (env PROXELO_ADMIN_LISTEN)")
	socket := fs.String("socket", "", "control socket (default <data>/run/control.sock)")
	proxyBin := fs.String("proxy", envOr("PROXELO_PROXY", ""), "proxelo-proxy binary (env PROXELO_PROXY; default: next to this binary, then $PATH)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	// Arguments after "--" go to proxelo-proxy run, e.g. -- --workers 4.
	proxyArgs := fs.Args()

	if *socket == "" {
		*socket = filepath.Join(*dataDir, "run", "control.sock")
	}
	bin, err := findProxy(*proxyBin)
	if err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	children := []child{
		{name: "control", path: self, args: []string{"control", "-data", *dataDir, "-listen", *listen, "-socket", *socket}},
		{name: "proxy", path: bin, args: append([]string{"run", "--data", *dataDir, "--socket", *socket}, proxyArgs...)},
	}
	var wg sync.WaitGroup
	for _, c := range children {
		wg.Go(func() { c.supervise(ctx, log) })
	}
	log.Info("up", "admin", *listen, "socket", *socket, "data", *dataDir, "proxy", bin)
	wg.Wait()
	return nil
}

// findProxy resolves the proxelo-proxy binary: the flag, then a binary next
// to this one (release packages ship them together), then $PATH.
func findProxy(flagValue string) (string, error) {
	if flagValue != "" {
		return exec.LookPath(flagValue)
	}
	if self, err := os.Executable(); err == nil {
		p := filepath.Join(filepath.Dir(self), "proxelo-proxy")
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p, nil
		}
	}
	p, err := exec.LookPath("proxelo-proxy")
	if err != nil {
		return "", errors.New("proxelo-proxy not found next to proxelo or in $PATH; pass -proxy")
	}
	return p, nil
}

type child struct {
	name string
	path string
	args []string
}

const (
	minRestartDelay = 500 * time.Millisecond
	maxRestartDelay = 30 * time.Second
	// A child that ran at least this long is considered healthy, so the next
	// failure restarts it quickly again.
	healthyRun = 10 * time.Second
	stopGrace  = 10 * time.Second
)

// supervise runs the child until ctx ends, restarting it with backoff
// whenever it exits. On shutdown the child gets SIGTERM, then SIGKILL after
// stopGrace.
func (c child) supervise(ctx context.Context, log *slog.Logger) {
	delay := minRestartDelay
	for ctx.Err() == nil {
		cmd := exec.Command(c.path, c.args...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		// Own process group: a terminal Ctrl-C reaches only this supervisor,
		// which then stops the children in order.
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		started := time.Now()
		if err := cmd.Start(); err != nil {
			log.Error("start failed", "child", c.name, "err", err)
		} else {
			log.Info("started", "child", c.name, "pid", cmd.Process.Pid)
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			select {
			case err := <-done:
				log.Warn("exited", "child", c.name, "err", err)
			case <-ctx.Done():
				cmd.Process.Signal(syscall.SIGTERM)
				select {
				case <-done:
				case <-time.After(stopGrace):
					cmd.Process.Kill()
					<-done
				}
				log.Info("stopped", "child", c.name)
				return
			}
		}
		if time.Since(started) >= healthyRun {
			delay = minRestartDelay
		}
		log.Info("restarting", "child", c.name, "in", delay)
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		delay = min(delay*2, maxRestartDelay)
	}
}
