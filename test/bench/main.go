// Command bench measures nginx and proxelo-proxy under the same load
// (scenarios S1 static and S3 reverse proxy) and writes a report.
//
// Every process runs in its own Docker container on the host network, pinned
// to its own CPUs: the proxy under test, the dummy upstream (nginx) and the
// load generators (wrk, wrk2). Runs of different targets are interleaved so
// slow drift of the machine affects all targets alike.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Pinned images and sources. Change them deliberately and re-run the
// baseline: reports are only comparable at equal versions.
const (
	nginxImage   = "nginx:1.31.10"
	loadgenImage = "proxelo-bench-loadgen"
	proxyListen  = "127.0.0.1:18080"
	upstreamAddr = "127.0.0.1:18081"
)

type config struct {
	scenarios    []Scenario
	targets      []Target
	runs         int
	duration     time.Duration
	warmup       time.Duration
	connections  int
	latencyLoad  float64
	latencyRate  int
	proxyCPUs    string
	upstreamCPUs string
	loadgenCPUs  string
	proxySrc     string
	out          string
	build        bool
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "bench:", err)
		os.Exit(1)
	}
}

func run() error {
	var c config
	var scenarioList, targetList string
	flag.StringVar(&scenarioList, "scenarios", "S1,S3", "comma-separated scenario IDs")
	flag.StringVar(&targetList, "targets", "nginx,proxelo:shared:system,proxelo:per-core:system",
		"comma-separated targets: nginx, proxelo[:shared|per-core[:system|jemalloc|mimalloc]]")
	flag.IntVar(&c.runs, "runs", 3, "measured runs per scenario and target")
	flag.DurationVar(&c.duration, "duration", 30*time.Second, "length of each measured run")
	flag.DurationVar(&c.warmup, "warmup", 10*time.Second, "unmeasured load before each run")
	flag.IntVar(&c.connections, "connections", 256, "client connections")
	flag.Float64Var(&c.latencyLoad, "latency-load", 0.5, "fixed rate for latency runs as a fraction of nginx saturation RPS")
	flag.IntVar(&c.latencyRate, "latency-rate", 0, "fixed rate for latency runs in requests/s (overrides -latency-load)")
	flag.StringVar(&c.proxyCPUs, "proxy-cpus", "0-1", "cpuset of the proxy under test; its size sets the worker count")
	flag.StringVar(&c.upstreamCPUs, "upstream-cpus", "2-3", "cpuset of the dummy upstream; it must stay below saturation in S3")
	flag.StringVar(&c.loadgenCPUs, "loadgen-cpus", "4-7", "cpuset of the load generator; its size sets the thread count")
	flag.StringVar(&c.proxySrc, "proxy-src", "../proxelo-proxy", "proxelo-proxy checkout to build")
	flag.StringVar(&c.out, "out", "", "report directory (default test/bench/results/<time>)")
	flag.BoolVar(&c.build, "build", true, "build the load generator and proxy images first")
	flag.Parse()
	if flag.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", flag.Arg(0))
	}

	for id := range strings.SplitSeq(scenarioList, ",") {
		s, ok := scenarioByID(strings.TrimSpace(id))
		if !ok {
			return fmt.Errorf("unknown scenario %q", id)
		}
		c.scenarios = append(c.scenarios, s)
	}
	for t := range strings.SplitSeq(targetList, ",") {
		tg, err := ParseTarget(strings.TrimSpace(t))
		if err != nil {
			return err
		}
		c.targets = append(c.targets, tg)
	}
	if c.runs < 1 || c.duration < time.Second || c.connections < 1 {
		return errors.New("-runs, -duration and -connections must be positive")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	h, err := newHarness(ctx, c)
	if err != nil {
		return err
	}
	defer os.RemoveAll(h.work)

	report, err := h.runAll(ctx)
	if err != nil {
		return err
	}
	return h.write(report)
}

type harness struct {
	config
	work                        string // configs and content mounted into containers
	proxyN, upstreamN, loadgenN int
	env                         Environment
}

func newHarness(ctx context.Context, c config) (*harness, error) {
	h := &harness{config: c}
	var err error
	for _, p := range []struct {
		set string
		n   *int
	}{{c.proxyCPUs, &h.proxyN}, {c.upstreamCPUs, &h.upstreamN}, {c.loadgenCPUs, &h.loadgenN}} {
		if *p.n, err = cpusetSize(p.set); err != nil {
			return nil, err
		}
	}
	if overlaps(c.proxyCPUs, c.upstreamCPUs, c.loadgenCPUs) {
		return nil, errors.New("-proxy-cpus, -upstream-cpus and -loadgen-cpus must not overlap")
	}

	if c.build {
		if err := h.buildImages(ctx); err != nil {
			return nil, err
		}
	}
	if _, err := docker(ctx, "image", "inspect", nginxImage); err != nil {
		if _, err := docker(ctx, "pull", nginxImage); err != nil {
			return nil, err
		}
	}

	// The work directory must be visible to the Docker daemon; a temporary
	// directory is, both on Linux and with Docker Desktop or OrbStack on macOS.
	if h.work, err = os.MkdirTemp("", "proxelo-bench-"); err != nil {
		return nil, err
	}
	if err := WriteContent(filepath.Join(h.work, "www")); err != nil {
		return nil, err
	}
	snap, err := ProxeloSnapshot(proxyListen, upstreamAddr)
	if err != nil {
		return nil, fmt.Errorf("compiling the benchmark snapshot: %w", err)
	}
	files := map[string][]byte{
		"snapshot.bin":  snap,
		"nginx.conf":    NginxConfig(h.proxyN, proxyListen, upstreamAddr),
		"upstream.conf": UpstreamConfig(h.upstreamN, upstreamAddr),
	}
	for name, b := range files {
		if err := os.WriteFile(filepath.Join(h.work, name), b, 0o644); err != nil {
			return nil, err
		}
	}
	// Mounted files must be readable by the unprivileged nginx workers.
	if err := os.Chmod(h.work, 0o755); err != nil {
		return nil, err
	}
	h.env, err = h.environment(ctx)
	return h, err
}

func (h *harness) buildImages(ctx context.Context) error {
	dir := benchDir()
	fmt.Fprintln(os.Stderr, "building", loadgenImage)
	if err := stream(ctx, "docker", "build", "-q", "-t", loadgenImage, filepath.Join(dir, "loadgen")); err != nil {
		return err
	}
	built := map[string]bool{}
	for _, t := range h.targets {
		if t.Kind != "proxelo" || built[t.Allocator] {
			continue
		}
		built[t.Allocator] = true
		features := t.Allocator
		if features == "system" {
			features = ""
		}
		fmt.Fprintln(os.Stderr, "building", proxyImage(t.Allocator), "from", h.proxySrc)
		if err := stream(ctx, "docker", "build", "-q", "-t", proxyImage(t.Allocator),
			"-f", filepath.Join(dir, "proxy", "Dockerfile"),
			"--build-arg", "FEATURES="+features, h.proxySrc); err != nil {
			return err
		}
	}
	return nil
}

func proxyImage(allocator string) string { return "proxelo-bench-proxy:" + allocator }

// benchDir is the directory holding this harness's Dockerfiles.
func benchDir() string {
	_, file, _, ok := runtime.Caller(0)
	if ok {
		if _, err := os.Stat(filepath.Join(filepath.Dir(file), "loadgen")); err == nil {
			return filepath.Dir(file)
		}
	}
	return filepath.Join("test", "bench")
}

func stream(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return nil
}

func (h *harness) runAll(ctx context.Context) (Report, error) {
	loadgen, err := startContainer(ctx, "proxelo-bench-loadgen", h.loadgenCPUs, h.loadgenN, loadgenImage,
		[]string{"--entrypoint", "sleep"}, []string{"infinity"})
	if err != nil {
		return Report{}, err
	}
	defer loadgen.stop(ctx)

	var ms []Measurement
	for _, sc := range h.scenarios {
		// Saturation runs, interleaved across targets.
		for run := 1; run <= h.runs; run++ {
			for _, t := range h.targets {
				m, err := h.runOne(ctx, loadgen, sc, t, run, loadSpec{tool: "wrk", threads: h.loadgenN, conns: h.connections})
				if err != nil {
					return Report{}, fmt.Errorf("%s %s run %d: %w", sc.ID, t, run, err)
				}
				ms = append(ms, m)
			}
		}
		if !sc.Latency {
			continue
		}
		rate, err := h.latencyRateFor(ms, sc)
		if err != nil {
			return Report{}, err
		}
		h.env.Settings.LatencyRate = rate
		for run := 1; run <= h.runs; run++ {
			for _, t := range h.targets {
				m, err := h.runOne(ctx, loadgen, sc, t, run, loadSpec{tool: "wrk2", threads: h.loadgenN, conns: h.connections, rate: rate})
				if err != nil {
					return Report{}, fmt.Errorf("%s %s latency run %d: %w", sc.ID, t, run, err)
				}
				ms = append(ms, m)
			}
		}
	}

	ids := make([]string, len(h.scenarios))
	for i, s := range h.scenarios {
		ids[i] = s.ID
	}
	names := make([]string, len(h.targets))
	for i, t := range h.targets {
		names[i] = t.String()
	}
	return Report{Environment: h.env, Measurements: ms, Summaries: summarize(ms, ids, names)}, nil
}

// latencyRateFor picks the fixed rate for the latency phase: the explicit
// -latency-rate, or a fraction of nginx's mean saturation RPS so every target
// is measured at the same offered load.
func (h *harness) latencyRateFor(ms []Measurement, sc Scenario) (int, error) {
	if h.latencyRate > 0 {
		return h.latencyRate, nil
	}
	var sum float64
	var n int
	for _, m := range ms {
		if m.Scenario == sc.ID && m.Target == "nginx" && m.Phase == "saturation" && m.Valid() {
			sum += m.RPS
			n++
		}
	}
	if n == 0 {
		return 0, fmt.Errorf("%s: latency runs need -latency-rate or a valid nginx saturation run", sc.ID)
	}
	return int(math.Round(h.latencyLoad * sum / float64(n))), nil
}

// runOne starts a fresh stack for target t, warms it up and measures one run.
func (h *harness) runOne(ctx context.Context, loadgen *container, sc Scenario, t Target, run int, l loadSpec) (Measurement, error) {
	phase := "saturation"
	if l.tool == "wrk2" {
		phase = "latency"
	}
	fmt.Fprintf(os.Stderr, "%s %-28s %-10s run %d/%d\n", sc.ID, t, phase, run, h.runs)

	st := stack{loadgen: loadgen}
	if sc.Upstream {
		up, err := startContainer(ctx, "proxelo-bench-upstream", h.upstreamCPUs, h.upstreamN, nginxImage,
			[]string{"--entrypoint", "nginx", "-v", h.work + ":/bench:ro"},
			[]string{"-c", "/bench/upstream.conf", "-g", "daemon off;"})
		if err != nil {
			return Measurement{}, err
		}
		defer up.stop(ctx)
		st.upstream = up
		if err := checkResponse(ctx, "http://"+upstreamAddr, ProxyPath); err != nil {
			return Measurement{}, fmt.Errorf("upstream: %w\n%s", err, up.logs(ctx))
		}
	}

	proxy, err := h.startProxy(ctx, t)
	if err != nil {
		return Measurement{}, err
	}
	defer proxy.stop(ctx)
	st.proxy = proxy
	if err := checkResponse(ctx, "http://"+proxyListen, sc.Path); err != nil {
		return Measurement{}, fmt.Errorf("%s: %w\n%s", t, err, proxy.logs(ctx))
	}

	l.url = "http://" + proxyListen + sc.Path
	if h.warmup > 0 {
		w := l
		w.duration = h.warmup
		if _, err := docker(ctx, append([]string{"exec", loadgen.name}, w.args()...)...); err != nil {
			return Measurement{}, fmt.Errorf("warm-up: %w", err)
		}
	}
	l.duration = h.duration
	m, err := measure(ctx, st, l)
	if err != nil {
		return Measurement{}, err
	}
	m.Scenario, m.Target, m.Phase, m.Run, m.Rate = sc.ID, t.String(), phase, run, l.rate
	if !m.Valid() {
		fmt.Fprintf(os.Stderr, "  %.0f errors in this run\n", m.Wrk.ErrorCount())
	}
	fmt.Fprintf(os.Stderr, "  %.0f req/s, p99 %.0f µs, proxy CPU %.0f%%, load generator CPU %.0f%%\n",
		m.RPS, m.Wrk.LatencyUs.P99, 100*m.ProxyCPUUtil, 100*m.LoadgenCPUUtil)
	return m, nil
}

// startProxy starts the target with the served files copied onto a tmpfs:
// a bind mount from the host (a VM file share on macOS) would make S1 measure
// the file share rather than the proxy.
func (h *harness) startProxy(ctx context.Context, t Target) (*container, error) {
	args := []string{"-v", h.work + ":/bench:ro", "--tmpfs", "/srv/www:size=1m,mode=0755", "--entrypoint", "sh"}
	prep := "cp -r /bench/www/. /srv/www/ && chmod -R a+rX /srv/www && exec "
	if t.Kind == "nginx" {
		return startContainer(ctx, "proxelo-bench-proxy", h.proxyCPUs, h.proxyN, nginxImage, args,
			[]string{"-c", prep + `nginx -c /bench/nginx.conf -g "daemon off;"`})
	}
	return startContainer(ctx, "proxelo-bench-proxy", h.proxyCPUs, h.proxyN, proxyImage(t.Allocator), args,
		[]string{"-c", prep + "proxelo-proxy serve /bench/snapshot.bin --workers " + strconv.Itoa(h.proxyN) + " --runtime " + t.Runtime})
}

func (h *harness) environment(ctx context.Context) (Environment, error) {
	e := Environment{
		StartedAt: time.Now().UTC().Format(time.RFC3339),
		CPUSets:   map[string]string{"proxy": h.proxyCPUs, "upstream": h.upstreamCPUs, "loadgen": h.loadgenCPUs},
		Images:    map[string]string{},
		Versions:  map[string]string{},
		Settings: Settings{
			Runs: h.runs, DurationSec: int(h.duration.Seconds()), WarmupSec: int(h.warmup.Seconds()),
			Connections: h.connections, Threads: h.loadgenN, LatencyLoad: h.latencyLoad, ProxyWorkers: h.proxyN,
		},
	}
	e.Host, _ = os.Hostname()
	info, err := docker(ctx, "info", "--format", "{{json .}}")
	if err != nil {
		return e, err
	}
	var di struct {
		ServerVersion   string
		KernelVersion   string
		OperatingSystem string
		Architecture    string
		NCPU            int
		MemTotal        int64
	}
	if err := json.Unmarshal([]byte(info), &di); err != nil {
		return e, fmt.Errorf("docker info: %w", err)
	}
	e.DockerServer, e.Kernel, e.OS, e.Arch, e.CPUs, e.MemBytes = di.ServerVersion, di.KernelVersion, di.OperatingSystem, di.Architecture, di.NCPU, di.MemTotal

	images := []string{nginxImage, loadgenImage}
	for _, t := range h.targets {
		if t.Kind == "proxelo" {
			images = append(images, proxyImage(t.Allocator))
		}
	}
	for _, img := range images {
		id, err := docker(ctx, "image", "inspect", "--format", "{{.Id}}", img)
		if err != nil {
			return e, err
		}
		e.Images[img] = id
	}

	versions := map[string][]string{
		"nginx": {"run", "--rm", "--entrypoint", "nginx", nginxImage, "-v"},
		"wrk":   {"run", "--rm", "--entrypoint", "wrk", loadgenImage, "-v"},
		"wrk2":  {"run", "--rm", "--entrypoint", "wrk2", loadgenImage, "-v"},
	}
	for _, t := range h.targets {
		if t.Kind == "proxelo" {
			versions["proxelo-proxy"] = []string{"run", "--rm", proxyImage(t.Allocator), "version"}
			break
		}
	}
	for name, args := range versions {
		// These tools print their version on stderr and some exit non-zero.
		out, _ := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
		e.Versions[name] = firstLine(string(out))
	}

	e.HarnessCommit = gitDescribe(".")
	for _, t := range h.targets {
		if t.Kind == "proxelo" {
			e.ProxyCommit = gitDescribe(h.proxySrc)
			break
		}
	}
	return e, nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// gitDescribe returns the commit of the checkout at dir, marked "-dirty" when
// it has uncommitted changes.
func gitDescribe(dir string) string {
	out, err := exec.Command("git", "-C", dir, "rev-parse", "--short=12", "HEAD").Output()
	if err != nil {
		return "unknown"
	}
	rev := strings.TrimSpace(string(out))
	status, err := exec.Command("git", "-C", dir, "status", "--porcelain", "--untracked-files=no").Output()
	if err == nil && len(strings.TrimSpace(string(status))) > 0 {
		rev += "-dirty"
	}
	return rev
}

func (h *harness) write(r Report) error {
	out := h.out
	if out == "" {
		out = filepath.Join(benchDir(), "results", time.Now().UTC().Format("20060102T150405Z"))
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	j, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, "report.json"), append(j, '\n'), 0o644); err != nil {
		return err
	}
	md := r.Markdown()
	if err := os.WriteFile(filepath.Join(out, "report.md"), []byte(md), 0o644); err != nil {
		return err
	}
	fmt.Print(md)
	fmt.Fprintln(os.Stderr, "\nreport written to", out)
	return nil
}

// cpusetSize counts the CPUs in a cpuset such as "0-3,6".
func cpusetSize(set string) (int, error) {
	cpus, err := parseCPUSet(set)
	return len(cpus), err
}

func parseCPUSet(set string) (map[int]bool, error) {
	cpus := map[int]bool{}
	for part := range strings.SplitSeq(set, ",") {
		lo, hi, isRange := strings.Cut(strings.TrimSpace(part), "-")
		a, err := strconv.Atoi(lo)
		if err != nil {
			return nil, fmt.Errorf("cpuset %q: %w", set, err)
		}
		b := a
		if isRange {
			if b, err = strconv.Atoi(hi); err != nil {
				return nil, fmt.Errorf("cpuset %q: %w", set, err)
			}
		}
		if a < 0 || b < a {
			return nil, fmt.Errorf("cpuset %q: bad range %q", set, part)
		}
		for i := a; i <= b; i++ {
			cpus[i] = true
		}
	}
	return cpus, nil
}

func overlaps(sets ...string) bool {
	seen := map[int]bool{}
	for _, s := range sets {
		cpus, err := parseCPUSet(s)
		if err != nil {
			continue
		}
		for c := range cpus {
			if seen[c] {
				return true
			}
			seen[c] = true
		}
	}
	return false
}
