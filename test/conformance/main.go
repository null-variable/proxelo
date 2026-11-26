// Command conformance sends the same requests to nginx and to proxelo-proxy
// configured alike, and compares status, response headers, body and the
// request each forwards upstream.
//
// A case is a directory under cases/ with nginx.conf (the server blocks, put
// inside an http block), proxelo.json (the same configuration as Proxelo
// resources), case.yaml (requests and the directives they exercise) and
// optionally a www/ tree served as static files. Until the nginx importer
// exists the resources are written by hand.
//
//	go run ./test/conformance -proxy ../proxelo-proxy/target/release/proxelo-proxy
//
// nginx runs in Docker on the host network; the proxy runs on the host. The
// report goes to stdout (and -report), including directive coverage.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.yaml.in/yaml/v3"
	"google.golang.org/protobuf/proto"

	"github.com/null-variable/proxelo/internal/compile"
	"github.com/null-variable/proxelo/internal/model"
	"github.com/null-variable/proxelo/test/conformance/coverage"
)

// nginxImage is the reference nginx. Its version must match directives.yaml.
const nginxImage = "nginx:1.31.10"

// Ports on 127.0.0.1. nginx and the proxy listen on the same port in turn,
// so the Host header and absolute redirects are identical. The echo upstream
// listens on upstreamPorts consecutive ports from upstreamPort, so cases
// with several targets show which one took a request.
const (
	listenPort    = 18480
	upstreamPort  = 18481
	upstreamPorts = 4
)

type config struct {
	proxyBin string
	casesDir string
	listFile string
	report   string
	only     string
	keep     bool
	// A local nginx binary to run instead of the container. It must be the
	// version in nginxImage, built with the modules the cases use.
	nginxBin string
}

func main() {
	var c config
	flag.StringVar(&c.proxyBin, "proxy", "", "proxelo-proxy binary")
	flag.StringVar(&c.casesDir, "cases", "test/conformance/cases", "case directory")
	flag.StringVar(&c.listFile, "directives", "test/conformance/directives.yaml", "directive list")
	flag.StringVar(&c.report, "report", "", "also write the Markdown report to this file")
	flag.StringVar(&c.only, "case", "", "run only this case")
	flag.BoolVar(&c.keep, "keep", false, "keep the work directory")
	flag.StringVar(&c.nginxBin, "nginx", "", "run this nginx binary instead of the "+nginxImage+" container")
	flag.Parse()
	if c.proxyBin == "" {
		fmt.Fprintln(os.Stderr, "usage: conformance -proxy <proxelo-proxy> [-case name] [-report file]")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	failed, err := run(ctx, c)
	if err != nil {
		fmt.Fprintln(os.Stderr, "conformance:", err)
		os.Exit(1)
	}
	if failed {
		os.Exit(1)
	}
}

func run(ctx context.Context, c config) (bool, error) {
	raw, err := os.ReadFile(c.listFile)
	if err != nil {
		return false, err
	}
	list, err := coverage.Parse(raw)
	if err != nil {
		return false, err
	}
	if image := "nginx:" + list.Nginx; image != nginxImage {
		return false, fmt.Errorf("directives.yaml is from nginx %s but the reference image is %s", list.Nginx, nginxImage)
	}
	cases, err := loadCases(c.casesDir, list)
	if err != nil {
		return false, err
	}
	if c.only != "" {
		cases = slices.DeleteFunc(cases, func(k *Case) bool { return k.Name != c.only })
		if len(cases) == 0 {
			return false, fmt.Errorf("no case %q", c.only)
		}
	}

	work, err := os.MkdirTemp("", "proxelo-conformance-")
	if err != nil {
		return false, err
	}
	if c.keep {
		fmt.Fprintln(os.Stderr, "work directory:", work)
	} else {
		defer os.RemoveAll(work)
	}

	var addrs []string
	for i := range upstreamPorts {
		addrs = append(addrs, fmt.Sprintf("127.0.0.1:%d", upstreamPort+i))
	}
	up, err := startEcho(addrs...)
	if err != nil {
		return false, err
	}
	defer up.Close()

	var results []CaseResult
	for _, k := range cases {
		r, err := runCase(ctx, c, k, filepath.Join(work, k.Name), up)
		if err != nil {
			return false, fmt.Errorf("case %s: %w", k.Name, err)
		}
		results = append(results, r)
	}

	tested := map[string]bool{}
	for _, k := range cases {
		for _, d := range k.Directives {
			tested[d] = true
		}
	}
	rep := report(results, list, tested)
	fmt.Print(rep)
	if c.report != "" {
		if err := os.WriteFile(c.report, []byte(rep), 0o644); err != nil {
			return false, err
		}
	}
	return slices.ContainsFunc(results, func(r CaseResult) bool { return !r.Passed() }), nil
}

// Case is one directory under cases/.
type Case struct {
	Name string `yaml:"-"`
	Dir  string `yaml:"-"`
	// Directives exercised, as "module/name" or a bare HTTP directive name.
	Directives []string `yaml:"directives"`
	Requests   []Req    `yaml:"requests"`
	// Ignore lists response headers left out of the comparison for this case,
	// with the reason in a comment.
	Ignore []string `yaml:"ignore,omitempty"`
}

// Req is one request of a case.
type Req struct {
	Method  string            `yaml:"method,omitempty"`
	Target  string            `yaml:"target"`
	Headers map[string]string `yaml:"headers,omitempty"`
	Body    string            `yaml:"body,omitempty"`
}

func (r Req) String() string {
	return cmpOr(r.Method, "GET") + " " + r.Target
}

func loadCases(dir string, list coverage.List) ([]*Case, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []*Case
	// Absolute paths: they become Docker bind mounts.
	dir, err = filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		k := &Case{Name: e.Name(), Dir: filepath.Join(dir, e.Name())}
		raw, err := os.ReadFile(filepath.Join(k.Dir, "case.yaml"))
		if err != nil {
			return nil, err
		}
		dec := yaml.NewDecoder(bytes.NewReader(raw))
		dec.KnownFields(true)
		if err := dec.Decode(k); err != nil {
			return nil, fmt.Errorf("%s/case.yaml: %w", k.Name, err)
		}
		if len(k.Requests) == 0 {
			return nil, fmt.Errorf("%s/case.yaml: no requests", k.Name)
		}
		for i, ref := range k.Directives {
			d, err := list.Lookup(ref)
			if err != nil {
				return nil, fmt.Errorf("%s/case.yaml: %w", k.Name, err)
			}
			k.Directives[i] = d.Key()
		}
		out = append(out, k)
	}
	return out, nil
}

// Response is what one server answered, normalized for comparison.
type Response struct {
	Status   int
	Headers  map[string]string
	BodyHash string
	BodyLen  int
	Body     string // first bytes, for the report
	Upstream *EchoRecord
	Err      string
}

// CaseResult is a case's outcome.
type CaseResult struct {
	Case  *Case
	Diffs []RequestDiff
	Total int
}

func (r CaseResult) Passed() bool { return len(r.Diffs) == 0 }

// RequestDiff is a request whose answers differ.
type RequestDiff struct {
	Req   Req
	Lines []string
}

func runCase(ctx context.Context, c config, k *Case, work string, up *echo) (CaseResult, error) {
	if err := os.MkdirAll(work, 0o755); err != nil {
		return CaseResult{}, err
	}
	www := filepath.Join(k.Dir, "www")
	if _, err := os.Stat(www); err != nil {
		www = ""
	}

	var ngx server
	var err error
	if c.nginxBin != "" {
		ngx, err = runLocalNginx(ctx, c.nginxBin, k, work, www)
	} else {
		ngx, err = runNginx(ctx, k, work, www)
	}
	if err != nil {
		return CaseResult{}, err
	}
	nginxAnswers := sendAll(ctx, k.Requests, up)
	ngx.stop()

	px, err := runProxy(ctx, c.proxyBin, k, work, www)
	if err != nil {
		return CaseResult{}, err
	}
	proxyAnswers := sendAll(ctx, k.Requests, up)
	px.stop()

	res := CaseResult{Case: k, Total: len(k.Requests)}
	for i, req := range k.Requests {
		if lines := compare(nginxAnswers[i], proxyAnswers[i], k.Ignore); len(lines) > 0 {
			res.Diffs = append(res.Diffs, RequestDiff{Req: req, Lines: lines})
		}
	}
	return res, nil
}

type server interface{ stop() }

type nginxServer struct{ name string }

// stop removes the container and waits until its port is free: with Docker
// on a VM (macOS) the forwarded port can outlive the container briefly, and
// the proxy started next would not get it.
func (n nginxServer) stop() {
	exec.Command("docker", "rm", "-f", n.name).Run()
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(listenPort))
	for range 100 {
		ln, err := net.Listen("tcp", addr)
		if err == nil {
			ln.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// nginxMain wraps a case's server blocks. Static files are served from
// /srv/www inside the container; the case's root directives point there.
const nginxMain = `worker_processes 1;
error_log stderr warn;
pid /tmp/nginx.pid;
events {}
http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    access_log off;
    sendfile on;
    server_tokens off;
    include /etc/nginx/case.conf;
}
`

func runNginx(ctx context.Context, k *Case, work, www string) (server, error) {
	if err := os.WriteFile(filepath.Join(work, "nginx.conf"), []byte(nginxMain), 0o644); err != nil {
		return nil, err
	}
	if _, err := os.Stat(filepath.Join(k.Dir, "nginx.conf")); err != nil {
		return nil, err
	}
	name := "proxelo-conformance-nginx"
	exec.Command("docker", "rm", "-f", name).Run()
	args := []string{"run", "-d", "--name", name, "--network", "host",
		"-v", filepath.Join(work, "nginx.conf") + ":/etc/nginx/nginx.conf:ro",
		"-v", filepath.Join(k.Dir, "nginx.conf") + ":/etc/nginx/case.conf:ro"}
	if www != "" {
		args = append(args, "-v", www+":/srv/www:ro")
	}
	args = append(args, nginxImage, "nginx", "-g", "daemon off;")
	if out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("docker run nginx: %w: %s", err, out)
	}
	n := nginxServer{name}
	if err := waitListening(ctx, listenPort); err != nil {
		logs, _ := exec.Command("docker", "logs", "--tail", "20", name).CombinedOutput()
		n.stop()
		return nil, fmt.Errorf("nginx: %w: %s", err, logs)
	}
	return n, nil
}

// runLocalNginx runs a local nginx binary on the same configuration as the
// container: the case's /etc/nginx and /srv/www paths point into the work
// directory and the case's www/ tree.
func runLocalNginx(ctx context.Context, bin string, k *Case, work, www string) (server, error) {
	prefix, err := filepath.Abs(filepath.Join(work, "nginx"))
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(prefix, "logs"), 0o755); err != nil {
		return nil, err
	}
	caseConf, err := os.ReadFile(filepath.Join(k.Dir, "nginx.conf"))
	if err != nil {
		return nil, err
	}
	if www != "" {
		abs, err := filepath.Abs(www)
		if err != nil {
			return nil, err
		}
		caseConf = bytes.ReplaceAll(caseConf, []byte("/srv/www"), []byte(abs))
	}
	mime, err := filepath.Abs(filepath.Join(filepath.Dir(bin), "..", "conf", "mime.types"))
	if err != nil {
		return nil, err
	}
	main := strings.NewReplacer(
		"/etc/nginx/mime.types", mime,
		"/etc/nginx/case.conf", filepath.Join(prefix, "case.conf"),
		"pid /tmp/nginx.pid", "pid "+filepath.Join(prefix, "nginx.pid"),
	).Replace(nginxMain)
	if err := os.WriteFile(filepath.Join(prefix, "case.conf"), caseConf, 0o644); err != nil {
		return nil, err
	}
	conf := filepath.Join(prefix, "nginx.conf")
	if err := os.WriteFile(conf, []byte(main), 0o644); err != nil {
		return nil, err
	}
	var log syncBuffer
	cmd := exec.CommandContext(ctx, bin, "-p", prefix, "-c", conf, "-g", "daemon off;")
	cmd.Stdout, cmd.Stderr = &log, &log
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	p := proxyServer{cmd, &log}
	if err := waitListening(ctx, listenPort); err != nil {
		p.stop()
		return nil, fmt.Errorf("nginx: %w: %s", err, log.String())
	}
	return p, nil
}

type proxyServer struct {
	cmd *exec.Cmd
	log *syncBuffer
}

func (p proxyServer) stop() {
	p.cmd.Process.Signal(os.Interrupt)
	done := make(chan struct{})
	go func() { p.cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		p.cmd.Process.Kill()
		<-done
	}
}

// runProxy compiles the case's resources with the control plane compiler and
// serves them. "/srv/www" in roots is replaced with the case's www/ tree, the
// directory nginx sees at that path.
func runProxy(ctx context.Context, bin string, k *Case, work, www string) (server, error) {
	raw, err := os.ReadFile(filepath.Join(k.Dir, "proxelo.json"))
	if err != nil {
		return nil, err
	}
	if www != "" {
		abs, err := filepath.Abs(www)
		if err != nil {
			return nil, err
		}
		raw = bytes.ReplaceAll(raw, []byte(`"/srv/www`), []byte(`"`+abs))
	}
	var cfg model.Config
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("proxelo.json: %w", err)
	}
	snap, err := compile.Compile(cfg, 1)
	if err != nil {
		return nil, fmt.Errorf("proxelo.json: %w", err)
	}
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(snap)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(work, "snapshot.bin")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return nil, err
	}
	var log syncBuffer
	cmd := exec.CommandContext(ctx, bin, "serve", path, "--workers", "1", "--metrics", "off")
	cmd.Stdout, cmd.Stderr = &log, &log
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	p := proxyServer{cmd, &log}
	if err := waitLog(ctx, &log, "serving revision"); err != nil {
		p.stop()
		return nil, fmt.Errorf("proxelo-proxy: %w: %s", err, log.String())
	}
	return p, nil
}

// waitLog waits for the proxy to report it is serving: a TCP probe could
// reach whatever still held the port.
func waitLog(ctx context.Context, log *syncBuffer, want string) error {
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(log.String(), want) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	return fmt.Errorf("no %q from the proxy", want)
}

// syncBuffer is a bytes.Buffer safe for the process's output goroutine and
// the reader.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func waitListening(ctx context.Context, port int) error {
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond); err == nil {
			c.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return fmt.Errorf("nothing listening on %s", addr)
}

func sendAll(ctx context.Context, reqs []Req, up *echo) []Response {
	client := &http.Client{
		Timeout: 10 * time.Second,
		// Redirects are compared, not followed.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport:     &http.Transport{DisableKeepAlives: true, DisableCompression: true},
	}
	out := make([]Response, len(reqs))
	for i, r := range reqs {
		out[i] = send(ctx, client, r, up)
	}
	return out
}

func send(ctx context.Context, client *http.Client, r Req, up *echo) Response {
	url := fmt.Sprintf("http://127.0.0.1:%d%s", listenPort, r.Target)
	req, err := http.NewRequestWithContext(ctx, cmpOr(r.Method, http.MethodGet), url, strings.NewReader(r.Body))
	if err != nil {
		return Response{Err: err.Error()}
	}
	// The target is sent as written, without Go's path cleaning.
	req.URL.Opaque = strings.SplitN(r.Target, "?", 2)[0]
	for k, v := range r.Headers {
		if strings.EqualFold(k, "Host") {
			req.Host = v
		} else {
			req.Header.Set(k, v)
		}
	}
	up.reset()
	resp, err := client.Do(req)
	if err != nil {
		return Response{Err: err.Error()}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return Response{Err: err.Error()}
	}
	// Generated error pages name the server; that is the only expected
	// difference in them.
	normalized := bytes.Replace(body, []byte("<hr><center>nginx</center>"), []byte("<hr><center>proxelo</center>"), 1)
	// Multipart boundaries are counters local to each server.
	if b, ok := strings.CutPrefix(resp.Header.Get("Content-Type"), "multipart/byteranges; boundary="); ok {
		normalized = bytes.ReplaceAll(normalized, []byte(b), []byte("BOUNDARY"))
		resp.Header.Set("Content-Type", "multipart/byteranges; boundary=BOUNDARY")
	}
	grew := len(normalized) - len(body)
	body = normalized
	sum := sha256.Sum256(body)
	out := Response{
		Status:   resp.StatusCode,
		Headers:  map[string]string{},
		BodyHash: hex.EncodeToString(sum[:8]),
		BodyLen:  len(body),
		Body:     preview(body),
		Upstream: up.last(),
	}
	for k, v := range resp.Header {
		out.Headers[strings.ToLower(k)] = strings.Join(v, ", ")
	}
	if n, err := strconv.Atoi(out.Headers["content-length"]); err == nil && grew != 0 {
		out.Headers["content-length"] = strconv.Itoa(n + grew)
	}
	return out
}

// volatile headers differ between any two servers or runs.
var volatile = map[string]bool{"date": true, "server": true}

func compare(n, p Response, ignore []string) []string {
	var d []string
	if n.Err != "" || p.Err != "" {
		if n.Err != p.Err {
			d = append(d, fmt.Sprintf("error: nginx %q, proxelo %q", n.Err, p.Err))
		}
		return d
	}
	if n.Status != p.Status {
		d = append(d, fmt.Sprintf("status: nginx %d, proxelo %d", n.Status, p.Status))
	}
	skip := map[string]bool{}
	for _, h := range ignore {
		skip[strings.ToLower(h)] = true
	}
	for _, k := range unionKeys(n.Headers, p.Headers) {
		if volatile[k] || skip[k] {
			continue
		}
		nv, nok := n.Headers[k]
		pv, pok := p.Headers[k]
		switch {
		case !pok:
			d = append(d, fmt.Sprintf("header %s: nginx %q, proxelo absent", k, nv))
		case !nok:
			d = append(d, fmt.Sprintf("header %s: nginx absent, proxelo %q", k, pv))
		case nv != pv:
			d = append(d, fmt.Sprintf("header %s: nginx %q, proxelo %q", k, nv, pv))
		}
	}
	if n.BodyHash != p.BodyHash {
		d = append(d, fmt.Sprintf("body: nginx %d bytes %q, proxelo %d bytes %q", n.BodyLen, n.Body, p.BodyLen, p.Body))
	}
	switch {
	case n.Upstream == nil && p.Upstream != nil:
		d = append(d, "upstream: nginx did not proxy, proxelo did: "+p.Upstream.String())
	case n.Upstream != nil && p.Upstream == nil:
		d = append(d, "upstream: nginx proxied, proxelo did not: "+n.Upstream.String())
	case n.Upstream != nil:
		d = append(d, n.Upstream.diff(p.Upstream)...)
	}
	return d
}

func unionKeys(a, b map[string]string) []string {
	var keys []string
	for k := range a {
		keys = append(keys, k)
	}
	for k := range b {
		if _, ok := a[k]; !ok {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	return keys
}

func preview(b []byte) string {
	if len(b) > 60 {
		b = b[:60]
	}
	return string(b)
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
