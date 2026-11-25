package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Scenario is one benchmark scenario.
type Scenario struct {
	ID       string
	Title    string
	Path     string
	Upstream bool
	// Latency adds a fixed-rate wrk2 phase after the saturation phase.
	Latency bool
}

var scenarios = []Scenario{
	{ID: "S1", Title: "static 1 KiB file, HTTP/1.1 keepalive", Path: StaticPath},
	{ID: "S3", Title: "reverse proxy, HTTP/1.1 keepalive, 1 KiB response", Path: ProxyPath, Upstream: true, Latency: true},
}

func scenarioByID(id string) (Scenario, bool) {
	for _, s := range scenarios {
		if s.ID == id {
			return s, true
		}
	}
	return Scenario{}, false
}

// WrkResult is the line report.lua prints after a wrk or wrk2 run.
type WrkResult struct {
	DurationUs float64 `json:"durationUs"`
	Requests   float64 `json:"requests"`
	Bytes      float64 `json:"bytes"`
	Errors     struct {
		Connect float64 `json:"connect"`
		Read    float64 `json:"read"`
		Write   float64 `json:"write"`
		Status  float64 `json:"status"`
		Timeout float64 `json:"timeout"`
	} `json:"errors"`
	LatencyUs struct {
		Mean float64 `json:"mean"`
		P50  float64 `json:"p50"`
		P90  float64 `json:"p90"`
		P99  float64 `json:"p99"`
		P999 float64 `json:"p999"`
		Max  float64 `json:"max"`
	} `json:"latencyUs"`
}

// ErrorCount sums every error class wrk reports.
func (r WrkResult) ErrorCount() float64 {
	e := r.Errors
	return e.Connect + e.Read + e.Write + e.Status + e.Timeout
}

// RPS is completed requests per second.
func (r WrkResult) RPS() float64 {
	if r.DurationUs == 0 {
		return 0
	}
	return r.Requests / (r.DurationUs / 1e6)
}

// parseWrk finds the BENCH line in wrk output.
func parseWrk(out string) (WrkResult, error) {
	var r WrkResult
	for line := range strings.SplitSeq(out, "\n") {
		if j, ok := strings.CutPrefix(strings.TrimSpace(line), "BENCH "); ok {
			if err := json.Unmarshal([]byte(j), &r); err != nil {
				return r, fmt.Errorf("parsing wrk report: %w", err)
			}
			return r, nil
		}
	}
	return r, fmt.Errorf("wrk output has no BENCH line:\n%s", out)
}

// Measurement is one load run against one target.
type Measurement struct {
	Scenario string    `json:"scenario"`
	Target   string    `json:"target"`
	Phase    string    `json:"phase"` // saturation | latency
	Run      int       `json:"run"`
	Rate     int       `json:"rate,omitempty"` // requests/s offered in the latency phase
	Wrk      WrkResult `json:"wrk"`
	RPS      float64   `json:"rps"`
	// CPU time used by the proxy per completed request.
	ProxyCPUUsPerReq float64 `json:"proxyCpuUsPerReq"`
	// Busy fraction of the CPUs given to each container (1 = all busy).
	ProxyCPUUtil    float64 `json:"proxyCpuUtil"`
	LoadgenCPUUtil  float64 `json:"loadgenCpuUtil"`
	UpstreamCPUUtil float64 `json:"upstreamCpuUtil,omitempty"`
	// Proxy cgroup memory at the end of the run.
	ProxyMemBytes int64  `json:"proxyMemBytes"`
	Output        string `json:"output"`
}

// Valid reports whether the run completed without errors.
func (m Measurement) Valid() bool { return m.Wrk.ErrorCount() == 0 && m.Wrk.Requests > 0 }

// loadSpec is the load shape of one wrk run.
type loadSpec struct {
	tool     string // wrk | wrk2
	url      string
	threads  int
	conns    int
	duration time.Duration
	rate     int // wrk2 only
}

func (l loadSpec) args() []string {
	a := []string{l.tool,
		"-t", strconv.Itoa(l.threads),
		"-c", strconv.Itoa(l.conns),
		"-d", strconv.Itoa(int(l.duration.Seconds())) + "s",
		"--timeout", "5s",
		"--latency",
		"-s", "/bench/report.lua",
		"-H", "Host: " + HostHeader,
	}
	if l.tool == "wrk2" {
		a = append(a, "-R", strconv.Itoa(l.rate))
	}
	return append(a, l.url)
}

// stack is the set of running containers for one target.
type stack struct {
	proxy, upstream, loadgen *container
}

// measure runs one load phase and samples the containers' cgroups around it.
func measure(ctx context.Context, st stack, l loadSpec) (Measurement, error) {
	type sample struct{ proxy, upstream, loadgen int64 }
	read := func() (sample, error) {
		var s sample
		var err error
		if s.proxy, err = st.proxy.cpuUsec(ctx); err != nil {
			return s, err
		}
		if s.loadgen, err = st.loadgen.cpuUsec(ctx); err != nil {
			return s, err
		}
		if st.upstream != nil {
			if s.upstream, err = st.upstream.cpuUsec(ctx); err != nil {
				return s, err
			}
		}
		return s, nil
	}

	before, err := read()
	if err != nil {
		return Measurement{}, err
	}
	start := time.Now()
	out, err := docker(ctx, append([]string{"exec", st.loadgen.name}, l.args()...)...)
	wall := time.Since(start)
	if err != nil {
		return Measurement{}, err
	}
	after, err := read()
	if err != nil {
		return Measurement{}, err
	}
	mem, err := st.proxy.memBytes(ctx)
	if err != nil {
		return Measurement{}, err
	}
	r, err := parseWrk(out)
	if err != nil {
		return Measurement{}, err
	}

	util := func(delta int64, cpus int) float64 {
		return float64(delta) / (float64(wall.Microseconds()) * float64(cpus))
	}
	m := Measurement{
		Wrk:            r,
		RPS:            r.RPS(),
		ProxyCPUUtil:   util(after.proxy-before.proxy, st.proxy.cpus),
		LoadgenCPUUtil: util(after.loadgen-before.loadgen, st.loadgen.cpus),
		ProxyMemBytes:  mem,
		Output:         out,
	}
	if r.Requests > 0 {
		m.ProxyCPUUsPerReq = float64(after.proxy-before.proxy) / r.Requests
	}
	if st.upstream != nil {
		m.UpstreamCPUUtil = util(after.upstream-before.upstream, st.upstream.cpus)
	}
	return m, nil
}

// checkResponse fetches path through the proxy and checks it returns the
// benchmark file. It retries until the proxy is up or ctx expires.
func checkResponse(ctx context.Context, base, path string) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var last error
	for {
		last = fetchOnce(ctx, base+path)
		if last == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("GET %s: %w", path, last)
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func fetchOnce(ctx context.Context, url string) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	req.Host = HostHeader
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	if string(body) != string(FileBody) {
		return fmt.Errorf("body is %d bytes, not the %d byte benchmark file", len(body), FileSize)
	}
	return nil
}
