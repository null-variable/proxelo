package main

import (
	"strings"
	"testing"

	snapshotv1 "github.com/null-variable/proxelo-api/gen/go/proxelo/snapshot/v1"
	"google.golang.org/protobuf/proto"
)

func TestParseTarget(t *testing.T) {
	ok := map[string]string{
		"nginx":                     "nginx",
		"proxelo":                   "proxelo:shared:system",
		"proxelo:per-core":          "proxelo:per-core:system",
		"proxelo:shared:jemalloc":   "proxelo:shared:jemalloc",
		"proxelo:per-core:mimalloc": "proxelo:per-core:mimalloc",
	}
	for in, want := range ok {
		tg, err := ParseTarget(in)
		if err != nil || tg.String() != want {
			t.Errorf("ParseTarget(%q) = %v, %v; want %s", in, tg, err, want)
		}
	}
	for _, in := range []string{"", "nginx:x", "caddy", "proxelo:threads", "proxelo:shared:tcmalloc", "proxelo:a:b:c"} {
		if _, err := ParseTarget(in); err == nil {
			t.Errorf("ParseTarget(%q) succeeded", in)
		}
	}
}

func TestCPUSets(t *testing.T) {
	if n, err := cpusetSize("0-3,6,8-9"); err != nil || n != 7 {
		t.Fatalf("cpusetSize = %d, %v", n, err)
	}
	for _, bad := range []string{"", "a", "3-1", "1-"} {
		if _, err := cpusetSize(bad); err == nil {
			t.Errorf("cpusetSize(%q) succeeded", bad)
		}
	}
	if !overlaps("0-3", "4-5", "3") || overlaps("0-3", "4-5", "6-9") {
		t.Fatal("overlaps is wrong")
	}
}

func TestParseWrk(t *testing.T) {
	out := `Running 1s test @ http://127.0.0.1:18080/1k.html
  4 threads and 64 connections
BENCH {"durationUs":2000000,"requests":100000,"bytes":1,"errors":{"connect":0,"read":1,"write":0,"status":2,"timeout":0},"latencyUs":{"mean":10.5,"p50":9,"p90":12,"p99":30,"p999":80,"max":900}}
`
	r, err := parseWrk(out)
	if err != nil {
		t.Fatal(err)
	}
	if r.RPS() != 50000 || r.ErrorCount() != 3 || r.LatencyUs.P99 != 30 {
		t.Fatalf("parsed %+v", r)
	}
	if _, err := parseWrk("no report"); err == nil {
		t.Fatal("missing BENCH line accepted")
	}
}

func meas(target, phase string, run int, rps, p99 float64, mem int64) Measurement {
	m := Measurement{Scenario: "S3", Target: target, Phase: phase, Run: run, RPS: rps, ProxyMemBytes: mem}
	m.Wrk.Requests = 1
	m.Wrk.LatencyUs.P99 = p99
	return m
}

func TestSummarizeAndVerdict(t *testing.T) {
	var ms []Measurement
	for run, rps := range []float64{100, 101, 99} {
		ms = append(ms, meas("nginx", "saturation", run+1, rps, 0, 100))
		ms = append(ms, meas("nginx", "latency", run+1, 0, 1000, 0))
	}
	add := func(target string, rps, p99 float64, mem int64) {
		for run := 1; run <= 3; run++ {
			ms = append(ms, meas(target, "saturation", run, rps, 0, mem))
			ms = append(ms, meas(target, "latency", run, 0, p99, 0))
		}
	}
	add("ahead", 110, 900, 100)
	add("equal", 96, 1040, 109)
	add("slow", 94, 900, 100)
	add("laggy", 120, 1060, 100)
	add("fat", 120, 900, 111)

	got := map[string]Summary{}
	for _, s := range summarize(ms, []string{"S3"}, []string{"nginx", "ahead", "equal", "slow", "laggy", "fat"}) {
		got[s.Target] = s
	}
	want := map[string]string{"nginx": "", "ahead": "ahead", "equal": "equal", "slow": "behind", "laggy": "behind", "fat": "behind"}
	for target, v := range want {
		if got[target].Verdict != v {
			t.Errorf("%s verdict = %q (%v), want %q", target, got[target].Verdict, got[target].VerdictReason, v)
		}
	}
	n := got["nginx"]
	if n.Bottlenecked {
		t.Fatal("nginx marked bottlenecked")
	}
	if n.RPS.Mean != 100 || n.ValidRuns != 3 || !n.Reproducible || n.P99Us.Mean != 1000 {
		t.Fatalf("nginx summary = %+v", n)
	}
}

func TestReproducibility(t *testing.T) {
	ms := []Measurement{
		meas("nginx", "saturation", 1, 100, 0, 1),
		meas("nginx", "saturation", 2, 100, 0, 1),
		meas("nginx", "saturation", 3, 108, 0, 1),
	}
	s := summarizeOne(ms, "S3", "nginx")
	if s.Reproducible || s.RPS.Deviation < 0.03 {
		t.Fatalf("deviation %.3f accepted as reproducible", s.RPS.Deviation)
	}

	ms[2].RPS = 100
	lat := []Measurement{meas("nginx", "latency", 1, 0, 1000, 0), meas("nginx", "latency", 2, 0, 1100, 0)}
	if s := summarizeOne(append(ms, lat...), "S3", "nginx"); s.Reproducible {
		t.Fatalf("p99 deviation %.3f accepted as reproducible", s.P99Us.Deviation)
	}

	ms[2].Wrk.Errors.Timeout = 5
	s = summarizeOne(ms, "S3", "nginx")
	if s.Reproducible || s.ValidRuns != 2 || s.TotalRuns != 3 {
		t.Fatalf("run with errors counted: %+v", s)
	}
}

func TestProxeloSnapshotMatchesNginxConfig(t *testing.T) {
	b, err := ProxeloSnapshot("127.0.0.1:18080", "127.0.0.1:18081")
	if err != nil {
		t.Fatal(err)
	}
	var snap snapshotv1.Snapshot
	if err := proto.Unmarshal(b, &snap); err != nil {
		t.Fatal(err)
	}
	l := snap.GetListeners()[0]
	if l.GetAddress() != "127.0.0.1:18080" || !l.GetReusePort() || l.GetBacklog() != Backlog {
		t.Fatalf("listener = %v", l)
	}
	routes := map[string]*snapshotv1.Action{}
	for _, r := range snap.GetSites()[0].GetRoutes() {
		routes[r.GetPath().GetValue()] = r.GetAction()
	}
	if routes["/"].GetStatic().GetRoot() != "/srv/www" || routes["/proxy/"].GetProxy() == nil {
		t.Fatalf("routes = %v", routes)
	}
	if u := snap.GetUpstreams()[0]; u.GetKeepaliveIdle() != UpstreamKeepalive || u.GetTargets()[0].GetAddress() != "127.0.0.1:18081" {
		t.Fatalf("upstream = %v", u)
	}

	conf := string(NginxConfig(4, "127.0.0.1:18080", "127.0.0.1:18081"))
	for _, want := range []string{"worker_processes 4;", "listen 127.0.0.1:18080 reuseport backlog=4096;", "server 127.0.0.1:18081;",
		"keepalive 64;", "proxy_pass http://backend;", "root /srv/www;", "access_log off;"} {
		if !strings.Contains(conf, want) {
			t.Errorf("nginx.conf lacks %q", want)
		}
	}
	if up := string(UpstreamConfig(2, "127.0.0.1:18081")); strings.Contains(up, "proxy_pass") || strings.Contains(up, "root ") ||
		!strings.Contains(up, "worker_processes 2;") || !strings.Contains(up, `return 200 "`+string(FileBody)+`";`) {
		t.Errorf("upstream.conf:\n%s", up)
	}
}

func TestBottleneckMakesVerdictInconclusive(t *testing.T) {
	var ms []Measurement
	for run := 1; run <= 3; run++ {
		ms = append(ms, meas("nginx", "saturation", run, 100, 0, 1))
		m := meas("proxelo", "saturation", run, 150, 0, 1)
		if run == 2 {
			m.UpstreamCPUUtil = 0.95
		}
		ms = append(ms, m)
	}
	for _, s := range summarize(ms, []string{"S3"}, []string{"nginx", "proxelo"}) {
		if s.Target == "proxelo" && (s.Verdict != "inconclusive" || !s.Bottlenecked) {
			t.Fatalf("verdict = %q, bottlenecked = %v", s.Verdict, s.Bottlenecked)
		}
	}
}
