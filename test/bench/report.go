package main

import (
	"fmt"
	"math"
	"slices"
	"strings"
)

// Environment records what produced a report.
type Environment struct {
	StartedAt     string            `json:"startedAt"`
	Host          string            `json:"host"`
	DockerServer  string            `json:"dockerServer"`
	Kernel        string            `json:"kernel"`
	OS            string            `json:"os"`
	Arch          string            `json:"arch"`
	CPUs          int               `json:"cpus"`
	MemBytes      int64             `json:"memBytes"`
	CPUSets       map[string]string `json:"cpuSets"`
	Images        map[string]string `json:"images"` // tag -> image ID
	Versions      map[string]string `json:"versions"`
	HarnessCommit string            `json:"harnessCommit"`
	ProxyCommit   string            `json:"proxyCommit,omitempty"`
	Settings      Settings          `json:"settings"`
}

// Settings are the load parameters shared by every run.
type Settings struct {
	Runs         int     `json:"runs"`
	DurationSec  int     `json:"durationSec"`
	WarmupSec    int     `json:"warmupSec"`
	Connections  int     `json:"connections"`
	Threads      int     `json:"threads"`
	LatencyLoad  float64 `json:"latencyLoad"`
	LatencyRate  int     `json:"latencyRate,omitempty"`
	ProxyWorkers int     `json:"proxyWorkers"`
}

// Report is the full result of one harness invocation.
type Report struct {
	Environment  Environment   `json:"environment"`
	Measurements []Measurement `json:"measurements"`
	Summaries    []Summary     `json:"summaries"`
}

// Stat summarizes repeated runs of one metric.
type Stat struct {
	Mean float64   `json:"mean"`
	Min  float64   `json:"min"`
	Max  float64   `json:"max"`
	All  []float64 `json:"all"`
	// Largest distance of a run from the mean, as a fraction of the mean.
	Deviation float64 `json:"deviation"`
}

func newStat(xs []float64) Stat {
	if len(xs) == 0 {
		return Stat{}
	}
	s := Stat{Min: slices.Min(xs), Max: slices.Max(xs), All: xs}
	for _, x := range xs {
		s.Mean += x
	}
	s.Mean /= float64(len(xs))
	if s.Mean != 0 {
		for _, x := range xs {
			s.Deviation = math.Max(s.Deviation, math.Abs(x-s.Mean)/s.Mean)
		}
	}
	return s
}

// MaxDeviation is the reproducibility bound: three runs within ±3%
// of their mean.
const MaxDeviation = 0.03

// BusyCPU is the CPU utilization above which a helper container (load
// generator, upstream) is treated as a possible bottleneck.
const BusyCPU = 0.9

// Summary aggregates the runs of one scenario and target.
type Summary struct {
	Scenario      string `json:"scenario"`
	Target        string `json:"target"`
	ValidRuns     int    `json:"validRuns"`
	TotalRuns     int    `json:"totalRuns"`
	RPS           Stat   `json:"rps"`
	CPUUsPerReq   Stat   `json:"cpuUsPerReq"`
	ProxyMemBytes Stat   `json:"proxyMemBytes"`
	// Fixed-rate latency phase, when the scenario has one.
	LatencyRate int  `json:"latencyRate,omitempty"`
	P50Us       Stat `json:"p50Us"`
	P99Us       Stat `json:"p99Us"`
	P999Us      Stat `json:"p999Us"`
	// Reproducible is true when every run is valid and RPS and, with a
	// latency phase, p99 stay within MaxDeviation across runs.
	Reproducible bool `json:"reproducible"`
	// Bottlenecked is true when the load generator or the upstream, rather
	// than the proxy, may have limited a saturation run.
	Bottlenecked bool     `json:"bottlenecked"`
	Warnings     []string `json:"warnings,omitempty"`
	// Verdict against nginx: ahead | equal | behind, or inconclusive
	// when either side was bottlenecked elsewhere. Empty for nginx.
	Verdict       string   `json:"verdict,omitempty"`
	VerdictReason []string `json:"verdictReason,omitempty"`
}

// summarize groups measurements by scenario and target in the given order.
func summarize(ms []Measurement, scenarioIDs []string, targets []string) []Summary {
	var out []Summary
	for _, sc := range scenarioIDs {
		var nginx *Summary
		start := len(out)
		for _, tg := range targets {
			s := summarizeOne(ms, sc, tg)
			if s.TotalRuns == 0 {
				continue
			}
			out = append(out, s)
		}
		for i := start; i < len(out); i++ {
			if out[i].Target == "nginx" {
				nginx = &out[i]
			}
		}
		if nginx == nil {
			continue
		}
		for i := start; i < len(out); i++ {
			if out[i].Target != "nginx" {
				out[i].Verdict, out[i].VerdictReason = verdict(*nginx, out[i])
			}
		}
	}
	return out
}

func summarizeOne(ms []Measurement, scenario, target string) Summary {
	s := Summary{Scenario: scenario, Target: target}
	var rps, cpu, mem, p50, p99, p999 []float64
	for _, m := range ms {
		if m.Scenario != scenario || m.Target != target {
			continue
		}
		if m.Phase == "saturation" {
			s.TotalRuns++
		}
		if !m.Valid() {
			s.Warnings = append(s.Warnings, fmt.Sprintf("run %d %s: %.0f errors, excluded", m.Run, m.Phase, m.Wrk.ErrorCount()))
			continue
		}
		if m.Phase == "saturation" && (m.LoadgenCPUUtil > BusyCPU || m.UpstreamCPUUtil > BusyCPU) {
			s.Bottlenecked = true
		}
		if m.LoadgenCPUUtil > BusyCPU {
			s.Warnings = append(s.Warnings, fmt.Sprintf("run %d %s: load generator CPUs %.0f%% busy, it may be the bottleneck", m.Run, m.Phase, 100*m.LoadgenCPUUtil))
		}
		if m.UpstreamCPUUtil > BusyCPU {
			s.Warnings = append(s.Warnings, fmt.Sprintf("run %d %s: upstream CPUs %.0f%% busy, it may be the bottleneck", m.Run, m.Phase, 100*m.UpstreamCPUUtil))
		}
		switch m.Phase {
		case "saturation":
			s.ValidRuns++
			rps = append(rps, m.RPS)
			cpu = append(cpu, m.ProxyCPUUsPerReq)
			mem = append(mem, float64(m.ProxyMemBytes))
		case "latency":
			s.LatencyRate = m.Rate
			if m.Rate > 0 && m.RPS < 0.95*float64(m.Rate) {
				s.Warnings = append(s.Warnings, fmt.Sprintf("run %d latency: served %.0f of %d requests/s offered, latency includes queueing", m.Run, m.RPS, m.Rate))
			}
			p50 = append(p50, m.Wrk.LatencyUs.P50)
			p99 = append(p99, m.Wrk.LatencyUs.P99)
			p999 = append(p999, m.Wrk.LatencyUs.P999)
		}
	}
	s.RPS, s.CPUUsPerReq, s.ProxyMemBytes = newStat(rps), newStat(cpu), newStat(mem)
	s.P50Us, s.P99Us, s.P999Us = newStat(p50), newStat(p99), newStat(p999)
	s.Reproducible = s.ValidRuns == s.TotalRuns && s.ValidRuns > 0 && s.RPS.Deviation <= MaxDeviation && s.P99Us.Deviation <= MaxDeviation
	if s.ValidRuns != s.TotalRuns {
		s.Warnings = append(s.Warnings, "not every run is valid")
	}
	if s.RPS.Deviation > MaxDeviation {
		s.Warnings = append(s.Warnings, fmt.Sprintf("RPS deviation ±%.1f%% exceeds ±%.0f%%", 100*s.RPS.Deviation, 100*MaxDeviation))
	}
	if s.P99Us.Deviation > MaxDeviation {
		s.Warnings = append(s.Warnings, fmt.Sprintf("p99 deviation ±%.1f%% exceeds ±%.0f%%", 100*s.P99Us.Deviation, 100*MaxDeviation))
	}
	return s
}

// verdict applies the nginx parity thresholds to the run means:
//
//	ahead:  throughput > 100% and p99 < 100%
//	equal:  throughput ≥ 95%, p99 ≤ 105%, memory ≤ 110%
//	behind: otherwise
//
// p99 only counts in scenarios with a latency phase.
func verdict(base, s Summary) (string, []string) {
	if base.ValidRuns == 0 || s.ValidRuns == 0 {
		return "", []string{"no valid runs to compare"}
	}
	if base.Bottlenecked || s.Bottlenecked {
		return "inconclusive", []string{"load generator or upstream was saturated"}
	}
	rps := s.RPS.Mean / base.RPS.Mean
	mem := s.ProxyMemBytes.Mean / base.ProxyMemBytes.Mean
	reasons := []string{fmt.Sprintf("throughput %.1f%%", 100*rps), fmt.Sprintf("memory %.1f%%", 100*mem)}
	hasP99 := len(base.P99Us.All) > 0 && len(s.P99Us.All) > 0 && base.P99Us.Mean > 0
	p99 := 1.0
	if hasP99 {
		p99 = s.P99Us.Mean / base.P99Us.Mean
		reasons = append(reasons, fmt.Sprintf("p99 %.1f%%", 100*p99))
	}
	switch {
	case rps < 0.95 || p99 > 1.05 || mem > 1.10:
		return "behind", reasons
	case rps > 1.0 && (!hasP99 || p99 < 1.0):
		return "ahead", reasons
	default:
		return "equal", reasons
	}
}

// Markdown renders the report for humans; report.json keeps the raw data.
func (r Report) Markdown() string {
	var b strings.Builder
	e := r.Environment
	fmt.Fprintf(&b, "# Benchmark report %s\n\n", e.StartedAt)
	b.WriteString("## Environment\n\n| | |\n|---|---|\n")
	fmt.Fprintf(&b, "| Host | %s |\n| OS / kernel | %s / %s |\n| Arch, CPUs, memory | %s, %d, %.1f GiB |\n| Docker | %s |\n",
		e.Host, e.OS, e.Kernel, e.Arch, e.CPUs, float64(e.MemBytes)/(1<<30), e.DockerServer)
	for _, k := range sortedKeys(e.CPUSets) {
		fmt.Fprintf(&b, "| CPUs %s | %s |\n", k, e.CPUSets[k])
	}
	for _, k := range sortedKeys(e.Versions) {
		fmt.Fprintf(&b, "| %s | %s |\n", k, e.Versions[k])
	}
	for _, k := range sortedKeys(e.Images) {
		fmt.Fprintf(&b, "| image %s | `%s` |\n", k, e.Images[k])
	}
	fmt.Fprintf(&b, "| Harness commit | %s |\n", e.HarnessCommit)
	if e.ProxyCommit != "" {
		fmt.Fprintf(&b, "| proxelo-proxy commit | %s |\n", e.ProxyCommit)
	}
	st := e.Settings
	fmt.Fprintf(&b, "| Load | %d runs × %ds (warm-up %ds), %d connections, %d threads, %d proxy workers |\n",
		st.Runs, st.DurationSec, st.WarmupSec, st.Connections, st.Threads, st.ProxyWorkers)

	for _, sc := range scenarios {
		var rows []Summary
		for _, s := range r.Summaries {
			if s.Scenario == sc.ID {
				rows = append(rows, s)
			}
		}
		if len(rows) == 0 {
			continue
		}
		fmt.Fprintf(&b, "\n## %s: %s\n\n", sc.ID, sc.Title)
		b.WriteString("| Target | RPS (mean) | runs | ± | CPU µs/req | memory MiB |")
		if sc.Latency {
			fmt.Fprintf(&b, " p50 µs | p99 µs | p99.9 µs |")
		}
		b.WriteString(" reproducible | vs nginx |\n|---|---|---|---|---|---|---|")
		if sc.Latency {
			b.WriteString("---|---|---|")
		}
		b.WriteString("---|\n")
		for _, s := range rows {
			runs := make([]string, len(s.RPS.All))
			for i, x := range s.RPS.All {
				runs[i] = fmt.Sprintf("%.0f", x)
			}
			fmt.Fprintf(&b, "| %s | %.0f | %s | ±%.1f%% | %.1f | %.1f |", s.Target, s.RPS.Mean, strings.Join(runs, ", "),
				100*s.RPS.Deviation, s.CPUUsPerReq.Mean, s.ProxyMemBytes.Mean/(1<<20))
			if sc.Latency {
				fmt.Fprintf(&b, " %.0f | %.0f ±%.0f%% | %.0f |", s.P50Us.Mean, s.P99Us.Mean, 100*s.P99Us.Deviation, s.P999Us.Mean)
			}
			fmt.Fprintf(&b, " %s |", map[bool]string{true: "yes", false: "**no**"}[s.Reproducible])
			v := "baseline"
			if s.Target != "nginx" {
				v = s.Verdict
				if len(s.VerdictReason) > 0 {
					v += " (" + strings.Join(s.VerdictReason, ", ") + ")"
				}
			}
			fmt.Fprintf(&b, " %s |\n", v)
		}
		if sc.Latency && len(rows) > 0 && rows[0].LatencyRate > 0 {
			fmt.Fprintf(&b, "\nLatency measured with wrk2 at a fixed %d requests/s.\n", rows[0].LatencyRate)
		}
		for _, s := range rows {
			for _, w := range s.Warnings {
				fmt.Fprintf(&b, "\n- %s: %s", s.Target, w)
			}
		}
		b.WriteString("\n")
	}
	return b.String()
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
