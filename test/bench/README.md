# Benchmark harness

Measures nginx and `proxelo-proxy` under the same load and writes a report. Scenarios built so far:

| ID | Scenario | Measured |
|---|---|---|
| S1 | Static 1 KiB file, HTTP/1.1 keepalive | Saturated RPS (wrk), CPU per request, memory |
| S3 | Reverse proxy, HTTP/1.1 keepalive, 1 KiB response | Saturated RPS (wrk), then p50/p99/p99.9 at a fixed rate (wrk2) |

## Running

Needs Docker and Go. From the repository root, with a `proxelo-proxy` checkout
next to it:

```sh
go run ./test/bench                                   # S1 and S3, nginx and both proxelo runtimes
go run ./test/bench -targets nginx                    # nginx baseline only
go run ./test/bench -targets nginx,proxelo:per-core:jemalloc,proxelo:per-core:mimalloc
go run ./test/bench -proxy-src ~/src/proxelo-proxy -runs 5 -duration 60s
```

Each invocation writes `report.md` and `report.json` (every run, raw wrk
output, environment) to `test/bench/results/<UTC time>/`, or `-out`. Commit
results that serve as a baseline or a comparison.

Targets are `nginx` or `proxelo[:shared|per-core[:system|jemalloc|mimalloc]]`,
the runtime and allocator candidates still being chosen between.

## How a run works

- Every process gets its own container on the host network, pinned with
  `--cpuset-cpus`: proxy under test (`-proxy-cpus`, default `0-1`), upstream
  (`-upstream-cpus`, `2-3`), load generator (`-loadgen-cpus`, `4-7`). The proxy
  runs one worker per CPU in its set; wrk one thread per CPU in its set.
- nginx and proxelo get the same configuration: `nginx.conf` is rendered from
  `targets.go` and the proxelo snapshot is compiled from the equivalent
  resources by `internal/compile`. nginx uses its documented performance
  settings (`sendfile`, `tcp_nopush`, `reuseport`, upstream `keepalive`) and
  nothing proxelo lacks: access logging is off and `keepalive_requests` is
  unbounded.
- The S3 upstream is nginx answering from memory (`return 200`), the cheapest
  response it can produce.
- The served file is copied onto a tmpfs inside the proxy container. Served
  straight from a bind mount, S1 measured the host file share (Docker on macOS
  is 7× slower that way) instead of the proxy.
- Every run starts fresh containers, checks the response body, warms up
  (`-warmup`, unmeasured) and measures (`-duration`). Runs alternate between
  targets so drift of the machine hits all of them alike.
- CPU time comes from each container's cgroup `cpu.stat`, memory from
  `memory.current` at the end of the run.
- The fixed rate for the S3 latency phase is `-latency-load` (default 0.5)
  times nginx's mean saturated RPS, or `-latency-rate`, so every target gets
  the same offered load.

## Reading the report

| Column | Meaning |
|---|---|
| RPS, runs, ± | Mean saturated RPS, each run, largest deviation of a run from the mean |
| CPU µs/req | Proxy CPU time per completed request |
| memory MiB | Proxy container memory at the end of the run |
| p50/p99/p99.9 | wrk2 latency at the fixed rate, corrected for coordinated omission |
| vs nginx | Verdict against nginx from the run means |

Verdicts: **ahead** (throughput > 100%, p99 < 100%), **equal** (throughput ≥
95%, p99 ≤ 105%, memory ≤ 110%), **behind** (anything else). p99 only counts
in scenarios with a latency phase. A verdict is **inconclusive** when the load
generator or the upstream was more than 90% busy in a saturation run, because
then the proxy was not what limited throughput.

A result is reproducible when every run is error-free and saturated RPS stays
within ±3% of the mean. The report
lists every run that misses this.

## Limits of a single machine

Proxy, upstream and load generator share one machine's memory bandwidth,
caches and kernel even when pinned to separate CPUs. Fair numbers need
separate machines or cpusets; this harness does cpusets. Numbers from Docker
on macOS (OrbStack, Docker Desktop) run inside a Linux VM and are only useful
for comparing targets on that machine, not as a published baseline. Publish
baselines from a dedicated Linux host with CPU frequency scaling fixed.

## Versions

Pinned in `main.go` (`nginxImage`) and `loadgen/Dockerfile` (wrk 4.2.0, wrk2
at its last commit, h2load from Debian trixie). Every report records image IDs,
tool versions and the commits of both repositories. Change a version on
purpose and re-run the baseline; reports are only comparable at equal
versions.
