# Proxelo

Proxelo is a web server, reverse proxy and load balancer managed through an
API and a web UI.

It runs as two processes:

| Process | Repository | Role |
|---|---|---|
| `proxelo` | this repository (Go) | Control plane: API, web UI, storage, certificates, compiles configuration into snapshots |
| `proxelo-proxy` | [proxelo-proxy](https://github.com/null-variable/proxelo-proxy) (Rust) | Data plane: serves traffic from the active snapshot |

They share only the protocol in
[proxelo-api](https://github.com/null-variable/proxelo-api). A proxy keeps
serving its last good snapshot when the control plane is unavailable.

## Status

Early development. The control plane stores Listener, Site, Route, Upstream,
Certificate and Policy resources in SQLite, serves them over a REST API, compiles them into snapshots
and pushes every applied snapshot to connected proxies. Routes cover the nginx
location kinds (exact, prefix, `^~`, `~`, `~*`) and nesting, rewrite, return,
error_page and try_files; error pages and try_files can hand off to another
route like an nginx named location. Routes can also match on methods, headers,
query arguments and a CEL expression; expressions are type-checked when saved.

Listeners can terminate TLS and offer HTTP/2; sites pick certificates by SNI
and can redirect plain requests to https. Certificates are uploaded as PEM
(the key is never returned by the API) or issued and renewed by the control
plane over ACME (HTTP-01 and TLS-ALPN-01, Let's Encrypt by default, 30 days
before expiry); a renewal makes a revision that changes only that
certificate. Upstreams balance by round robin or least_conn with backup
targets and passive health, and proxy routes set timeouts and retries.

Policies attach to sites and routes and are inherited down the route tree:
`headers` sets, adds or removes response headers and headers
sent upstream, merged by name with the closest policy winning; `accessLog`
picks the log for its routes (`combined`, `main`, `json` or a template). A
route with `"inheritPolicies": false` starts over.

Applies are dry-loaded by the proxy engine (`proxelo-proxy sim`, a resident
helper) before a revision is stored, so a snapshot the proxy would reject never
becomes a revision. The same helper answers `POST /api/v1/simulate`.

Run both processes together (development, home lab):

```sh
go build -o proxelo ./cmd/proxelo
./proxelo up -data ./data -listen 127.0.0.1:9443 -proxy ../proxelo-proxy/target/release/proxelo-proxy
```

Proxies expose Prometheus metrics on `127.0.0.1:9145/metrics` by default
(`-- --metrics <addr|off>`). ACME uses `-acme-directory` and `-acme-email`.

`up` starts `proxelo control` and `proxelo-proxy run` as children, restarts
either one if it exits and stops both on SIGTERM. Arguments after `--` go to
the proxy (`-- --workers 4 --runtime per-core`). In production run them as two
services instead:

```sh
proxelo control -data /var/lib/proxelo -listen 127.0.0.1:9443 -socket /run/proxelo/control.sock
proxelo-proxy run --data /var/lib/proxelo --socket /run/proxelo/control.sock
```

The proxy dials the control socket (gRPC `DistributionService.Sync` from
`proxelo-api`), receives the newest snapshot on connect and on every apply,
and answers each with an ack. It keeps the last snapshot it applied in
`<data>/proxy/lkg.snap` and starts from it, so it serves traffic while the
control plane is down and reconnects when it is back.

| Endpoint | Purpose |
|---|---|
| `GET/POST /api/v1/{kind}` | List or create `listeners`, `sites`, `routes`, `upstreams`, `certificates`, `policies` |
| `GET/PATCH/DELETE /api/v1/{kind}/{id}` | Read, merge-patch (RFC 7396) or delete; `If-Match: "<resourceVersion>"` guards writes |
| `POST /api/v1/apply` | Compile all resources into the next revision (`{"message": "..."}`) |
| `GET /api/v1/revisions[/{rev}]` | Revision history, or one revision with its resources |
| `GET /api/v1/revisions/{rev}/snapshot` | Compiled snapshot (protobuf) |
| `GET /api/v1/nodes` | Connected proxies: active, last sent and last rejected revision |
| `POST /api/v1/simulate` | Run requests (`{"requests":[{"method","target","headers","remoteAddr","listener"}]}`) against the latest or a given `revision`, and with `"draft": true` against the unapplied resources; returns site, route, rewritten URI, upstream or file, status and a trace |

Validation errors return `422` with field paths such as
`routes[rt_...].spec.action.proxy.upstream`.

A resource file can also be compiled offline:

```sh
go run ./cmd/proxelo compile examples/basic.json snapshot.bin
proxelo-proxy check snapshot.bin
```

## Layout

| Path | Contents |
|---|---|
| `cmd/proxelo` | Control plane binary |
| `internal/model` | Resources edited through the API and their field validation |
| `internal/compile` | Resource to snapshot compiler, golden tests in `testdata/` |
| `internal/store` | SQLite storage for resources and revisions |
| `internal/api` | REST API |
| `internal/distrib` | Snapshot and ACME challenge distribution to proxies over the control socket |
| `internal/acme` | ACME issuance and renewal |
| `internal/simulate` | Resident `proxelo-proxy sim` helper for dry-loads and simulation |
| `examples` | Sample resource files |
| `test/bench` | Benchmark harness: nginx vs `proxelo-proxy` (S1, S3), see its README |

## Development

```sh
go vet ./...
go test ./...
go test ./internal/compile -update   # rewrite golden snapshots
```

## License

Licensed under the [Apache License, Version 2.0](LICENSE). See [NOTICE](NOTICE).
