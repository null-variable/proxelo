# Conformance against nginx

Proxelo aims to behave like nginx for every directive nginx has. Two tools
measure how far it is:

| Tool | Answers |
|---|---|
| `directives.yaml` and `./directives` | Which nginx directives exist, and which Proxelo field implements each one |
| `go run ./test/conformance` | Whether Proxelo answers the same requests as nginx configured alike |

The reference is one nginx release, recorded at the top of
`directives.yaml` and as `nginxImage` in `main.go`. Both move together.

## Directive list

`directives.yaml` lists every directive of every nginx module, extracted from
the `ngx_command_t` tables of an nginx source tree, with the contexts it is
allowed in. Each entry has a status:

| Status | Meaning |
|---|---|
| `implemented` | Every parameter has an equivalent; `field` names it |
| `partial` | The common form works; `note` says what is missing |
| `fixed` | Proxelo behaves as nginx's default value, which cannot be changed yet |
| `missing` | Not implemented |

Coverage counts implemented as 1, partial as ½ and the rest as 0.

To refresh the list from a new nginx release (statuses, fields and notes are
kept; new directives arrive as `missing`, removed ones are printed):

```sh
git clone --depth 1 -b release-1.31.10 https://github.com/nginx/nginx /tmp/nginx
go run ./test/conformance/directives -src /tmp/nginx
```

`-check` writes nothing and fails when the file would change. CI runs it
against the reference release, and weekly against the newest nginx release
so new directives show up.

When a change implements a directive, set its status and field in the same
commit.

## Differential test

Each directory under `cases/` is one case:

| File | Contents |
|---|---|
| `nginx.conf` | `server` and `upstream` blocks, placed inside an `http` block |
| `proxelo.json` | The same configuration as Proxelo resources (until the nginx importer exists) |
| `case.yaml` | `directives` it exercises, `requests` to send, and response headers to `ignore` |
| `www/` | Optional files, served at `/srv/www` |

The harness starts nginx in Docker (host network), sends every request, then
compiles `proxelo.json` with the control plane compiler and serves it with
`proxelo-proxy serve` on the same port and sends them again. For each request
it compares the status, the response headers, the body, and the request that
reached the upstream (method, URI, headers, body).

Expected differences are normalized, not ignored:

- `Date` and `Server` are dropped.
- The server name in built-in error pages (`<center>nginx</center>`) is
  replaced, and Content-Length adjusted.
- Multipart byte-range boundaries are replaced.
- `Connection` sent upstream is dropped: it depends on upstream keepalive.

Anything else a case leaves out goes in its `ignore` list with the reason
next to it.

```sh
(cd ../proxelo-proxy && cargo build --release -p proxelo-proxy)
go run ./test/conformance -proxy ../proxelo-proxy/target/release/proxelo-proxy
go run ./test/conformance -proxy ... -case static-root -keep   # one case, keep the work directory
```

Requests listen on 127.0.0.1:18480 and the upstream on 127.0.0.1:18481 to
18484; its answer names the port, so cases with several targets compare
which target took each request. A request with `X-Echo-Status` gets that
status from the echo (401 with a Basic challenge), so cases can make the
upstream refuse, as a forward auth check does. The
report (stdout, and `-report file`) lists every differing request and the
directive coverage.

Without Docker, `-nginx path/to/sbin/nginx` runs a local build of the same
nginx version instead; it needs the modules the cases use
(`--with-http_auth_request_module --with-http_realip_module`). nginx built
on macOS matches `location ~` regexes caselessly, unlike the Linux
reference, so a case relying on case-sensitive regexes differs there.

### Writing a case

Start from what nginx does: write `nginx.conf` and the requests, including
edge cases (case, encoding, trailing slashes, missing files, methods, ranges).
Write the equivalent `proxelo.json`, run the case, and fix Proxelo until it
passes. List the directives the case exercises in `case.yaml`, as
`module/name` or a bare name when only one HTTP module has it; the report
counts a directive as tested once a case lists it.
