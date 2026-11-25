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

Early development. `proxelo compile` turns a JSON resource file into a
snapshot that `proxelo-proxy check` accepts:

```sh
go run ./cmd/proxelo compile examples/basic.json snapshot.bin
proxelo-proxy check snapshot.bin
```

## Layout

| Path | Contents |
|---|---|
| `cmd/proxelo` | Control plane binary |
| `internal/model` | Resources edited through the API |
| `internal/compile` | Resource to snapshot compiler |
| `examples` | Sample resource files |

## Development

```sh
go vet ./...
go test ./...
```

## License

[MIT](LICENSE)
