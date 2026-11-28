# syntax=docker/dockerfile:1
# proxelo image: the control plane with the web console embedded, and
# proxelo-proxy next to it for dry-loads and the request simulator. The proxy
# source comes from the build context named "proxy":
#   docker build --build-context proxy=../proxelo-proxy -t proxelo .
# compose.yaml passes it the same way.

FROM oven/bun:1.4 AS web
WORKDIR /src/web
COPY web/package.json web/bun.lock ./
RUN bun install --frozen-lockfile
COPY web/ ./
RUN mkdir -p ../internal/ui/dist && bun run build

FROM rust:1.98-slim-trixie AS proxy-build
RUN apt-get update \
 && apt-get install -y --no-install-recommends make git pkg-config libssl-dev \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY --from=proxy . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p proxelo-proxy \
 && cp target/release/proxelo-proxy /proxelo-proxy

FROM golang:1.26-trixie AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
COPY --from=web /src/internal/ui/dist internal/ui/dist
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /proxelo ./cmd/proxelo

FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates libssl3t64 \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10001 proxelo \
 && useradd --system --uid 10001 --gid proxelo --home-dir /var/lib/proxelo proxelo \
 && install -d -o proxelo -g proxelo -m 0750 /var/lib/proxelo /run/proxelo
COPY --from=build /proxelo /usr/local/bin/proxelo
COPY --from=proxy-build /proxelo-proxy /usr/local/bin/proxelo-proxy
USER proxelo
ENV PROXELO_DATA=/var/lib/proxelo \
    PROXELO_CONTROL_SOCKET=/run/proxelo/control.sock \
    PROXELO_ADMIN_LISTEN=0.0.0.0:9443
VOLUME ["/var/lib/proxelo"]
EXPOSE 9443
ENTRYPOINT ["proxelo"]
CMD ["control"]
