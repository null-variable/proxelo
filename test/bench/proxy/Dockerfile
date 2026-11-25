# Builds proxelo-proxy from a local checkout, passed as the build context:
#   docker build -f test/bench/proxy/Dockerfile --build-arg FEATURES=jemalloc ../proxelo-proxy
FROM rust:1.98-slim-trixie AS build
RUN apt-get update && apt-get install -y --no-install-recommends make git && rm -rf /var/lib/apt/lists/*
ARG FEATURES=""
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p proxelo-proxy ${FEATURES:+--features "$FEATURES"} \
 && cp target/release/proxelo-proxy /proxelo-proxy

FROM debian:trixie-slim
COPY --from=build /proxelo-proxy /usr/local/bin/proxelo-proxy
ENTRYPOINT ["proxelo-proxy"]
