# Load generators for the benchmark harness: wrk (saturated throughput),
# wrk2 (fixed-rate latency) and h2load (HTTP/2). Versions are pinned so runs
# stay comparable; the harness records them in every report.
FROM debian:trixie-slim AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential git ca-certificates libssl-dev zlib1g-dev libluajit-5.1-dev luajit \
 && rm -rf /var/lib/apt/lists/*

# wrk 4.2.0 against the system LuaJIT and OpenSSL.
RUN git clone https://github.com/wg/wrk /wrk \
 && cd /wrk && git checkout 4.2.0 \
 && make -j"$(nproc)" WITH_LUAJIT=/usr WITH_OPENSSL=/usr CFLAGS="-I/usr/include/luajit-2.1 -O2" VER=4.2.0

# wrk2 has no releases; pin the last commit. Its bundled LuaJIT predates
# arm64 support, so LDIR points at a directory laid out the way its Makefile
# expects (luajit, libluajit.a, headers) but filled from the system LuaJIT 2.1.
# That LuaJIT renamed luaL_reg, and the x86-only include is unused.
# parse_args stores getopt's result in a char, which is unsigned on arm64, so
# the -1 end marker is never seen and every command line is rejected.
RUN git clone https://github.com/giltene/wrk2 /wrk2 \
 && cd /wrk2 && git checkout 44a94c17d8e6a0bac8559b53da76848e430cb7a7 \
 && sed -i 's/struct luaL_reg /struct luaL_Reg /g' src/script.c \
 && sed -i '/x86intrin.h/d' src/hdr_histogram.c \
 && sed -i 's/^    char c, \*\*header = headers;/    int c; char **header = headers;/' src/wrk.c \
 && grep -q '^    int c; char \*\*header = headers;' src/wrk.c \
 && mkdir /lj && cp /usr/include/luajit-2.1/*.h /lj/ \
 && ln -s "$(gcc -print-file-name=libluajit-5.1.a)" /lj/libluajit.a \
 && ln -s "$(command -v luajit)" /lj/luajit \
 && make -j"$(nproc)" LDIR=/lj

FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends libluajit-5.1-2 libssl3t64 nghttp2-client util-linux \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /wrk/wrk /usr/local/bin/wrk
COPY --from=build /wrk2/wrk /usr/local/bin/wrk2
COPY report.lua /bench/report.lua
