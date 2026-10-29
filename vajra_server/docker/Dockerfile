# vajra_server / vajra_engine_v2 / rule_builder image.
#
# Single stage, deliberately not size-optimized: the environment this
# Dockerfile was authored in has no working docker daemon access (confirmed
# via `docker ps` -> "permission denied"), so a slimmer multi-stage image
# with a hand-picked runtime-only package set could not actually be built
# and verified here. The apt list below is the exact one already verified
# end-to-end on a real host (configures, builds, links, and runs
# every target plus the full test suite) -- reusing it as
# the runtime layer too, instead of guessing a slimmer set that has never
# been built, is the safe default until someone with real docker access
# can build this image and confirm a multi-stage split still works.
#
# Runtime layout produced below (see docker/entrypoint.sh):
#   /app/bin/{vajra_server,vajra_engine_v2,rule_builder,libvajraServerSdk.so}
#   /app/ssl/                  -- generated on first boot (see gen-ssl.sh)
#   /app/sql/                  -- schema + migrations (used by the db-init
#                                  compose service, not by these binaries
#                                  directly)
#   /app/rules/                -- engine_v2/rules/*.json (VAJRA_ENGINE_RULES)
#   /app/config.template.json
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake g++ make \
    libboost-all-dev \
    libpq-dev \
    librdkafka-dev \
    libssl-dev \
    libcurl4-openssl-dev \
    libsqlite3-dev \
    nlohmann-json3-dev \
    curl ca-certificates openssl python3 bash \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

# Vendored, C++20-ABI-matched libpqxx -- see CMakeLists.txt's top-of-file
# comment and scripts/bootstrap_deps_pqxx.sh for why this can't be the
# distro package. Skip the fetch+build if 3rdparty/local was already
# populated in the build context (e.g. a CI cache), mirroring
# the same check.
RUN set -eux; \
    if [ ! -f 3rdparty/local/lib/libpqxx.a ]; then \
        mkdir -p 3rdparty; \
        curl -fsSL https://github.com/jtv/libpqxx/archive/refs/tags/7.8.1.tar.gz -o /tmp/libpqxx.tar.gz; \
        tar -xzf /tmp/libpqxx.tar.gz -C 3rdparty; \
        rm -f /tmp/libpqxx.tar.gz; \
        bash scripts/bootstrap_deps_pqxx.sh; \
    fi

RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
 && cmake --build build -j"$(nproc)" --target vajra_server rule_builder \
 && cmake -S engine_v2 -B engine_v2/build -DCMAKE_BUILD_TYPE=Release \
 && cmake --build engine_v2/build -j"$(nproc)" --target vajra_engine_v2

RUN set -eux; \
    mkdir -p /app/bin /app/ssl /app/rules; \
    cp build/vajra_server build/rule_builder engine_v2/build/vajra_engine_v2 /app/bin/; \
    cp build/common/libvajraServerSdk.so /app/bin/; \
    cp -r sql /app/sql; \
    cp -r scripts /app/scripts; \
    cp engine_v2/rules/ruleset.json /app/rules/; \
    cp -r engine_v2/schema /app/schema; \
    cp config.template.json /app/config.template.json; \
    cp docker/entrypoint.sh docker/gen-ssl.sh /app/; \
    cp docker/render-config.py /app/; \
    chmod +x /app/entrypoint.sh /app/gen-ssl.sh /app/scripts/migrate.sh; \
    rm -rf /src

ENV LD_LIBRARY_PATH=/app/bin
ENV VAJRA_ENGINE_RULES=/app/rules/ruleset.json
WORKDIR /app/bin

EXPOSE 1234

ENTRYPOINT ["/app/entrypoint.sh"]
