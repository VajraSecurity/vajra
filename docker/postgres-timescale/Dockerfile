# postgres:16 (Debian) plus the TimescaleDB extension. Built on the same Debian image as plain
# postgres:16 on purpose: an existing pgdata volume keeps its glibc text collation, which the
# Alpine-based timescale/timescaledb images would silently change (corrupting text indexes).
FROM postgres:16

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl gnupg lsb-release \
 && curl -fsSL https://packagecloud.io/timescale/timescaledb/gpgkey | gpg --dearmor -o /usr/share/keyrings/timescaledb.gpg \
 && echo "deb [signed-by=/usr/share/keyrings/timescaledb.gpg] https://packagecloud.io/timescale/timescaledb/debian/ $(lsb_release -c -s) main" \
      > /etc/apt/sources.list.d/timescaledb.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends timescaledb-2-postgresql-16 \
 && apt-get purge -y --auto-remove curl gnupg lsb-release \
 && rm -rf /var/lib/apt/lists/*

# Set on the command line, not in postgresql.conf, so it also applies to a data directory that
# was created by the plain postgres image.
CMD ["postgres", "-c", "shared_preload_libraries=timescaledb", "-c", "timescaledb.telemetry_level=off"]
