# Vajra server (C++)

The C++ half of the Vajra endpoint security platform. It receives telemetry from the
[Linux and Windows agents](#related-repositories), stores it in PostgreSQL, publishes events to
Kafka, and runs the detection engine that raises alerts and incidents.

## What is in this repository

| Folder | What it is |
|---|---|
| `server/` | `vajra_server`: the osquery TLS endpoint that agents enroll with and send data to (port 1234). |
| `engine_v2/` | `vajra_engine_v2`: reads events from Kafka, matches rules and correlations, writes alerts and incidents. Its own CMake project. |
| `rule_builder/` | `rule_builder`: a small service that processes rules stored in the database. |
| `common/` | Shared code: configuration, database pool, logging. |
| `sql/` | `schema.sql` and numbered migrations. |
| `docker/`, `docker-compose.yml` | Container image and a compose file for this server alone. For the whole platform use the compose file one level up. |
| `scripts/` | Database migration, data retention and libpqxx build helpers. |
| `docs/` | `RULE_AUTHORING_TEMPLATE.md`: how to write detection rules. |
| `vajra.sh` | Build, deploy and service management on one Ubuntu/Debian machine. |

## Requirements

Ubuntu or Debian with a C++20 compiler, CMake 3.16+, PostgreSQL, Apache Kafka, OpenSSL and the
Boost, librdkafka and libcurl development packages. `vajra.sh deploy` installs these for you.

The code links a static build of libpqxx 7.8.1 compiled as C++20 (the distribution package is
built as C++17 and does not link). `scripts/bootstrap_deps_pqxx.sh` builds it into `3rdparty/local`:

```bash
mkdir -p 3rdparty
curl -fsSL https://github.com/jtv/libpqxx/archive/refs/tags/7.8.1.tar.gz | tar -xz -C 3rdparty
bash scripts/bootstrap_deps_pqxx.sh
```

`vajra.sh deploy` does this automatically when `3rdparty/local` is missing.

## Quick start (one machine)

```bash
SSL_PASSWORD=choose-a-passphrase DB_PASS=choose-a-password \
  ./vajra.sh deploy -d vajra.local -y --with-rule-engine
./vajra.sh status
```

`deploy` installs dependencies, creates the certificate authority and server certificate in
`ssl/`, creates the database and applies `sql/`, sets up Kafka and its topics, builds, installs
systemd units and starts everything. `SSL_PASSWORD` protects the certificate authority key and
has no default. Agents need `ssl/myCA.pem` (the CA certificate) and the enrollment secret in
`enrollment_secret.txt`.

Useful commands: `./vajra.sh help`, `status`, `logs [name]`, `restart [server|rule_engine|rule_builder]`,
`reload rule_engine` (reload rules without a restart), `verify`, `uninstall`.

## Docker

`docker-compose.yml` here starts PostgreSQL, Kafka, `vajra_server` and `vajra_engine_v2`. To run
the whole platform (including the web console), use the `docker-compose.yml` in the parent
directory instead.

## Building by hand

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
ctest --test-dir build --output-on-failure
cmake -S engine_v2 -B engine_v2/build -DCMAKE_BUILD_TYPE=Release && cmake --build engine_v2/build -j
ctest --test-dir engine_v2/build --output-on-failure
```

## Configuration

Copy `config.template.json` to `config.json` (`vajra.sh` does this and fills in the passwords).
It holds the TLS paths, the enrollment secret, database and Kafka settings.
`max_enrolled_devices` caps how many devices may enroll.

## Rules

`engine_v2/rules/ruleset.json` holds the detection rules and `docs/RULE_AUTHORING_TEMPLATE.md`
explains how to write more. Many rules were converted from the Sigma project; see
`THIRD_PARTY.md` for the license and attribution that applies to them.

## Upgrading from an older install

Earlier versions also ran `vajra_engine` (the first engine) and a SIEM syslog forwarder. Remove
their services with `sudo systemctl disable --now vajra_engine vajra_siem_forwarder` and delete
`/etc/systemd/system/vajra_engine.service` and `vajra_siem_forwarder.service`. Migration
`sql/migrations/0004_drop_siem_forwarder.sql` removes the forwarder's tables (run
`scripts/migrate.sh`).

## Related repositories

- `vajranet_server`: web console and API (Node.js and React)
- `linux_agent`: the Linux agent
- `windows_agent`: the Windows agent

Clone them next to each other. Replace this list with the real repository links when they are published.

## License

MIT, see `LICENSE`. Third-party components are listed in `THIRD_PARTY.md`.
