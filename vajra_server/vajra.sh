#!/usr/bin/env bash
#
# ============================================================================
#  vajra.sh — Vajra Server unified deployment & operations tool
# ============================================================================
#
#  What it does: build, ssl-gen, db-init, migrate, kafka setup + topics,
#  systemd install, start/stop/restart/status, log/debug helpers, health
#  verification, retention cleanup, clean/uninstall.
#
#  Targeted operations: install-services/start/stop/restart take an optional
#  trailing service name (kafka|server|rule_engine|rule_builder). With
#  a target, ONLY that service is touched -- every other running service is
#  left alone. `restart <target>` and `start <target>` auto-create the systemd
#  unit first if it isn't installed yet. Omit the target and every command
#  operates on the whole fleet. `status` also reports any vajra_*.service unit
#  installed on disk, not just the ones implied by this invocation's flags.
#
#  Optional services (opt-in flags):
#    --with-rule-engine   engine_v2 (the Kafka-consuming detection/correlation
#                         engine) as its own standalone CMake project; applies
#                         its incidents/incident_alerts schema and installs it as
#                         vajra_engine_v2.service. `reload rule_engine` SIGHUPs it
#                         to hot-reload its ruleset without a restart.
#    --with-rule-builder  vajra_rule_builder.service; needs only DB access.
#
#  Components: vajra_server is the only application service started by
#  default; the rule engine and rule_builder are opt-in. event_processor is not
#  part of this repository, so --with-processors is not available and dies
#  with a clear error.
#
#  Usage:
#     ./vajra.sh <command> [target] [options]
#
#  Commands:
#     deploy            Full end-to-end deploy (deps, ssl, db, kafka, build,
#                       services, start, verify). Idempotent.
#     build             Configure + compile the binaries only.
#     ssl               Generate CA + server certificate + DH params.
#     db-init           Create role/database and apply sql/schema.sql (+indexes).
#     migrate           Apply pending versioned migrations (sql/migrations/*).
#     kafka-setup       Install/configure a local KRaft Kafka broker.
#     kafka-topics      Create/verify the Vajra Kafka topics.
#     install-services [target]
#                       Generate + enable systemd units. With a target
#                       (kafka|server|rule_engine|rule_builder),
#                       writes/enables ONLY that one unit -- every other unit
#                       file (and any running service) is left untouched. No
#                       target = write/enable every unit implied by this
#                       run's flags (default behavior).
#     start [target]    Start services. Target = only that one service is
#                       started (auto-installs its unit first if missing).
#                       No target = start the whole fleet (kafka + vajra_server
#                       [+ rule_engine/rule_builder if their flags are set]).
#     stop [target]     Stop services. Target = only that one service.
#                       No target = stop everything this run's flags cover.
#     restart [target]  Restart services. Target = restart ONLY that one
#                       service -- e.g. `./vajra.sh restart rule_engine` never
#                       touches vajra_kafka.service or vajra_server.service,
#                       and creates+enables vajra_engine_v2.service first if it
#                       doesn't exist yet (the binary itself needs no
#                       rebuild if `build`/`deploy --with-rule-engine` already
#                       ran once). No target = restart the whole fleet.
#     reload [target]   SIGHUP vajra_engine_v2 to hot-reload its ruleset in
#                       place (requires --with-rule-engine; does not restart
#                       the process or drop its Kafka consumer group).
#                       Target = rule_engine (the only valid target).
#     status            Show service + port + broker status. Reports every
#                       vajra_*.service unit actually installed on disk, not
#                       just the ones this invocation's flags imply.
#     logs [name]       Tail logs (vajra_server|kafka|rule_engine|rule_builder).
#     verify            Run health/verification checks.
#     retention         Run the DB retention cleanup job.
#     uninstall         Stop + remove systemd units (keeps data by default).
#     help              Show this help.
#
#  Common options:
#     -d, --domain <name>   Use a DNS hostname for the cert/SAN (default: host IP).
#     -y, --yes             Non-interactive; assume "yes" to prompts.
#     -v, --verbose, --debug
#                           Trace every shell command this script runs (bash
#                           `set -x`) AND, for commands that patch config.json
#                           (deploy/build), force log_configuration.log_level
#                           to "debug" so the running binaries log verbosely
#                           too. Off by default (both this script and the
#                           binaries default to a quiet warning-level log).
#         --dev             Run app services via nohup instead of systemd.
#         --with-rule-engine
#                           Also build/install/start vajra_engine_v2 (the
#                           rule/correlation engine under engine_v2/, a
#                           standalone CMake project).
#         --with-rule-builder
#                           Also install/start rule_builder (DB-polling rule
#                           processor). Binary only needs Postgres, same
#                           config.json section as everything else -- no new
#                           certs, no Kafka.
#         --force-ssl       Rotate an existing server cert/key (prompts first).
#         --skip-deps       Skip OS package installation.
#         --skip-ssl        Skip certificate generation.
#         --skip-db         Skip database creation/schema/migrations.
#         --skip-kafka      Skip Kafka install/topic setup.
#         --skip-build      Skip the compile step.
#         --purge           (uninstall only) also drop DB, topics and certs.
#
#  Overridable environment variables (defaults in parentheses):
#     DB_NAME(fleet) DB_USER(vajra) DB_PASS(admin) DB_HOST(localhost) DB_PORT(5432)
#     KAFKA_VERSION(4.1.1) KAFKA_SCALA(2.13) KAFKA_PORT(9092)
#     FLEET_PORT(1234) IP_ADDRESS(auto)
#     SSL_PASSWORD (required when a certificate authority has to be created: the
#                          passphrase that protects the CA key; no default)
#     CERT_COUNTRY(IN) CERT_STATE(MH) CERT_LOCALITY(Mumbai) CERT_ORG(Vajra)
#     CERT_OU(EDR)      -- cert subject (DN) fields; CN comes from -d/--domain
#                          or the resolved IP_ADDRESS instead, not from here.
#     VAJRA_ENGINE_RULES   (not read from this script's environment) vajra_engine_v2
#                          always loads the bundled engine_v2/rules/ruleset.json;
#                          the variable is set directly in its systemd unit/dev
#                          launch.
#
#  Examples:
#     ./vajra.sh deploy -d fleet.example.com --with-rule-builder
#     ./vajra.sh deploy -d fleet.example.com --with-rule-engine
#     ./vajra.sh restart rule_engine         # only vajra_engine_v2 restarts
#     ./vajra.sh reload rule_engine          # hot-reload engine_v2's ruleset
#     ./vajra.sh restart rule_builder        # only vajra_rule_builder restarts
#     ./vajra.sh install-services engine     # create+enable just that unit
#     ./vajra.sh status                      # shows every installed unit
# ============================================================================

set -euo pipefail

# --------------------------------------------------------------------------
# Paths & configuration
# --------------------------------------------------------------------------
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${BUILD_DIR:-${REPO_ROOT}/cmake-build-debug}"
SQL_DIR="${REPO_ROOT}/sql"
SSL_DIR="${REPO_ROOT}/ssl"
LOG_DIR="${LOG_DIR:-/tmp/vajra}"

# engine_v2 -- the newer, standalone-CMake-project detection/correlation
# engine (see engine_v2/CMakeLists.txt's own header comment). It has its own
# build dir, its own ruleset, and its own systemd unit
# (vajra_engine_v2.service), opted into via --with-rule-engine.
RULE_ENGINE_DIR="${REPO_ROOT}/engine_v2"
RULE_ENGINE_BUILD_DIR="${RULE_ENGINE_DIR}/build"
RULE_ENGINE_RULESET="${RULE_ENGINE_DIR}/rules/ruleset.json"

DB_NAME="${DB_NAME:-fleet}"
DB_USER="${DB_USER:-vajra}"
DB_PASS="${DB_PASS:-admin}"
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"

KAFKA_VERSION="${KAFKA_VERSION:-4.1.1}"
KAFKA_SCALA="${KAFKA_SCALA:-2.13}"
KAFKA_DIR="${KAFKA_DIR:-${HOME}/kafka_${KAFKA_SCALA}-${KAFKA_VERSION}}"
KAFKA_DATA="${KAFKA_DATA:-${HOME}/kafka-data}"
KAFKA_PORT="${KAFKA_PORT:-9092}"
KAFKA_BOOTSTRAP="localhost:${KAFKA_PORT}"

# Current 3-topic architecture (matches server/KafkaProducerManager.h; was
# 2-topic before macOS support added vajra_macos_events).
KAFKA_TOPICS=("vajra_windows_events" "vajra_linux_events" "vajra_macos_events")
# Dead-letter topics vajra_engine_v2's KafkaConsumer publishes to on permanent/
# exhausted-retry failures (engine_v2/src/KafkaConsumer.cpp, "<topic>.dlq").
# Provisioned explicitly here (same as the main topics) rather than left to
# the Kafka broker's auto.create.topics.enable default: if that default is
# ever off (a common hardening step), an unprovisioned DLQ publish fails,
# and the consumer's own fail-safe logic then seeks back and never commits
# -- redelivering that message forever instead of losing it. Explicit
# provisioning also stops these topics from silently drifting onto whatever
# retention the broker's global default happens to be.
KAFKA_DLQ_TOPICS=("vajra_windows_events.dlq" "vajra_linux_events.dlq" "vajra_macos_events.dlq")
KAFKA_PARTITIONS="${KAFKA_PARTITIONS:-6}"
KAFKA_RF="${KAFKA_RF:-1}"
KAFKA_RETENTION_MS="${KAFKA_RETENTION_MS:-259200000}"        # 3 days
# DLQ entries need an operator to notice and replay/investigate them, so they
# get a longer retention than the main topics rather than inheriting theirs.
KAFKA_DLQ_RETENTION_MS="${KAFKA_DLQ_RETENTION_MS:-604800000}"  # 7 days
KAFKA_MAX_MSG_BYTES="${KAFKA_MAX_MSG_BYTES:-1048576}"        # 1 MiB

FLEET_PORT="${FLEET_PORT:-1234}"
SSL_PASSWORD="${SSL_PASSWORD:-}"                              # CA-key passphrase only; no default, see gen_ssl()

# Certificate subject (DN) fields for both the CA and the server cert.
# CN is set separately, from resolve_identity()'s SERVER_HOSTNAME (the
# domain/IP the cert is actually issued for -- see -d/--domain and
# IP_ADDRESS above), not from here.
CERT_COUNTRY="${CERT_COUNTRY:-IN}"
CERT_STATE="${CERT_STATE:-MH}"
CERT_LOCALITY="${CERT_LOCALITY:-Mumbai}"
CERT_ORG="${CERT_ORG:-Vajra}"
CERT_OU="${CERT_OU:-EDR}"

# Runtime flags (populated by parse_args)
DOMAIN=""
ASSUME_YES=0
VERBOSE=0
DEV_MODE=0
WITH_PROCESSORS=0
WITH_RULE_BUILDER=0
WITH_RULE_ENGINE=0
SKIP_DEPS=0
SKIP_SSL=0
SKIP_DB=0
SKIP_KAFKA=0
SKIP_BUILD=0
PURGE=0
FORCE_SSL=0

SERVICE_USER="${SUDO_USER:-$USER}"
APP_SERVICES=("vajra_server")           # extended at runtime if --with-processors

# --------------------------------------------------------------------------
# Output helpers
# --------------------------------------------------------------------------
if [[ -t 1 ]]; then
    C_RESET=$'\033[0m'; C_INFO=$'\033[0;34m'; C_OK=$'\033[0;32m'
    C_WARN=$'\033[0;33m'; C_ERR=$'\033[0;31m'; C_BOLD=$'\033[1m'
else
    C_RESET=""; C_INFO=""; C_OK=""; C_WARN=""; C_ERR=""; C_BOLD=""
fi
log_info()  { echo "${C_INFO}[*]${C_RESET} $*"; }
log_ok()    { echo "${C_OK}[+]${C_RESET} $*"; }
log_warn()  { echo "${C_WARN}[!]${C_RESET} $*" >&2; }
log_err()   { echo "${C_ERR}[x]${C_RESET} $*" >&2; }
log_step()  { echo; echo "${C_BOLD}==== $* ====${C_RESET}"; }
die()       { log_err "$*"; exit 1; }

confirm() {
    # confirm "prompt" -> 0 if yes
    [[ $ASSUME_YES -eq 1 ]] && return 0
    local reply
    read -r -p "$1 [y/N] " reply
    [[ "$reply" =~ ^[Yy]$ ]]
}

need_cmd() { command -v "$1" >/dev/null 2>&1; }

# Map a short service target name (as typed on the CLI) to its systemd unit
# base name (without .service). Returns 1 on an unrecognized target so every
# caller can give a clear error instead of silently acting on nothing.
resolve_unit_name() {
    case "$1" in
        kafka)         echo "vajra_kafka" ;;
        server|vajra)  echo "vajra_server" ;;
        rule_engine)   echo "vajra_engine_v2" ;;
        rule_builder)  echo "vajra_rule_builder" ;;
        processor)     echo "vajra_event_processor" ;;
        *)             return 1 ;;
    esac
}

# sudo wrapper — errors clearly if privilege escalation is required but absent.
SUDO=""
init_sudo() {
    if [[ $EUID -ne 0 ]]; then
        if need_cmd sudo; then SUDO="sudo"; else
            log_warn "not root and 'sudo' not found — privileged steps may fail"
        fi
    fi
}

# --------------------------------------------------------------------------
# Identity resolution (server IP / hostname for certs & Kafka advertising)
# --------------------------------------------------------------------------
resolve_identity() {
    if [[ -n "${IP_ADDRESS:-}" ]]; then
        SERVER_IP="$IP_ADDRESS"
    else
        SERVER_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
        if [[ -z "${SERVER_IP:-}" ]]; then
            die "Could not auto-detect a server IP (hostname -I is empty). Set it explicitly: IP_ADDRESS=x.x.x.x $0 <command>"
        fi
    fi
    if [[ -n "$DOMAIN" ]]; then
        SERVER_HOSTNAME="$DOMAIN"
        SAN_MODE="dns"
    else
        SERVER_HOSTNAME="$SERVER_IP"
        SAN_MODE="ip"
    fi
}

# --------------------------------------------------------------------------
# Preflight
# --------------------------------------------------------------------------
preflight() {
    log_step "Preflight"
    if [[ $EUID -eq 0 ]]; then
        die "Do not run as root. Run as your normal user; privileged steps use sudo."
    fi
    init_sudo
    resolve_identity
    log_info "Repo:        $REPO_ROOT"
    log_info "Build dir:   $BUILD_DIR"
    log_info "Server IP:   $SERVER_IP"
    log_info "Cert host:   $SERVER_HOSTNAME (${SAN_MODE^^} SAN)"
    log_info "DB:          ${DB_USER}@${DB_HOST}:${DB_PORT}/${DB_NAME}"
    log_info "Kafka:       $KAFKA_DIR  (bootstrap ${KAFKA_BOOTSTRAP})"
    if [[ $WITH_RULE_BUILDER -eq 1 ]]; then
        log_info "Rule builder: enabled (DB-only, no Kafka/TLS involvement)"
    fi
    if [[ $WITH_RULE_ENGINE -eq 1 ]]; then
        local rc="?"
        need_cmd python3 && [[ -f "$RULE_ENGINE_RULESET" ]] && \
            rc="$(python3 -c "import json;print(len(json.load(open('${RULE_ENGINE_RULESET}')).get('rules', [])))" 2>/dev/null || echo "?")"
        log_info "Rule engine v2: enabled (${rc} rules in ${RULE_ENGINE_RULESET})"
    fi
    if [[ "$DB_PASS" == "admin" ]]; then
        log_warn "DB_PASS is still the default ('admin') -- this will be set as the live"
        log_warn "PostgreSQL password for role '${DB_USER}'. Override it: DB_PASS=<strong-password> $0 ${COMMAND:-deploy} ..."
    fi
    log_ok "Preflight OK"
}

# --------------------------------------------------------------------------
# OS dependencies
# --------------------------------------------------------------------------
install_deps() {
    [[ $SKIP_DEPS -eq 1 ]] && { log_info "Skipping OS deps (--skip-deps)"; return 0; }
    log_step "Installing OS dependencies"
    if ! need_cmd apt-get; then
        log_warn "apt-get not found — install build deps manually; continuing"
        return 0
    fi
    $SUDO apt-get update -y
    # procps' dev package was renamed libprocps-dev -> libproc2-dev partway
    # through Debian/Ubuntu's libproc2 soname transition. A hardcoded list of
    # "which release has which name" breaks on every release not yet added
    # to it (e.g. anything newer than 25.04) -- ask apt-cache directly
    # instead, which is correct on any release past or future.
    local procps_dev="libprocps-dev"
    if apt-cache show libproc2-dev >/dev/null 2>&1; then
        procps_dev="libproc2-dev"
    fi
    $SUDO apt-get install -y \
        build-essential cmake g++ make wget tar curl git \
        netcat-openbsd \
        postgresql postgresql-contrib libpq-dev libpqxx-dev \
        libboost-all-dev librdkafka-dev libssl-dev libjsoncpp-dev \
        libsqlite3-dev libcrypto++-dev libcurl4-openssl-dev \
        python3 python3-pip "$procps_dev" \
        || die "dependency installation failed"
    install_java
    log_ok "Dependencies installed"
}

install_java() {
    local ver=0
    if need_cmd java; then
        ver=$(java -version 2>&1 | awk -F'"' '/version/{print $2}' | cut -d. -f1)
    fi
    if [[ "${ver:-0}" -ge 17 ]]; then
        log_info "Java ${ver} present"
    else
        log_info "Installing OpenJDK 17 (Kafka requirement)"
        $SUDO apt-get install -y openjdk-17-jdk || die "Java install failed"
    fi
    if [[ -z "${JAVA_HOME:-}" ]]; then
        JAVA_HOME="$(dirname "$(dirname "$(readlink -f "$(command -v java)")")")"
        export JAVA_HOME
    fi
}

# --------------------------------------------------------------------------
# Directories
# --------------------------------------------------------------------------
make_dirs() {
    mkdir -p "$BUILD_DIR" "$LOG_DIR" "$SSL_DIR" "$REPO_ROOT/logs" "$KAFKA_DATA"
}

# --------------------------------------------------------------------------
# SSL certificate generation (mirrors the proven unified_deploy_auto.sh flow)
# --------------------------------------------------------------------------
gen_ssl() {
    [[ $SKIP_SSL -eq 1 ]] && { log_info "Skipping SSL (--skip-ssl)"; return 0; }
    log_step "SSL certificate generation"
    need_cmd openssl || die "openssl not installed"
    mkdir -p "$SSL_DIR"; cd "$SSL_DIR"

    # CRITICAL: an existing server cert/key is the trust anchor for every
    # already-enrolled osquery agent. Regenerating it silently breaks TLS for
    # the whole fleet. Preserve it unless the operator explicitly forces a
    # rotation with --force-ssl. (This is guarded INDEPENDENTLY of the CA/DH so
    # a missing myCA.pem can never trigger a server-cert reissue.)
    if [[ -f "${SERVER_HOSTNAME}.crt" && -f "${SERVER_HOSTNAME}.key" && $FORCE_SSL -eq 0 ]]; then
        log_info "Server cert/key for ${SERVER_HOSTNAME} already exist — preserving them"
        log_info "(re-issuing would break TLS trust for enrolled agents; use --force-ssl to rotate)"
        if [[ ! -f "dh.pem" ]]; then
            log_info "Generating missing DH params (2048-bit; slow)"
            openssl dhparam -out dh.pem 2048 2>/dev/null
        fi
        chmod 640 "${SERVER_HOSTNAME}.key" 2>/dev/null || true
        # Idempotent hardening on every run, not just fresh CA creation below
        # -- an install that predates this fix would otherwise keep whatever
        # permissions the process umask happened to leave on the CA key.
        chmod 600 myCA.key 2>/dev/null || true
        cd "$REPO_ROOT"; return 0
    fi

    if [[ -f "${SERVER_HOSTNAME}.key" && $FORCE_SSL -eq 1 ]]; then
        confirm "--force-ssl will OVERWRITE the existing server key for ${SERVER_HOSTNAME} and break trust for enrolled agents. Continue?" \
            || die "SSL rotation aborted by operator"
    fi

    # Certificate Authority (key encrypted with SSL_PASSWORD; only used to sign).
    [[ -n "$SSL_PASSWORD" ]] || die "SSL_PASSWORD is required to create or use the certificate authority. Choose a passphrase and run: SSL_PASSWORD=<passphrase> $0 ${COMMAND:-deploy} ..."
    # Needed only when we are (re)issuing a server cert below.
    if [[ ! -f "myCA.pem" || ! -f "myCA.key" ]]; then
        log_info "Creating CA"
        openssl genrsa -des3 -passout pass:"${SSL_PASSWORD}" -out myCA.key 2048 2>/dev/null
        openssl req -x509 -new -nodes -key myCA.key -passin pass:"${SSL_PASSWORD}" \
            -sha256 -days 3650 -out myCA.pem \
            -subj "/C=${CERT_COUNTRY}/ST=${CERT_STATE}/L=${CERT_LOCALITY}/O=${CERT_ORG}/OU=${CERT_OU}/CN=VajraCA" 2>/dev/null
        # This key can mint certificates the whole enrolled fleet will trust
        # -- restrict it immediately, the same way the server key already is,
        # rather than leaving it at the process umask default (commonly
        # world-readable).
        chmod 600 myCA.key
    fi

    # Server key (UNENCRYPTED — boost::asio loads it without a passphrase)
    log_info "Creating server key + CSR for ${SERVER_HOSTNAME}"
    openssl genrsa -out "${SERVER_HOSTNAME}.key" 2048 2>/dev/null
    openssl req -new -key "${SERVER_HOSTNAME}.key" -out "${SERVER_HOSTNAME}.csr" \
        -subj "/C=${CERT_COUNTRY}/ST=${CERT_STATE}/L=${CERT_LOCALITY}/O=${CERT_ORG}/OU=${CERT_OU}/CN=${SERVER_HOSTNAME}" 2>/dev/null

    # SAN extension: IP or DNS depending on how identity resolved
    if [[ "$SAN_MODE" == "ip" ]]; then
        cat > "${SERVER_HOSTNAME}.ext" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
subjectAltName=IP:${SERVER_HOSTNAME}
EOF
    else
        cat > "${SERVER_HOSTNAME}.ext" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
subjectAltName=DNS:${SERVER_HOSTNAME}
EOF
    fi

    log_info "Signing server certificate (825 days)"
    openssl x509 -req -in "${SERVER_HOSTNAME}.csr" -CA myCA.pem -CAkey myCA.key \
        -passin pass:"${SSL_PASSWORD}" -CAcreateserial -out "${SERVER_HOSTNAME}.crt" \
        -days 825 -sha256 -extfile "${SERVER_HOSTNAME}.ext" 2>/dev/null

    if [[ ! -f "dh.pem" ]]; then
        log_info "Generating DH params (2048-bit; this is slow)"
        openssl dhparam -out dh.pem 2048 2>/dev/null
    fi

    chmod 640 "${SERVER_HOSTNAME}.key"
    rm -f "${SERVER_HOSTNAME}.csr" "${SERVER_HOSTNAME}.ext"
    cd "$REPO_ROOT"
    log_ok "Certificates ready in ${SSL_DIR}"
}

# --------------------------------------------------------------------------
# config.json patching (JSON-safe via python3; sed fallback for cert paths)
# --------------------------------------------------------------------------
patch_config() {
    log_step "Updating config.json"
    local cfg="${REPO_ROOT}/config.json"
    # config.json holds live credentials and is deliberately .gitignore'd --
    # a genuinely fresh checkout (e.g. a fresh scp'd deploy) never has one,
    # only config.template.json. Seed it here, the same COPYONLY fallback
    # CMakeLists.txt already does for BUILD_DIR/config.json, so a first-ever
    # deploy doesn't die before it even gets a chance to patch anything.
    if [[ ! -f "$cfg" ]]; then
        local tmpl="${REPO_ROOT}/config.template.json"
        [[ -f "$tmpl" ]] || die "neither config.json nor config.template.json found at $REPO_ROOT"
        log_info "config.json not found — seeding it from config.template.json"
        cp -f "$tmpl" "$cfg"
    fi
    # Keep the FIRST backup pristine; don't overwrite it with an already-patched
    # copy on subsequent runs.
    [[ -f "${cfg}.backup" ]] || cp -f "$cfg" "${cfg}.backup"

    if need_cmd python3; then
        local secret_file="${REPO_ROOT}/enrollment_secret.txt"
        local patch_out
        patch_out="$(SERVER_HOSTNAME="$SERVER_HOSTNAME" SERVER_IP="$SERVER_IP" \
            DB_PASS="$DB_PASS" DB_USER="$DB_USER" DB_HOST="$DB_HOST" \
            DB_PORT="$DB_PORT" KAFKA_BOOTSTRAP="$KAFKA_BOOTSTRAP" \
            VAJRA_VERBOSE="$VERBOSE" \
            python3 - "$cfg" "$secret_file" <<'PY'
import json, os, secrets, sys
path = sys.argv[1]
secret_out_path = sys.argv[2]
with open(path) as f:
    cfg = json.load(f)
host = os.environ["SERVER_HOSTNAME"]
ip   = os.environ["SERVER_IP"]
verbose = os.environ.get("VAJRA_VERBOSE") == "1"
state = {"generated_secret": None}

def walk(node):
    if isinstance(node, dict):
        # cert/key paths -> current host
        if "ssl_certificate" in node:
            node["ssl_certificate"] = f"../ssl/{host}.crt"
        if "ssl_private_key" in node:
            node["ssl_private_key"] = f"../ssl/{host}.key"
        if "dh_key" in node:
            node["dh_key"] = "../ssl/dh.pem"
        # DB credentials -> keep all app roles in sync with the created role
        if node is not cfg and set(node.keys()) >= {"username", "database_name"}:
            node["username"] = os.environ["DB_USER"]
            node["password"] = os.environ["DB_PASS"]
            node["hostname"] = os.environ["DB_HOST"]
            node["port"]     = int(os.environ["DB_PORT"])
        # Kafka bootstrap -> local broker
        if "bootstrap_servers" in node:
            node["bootstrap_servers"] = os.environ["KAFKA_BOOTSTRAP"]
        # VA-server placeholder hostname -> deploy identity (matches legacy
        # unified_deploy_auto.sh, which uses SERVER_HOSTNAME so it tracks the
        # cert CN/SAN in domain mode).
        if node.get("hostname") == "server's IP":
            node["hostname"] = host
        # Enrollment secret: only replace the shipped template placeholder,
        # never an operator-set value (including on a re-run after the first
        # deploy) -- this must stay stable once agents start enrolling with
        # it. config.template.json has this placeholder in TWO places
        # (fleet_server.node_configuration -- the live one enroll() actually
        # validates against -- and nodejs_user_server.node_configuration,
        # the dead Node.js API server's own config section); generate the
        # value once and reuse it for every occurrence, so the file written
        # out below always matches what fleet_server actually checks,
        # instead of each occurrence getting its own independent random
        # value.
        if node.get("enrollment_secret") == "CHANGE_ME_ENROLLMENT_SECRET":
            if state["generated_secret"] is None:
                state["generated_secret"] = secrets.token_hex(32)  # 256 bits
            node["enrollment_secret"] = state["generated_secret"]
        # -v/--verbose/--debug on the vajra.sh invocation -> debug-level app
        # logging, so a troubleshooting run doesn't also require hand-editing
        # config.json.
        if verbose and "log_level" in node:
            node["log_level"] = "debug"
        for v in node.values():
            walk(v)
    elif isinstance(node, list):
        for v in node:
            walk(v)

walk(cfg)
with open(path, "w") as f:
    json.dump(cfg, f, indent=2)
    f.write("\n")

if state["generated_secret"]:
    with open(secret_out_path, "w") as f:
        f.write(state["generated_secret"] + "\n")
    os.chmod(secret_out_path, 0o600)
    print(f"GENERATED_ENROLLMENT_SECRET_FILE={secret_out_path}")
PY
        )"
        if [[ "$patch_out" == *"GENERATED_ENROLLMENT_SECRET_FILE="* ]]; then
            log_ok "Generated a new enrollment_secret (config.json had the template placeholder)"
            log_ok "Saved to ${secret_file} (chmod 600) -- configure osquery agents with:"
            log_ok "  --enroll_secret_path=${secret_file}"
        fi
        log_ok "config.json patched (certs, DB creds, kafka bootstrap)"
    else
        sed -i "s|\"ssl_certificate\": \"../ssl/[^\"]*\"|\"ssl_certificate\": \"../ssl/${SERVER_HOSTNAME}.crt\"|g" "$cfg"
        sed -i "s|\"ssl_private_key\": \"../ssl/[^\"]*\"|\"ssl_private_key\": \"../ssl/${SERVER_HOSTNAME}.key\"|g" "$cfg"
        log_warn "python3 missing — patched cert paths via sed only (DB creds unchanged)"
    fi
    # The build runs from BUILD_DIR with a co-located config.json copy.
    cp -f "$cfg" "${BUILD_DIR}/config.json"
}

# --------------------------------------------------------------------------
# PostgreSQL: role + database + schema + migrations
# --------------------------------------------------------------------------
setup_db() {
    [[ $SKIP_DB -eq 1 ]] && { log_info "Skipping DB (--skip-db)"; return 0; }
    log_step "PostgreSQL setup"
    need_cmd psql || die "postgresql client not installed"

    $SUDO systemctl enable --now postgresql 2>/dev/null || $SUDO service postgresql start || true

    # Role
    if ! $SUDO -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='${DB_USER}'" | grep -q 1; then
        log_info "Creating role ${DB_USER}"
        $SUDO -u postgres psql -c \
          "CREATE ROLE ${DB_USER} LOGIN PASSWORD '${DB_PASS}';" || die "role creation failed"
    else
        log_info "Role ${DB_USER} exists — ensuring password matches config"
        $SUDO -u postgres psql -c "ALTER ROLE ${DB_USER} WITH LOGIN PASSWORD '${DB_PASS}';" || true
    fi

    # Database
    if ! $SUDO -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'" | grep -q 1; then
        log_info "Creating database ${DB_NAME}"
        $SUDO -u postgres psql -c "CREATE DATABASE ${DB_NAME} OWNER ${DB_USER};" || die "db creation failed"
    else
        log_info "Database ${DB_NAME} exists"
    fi
    $SUDO -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${DB_USER};" >/dev/null 2>&1 || true

    # Raise connection ceiling to accommodate the pool at fleet scale
    $SUDO -u postgres psql -c "ALTER SYSTEM SET max_connections = 1000;" >/dev/null 2>&1 || true
    $SUDO systemctl restart postgresql 2>/dev/null || $SUDO service postgresql restart || true

    apply_schema
    run_migrations
    log_ok "Database ready"
}

apply_schema() {
    local schema="${SQL_DIR}/schema.sql"
    [[ -f "$schema" ]] || die "schema not found: $schema"
    log_info "Applying schema.sql"
    PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
        -v ON_ERROR_STOP=0 -q -f "$schema" >/dev/null 2>&1 || \
        log_warn "schema.sql reported errors (often pre-existing objects) — continuing"
    # Apply the numbered supplemental SQL files (indexes, add-column/add-table
    # patches) in order. They are idempotent (IF NOT EXISTS / additive) so this
    # is safe to re-run; ON_ERROR_STOP=0 skips already-applied objects. This is
    # what previously never ran under deploy.sh, leaving e.g.
    # blocked_host_identifiers absent (now also folded into schema.sql).
    shopt -s nullglob
    for f in "${SQL_DIR}"/0[0-9]_*.sql; do
        log_info "Applying $(basename "$f")"
        PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
            -v ON_ERROR_STOP=0 -q -f "$f" >/dev/null 2>&1 || \
            log_warn "$(basename "$f") reported errors (often pre-existing objects) — continuing"
    done
    shopt -u nullglob
    local tcount
    tcount=$(PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
        -tAc "SELECT count(*) FROM information_schema.tables WHERE table_schema='public';" 2>/dev/null || echo "?")
    log_info "Public tables present: ${tcount}"
}

run_migrations() {
    local runner="${REPO_ROOT}/scripts/migrate.sh"
    [[ -f "$runner" ]] || { log_warn "migrate.sh missing — skipping versioned migrations"; return 0; }
    log_info "Applying versioned migrations (sql/migrations/*)"
    PGHOST="$DB_HOST" PGPORT="$DB_PORT" PGUSER="$DB_USER" \
    PGDATABASE="$DB_NAME" PGPASSWORD="$DB_PASS" bash "$runner" || \
        log_warn "migration runner reported an error — review with: $0 migrate --status"
}

# --------------------------------------------------------------------------
# Kafka install / configure (KRaft)
# --------------------------------------------------------------------------
kafka_config_file() {
    for c in "config/kraft/server.properties" "config/kraft/broker.properties" "config/server.properties"; do
        [[ -f "${KAFKA_DIR}/${c}" ]] && { echo "${KAFKA_DIR}/${c}"; return 0; }
    done
    return 1
}

setup_kafka() {
    [[ $SKIP_KAFKA -eq 1 ]] && { log_info "Skipping Kafka (--skip-kafka)"; return 0; }
    log_step "Kafka (KRaft) setup"

    if [[ ! -d "$KAFKA_DIR" ]]; then
        local tgz="kafka_${KAFKA_SCALA}-${KAFKA_VERSION}.tgz"
        log_info "Downloading ${tgz}"
        wget -q "https://downloads.apache.org/kafka/${KAFKA_VERSION}/${tgz}" -O "/tmp/${tgz}" \
            || wget -q "https://archive.apache.org/dist/kafka/${KAFKA_VERSION}/${tgz}" -O "/tmp/${tgz}" \
            || die "Kafka download failed"
        tar -xzf "/tmp/${tgz}" -C "$HOME"
        rm -f "/tmp/${tgz}"
    else
        log_info "Kafka already present at ${KAFKA_DIR}"
    fi

    local cfg; cfg="$(kafka_config_file)" || die "no Kafka config file found under ${KAFKA_DIR}"
    cp -f "$cfg" "${cfg}.backup" 2>/dev/null || true
    # Persistent log dir (never /tmp) + advertise the reachable IP
    sed -i "s|^log.dirs=.*|log.dirs=${KAFKA_DATA}|" "$cfg"
    if grep -q "^advertised.listeners=" "$cfg"; then
        sed -i "s|^advertised.listeners=.*|advertised.listeners=PLAINTEXT://${SERVER_IP}:${KAFKA_PORT}|" "$cfg"
    else
        echo "advertised.listeners=PLAINTEXT://${SERVER_IP}:${KAFKA_PORT}" >> "$cfg"
    fi
    if grep -q "^listeners=" "$cfg"; then
        sed -i "s|^listeners=PLAINTEXT://[^,]*|listeners=PLAINTEXT://0.0.0.0:${KAFKA_PORT}|" "$cfg"
    fi

    # Format KRaft storage once
    if [[ ! -f "${KAFKA_DATA}/meta.properties" ]]; then
        log_info "Formatting KRaft storage"
        local kid
        kid="$("${KAFKA_DIR}/bin/kafka-storage.sh" random-uuid)"
        "${KAFKA_DIR}/bin/kafka-storage.sh" format -t "$kid" -c "$cfg" --standalone >/dev/null 2>&1 \
            || "${KAFKA_DIR}/bin/kafka-storage.sh" format -t "$kid" -c "$cfg" >/dev/null 2>&1 \
            || die "KRaft format failed"
    fi
    log_ok "Kafka configured (config: ${cfg})"
}

kafka_running() {
    "${KAFKA_DIR}/bin/kafka-broker-api-versions.sh" --bootstrap-server "$KAFKA_BOOTSTRAP" >/dev/null 2>&1
}

kafka_wait_ready() {
    local attempts="${1:-8}" i=1
    while [[ $i -le $attempts ]]; do
        kafka_running && { log_ok "Kafka is ready"; return 0; }
        log_info "Waiting for Kafka ($i/$attempts)…"; sleep 8; i=$((i+1))
    done
    return 1
}

kafka_start_transient() {
    # Start broker in the background just long enough to create topics.
    local cfg; cfg="$(kafka_config_file)" || die "kafka config missing"
    if kafka_running; then STARTED_TRANSIENT=0; return 0; fi
    log_info "Starting Kafka broker (transient)"
    KAFKA_HEAP_OPTS="-Xmx512m -Xms256m" JAVA_HOME="${JAVA_HOME:-}" \
        nohup "${KAFKA_DIR}/bin/kafka-server-start.sh" "$cfg" > /tmp/kafka-server.log 2>&1 &
    STARTED_TRANSIENT=1
    kafka_wait_ready 8 || die "Kafka failed to become ready (see /tmp/kafka-server.log)"
}

create_topics() {
    log_step "Kafka topics"
    [[ -d "$KAFKA_DIR" ]] || { log_warn "Kafka not installed — skipping topics"; return 0; }
    local STARTED_TRANSIENT=0
    kafka_start_transient
    for t in "${KAFKA_TOPICS[@]}"; do
        log_info "Ensuring topic ${t}"
        "${KAFKA_DIR}/bin/kafka-topics.sh" --bootstrap-server "$KAFKA_BOOTSTRAP" \
            --create --if-not-exists --topic "$t" \
            --partitions "$KAFKA_PARTITIONS" --replication-factor "$KAFKA_RF" \
            --config "retention.ms=${KAFKA_RETENTION_MS}" \
            --config "compression.type=snappy" \
            --config "max.message.bytes=${KAFKA_MAX_MSG_BYTES}" >/dev/null 2>&1 \
            || log_warn "could not create/verify topic ${t}"
    done
    for t in "${KAFKA_DLQ_TOPICS[@]}"; do
        log_info "Ensuring DLQ topic ${t}"
        "${KAFKA_DIR}/bin/kafka-topics.sh" --bootstrap-server "$KAFKA_BOOTSTRAP" \
            --create --if-not-exists --topic "$t" \
            --partitions "$KAFKA_PARTITIONS" --replication-factor "$KAFKA_RF" \
            --config "retention.ms=${KAFKA_DLQ_RETENTION_MS}" \
            --config "compression.type=snappy" \
            --config "max.message.bytes=${KAFKA_MAX_MSG_BYTES}" >/dev/null 2>&1 \
            || log_warn "could not create/verify topic ${t}"
    done
    "${KAFKA_DIR}/bin/kafka-topics.sh" --bootstrap-server "$KAFKA_BOOTSTRAP" --list 2>/dev/null \
        | grep -E "vajra_" || true
    if [[ "$STARTED_TRANSIENT" == "1" ]]; then
        log_info "Stopping transient Kafka (will be managed by service)"
        pkill -f "kafka.Kafka" 2>/dev/null || true
        sleep 3
    fi
    log_ok "Topics ensured"
}

# --------------------------------------------------------------------------
# Build
# --------------------------------------------------------------------------
# The build links a static libpqxx built with C++20 into 3rdparty/local (the distro package is C++17
# and does not link). It is not stored in this repository, so fetch and build it once.
PQXX_VERSION="${PQXX_VERSION:-7.8.1}"
ensure_vendored_pqxx() {
    [[ -f "${REPO_ROOT}/3rdparty/local/lib/libpqxx.a" ]] && return 0
    log_step "Vendored libpqxx ${PQXX_VERSION}"
    need_cmd curl || die "curl not installed"
    need_cmd tar  || die "tar not installed"
    mkdir -p "${REPO_ROOT}/3rdparty"
    local tgz; tgz="$(mktemp)"
    curl -fsSL "https://github.com/jtv/libpqxx/archive/refs/tags/${PQXX_VERSION}.tar.gz" -o "$tgz" \
        || { rm -f "$tgz"; die "could not download libpqxx ${PQXX_VERSION}"; }
    tar -xzf "$tgz" -C "${REPO_ROOT}/3rdparty" || { rm -f "$tgz"; die "could not unpack libpqxx"; }
    rm -f "$tgz"
    bash "${REPO_ROOT}/scripts/bootstrap_deps_pqxx.sh" || die "building libpqxx failed"
    [[ -f "${REPO_ROOT}/3rdparty/local/lib/libpqxx.a" ]] || die "libpqxx.a was not produced"
    log_ok "libpqxx built into 3rdparty/local"
}

build() {
    [[ $SKIP_BUILD -eq 1 ]] && { log_info "Skipping build (--skip-build)"; return 0; }
    log_step "Build"
    need_cmd cmake || die "cmake not installed"
    make_dirs
    ensure_vendored_pqxx
    cp -f "${REPO_ROOT}/config.json" "${BUILD_DIR}/config.json" 2>/dev/null || true

    # Drop a stale cache that points at a different source tree
    if [[ -f "${BUILD_DIR}/CMakeCache.txt" ]] && \
       ! grep -q "${REPO_ROOT}" "${BUILD_DIR}/CMakeCache.txt" 2>/dev/null; then
        log_warn "Stale CMake cache detected — clearing"
        rm -f "${BUILD_DIR}/CMakeCache.txt"
    fi

    cd "$BUILD_DIR"
    cmake .. -DCMAKE_BUILD_TYPE=Release >/dev/null || die "cmake configure failed"

    # vajra_server is the deployed service — its build MUST succeed.
    log_info "Compiling vajra_server (required)"
    make -j"$(nproc)" vajra_server || die "vajra_server build failed"


    if [[ $WITH_RULE_BUILDER -eq 1 ]]; then
        log_info "Compiling rule_builder (required — --with-rule-builder)"
        make -j"$(nproc)" rule_builder || die "rule_builder build failed"
    fi


    # Everything else (event_processor, rule_builder when not
    # requested, tests) is not part of the deployed
    # default architecture; build it best-effort so the tree stays complete
    # without blocking deploy. This is also what makes `restart rule_engine` /
    # `restart rule_builder` "just work" later even on a run that didn't
    # pass --with-rule-builder: the binary is already there.
    log_info "Compiling optional components (best-effort)"
    make -j"$(nproc)" >/dev/null 2>&1 || \
        log_warn "optional components failed to build — not required, continuing"

    cd "$REPO_ROOT"
    [[ -x "${BUILD_DIR}/vajra_server" ]] || die "vajra_server binary missing after build"
    log_ok "Build complete ($(du -h "${BUILD_DIR}/vajra_server" | cut -f1) vajra_server)"
}

# build_rule_engine -- configures/builds engine_v2 as its own standalone
# CMake project (see engine_v2/CMakeLists.txt's header comment for why it's
# separate from the root build() above). Only runs when --with-rule-engine
# is passed; a fresh checkout without that flag never touches engine_v2 at
# all, matching every other opt-in component's posture in this script.
build_rule_engine() {
    [[ $WITH_RULE_ENGINE -eq 1 ]] || return 0
    [[ $SKIP_BUILD -eq 1 ]] && { log_info "Skipping rule engine build (--skip-build)"; return 0; }
    log_step "Build (rule engine v2)"
    need_cmd cmake || die "cmake not installed"
    [[ -d "$RULE_ENGINE_DIR" ]] || die "engine_v2 not found at ${RULE_ENGINE_DIR}"

    ensure_vendored_pqxx

    cmake -S "$RULE_ENGINE_DIR" -B "$RULE_ENGINE_BUILD_DIR" -DCMAKE_BUILD_TYPE=Release >/dev/null \
        || die "engine_v2 cmake configure failed"

    log_info "Compiling vajra_engine_v2 (required — --with-rule-engine)"
    cmake --build "$RULE_ENGINE_BUILD_DIR" -j"$(nproc)" --target vajra_engine_v2 \
        || die "vajra_engine_v2 build failed"

    # Offline eval tool: not part of the deployed service, best-effort only.
    cmake --build "$RULE_ENGINE_BUILD_DIR" -j"$(nproc)" --target vajra_engine_v2_eval >/dev/null 2>&1 \
        || log_warn "vajra_engine_v2_eval failed to build — not required, continuing"

    [[ -x "${RULE_ENGINE_BUILD_DIR}/vajra_engine_v2" ]] || die "vajra_engine_v2 binary missing after build"
    log_ok "Rule engine v2 build complete ($(du -h "${RULE_ENGINE_BUILD_DIR}/vajra_engine_v2" | cut -f1) vajra_engine_v2)"
}

# setup_rule_engine_data -- applies engine_v2's own incidents/incident_alerts
# schema additively (IF NOT EXISTS-style, safe to re-run) and reports the
# ruleset that will be loaded. Gated by --skip-db like every other DB step.
setup_rule_engine_data() {
    [[ $WITH_RULE_ENGINE -eq 1 ]] || return 0
    [[ $SKIP_DB -eq 1 ]] && { log_info "Skipping rule engine schema (--skip-db)"; return 0; }
    log_step "Rule engine v2 data setup"

    if need_cmd python3 && [[ -f "$RULE_ENGINE_RULESET" ]]; then
        local rc
        rc="$(python3 -c "import json;print(len(json.load(open('${RULE_ENGINE_RULESET}')).get('rules', [])))" 2>/dev/null || echo "?")"
        log_info "Ruleset: ${RULE_ENGINE_RULESET} (${rc} rules)"
    else
        log_warn "Ruleset not found at ${RULE_ENGINE_RULESET} — vajra_engine_v2 will fall back to its builtin set"
    fi

    local schema="${RULE_ENGINE_DIR}/schema/incidents.sql"
    if [[ -f "$schema" ]]; then
        log_info "Applying engine_v2/schema/incidents.sql"
        PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
            -v ON_ERROR_STOP=0 -q -f "$schema" >/dev/null 2>&1 || \
            log_warn "incidents.sql reported errors (often pre-existing objects) — continuing"
    else
        log_warn "engine_v2/schema/incidents.sql not found — skipping incidents schema"
    fi
    log_ok "Rule engine v2 data ready"
}

# --------------------------------------------------------------------------
# systemd units
# --------------------------------------------------------------------------
SYSTEMD_DIR="/etc/systemd/system"

write_unit() {
    # write_unit <name> <content>
    local name="$1"; shift
    echo "$*" | $SUDO tee "${SYSTEMD_DIR}/${name}" >/dev/null
}

write_unit_kafka() {
    local cfg; cfg="$(kafka_config_file 2>/dev/null || echo "${KAFKA_DIR}/config/kraft/server.properties")"
    local jhome="${JAVA_HOME:-/usr/lib/jvm/java-17-openjdk-amd64}"
    write_unit "vajra_kafka.service" "[Unit]
Description=Vajra Kafka (KRaft) broker
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Environment=JAVA_HOME=${jhome}
Environment=\"KAFKA_HEAP_OPTS=-Xmx1g -Xms512m\"
ExecStart=${KAFKA_DIR}/bin/kafka-server-start.sh ${cfg}
ExecStop=${KAFKA_DIR}/bin/kafka-server-stop.sh
Restart=on-failure
RestartSec=5
LimitNOFILE=100000

[Install]
WantedBy=multi-user.target"
}

write_unit_server() {
    local kafka_ready="${KAFKA_DIR}/bin/kafka-broker-api-versions.sh --bootstrap-server ${KAFKA_BOOTSTRAP}"
    write_unit "vajra_server.service" "[Unit]
Description=Vajra Fleet Server
After=network-online.target postgresql.service vajra_kafka.service
Wants=network-online.target
Requires=postgresql.service

[Service]
Type=simple
User=${SERVICE_USER}
WorkingDirectory=${BUILD_DIR}
ExecStartPre=/bin/bash -c 'for i in \$(seq 1 30); do ${kafka_ready} >/dev/null 2>&1 && exit 0; sleep 2; done; exit 0'
ExecStart=${BUILD_DIR}/vajra_server
Restart=on-failure
RestartSec=5
LimitNOFILE=100000
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=read-only
ReadWritePaths=${LOG_DIR}

[Install]
WantedBy=multi-user.target"
}

write_unit_processor() {
    write_unit "vajra_event_processor.service" "[Unit]
Description=Vajra Event Processor
After=vajra_kafka.service postgresql.service
Requires=postgresql.service

[Service]
Type=simple
User=${SERVICE_USER}
WorkingDirectory=${BUILD_DIR}
ExecStart=${BUILD_DIR}/event_processor
Restart=on-failure
RestartSec=5
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target"
}

write_unit_rule_engine() {
    local kafka_ready="${KAFKA_DIR}/bin/kafka-broker-api-versions.sh --bootstrap-server ${KAFKA_BOOTSTRAP}"
    write_unit "vajra_engine_v2.service" "[Unit]
Description=Vajra Rule Engine v2 (correlation engine)
After=network-online.target postgresql.service vajra_kafka.service
Wants=network-online.target
Requires=postgresql.service

[Service]
Type=simple
User=${SERVICE_USER}
WorkingDirectory=${RULE_ENGINE_BUILD_DIR}
Environment=VAJRA_ENGINE_RULES=${RULE_ENGINE_RULESET}
ExecStartPre=/bin/bash -c 'for i in \$(seq 1 30); do ${kafka_ready} >/dev/null 2>&1 && exit 0; sleep 2; done; exit 0'
ExecStart=${RULE_ENGINE_BUILD_DIR}/vajra_engine_v2 ${BUILD_DIR}/config.json
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5
LimitNOFILE=100000
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=read-only
ReadWritePaths=${LOG_DIR}

[Install]
WantedBy=multi-user.target"
}

# rule_builder needs only Postgres (it reads fleet_server.db_configuration
# via the same ConfigurationParser/config.json every other component uses --
# confirmed by reading rule_builder/main.cpp: no Kafka, no TLS, no separate
# config section). Its own doc comment describes it as a [[noreturn]]
# DB-polling loop -- After=postgresql.service + Requires=postgresql.service
# is the whole dependency story, unlike vajra_server/vajra_engine_v2 which also
# wait on Kafka.
write_unit_rule_builder() {
    write_unit "vajra_rule_builder.service" "[Unit]
Description=Vajra Rule Builder
After=network-online.target postgresql.service
Wants=network-online.target
Requires=postgresql.service

[Service]
Type=simple
User=${SERVICE_USER}
WorkingDirectory=${BUILD_DIR}
ExecStart=${BUILD_DIR}/rule_builder
Restart=on-failure
RestartSec=5
LimitNOFILE=100000
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=read-only
ReadWritePaths=${LOG_DIR}

[Install]
WantedBy=multi-user.target"
}


# install_services [target]
#   target omitted -> default behavior: write/enable every unit
#     implied by this run's flags (kafka+server always, +processor/
#     rule_engine/rule_builder per their --with-* flags).
#   target given (kafka|server|rule_engine|rule_builder) -> write/
#     enable ONLY that one unit. Every other unit file on disk, and every
#     other running service, is left completely untouched.
install_services() {
    local target="${1:-}"

    if [[ -n "$target" ]]; then
        log_step "Installing systemd service (${target} only)"
        init_sudo
        local unit
        unit="$(resolve_unit_name "$target")" || die "Unknown service target '${target}' (expected: kafka|server|rule_engine|rule_builder)"
        case "$target" in
            kafka)          write_unit_kafka ;;
            server|vajra)   write_unit_server ;;
            rule_engine)    write_unit_rule_engine ;;
            rule_builder)   write_unit_rule_builder ;;
            processor)     die "--with-processors is not available: event_processor is not part of this repository." ;;
        esac
        $SUDO systemctl daemon-reload
        $SUDO systemctl enable "${unit}.service" >/dev/null 2>&1 || true
        log_ok "${unit}.service installed & enabled (no other unit touched)"
        return 0
    fi

    log_step "Installing systemd services"
    init_sudo

    write_unit_kafka
    write_unit_server
    if [[ $WITH_PROCESSORS -eq 1 ]]; then
        write_unit_processor
    fi
    if [[ $WITH_RULE_ENGINE -eq 1 ]]; then
        write_unit_rule_engine
    fi
    if [[ $WITH_RULE_BUILDER -eq 1 ]]; then
        write_unit_rule_builder
    fi

    $SUDO systemctl daemon-reload
    $SUDO systemctl enable vajra_kafka.service vajra_server.service >/dev/null 2>&1 || true
    if [[ $WITH_PROCESSORS -eq 1 ]]; then
        $SUDO systemctl enable vajra_event_processor.service >/dev/null 2>&1 || true
    fi
    if [[ $WITH_RULE_ENGINE -eq 1 ]]; then
        $SUDO systemctl enable vajra_engine_v2.service >/dev/null 2>&1 || true
    fi
    if [[ $WITH_RULE_BUILDER -eq 1 ]]; then
        $SUDO systemctl enable vajra_rule_builder.service >/dev/null 2>&1 || true
    fi
    log_ok "systemd units installed & enabled"
}

# --------------------------------------------------------------------------
# start / stop / restart / status
# --------------------------------------------------------------------------
all_units() {
    local u=("vajra_kafka" "vajra_server")
    [[ $WITH_PROCESSORS -eq 1 ]] && u+=("vajra_event_processor")
    [[ $WITH_RULE_ENGINE -eq 1 ]] && u+=("vajra_engine_v2")
    [[ $WITH_RULE_BUILDER -eq 1 ]] && u+=("vajra_rule_builder")
    printf '%s\n' "${u[@]}"
}

# start_services [target] — see install_services()'s doc comment for the
# target-vs-no-target contract. A targeted start auto-installs the unit
# first if it isn't there yet (e.g. the binary already exists from a prior
# best-effort build; this is what turns that into a running service with
# one command and zero effect on anything else already running).
start_services() {
    local target="${1:-}"
    init_sudo
    if [[ $DEV_MODE -eq 1 ]]; then
        start_dev "$target"; return 0
    fi

    if [[ -n "$target" ]]; then
        log_step "Starting service (${target} only)"
        local unit
        unit="$(resolve_unit_name "$target")" || die "Unknown service target '${target}' (expected: kafka|server|rule_engine|rule_builder)"
        if [[ ! -f "${SYSTEMD_DIR}/${unit}.service" ]]; then
            log_info "${unit}.service not installed yet — creating it first"
            install_services "$target"
        fi
        $SUDO systemctl start "${unit}.service" || die "${unit} failed to start"
        if [[ "$target" == "kafka" ]]; then
            kafka_wait_ready 8 || log_warn "Kafka not confirmed ready; continuing"
        fi
        log_ok "${unit}.service started (no other service touched)"
        return 0
    fi

    log_step "Starting services"
    $SUDO systemctl start vajra_kafka.service || die "kafka failed to start"
    kafka_wait_ready 8 || log_warn "Kafka not confirmed ready; continuing"
    $SUDO systemctl start vajra_server.service || die "vajra_server failed to start"
    if [[ $WITH_PROCESSORS -eq 1 ]]; then
        $SUDO systemctl start vajra_event_processor.service 2>/dev/null || log_warn "event_processor start failed"
    fi
    if [[ $WITH_RULE_ENGINE -eq 1 ]]; then
        $SUDO systemctl start vajra_engine_v2.service 2>/dev/null || log_warn "vajra_engine_v2 start failed"
    fi
    if [[ $WITH_RULE_BUILDER -eq 1 ]]; then
        $SUDO systemctl start vajra_rule_builder.service 2>/dev/null || log_warn "rule_builder start failed"
    fi
    log_ok "Services started"
}

# start_dev [target] — --dev (nohup) equivalent of start_services()'s
# target-vs-no-target contract.
start_dev() {
    local target="${1:-}"
    local cfg; cfg="$(kafka_config_file)" || die "kafka config missing"

    if [[ -n "$target" ]]; then
        local logfile=""
        case "$target" in
            kafka)
                logfile="${LOG_DIR}/kafka.log"
                if ! kafka_running; then
                    KAFKA_HEAP_OPTS="-Xmx1g -Xms512m" nohup "${KAFKA_DIR}/bin/kafka-server-start.sh" "$cfg" \
                        > "$logfile" 2>&1 &
                    kafka_wait_ready 8 || log_warn "Kafka not confirmed ready"
                fi ;;
            server|vajra)
                logfile="${LOG_DIR}/vajra_server.log"
                ( cd "$BUILD_DIR" && nohup ./vajra_server > "$logfile" 2>&1 & ) ;;
            rule_engine)
                logfile="${LOG_DIR}/engine_v2.log"
                ( cd "$RULE_ENGINE_BUILD_DIR" && VAJRA_ENGINE_RULES="${RULE_ENGINE_RULESET}" \
                    nohup ./vajra_engine_v2 "${BUILD_DIR}/config.json" > "$logfile" 2>&1 & ) ;;
            rule_builder)
                logfile="${LOG_DIR}/rule_builder.log"
                ( cd "$BUILD_DIR" && nohup ./rule_builder > "$logfile" 2>&1 & ) ;;
            *) die "Unknown service target '${target}' (expected: kafka|server|rule_engine|rule_builder)" ;;
        esac
        sleep 2
        log_ok "Dev service '${target}' launched (log: ${logfile}) — no other dev process touched"
        return 0
    fi

    log_info "Dev mode: launching via nohup"
    if ! kafka_running; then
        KAFKA_HEAP_OPTS="-Xmx1g -Xms512m" nohup "${KAFKA_DIR}/bin/kafka-server-start.sh" "$cfg" \
            > "${LOG_DIR}/kafka.log" 2>&1 &
        kafka_wait_ready 8 || log_warn "Kafka not confirmed ready"
    fi
    ( cd "$BUILD_DIR" && nohup ./vajra_server > "${LOG_DIR}/vajra_server.log" 2>&1 & )
    if [[ $WITH_PROCESSORS -eq 1 ]]; then
        ( cd "$BUILD_DIR" && nohup ./event_processor > "${LOG_DIR}/event_processor.log" 2>&1 & )
    fi
    if [[ $WITH_RULE_ENGINE -eq 1 ]]; then
        ( cd "$RULE_ENGINE_BUILD_DIR" && VAJRA_ENGINE_RULES="${RULE_ENGINE_RULESET}" \
            nohup ./vajra_engine_v2 "${BUILD_DIR}/config.json" > "${LOG_DIR}/engine_v2.log" 2>&1 & )
    fi
    if [[ $WITH_RULE_BUILDER -eq 1 ]]; then
        ( cd "$BUILD_DIR" && nohup ./rule_builder > "${LOG_DIR}/rule_builder.log" 2>&1 & )
    fi
    sleep 2
    log_ok "Dev services launched (logs in ${LOG_DIR})"
}

# stop_services [target] — target stops only that one unit; no target stops
# everything this run's flags cover (default behavior).
stop_services() {
    local target="${1:-}"
    init_sudo

    if [[ -n "$target" ]]; then
        log_step "Stopping service (${target} only)"
        local unit
        unit="$(resolve_unit_name "$target")" || die "Unknown service target '${target}' (expected: kafka|server|rule_engine|rule_builder)"
        $SUDO systemctl stop "${unit}.service" 2>/dev/null || true
        log_ok "${unit}.service stopped (no other service touched)"
        return 0
    fi

    log_step "Stopping services"
    local u
    for u in $(all_units); do
        $SUDO systemctl stop "${u}.service" 2>/dev/null || true
    done
    # Fallback: kill stray nohup processes
    pkill -f "${BUILD_DIR}/vajra_server" 2>/dev/null || true
    pkill -f "${BUILD_DIR}/event_processor" 2>/dev/null || true
    # Anchored with a trailing space (not just "$") since the dev-mode launch
    # passes an explicit config path arg -- "vajra_engine_v2$" would never
    # match "vajra_engine_v2 /path/to/config.json". The trailing space also
    # still can't match vajra_engine_v2_eval (developer tool, same dir).
    pkill -f "${RULE_ENGINE_BUILD_DIR}/vajra_engine_v2 " 2>/dev/null || true
    pkill -f "${BUILD_DIR}/rule_builder\$" 2>/dev/null || true
    pkill -f "kafka_rule_engine" 2>/dev/null || true
    log_ok "Stopped"
}

# restart_services [target] — the main v2 addition: `restart rule_engine` (or
# `restart rule_builder`/`restart kafka`/`restart server`) touches ONLY that
# one systemd unit. Auto-installs the unit first if it doesn't exist yet, so
# "enable vajra_engine_v2 as a service" and "restart just vajra_engine_v2" collapse
# into the single command described in this script's usage header. No target
# = restart the whole fleet, for the whole fleet.
restart_services() {
    local target="${1:-}"
    init_sudo

    if [[ -n "$target" ]]; then
        log_step "Restarting service (${target} only)"
        local unit
        unit="$(resolve_unit_name "$target")" || die "Unknown service target '${target}' (expected: kafka|server|rule_engine|rule_builder)"
        if [[ ! -f "${SYSTEMD_DIR}/${unit}.service" ]]; then
            log_info "${unit}.service not installed yet — creating it first"
            install_services "$target"
        fi
        if ! $SUDO systemctl restart "${unit}.service"; then
            die "Failed to restart ${unit}.service -- run 'sudo -v' first if this is a non-interactive/scripted invocation, or check 'systemctl status ${unit}.service' for the real error."
        fi
        if [[ "$target" == "kafka" ]]; then
            kafka_wait_ready 8 || log_warn "Kafka not confirmed ready"
        fi
        log_ok "${unit}.service restarted — no other service was touched"
        return 0
    fi

    log_step "Restarting services"
    local failed=0

    # Each restart is checked individually (not blanket `|| true`) so a
    # failure -- e.g. sudo needing a password with no TTY to prompt on, a
    # unit file error, the service refusing to start -- is reported instead
    # of silently swallowed.
    if ! $SUDO systemctl restart vajra_kafka.service; then
        log_err "Failed to restart vajra_kafka.service"
        failed=1
    fi
    kafka_wait_ready 8 || log_warn "Kafka not confirmed ready"

    if ! $SUDO systemctl restart vajra_server.service; then
        log_err "Failed to restart vajra_server.service"
        failed=1
    fi
    if [[ $WITH_PROCESSORS -eq 1 ]]; then
        if ! $SUDO systemctl restart vajra_event_processor.service; then
            log_err "Failed to restart vajra_event_processor.service"
            failed=1
        fi
    fi
    if [[ $WITH_RULE_ENGINE -eq 1 ]]; then
        if ! $SUDO systemctl restart vajra_engine_v2.service; then
            log_err "Failed to restart vajra_engine_v2.service"
            failed=1
        fi
    fi
    if [[ $WITH_RULE_BUILDER -eq 1 ]]; then
        if ! $SUDO systemctl restart vajra_rule_builder.service; then
            log_err "Failed to restart vajra_rule_builder.service"
            failed=1
        fi
    fi

    if [[ $failed -eq 1 ]]; then
        die "One or more services failed to restart (see above) -- run 'sudo -v' first if this is a non-interactive/scripted invocation, or check 'systemctl status <service>' for the real error."
    fi
    log_ok "Restarted"
}

# reload_engine [target] -- SIGHUP hot-reloads the vajra_engine_v2 ruleset in
# place (rules + decoders re-read from disk; on parse failure the previous
# ruleset stays active). Does NOT restart the process or drop its Kafka
# consumer group, unlike `restart`. Errors if the rule engine isn't enabled.
reload_engine() {
    local target="${1:-}"

    if [[ -n "$target" && "$target" != "rule_engine" ]]; then
        die "Unknown reload target '${target}' (expected: rule_engine)"
    fi
    if [[ $WITH_RULE_ENGINE -ne 1 ]]; then
        log_err "vajra_engine_v2 is not enabled (rerun with --with-rule-engine)"
        exit 1
    fi

    local did_any=0
    log_step "Reloading vajra_engine_v2 ruleset"
    if [[ $DEV_MODE -eq 1 ]]; then
        # Trailing-space anchor: dev mode launches with an explicit config
        # path arg, so "vajra_engine_v2$" would never match.
        if pkill -HUP -f "${RULE_ENGINE_BUILD_DIR}/vajra_engine_v2 " 2>/dev/null; then
            log_ok "Sent SIGHUP to vajra_engine_v2"; did_any=1
        else
            log_err "No running vajra_engine_v2 process found"
        fi
    else
        init_sudo
        if $SUDO systemctl reload vajra_engine_v2.service; then
            log_ok "Reloaded vajra_engine_v2"; did_any=1
        else
            log_err "vajra_engine_v2 reload failed"
        fi
    fi

    [[ $did_any -eq 1 ]] || exit 1
}

status_services() {
    log_step "Status"
    # Union of flag-implied units and anything actually installed on disk --
    # a service enabled by a PAST --with-rule-engine/--with-rule-builder run must
    # still show up in `status` even when this invocation didn't repeat that
    # flag (flags only need to be passed once, at enable time; status is
    # read-only so it can afford to be maximally informative rather than
    # mirroring this run's flags exactly the way stop/restart's no-target
    # path deliberately does).
    local units=()
    while IFS= read -r name; do units+=("$name"); done < <(all_units)
    local f
    for f in "${SYSTEMD_DIR}"/vajra_*.service; do
        [[ -f "$f" ]] || continue
        local base; base="$(basename "$f" .service)"
        local already=0 existing
        for existing in "${units[@]}"; do
            [[ "$existing" == "$base" ]] && { already=1; break; }
        done
        [[ $already -eq 0 ]] && units+=("$base")
    done
    local u
    for u in "${units[@]}"; do
        local st; st=$(systemctl is-active "${u}.service" 2>/dev/null || echo "unknown")
        printf "  %-26s %s\n" "$u" "$st"
    done
    echo
    log_info "Listening ports:"
    ss -tlnp 2>/dev/null | grep -E ":(${FLEET_PORT}|${KAFKA_PORT})\b" || echo "  (none of ${FLEET_PORT}/${KAFKA_PORT} listening)"
}

show_logs() {
    local svc="${1:-vajra_server}"
    case "$svc" in
        kafka)            svc="vajra_kafka" ;;
        server|vajra)     svc="vajra_server" ;;
        event_processor)  svc="vajra_event_processor" ;;
        rule_engine|rule-engine|engine_v2|engine-v2) svc="vajra_engine_v2" ;;
        rule_builder)     svc="vajra_rule_builder" ;;
        vajra_*)          ;;
        *)                svc="vajra_server" ;;
    esac
    if systemctl list-units --all 2>/dev/null | grep -q "${svc}.service"; then
        journalctl -u "${svc}.service" -n 200 -f
    else
        local f="${LOG_DIR}/${svc#vajra_}.log"
        [[ -f "$f" ]] || f="${LOG_DIR}/vajra_server.log"
        log_info "Tailing ${f}"; tail -n 200 -f "$f"
    fi
}

# --------------------------------------------------------------------------
# Verify / health
# --------------------------------------------------------------------------
verify() {
    log_step "Verification"
    local ok=0 fail=0
    _chk() { if eval "$2" >/dev/null 2>&1; then log_ok "$1"; ok=$((ok+1)); else log_err "$1"; fail=$((fail+1)); fi; }

    _chk "vajra_server binary present"      "test -x '${BUILD_DIR}/vajra_server'"
    _chk "certificate present"              "test -f '${SSL_DIR}/${SERVER_HOSTNAME}.crt'"
    _chk "PostgreSQL reachable"             "PGPASSWORD='${DB_PASS}' pg_isready -h '${DB_HOST}' -p '${DB_PORT}' -U '${DB_USER}'"
    _chk "database '${DB_NAME}' has tables" "test \"\$(PGPASSWORD='${DB_PASS}' psql -h '${DB_HOST}' -p '${DB_PORT}' -U '${DB_USER}' -d '${DB_NAME}' -tAc \"SELECT count(*) FROM information_schema.tables WHERE table_schema='public'\")\" -gt 0"
    _chk "Kafka broker responding"          "kafka_running"
    _chk "fleet port ${FLEET_PORT} listening" "ss -tln | grep -q ':${FLEET_PORT}\b'"
    _chk "Kafka port ${KAFKA_PORT} listening"  "ss -tln | grep -q ':${KAFKA_PORT}\b'"
    # /health endpoint over TLS (self-signed -> -k)
    _chk "/health responds"                 "curl -sk --max-time 5 https://localhost:${FLEET_PORT}/health"
    if [[ $WITH_RULE_ENGINE -eq 1 ]]; then
        _chk "vajra_engine_v2.service active" "systemctl is-active --quiet vajra_engine_v2.service"
    fi
    if [[ $WITH_RULE_BUILDER -eq 1 ]]; then
        _chk "vajra_rule_builder.service active" "systemctl is-active --quiet vajra_rule_builder.service"
    fi

    echo
    if [[ $fail -eq 0 ]]; then
        log_ok "All ${ok} checks passed"
    else
        log_warn "${ok} passed, ${fail} failed — inspect with: $0 logs ; $0 status"
    fi
    return 0
}

# --------------------------------------------------------------------------
# Retention
# --------------------------------------------------------------------------
retention() {
    log_step "Retention cleanup"
    local r="${REPO_ROOT}/scripts/retention_cleanup.sh"
    [[ -f "$r" ]] || die "scripts/retention_cleanup.sh not found"
    PGHOST="$DB_HOST" PGPORT="$DB_PORT" PGUSER="$DB_USER" \
    PGDATABASE="$DB_NAME" PGPASSWORD="$DB_PASS" bash "$r" "$@"
}

# --------------------------------------------------------------------------
# Uninstall
# --------------------------------------------------------------------------
uninstall() {
    log_step "Uninstall"
    init_sudo
    stop_services
    local u
    # Disabling/removing a unit that was never installed (e.g. vajra_engine_v2
    # when --with-rule-engine was never used) is a harmless no-op, so this list is
    # unconditionally exhaustive rather than gated on this invocation's flags.
    for u in vajra_kafka vajra_server vajra_event_processor vajra_engine_v2 vajra_rule_builder; do
        $SUDO systemctl disable "${u}.service" 2>/dev/null || true
        $SUDO rm -f "${SYSTEMD_DIR}/${u}.service"
    done
    $SUDO systemctl daemon-reload 2>/dev/null || true
    log_ok "systemd units removed"
    if [[ $PURGE -eq 1 ]]; then
        if confirm "PURGE requested — drop database '${DB_NAME}', Kafka topics and certs?"; then
            $SUDO -u postgres psql -c "DROP DATABASE IF EXISTS ${DB_NAME};" 2>/dev/null || true
            for t in "${KAFKA_TOPICS[@]}" "${KAFKA_DLQ_TOPICS[@]}"; do
                "${KAFKA_DIR}/bin/kafka-topics.sh" --bootstrap-server "$KAFKA_BOOTSTRAP" --delete --topic "$t" 2>/dev/null || true
            done
            rm -f "${SSL_DIR}/${SERVER_HOSTNAME}."{crt,key} 2>/dev/null || true
            log_ok "Purged database, topics and certs"
        fi
    fi
}

# --------------------------------------------------------------------------
# Full deploy
# --------------------------------------------------------------------------
deploy() {
    preflight
    install_deps
    make_dirs
    gen_ssl
    setup_db
    setup_kafka
    create_topics
    patch_config
    build
    build_rule_engine
    setup_rule_engine_data
    if [[ $DEV_MODE -eq 1 ]]; then
        start_services
    else
        install_services
        start_services
    fi
    sleep 3
    verify || true
    print_summary
}

print_summary() {
    log_step "Deployment summary"
    cat <<EOF
  Server host   : ${SERVER_HOSTNAME}  (IP ${SERVER_IP})
  Fleet TLS     : https://${SERVER_HOSTNAME}:${FLEET_PORT}
  Database      : ${DB_USER}@${DB_HOST}:${DB_PORT}/${DB_NAME}
  Kafka         : ${KAFKA_BOOTSTRAP}   topics: ${KAFKA_TOPICS[*]} ${KAFKA_DLQ_TOPICS[*]}
  Certificates  : ${SSL_DIR}/${SERVER_HOSTNAME}.{crt,key}, dh.pem, myCA.pem
  Binary        : ${BUILD_DIR}/vajra_server
  Rule engine v2: $([[ $WITH_RULE_ENGINE -eq 1 ]] && echo "vajra_engine_v2 (enabled)" || echo "not started (opt in with --with-rule-engine, or run: $0 restart rule_engine)")
  Rule builder  : $([[ $WITH_RULE_BUILDER -eq 1 ]] && echo "rule_builder (enabled)" || echo "not started (opt in with --with-rule-builder, or run: $0 restart rule_builder)")

  Manage:   $0 status | $0 logs [name] | $0 restart [kafka|server|rule_engine|rule_builder] | $0 stop [target]
  Verify:   $0 verify
EOF
    echo
    log_warn "Firewall: allow ${FLEET_PORT}/tcp (agents) and ${KAFKA_PORT}/tcp if remote consumers exist."
    log_ok "Done."
}

# --------------------------------------------------------------------------
# Argument parsing
# --------------------------------------------------------------------------
usage() { sed -n '2,120p' "$0" | sed 's/^# \{0,1\}//'; }

parse_args() {
    COMMAND="${1:-help}"; shift || true
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -d|--domain)        DOMAIN="$2"; shift 2 ;;
            -y|--yes)           ASSUME_YES=1; shift ;;
            -v|--verbose|--debug) VERBOSE=1; shift ;;
            --dev)              DEV_MODE=1; shift ;;
            --with-processors)  die "--with-processors is not available: event_processor is not part of this repository." ;;
            --with-rule-engine) WITH_RULE_ENGINE=1; shift ;;
            --with-rule-builder) WITH_RULE_BUILDER=1; shift ;;
            --force-ssl)        FORCE_SSL=1; shift ;;
            --skip-deps)        SKIP_DEPS=1; shift ;;
            --skip-ssl)         SKIP_SSL=1; shift ;;
            --skip-db)          SKIP_DB=1; shift ;;
            --skip-kafka)       SKIP_KAFKA=1; shift ;;
            --skip-build)       SKIP_BUILD=1; shift ;;
            --purge)            PURGE=1; shift ;;
            --dry-run)          RETENTION_ARGS+=("--dry-run"); shift ;;
            --status)           MIGRATE_STATUS=1; shift ;;
            *)                  EXTRA_ARGS+=("$1"); shift ;;
        esac
    done
}

# --------------------------------------------------------------------------
# Main dispatch
# --------------------------------------------------------------------------
RETENTION_ARGS=()
EXTRA_ARGS=()
MIGRATE_STATUS=0

main() {
    parse_args "$@"
    if [[ $VERBOSE -eq 1 ]]; then
        log_info "Verbose mode: tracing every command (bash -x) and requesting debug-level app logging"
        set -x
    fi
    case "$COMMAND" in
        deploy)            deploy ;;
        build)              preflight; build; build_rule_engine ;;
        ssl)                preflight; gen_ssl ;;
        db-init)            preflight; setup_db; setup_rule_engine_data ;;
        migrate)
            resolve_identity
            if [[ $MIGRATE_STATUS -eq 1 ]]; then
                PGHOST="$DB_HOST" PGPORT="$DB_PORT" PGUSER="$DB_USER" \
                PGDATABASE="$DB_NAME" PGPASSWORD="$DB_PASS" bash "${REPO_ROOT}/scripts/migrate.sh" --status
            else
                run_migrations
            fi ;;
        kafka-setup)        preflight; setup_kafka ;;
        kafka-topics)       resolve_identity; create_topics ;;
        install-services)   preflight; install_services "${EXTRA_ARGS[0]:-}" ;;
        start)               resolve_identity; start_services "${EXTRA_ARGS[0]:-}" ;;
        stop)                 resolve_identity; stop_services "${EXTRA_ARGS[0]:-}" ;;
        restart)              resolve_identity; restart_services "${EXTRA_ARGS[0]:-}" ;;
        reload)              resolve_identity; reload_engine "${EXTRA_ARGS[0]:-}" ;;
        status)              status_services ;;
        logs)                show_logs "${EXTRA_ARGS[0]:-vajra_server}" ;;
        verify)              resolve_identity; verify ;;
        retention)           resolve_identity; retention "${RETENTION_ARGS[@]}" ;;
        uninstall)           resolve_identity; uninstall ;;
        help|-h|--help)      usage ;;
        *)                   log_err "Unknown command: $COMMAND"; echo; usage; exit 1 ;;
    esac
}

main "$@"
