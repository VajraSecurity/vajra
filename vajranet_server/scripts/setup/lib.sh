# Shared helpers for the setup steps. Source this file; do not run it.

set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

SETUP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SETUP_DIR/../.." && pwd)"     # the vajranet_server checkout
SERVICE_USER="${SERVICE_USER:-$(id -un)}"        # user the backend service runs as
WEB_PORT="${WEB_PORT:-8080}"                     # port nginx serves the web console on (same as the Docker setup)

handle_error() { echo "ERROR: $1" >&2; exit 1; }

log_step() { echo; echo "==== DONE: $1 ===="; echo; }

# ensure_repo DIR URL NAME : make sure a sibling repo (vajra_server, linux_agent, ...) is
# at DIR. If it is missing, clone URL when one is given, otherwise stop with a hint.
ensure_repo() {
  local dir="$1" url="$2" name="$3"
  [ -d "$dir" ] && return 0
  [ -n "$url" ] || handle_error "$name not found at $dir. Clone it there, or set its *_DIR / *_REPO_URL variable."
  git clone "$url" "$dir" || handle_error "Cloning $name failed"
}

# require_vars VAR... : stop if any of the named environment variables is empty.
require_vars() {
  local v
  for v in "$@"; do
    [ -n "${!v:-}" ] || handle_error "Missing required environment variable: $v"
  done
}
