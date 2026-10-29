#!/usr/bin/env bash
# Step 7: wait until the backend answers on /health.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

for i in $(seq 1 30); do
  if body="$(curl -sf http://localhost:4000/health)"; then
    echo "Backend is healthy: $body"
    log_step "Backend health verified"
    exit 0
  fi
  sleep 1
done

echo "Last backend log lines:" >&2
sudo tail -n 30 /var/log/vajra-backend.log >&2 || true
handle_error "Backend did not answer on /health within 30 seconds"
