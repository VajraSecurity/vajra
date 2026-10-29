#!/usr/bin/env bash
# Removes everything the Docker setup created: containers, networks, volumes (all data), the
# images built here, and .env. Public images (postgres, redis, kafka, alpine) are removed only if
# they were not on this machine before docker/init-env.sh ran (it saved a list in
# .docker-images-before).
#
#   ./docker/cleanup.sh [--yes] [--keep-env]
set -uo pipefail
cd "$(dirname "$0")/.."

YES=0; KEEP_ENV=0
for a in "$@"; do
  case "$a" in --yes|-y) YES=1 ;; --keep-env) KEEP_ENV=1 ;; *) sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 1 ;; esac
done
echo "This deletes the Vajra containers, ALL their data (volumes) and the images built here."
if [ "$YES" != 1 ]; then read -r -p "Continue? [y/N] " r; [[ "$r" =~ ^[Yy]$ ]] || { echo "Cancelled."; exit 0; }; fi

# compose needs the variables to parse the file even when only removing; dummies are fine.
export DB_PASSWORD="${DB_PASSWORD:-x}" SSL_PASSWORD="${SSL_PASSWORD:-x}" ENROLLMENT_SECRET="${ENROLLMENT_SECRET:-x}" \
       ACCESS_JWT_SECRET="${ACCESS_JWT_SECRET:-x}" REFRESH_JWT_SECRET="${REFRESH_JWT_SECRET:-x}" NESSUS_ENCRYPTION_KEY="${NESSUS_ENCRYPTION_KEY:-x}"
docker compose down -v --remove-orphans

# Images built by this project.
docker image rm vajra/server:local vajra/backend:local vajra/frontend:local 2>/dev/null || true

# Public images pulled for this project: remove only those that were not here before.
for img in postgres:16 redis:7-alpine apache/kafka:3.8.0 alpine:3.20; do
  if [ -f .docker-images-before ] && ! grep -qx "$img" .docker-images-before; then
    docker image rm "$img" 2>/dev/null || true   # fails harmlessly if another container uses it
  fi
done

rm -f .docker-images-before
[ "$KEEP_ENV" = 1 ] || rm -f .env
echo "Done. Vajra's Docker containers, volumes and images are removed."
