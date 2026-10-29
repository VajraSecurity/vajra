#!/usr/bin/env bash
# Step 1: install Node.js, nginx, PostgreSQL, Redis and the tools the steps use.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

APT="sudo apt-get -o DPkg::Lock::Timeout=60"   # wait up to 60s for another apt run

$APT update || handle_error "apt-get update failed"
curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo bash - || handle_error "NodeSource setup failed"

$APT install -y nodejs nginx postgresql postgresql-contrib redis-server redis-tools \
  build-essential git curl ca-certificates jq openssl \
  || handle_error "apt-get install failed"

log_step "System dependencies installed"
