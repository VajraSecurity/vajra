#!/usr/bin/env bash
# Step 0: check that every variable the later steps need is set.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# DB_PASSWORD   password for the 'vajra' Postgres role
# FULL_DOMAIN   host name users open in the browser, e.g. vajra.example.com
# IP_ADDRESS    public/LAN IP of this machine
# USER_*        details of the first admin account
require_vars DB_PASSWORD FULL_DOMAIN IP_ADDRESS \
             USER_NAME USER_EMAIL USER_MOBILE USER_COMPANY USER_ADDRESS

log_step "Environment validated"
