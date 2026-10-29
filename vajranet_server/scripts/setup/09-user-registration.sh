#!/usr/bin/env bash
# Step 9: create the first admin account with a random one-time password.
# The password is printed once; the user must change it at first login.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_vars USER_NAME USER_EMAIL USER_MOBILE USER_COMPANY USER_ADDRESS

PASSWORD="$(openssl rand -hex 8)Aa1!"   # random, and meets the strong-password rule

payload="$(jq -n --arg name "$USER_NAME" --arg email "$USER_EMAIL" --arg pw "$PASSWORD" \
  --arg mob "$USER_MOBILE" --arg comp "$USER_COMPANY" --arg addr "$USER_ADDRESS" \
  '{name:$name, email:$email, password:$pw, passwordConfirm:$pw, mobile:$mob,
    company:$comp, address:$addr, role:"Super Administrator", forcePasswordChange:true}')"

status="$(curl -s -o /tmp/vajra_register.json -w '%{http_code}' -X POST \
  http://localhost:4000/api/auth/user_register -H 'Content-Type: application/json' -d "$payload")"

if [ "$status" -ge 200 ] && [ "$status" -lt 300 ]; then
  echo "Admin account created: $USER_EMAIL"
  echo "One-time password:     $PASSWORD   (change it at first login)"
else
  cat /tmp/vajra_register.json; echo
  handle_error "Admin registration failed (HTTP $status)"
fi

log_step "Admin user registered"
