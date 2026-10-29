#!/usr/bin/env bash
# Step 6: install the plain-HTTP nginx site from deploy/nginx/ and reload nginx.
# This is a local setup: HTTPS, public domains and certificates are up to whoever
# runs a production deployment (see deploy/nginx/nginx-https.conf.example).
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_vars FULL_DOMAIN
SITE="/etc/nginx/sites-available/${FULL_DOMAIN}"

sed "s|YOUR_DOMAIN|${FULL_DOMAIN}|g; s|listen 8080;|listen ${WEB_PORT};|" "$REPO_ROOT/deploy/nginx/nginx-http.conf.example" \
  | sudo tee "$SITE" >/dev/null
sudo ln -sf "$SITE" "/etc/nginx/sites-enabled/${FULL_DOMAIN}"
sudo rm -f /etc/nginx/sites-enabled/default

sudo nginx -t || handle_error "nginx configuration test failed"
sudo systemctl enable nginx
sudo systemctl restart nginx || handle_error "nginx restart failed"

log_step "nginx serving http://${FULL_DOMAIN}:${WEB_PORT}"
