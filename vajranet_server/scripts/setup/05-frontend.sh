#!/usr/bin/env bash
# Step 5: build the frontend and copy it to /var/www/<FULL_DOMAIN> for nginx.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_vars FULL_DOMAIN
WEBROOT="${WEBROOT:-/var/www/${FULL_DOMAIN}}"

cd "$REPO_ROOT/frontend" || handle_error "frontend directory not found"

# Backend address and agent download links baked into the build. The download links are relative:
# they inherit the scheme, host and port of the page, so they cannot be mixed content.
cat > .env <<ENV
VITE_API_BASE_URL=http://${FULL_DOMAIN}:4000
VITE_DEPLOYMENT_MODE=on_prem
VITE_WINDOWS_AGENT_INSTALLER_URL=/windows_agent.zip
VITE_LINUX_AGENT_INSTALLER_URL=/linux_agent.zip
ENV

npm install || handle_error "Frontend npm install failed"
npm run build || handle_error "Frontend build failed"

sudo mkdir -p "$WEBROOT"
sudo cp -r dist/* "$WEBROOT/" || handle_error "Failed to copy the build to $WEBROOT"
sudo chown -R "$SERVICE_USER:$SERVICE_USER" "$WEBROOT"

log_step "Frontend built into $WEBROOT"
