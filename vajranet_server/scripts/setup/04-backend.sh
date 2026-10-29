#!/usr/bin/env bash
# Step 4: build the backend, write backend/.env, start Redis and install the
# backend as the systemd service "vajra-backend".
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_vars DB_PASSWORD FULL_DOMAIN IP_ADDRESS

BACKEND_DIR="$REPO_ROOT/backend"
cd "$BACKEND_DIR" || handle_error "backend directory not found"

# ---- Build ----
npm install || handle_error "Backend npm install failed"
npm run build || handle_error "Backend build failed"
[ -f dist/index.js ] || handle_error "Build did not produce dist/index.js"

# ---- backend/.env ----
# An existing .env is kept, so re-running does not reset secrets or log everyone out.
# Set FORCE_ENV=1 to overwrite it.
if [ -f .env ] && [ "${FORCE_ENV:-0}" != 1 ]; then
  echo ".env already exists, keeping it (FORCE_ENV=1 to overwrite)"
  # The one thing that must follow the console's address: the backend only accepts requests
  # from FRONTEND_URL (CORS). Update it in place so a changed WEB_PORT does not need a new .env.
  sed -i "s|^FRONTEND_URL=.*|FRONTEND_URL=http://${FULL_DOMAIN}:${WEB_PORT}|; s|^BACKEND_URL=.*|BACKEND_URL=http://${FULL_DOMAIN}:${WEB_PORT}/api|" .env
else
  cat > .env <<ENV
PG_HOST=localhost
PG_PORT=5432
POSTGRES_USER=vajra
POSTGRES_PASSWORD=${DB_PASSWORD}
POSTGRES_DB=vajra_db

# Fleet database (created by 03-cpp-server.sh, same 'vajra' role and password)
PG_HOST1=localhost
PG_PORT1=5432
POSTGRES_USER1=vajra
POSTGRES_PASSWORD1=${DB_PASSWORD}
POSTGRES_DB1=fleet

PORT=4000
NODE_ENV=development

JWT_SECRET=$(openssl rand -hex 32)
ACCESS_JWT_SECRET=$(openssl rand -hex 32)
REFRESH_JWT_SECRET=$(openssl rand -hex 32)
ACCESS_JWT_EXPIRATION=120m
REFRESH_JWT_EXPIRATION=7d
CSRF_TOKEN_STRATEGY=UUID
CSRF_COOKIE_NAME=XSRF-TOKEN
CSRF_HEADER_NAME=X-XSRF-TOKEN
ACCESS_TOKEN_MAX_AGE_MS=7200000
REFRESH_TOKEN_MAX_AGE_MS=604800000

FRONTEND_URL=http://${FULL_DOMAIN}:${WEB_PORT}
BACKEND_URL=http://${FULL_DOMAIN}:${WEB_PORT}/api
LOGIN_MAX_FAILED_ATTEMPTS=5
LOGIN_CAPTCHA_EXPIRY_MS=300000
MAX_USER_COUNT=${MAX_USER_COUNT:-1000}

REDIS_HOST=localhost
REDIS_PORT=6379

RATE_LIMIT_LOGIN_WINDOW_MS=900000
RATE_LIMIT_LOGIN_MAX_ATTEMPTS=5
RATE_LIMIT_REGISTRATION_WINDOW_MS=900000
RATE_LIMIT_REGISTRATION_MAX_ATTEMPTS=10
RATE_LIMIT_LOGOUT_WINDOW_MS=900000
RATE_LIMIT_LOGOUT_MAX_ATTEMPTS=20

WS_NODE_STATUS_INTERVAL=5000
WS_ONLINE_THRESHOLD=10
WS_ALERT_BROADCAST_INTERVAL=10000
WS_ALERT_RESET_INTERVAL=360000
WS_ENABLED=false

HOST_IP=${IP_ADDRESS}
ENV
  chmod 600 .env
fi

# ---- Redis (the backend needs it) ----
sudo systemctl enable --now redis-server || handle_error "Redis start failed"
for i in $(seq 1 30); do
  redis-cli -h 127.0.0.1 -p 6379 ping 2>/dev/null | grep -q PONG && break
  [ "$i" -eq 30 ] && handle_error "Redis did not answer within 30 seconds"
  sleep 1
done

# ---- systemd service ----
sudo touch /var/log/vajra-backend.log
sudo chown "$SERVICE_USER:$SERVICE_USER" /var/log/vajra-backend.log

sudo tee /etc/systemd/system/vajra-backend.service >/dev/null <<UNIT
[Unit]
Description=Vajra Backend
After=network.target postgresql.service redis-server.service
Wants=postgresql.service redis-server.service

[Service]
Type=simple
User=${SERVICE_USER}
WorkingDirectory=${BACKEND_DIR}
Environment=NODE_ENV=development
ExecStart=$(command -v npm) start
Restart=always
RestartSec=10
StandardOutput=append:/var/log/vajra-backend.log
StandardError=append:/var/log/vajra-backend.log
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable --now vajra-backend.service || handle_error "vajra-backend failed to start (see: journalctl -u vajra-backend)"
sudo systemctl restart vajra-backend.service || handle_error "vajra-backend failed to restart (see: journalctl -u vajra-backend)"   # picks up a changed .env / new build on re-runs

log_step "Backend built and running as vajra-backend.service"
