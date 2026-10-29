# Vajranet Server

Vajranet Server is the management plane for the Vajra endpoint security platform. It gives you a web console and an API to monitor, assess and manage a fleet of hosts running the Vajra agent.

It is one of three open-source components:

| Component | Purpose |
|---|---|
| **Vajranet Server** (this repo) | Web UI (React) and API (Node.js/Express) |
| **Linux agent** | Collects telemetry from hosts and executes server-issued tasks |
| **Vajra C++ server** | Companion server component |

> Remote shell access is not part of the open-source edition.

## What is in this repository

```
backend/    Node.js + TypeScript API, WebSocket channels (/ws/ui, /ws/ext, /ws/live), SQL migrations
frontend/   React + Vite + TypeScript web console
grafana/    Grafana config, provisioned datasources and dashboards
scripts/    service.sh and setup/ (install and run the stack)
deploy/nginx/ Reverse-proxy templates for HTTPS and plain-HTTP deployments
```

## Requirements

- Node.js 22.15+ (backend) and 20.19+ (frontend)
- PostgreSQL (application database plus the fleet/osquery database)
- Redis
- nginx
- Grafana (optional, for dashboards)

## Quick start (development)

```bash
git clone <this-repo-url> vajranet_server
cd vajranet_server

# Backend
cd backend
cp .env.example .env     # fill in database, JWT secrets, etc.
npm install
npm run dev

# Frontend (in a second terminal)
cd frontend
cp .env.example .env
npm install
npm run dev
```

The backend listens on `PORT` (default `4000`). `backend/.env.example` documents every variable. At minimum, set the two Postgres connections (`PG_*` and `PG_*1`), `ACCESS_JWT_SECRET`, `REFRESH_JWT_SECRET`, and Redis.

## Install and run locally

`scripts/service.sh setup` installs everything on one Ubuntu/Debian machine by running the steps in `scripts/setup/` in order: dependencies, PostgreSQL, the Vajra C++ server (from the `vajra_server` repo), the Node.js backend as a systemd service, the frontend, nginx, a health check, the extra SQL for the fleet database, the first admin user, the agent download zips, and optional Grafana and CVE engine steps. Nothing is fetched from outside services: the certificate authority and enrollment secret are generated on your machine, and the agents are packaged to point at it. Clone `vajra_server`, `linux_agent` and `windows_agent` next to this repo first (or set `VAJRA_SERVER_DIR`, `LINUX_AGENT_DIR`, `WINDOWS_AGENT_DIR`). Settings come from environment variables:

```bash
DB_PASSWORD=change-me FULL_DOMAIN=vajra.local IP_ADDRESS=10.0.0.5 \
USER_NAME=Admin USER_EMAIL=admin@example.com USER_MOBILE=9999999999 \
USER_COMPANY=Acme USER_ADDRESS=Mumbai \
scripts/service.sh setup
```

- This is a local, plain-HTTP setup (backend in development mode, nginx on port 8080, change it with `WEB_PORT`). Production hardening is up to you: a public domain, TLS certificates, `NODE_ENV=production` and HTTPS. `deploy/nginx/nginx-https.conf.example` is a starting point.
- Run one step with its number, for example `scripts/service.sh setup 04`.
- The first admin gets a random one-time password, printed once at the end.
- Agents download from `http://<FULL_DOMAIN>/linux_agent.zip` and `/windows_agent.zip`. Each zip points at this machine (osquery on port 1234, the backend on port 4000) and carries this machine's certificate and enrollment secret.
- The CVE engine step is skipped unless you set `CVE_ENGINE_REPO_URL`. Its API keys (`NVD_API_KEY`, `SENDGRID_API_KEY`, ...) come from the environment.
- The Grafana step is skipped unless you set `INSTALL_GRAFANA=1`. It runs `grafana/setup.sh`, which needs a database superuser; the step grants that to the `vajra` role only while it runs.
- The backend runs in development mode, so it creates its own tables on first start; step 8 adds the fleet database's extra columns, indexes and triggers.

Day to day, `scripts/service.sh` starts, stops, restarts and checks the services (postgres, redis, grafana, backend, nginx):

```bash
scripts/service.sh status
scripts/service.sh restart backend
```

To update an install, pull the latest code and re-run `scripts/service.sh setup 04` (backend) and `setup 05` (frontend), which keeps the existing `backend/.env`. A `backend/Dockerfile` and `frontend/Dockerfile` are also provided. For development, `scripts/service.sh dev start` runs `npm run dev` for the backend and frontend as background processes (`dev status`, `dev stop`; stop the backend service first so port 4000 is free).

Set `ON_PREM` (backend) and `VITE_DEPLOYMENT_MODE` (frontend) to choose between on-prem mode, which enables the Network Security features, and cloud mode, which disables them.

## Not included

- **FIM worker (`vajra_fim`).** The File Integrity page stores policies, baselines and alerts, but the worker that scans hosts is a separate component that is not part of these repositories.
- **Rule engine console.** `/api/rule-engine/*` and the Rule Engine pages forward to a separate console (`RULE_ENGINE_API_URL`) that is not published here. The detection engine itself is in `vajra_server/engine_v2`.

## Connecting agents

Agents connect to the backend over WebSocket (`/ws/ext`). `AGENT_MTLS_MODE` (default `off`) controls whether agents must present a client certificate; see `backend/.env.example`. See the Linux agent repository for installing and enrolling the agent.

## File Integrity Monitoring

- Set `FIM_HISTORY_HMAC_KEY` (at least 32 characters) before enabling per-node registry coverage. Without it the registry feature is disabled: its write endpoints return 503 and the UI shows a banner. The rest of the backend keeps running. Key rotation uses `FIM_HISTORY_HMAC_KEY_ID` and `FIM_HISTORY_HMAC_PREVIOUS_KEYS` (a JSON object).
- The backend applies the FIM schema on boot, skipping blocks it has already applied, and takes the shared DDL lock `727299`.
- All `FIM_*` variables and their defaults are listed in `backend/.env.example`.
- For least-privilege deployments, apply the FIM migrations with an owner role and give the backend role only DML privileges. If a migration is missing, the backend reports "FIM migration required" instead of failing.
- DB selftests: `FIM_TEST_PG=host:port npm run test:fim-all` in `backend/`. Each process creates and drops its own throwaway database. Set `FIM_TEST_DB` to use a prepared one instead.

## Testing

```bash
cd backend && npm test
cd frontend && npm run lint
```

The CI workflow in `.github/workflows/ci.yml` runs the same checks.

## Related repositories

- `vajra_server`: the C++ server and detection engine
- `linux_agent` and `windows_agent`: the agents

Clone them next to this repository (the setup steps and the root `docker-compose.yml` expect that). Replace this list with the real repository links when they are published.

## Contributing

Issues and pull requests are welcome. Please keep changes focused, run the linters and tests before submitting, and never commit `.env` files, keys or certificates.

## Security

Please report vulnerabilities privately to the maintainers rather than opening a public issue. Do not expose the backend directly to the internet without TLS and agent mTLS enabled.

## License

MIT. See the `LICENSE` file. Third-party components keep their own licenses.
