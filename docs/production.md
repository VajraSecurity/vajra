# Production hardening

The default setup is for one machine on a trusted network:

- The console (port 8080) and the API (port 4000) use plain HTTP.
- The backend runs with `NODE_ENV=development`.
- Agents connect to the C++ server over TLS on port 1234, using the CA that setup generates.

Before you expose Vajra to a network you don't trust, work through this list. It is a checklist,
not a complete guide. Test each change on your own setup.

## 1. A real address

Give the server a stable DNS name and set it as `PUBLIC_HOST` (Docker) or `--host` (script). Then
rebuild so the console and the agent packages use it. Agent packages built for the old address
have to be reinstalled.

## 2. HTTPS for the console and API

- Put nginx (or another reverse proxy) with a real certificate in front of the console and the
  API. `vajranet_server/deploy/nginx/nginx-https.conf.example` is a starting point.
- Run the backend with `NODE_ENV=production`. In production mode the backend refuses to start
  unless `SSL_KEY_PATH` and `SSL_CERT_PATH` are set, and it sends `Strict-Transport-Security`.

## 3. Agent mTLS on the WebSocket

`AGENT_MTLS_MODE` controls whether agent extensions must present a client certificate on the
backend WebSocket. It is `off` by default. Set it to `required` once your agents have
certificates. If agents connect through nginx, also set `AGENT_MTLS_INTERNAL_SECRET`. All the
settings are documented in `vajranet_server/backend/.env.example`.

## 4. Network exposure

- Only ports 1234, 4000 and 8080 (or 443 behind your proxy) need to be reachable by agents and
  users.
- Keep PostgreSQL, Redis and Kafka off public interfaces.

## 5. Secrets and backups

- `.env` (Docker) or `.install.env` (script) holds the database password, JWT secrets and the
  enrollment secret. Keep it out of version control and back it up somewhere safe.
- Delete `admin-credentials.txt` after the first sign-in, change the admin password and enable MFA.
- Back up PostgreSQL. In Docker its data is in the `pgdata` volume.

## Reporting problems

If you find a security issue while hardening, report it privately as described in
[SECURITY.md](../SECURITY.md).
