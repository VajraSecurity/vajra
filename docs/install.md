# Install Vajra

There are two ways to run the server. Both give you the same result: the C++ server and detection
engine, the web console and API, and Linux and Windows agent packages that already point at this
machine (or at the address you give).

| | Docker | Script (no Docker) |
|---|---|---|
| Needs | Docker with the Compose plugin | Ubuntu or Debian with sudo |
| Start | `./docker/init-env.sh` then `docker compose up -d --build` | `./install.sh` |
| Web console | `http://ADDRESS:8080` | `http://ADDRESS:8080` |
| Agent downloads | `http://ADDRESS:8080/downloads/linux_agent.zip` and `.../windows_agent.zip` | `http://ADDRESS:8080/linux_agent.zip` and `.../windows_agent.zip` |
| Remove everything | `./docker/cleanup.sh` | `./uninstall.sh` |

> [!CAUTION]
> Use one option per machine. Both use the same ports (8080, 4000 and 1234), so running both on
> one machine makes them collide, and you may end up looking at the other one's console. Remove one
> (see [Uninstall](uninstall.md)) before you use the other.

## Address and ports

`ADDRESS` is this machine's first IP address by default. To use another address or a host name,
pass it in: `./docker/init-env.sh my-host.lan` or `./install.sh --host my-host.lan`.

Agents on other machines need these ports open on the server:

| Port | Used for |
|---|---|
| 1234 | osquery enrollment and telemetry (TLS) |
| 4000 | API and the agent extension's WebSocket |
| 8080 | Web console and agent downloads |

## Option 1: Docker

```bash
./docker/init-env.sh              # writes .env with random secrets and this machine's IP
docker compose up -d --build      # the first build takes a while (it compiles the C++ server)
docker compose ps                 # wait until backend and frontend are healthy
./docker/create-admin.sh          # creates the first admin and prints its one-time password
```

Open `http://ADDRESS:8080` and sign in.

You can change the ports in `.env` with `WEB_PORT`, `API_PORT` and `FLEET_PORT`. If you change
`PUBLIC_HOST` later, run `docker compose up -d --build` again so the console and the agent
packages are rebuilt for the new address.

### Day-to-day commands

| Task | Command |
|---|---|
| Start (first time, or after a change) | `docker compose up -d --build` |
| Start again after a stop | `docker compose start` |
| Stop, keep all data | `docker compose stop` |
| Status | `docker compose ps` |
| Follow logs | `docker compose logs -f backend vajra-server vajra-engine` |
| See what the agent packaging did | `docker compose logs agents` |
| Delete the containers, keep the data | `docker compose down` |

## Option 2: Script

```bash
./install.sh                      # installs everything with sudo; prints the URLs at the end
./install.sh --host 10.0.0.5      # the same, with an address you choose
```

The script installs PostgreSQL, Redis, Kafka, nginx and Node.js. It then:

- builds and starts the C++ server and the detection engine
- builds the console
- creates the first admin. The one-time password is printed and saved in `admin-credentials.txt`.
- builds the agent packages

Settings and generated passwords are kept in `.install.env`, so it is safe to run the script
again.

The steps are numbered scripts in `vajranet_server/scripts/setup/`. To repeat one, pass its number:
for example, `vajranet_server/scripts/service.sh setup 10` rebuilds the agent packages. The two
optional steps are Grafana dashboards (`INSTALL_GRAFANA=1`) and the CVE engine
(`CVE_ENGINE_REPO_URL`). Both are skipped unless you set those variables.

### Day-to-day commands

| Task | Command |
|---|---|
| Start, stop or restart all services | `./install.sh start`, `stop` or `restart` |
| Status | `./install.sh status` |
| Logs | `journalctl -u vajra-backend -u vajra_server -u vajra_engine_v2 -f` |

## Next steps

- [Add endpoints](agents.md)
- [Harden for production](production.md)
- [Troubleshooting](troubleshooting.md)
