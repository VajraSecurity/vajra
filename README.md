# Vajra

Vajra is an open-source endpoint security platform: agents for Linux and Windows collect
telemetry with osquery, a C++ server ingests it and runs a detection engine, and a web console
shows hosts, alerts, compliance, vulnerabilities and file integrity.

| Folder | What it is |
|---|---|
| `vajranet_server/` | Web console (React) and API (Node.js) |
| `vajra_server/` | C++ server that agents enroll with, and the detection engine |
| `linux_agent/` | Linux agent |
| `windows_agent/` | Windows agent |

## Two ways to run it

Both give you the same result: the C++ server and detection engine, the web console and API, and
Linux and Windows agent packages that already point at this machine (or at the address you give).
Everything is plain HTTP on one machine; production hardening is up to you.

| | Docker | Script (no Docker) |
|---|---|---|
| Needs | Docker with the Compose plugin | Ubuntu/Debian with sudo |
| Start | `./docker/init-env.sh` then `docker compose up -d --build` | `./install.sh` |
| Web console | `http://ADDRESS:8080` | `http://ADDRESS:8080` |
| Agent downloads | `http://ADDRESS:8080/downloads/linux_agent.zip` and `.../windows_agent.zip` | `http://ADDRESS:8080/linux_agent.zip` and `.../windows_agent.zip` |
| Stop / start | `docker compose stop` / `docker compose start` | `./install.sh stop` / `./install.sh start` |
| Remove everything | `./docker/cleanup.sh` | `./uninstall.sh` |

**Use one option per machine at a time.** Docker and the script install use the same ports (8080 for the console, 4000, 1234), so running both on one machine makes them collide and you may be looking at the other one's console. Remove one (`./docker/cleanup.sh` or `./uninstall.sh`) before using the other.

`ADDRESS` is this machine's IP by default. To use another address or a host name, pass it:
`./docker/init-env.sh my-host.lan` or `./install.sh --host my-host.lan`. Agents on other machines
need ports 1234 (osquery), 4000 (extension WebSocket) and 8080 (console and downloads) open.

### Option 1: Docker

```bash
./docker/init-env.sh              # writes .env with random secrets and this machine's IP
docker compose up -d --build      # the first build takes a while (it compiles the C++ server)
docker compose ps                 # wait until backend and frontend are healthy
./docker/create-admin.sh          # creates the first admin and prints its one-time password
```

Open `http://ADDRESS:8080` and sign in. Ports can be changed in `.env` (`WEB_PORT`, `API_PORT`,
`FLEET_PORT`). If you change `PUBLIC_HOST` later, run `docker compose up -d --build` again so the
console and the agent packages are rebuilt for the new address.

### Option 2: Script

```bash
./install.sh                      # installs everything with sudo; prints the URLs at the end
./install.sh --host 10.0.0.5      # same, with an address you choose
```

It installs PostgreSQL, Redis, Kafka, nginx and Node.js, builds and starts the C++ server and
engine, builds the console, creates the first admin (the one-time password is printed and saved
in `admin-credentials.txt`) and builds the agent packages. Settings and generated passwords are
kept in `.install.env`, so running it again is safe. Afterwards use `./install.sh status`, `stop`,
`start` or `restart`. The individual steps are in `vajranet_server/scripts/setup/`.

### Install an agent

Download the package for the machine from the console (sidebar) or with the links above, unzip it,
then:

- **Linux:** `sudo ./vajra_install.sh -install` inside `linux_agent/`.
- **Windows:** run `vajra_install.bat` as administrator inside `windows_agent\`.

The package already contains the server address, the CA certificate and the enrollment secret.
The machine appears in the console within a minute or two; telemetry and alerts follow.

The Linux package also needs the Vajra extension, which is not stored in this repository. Either
copy your build to `linux_agent/common/extension.ext`, or set `EXTENSION_URL` and `EXTENSION_SHA256`
in `.env` (Docker) or in the environment of `./install.sh` (script). The packager downloads the
file, checks the checksum and adds it to `linux_agent.zip`; a file that does not match is not used.
Then rebuild the packages: `docker compose up -d --force-recreate agents`, or
`vajranet_server/scripts/service.sh setup 10`. `osqueryd` is downloaded the same way automatically.

## Start, stop and remove

### Docker

| Task | Command |
|---|---|
| Start (first time, or after a change) | `docker compose up -d --build` |
| Start again after a stop | `docker compose start` |
| Stop, keep all data | `docker compose stop` |
| Status | `docker compose ps` |
| Follow logs | `docker compose logs -f backend vajra-server vajra-engine` |
| What the agent packaging did | `docker compose logs agents` |
| Stop and delete the containers, keep the data | `docker compose down` |
| **Remove everything** (containers, all data, built images, `.env`) | `./docker/cleanup.sh` |

`./docker/cleanup.sh` asks before it deletes. It removes the public images (postgres, redis,
kafka, alpine) only if they were not on your machine before `./docker/init-env.sh` ran; images you
already had stay. `--yes` skips the question and `--keep-env` keeps `.env`.

### Script

| Task | Command |
|---|---|
| Start / stop / restart all services | `./install.sh start` / `stop` / `restart` |
| Status | `./install.sh status` |
| Logs | `journalctl -u vajra-backend -u vajra_server -u vajra_engine_v2 -f` |
| **Remove everything** | `./uninstall.sh` |

`./uninstall.sh` stops and removes the Vajra services, drops the `vajra_db` and `fleet` databases
and the `vajra` database role, and deletes the nginx site, web files, build output, certificates,
generated keys, `.install.env` and `admin-credentials.txt`.

Packages are treated carefully. Before it changes anything `./install.sh` saves a list of the
packages already on the machine (`.install-snapshot/`). `./uninstall.sh` can remove only packages from
a fixed list of what Vajra installs (PostgreSQL, Redis, nginx, Node.js, the build tools and libraries,
Java, Grafana), and only those that were not on the machine before. It never removes anything else, so
desktop, login and system packages are safe, and common tools such as python3, curl, git and openssl
are always kept. If removing a package would also remove something outside that list, it removes
nothing and says so. Packages that were already installed stay, and only Vajra's data is removed from
them. It asks before purging (`--yes` skips the question, `--keep-packages` leaves all packages alone).

Neither cleanup removes agents from other machines. See below.

## Remove an agent from a machine

An agent is removed on the machine it runs on. Use the `linux_agent` or `windows_agent` folder from
the package you installed it with (or download the package again).

**Linux** (no token): in the `linux_agent` folder run `sudo ./vajra_install.sh -uninstall`.

**Windows** (no token): right-click `vajra_uninstall.bat` in the `windows_agent` folder and choose
Run as administrator.

Both stop the Vajra service and delete the files and configuration it installed. If osquery was
already on the machine before Vajra, it is put back as it was (its binary and its configuration);
if Vajra installed osquery, osquery is removed too. A Linux machine's `/var/osquery` database is
left alone when osquery was already there. After removal, delete the host from the console if you
no longer want it listed.

## What is not included

This is a local, plain-HTTP setup. Production hardening (public domain, TLS certificates,
production mode) is up to you. The remote shell, agent self-update and uninstall tokens are not
part of this edition. `FEATURES.md` lists what is offered and what was removed. See each folder's
`README.md` for known gaps.

## License

MIT, see `LICENSE` in each folder. Third-party components are listed in each `THIRD_PARTY.md`.
