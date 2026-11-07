# Troubleshooting

## The console doesn't load, or shows the wrong data

- **Docker:** run `docker compose ps` and wait until `backend` and `frontend` are healthy. The
  first build compiles the C++ server and takes a while.
- **Script:** run `./install.sh status`.
- **Both installed on one machine:** the Docker and script installs use the same ports and collide.
  Remove one of them (see [Uninstall](uninstall.md)).

## A host never appears in the console

1. **Check the ports.** From the endpoint, make sure it can reach the server on ports 1234
   (telemetry) and 4000 (WebSocket). A firewall on either machine is the most common cause.
2. **Check the package address.** The package was built for `PUBLIC_HOST` (Docker) or `--host`
   (script). If you changed the address after building, rebuild the packages and reinstall the
   agent.
3. **Check the packaging log.** Run `docker compose logs agents` (Docker) to see whether the
   agent packages were built, and for any warning about the Linux extension.
4. **Check the server logs:**
   - Docker: `docker compose logs -f vajra-server backend`
   - Script: `journalctl -u vajra_server -u vajra-backend -f`

## The Windows installer stops with an error

The [Windows troubleshooting guide](../windows_agent/README_TROUBLESHOOTING.md) covers every
installer error: administrator checks, unsupported Windows versions, missing certificate or
enrollment secret, and service creation and start errors such as 1053, 1067 and 1069.

## The first admin password is lost

- **Script:** look in `admin-credentials.txt` in the repository folder.
- **Docker:** `./docker/create-admin.sh` prints the password only once. Running it again fails if an
  admin already exists, and there is no reset command yet. On a fresh test setup, the simplest fix
  is to run `./docker/cleanup.sh` and start again.

## Still stuck?

Open an [issue](https://github.com/VajraSecurity/vajra/issues) with:

- your install method
- your OS version
- the relevant log lines, with secrets removed
