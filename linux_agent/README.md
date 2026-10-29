# Vajra Linux agent

The endpoint agent for Linux. It runs [osquery](https://osquery.io) with a Vajra extension and
reports to a Vajra server: telemetry goes to the C++ server (`vajra_server`) and live status
goes to the web backend (`vajranet_server`).

The agent has no remote shell and no self-update. To update it, uninstall it and install the
newer package.

## What is in this repository

```
common/            configuration and the files the installer copies
  osquery.flags      this host's server address (--tls_hostname) and how it enrolls
  vajra.flags        flags shared by every host
  extension.conf     address of the web backend for the Vajra extension
  extensions.load    tells osquery which extension to load
  vajra.service      systemd unit
  vajra.sh           launcher used by the unit
vajra_install.sh   installer and uninstaller
```

## Before you install

The installer expects these files in `common/`. The easiest way to get a complete package is to
download `linux_agent.zip` from the Vajra web console, which fills in your server for you.
To build the package yourself:

| File | What to put there |
|---|---|
| `osquery.flags` | replace `YOUR_SERVER_HOST` with your Vajra C++ server's host name or IP (port 1234) |
| `extension.conf` | replace `YOUR_SERVER_HOST` with your web backend's host name or IP (port 4000) |
| `cert.pem` | the certificate authority certificate of your Vajra C++ server (`vajra_server/ssl/myCA.pem`) |
| `enrollment_secret` | the enrollment secret of your Vajra C++ server (`vajra_server/enrollment_secret.txt`) |
| `osqueryd` | an osquery daemon binary (not stored in this repository) |
| `extension.ext` | the Vajra extension binary (not stored in this repository) |

## Install and uninstall

```bash
sudo ./vajra_install.sh              # full install (systemd service vajra)
./vajra_install.sh                   # reduced install without sudo, for a single user
sudo ./vajra_install.sh -uninstall   # remove the agent
```

Uninstalling needs no token, only root (or the same user for a reduced install).

Other options: `-installav` installs ClamAV support, `-update-osquery` replaces the installed
osqueryd with the one in the package (and puts the old one back if the agent does not come up),
`-installed-status` prints whether the agent is installed.

## Related repositories

- `vajra_server`: the C++ server and detection engine
- `vajranet_server`: the web console and API
- `windows_agent`: the Windows agent

Replace this list with the real repository links when they are published.

## License

MIT, see `LICENSE`. osquery is licensed by its authors (Apache-2.0 or GPL-2.0); see `THIRD_PARTY.md`.
