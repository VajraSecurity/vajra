# Agents

Vajra has an agent for Linux and an agent for Windows (7, 8, 8.1, 10 and 11, 64-bit). Both run
[osquery](https://osquery.io) with Vajra extensions:

- telemetry goes to the C++ server on port 1234, over TLS
- live status and server tasks go to the backend over a WebSocket on port 4000

The agents have no remote shell and no self-update. To update an agent, uninstall it and install
the newer package.

## Get a package

Download `linux_agent.zip` or `windows_agent.zip` from the console sidebar, or from the URLs in
the [install guide](install.md). Each package is built for your server and already contains its
address, CA certificate and enrollment secret.

To build a package by hand instead, see [`linux_agent/README.md`](../linux_agent/README.md) and
[`windows_agent/README.md`](../windows_agent/README.md).

## Install

**Linux**, inside the unzipped `linux_agent/` folder:

```bash
sudo ./vajra_install.sh -install     # full install, systemd service "vajra"
./vajra_install.sh                   # reduced install without sudo, for a single user
```

Other options:

- `-installav` adds ClamAV support.
- `-update-osquery` replaces the installed `osqueryd` with the one in the package. It puts the old
  one back if the agent does not come up.
- `-installed-status` reports whether the agent is installed.

**Windows**: inside the unzipped `windows_agent\` folder, run `vajra_install.bat` as administrator.
It checks the Windows version and architecture, copies the files to `C:\Program Files\osquery`, and
creates and starts the `vajra` service. The installer writes its logs next to the script.

The host appears in the console within a minute or two. Telemetry and alerts follow.

## The Linux extension

The Linux package includes the Vajra extension (`linux_agent/common/extension.ext`), a prebuilt
binary whose source is not published. The server adds it to `linux_agent.zip` automatically, so
you don't need to do anything.

To use a different build of the extension:

- Replace `linux_agent/common/extension.ext` with your build, or
- remove it and set `EXTENSION_URL` and `EXTENSION_SHA256`, in `.env` for Docker or in the environment of
  `./install.sh`. The packager downloads the file, checks its checksum and adds it to
  `linux_agent.zip`. A file whose checksum doesn't match is not used.

Then rebuild the packages:

```bash
docker compose up -d --force-recreate agents       # Docker
vajranet_server/scripts/service.sh setup 10        # script install
```

The packager downloads `osqueryd` automatically in the same way.

The Windows extensions are prebuilt binaries in `windows_agent/x64/`.

## Remove an agent

Remove an agent on the machine it runs on, using the `linux_agent` or `windows_agent` folder from
the package you installed it with. If you no longer have it, download the package again.

- **Linux**: `sudo ./vajra_install.sh -uninstall` (no token needed)
- **Windows**: right-click `vajra_uninstall.bat` and choose **Run as administrator** (no token
  needed)

Both stop the Vajra service and delete the files and configuration it installed.

- If osquery was already on the machine before Vajra, it is put back as it was, with its binary and
  its configuration.
- If Vajra installed osquery, osquery is removed too.
- On Linux, `/var/osquery` is left alone when osquery was already there.

After removal, delete the host from the console if you no longer want it listed.

Removing the server ([Uninstall](uninstall.md)) does not remove agents from other machines.
