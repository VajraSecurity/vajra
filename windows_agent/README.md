# Vajra Windows agent

The endpoint agent for Windows (7, 8, 8.1, 10 and 11, 64 bit). It runs
[osquery](https://osquery.io) as the Windows service `vajra` together with extensions, and
reports to a Vajra server: telemetry goes to the C++ server (`vajra_server`) and live status
goes to the web backend (`vajranet_server`).

## What is in this repository

```
common/                 extension.conf (address of the web backend)
x64/                    osqueryd, the extensions, osquery.flags and extensions.load
vajra_install.bat       installer (run as Administrator)
vajra_uninstall.bat     uninstaller
README_TROUBLESHOOTING.md   every installer error and how to fix it
```

## Before you install

The easiest way to get a complete package is to download `windows_agent.zip` from the Vajra web
console, which fills in your server for you. To prepare the package yourself:

| File | What to put there |
|---|---|
| `x64/osquery.flags` | replace `YOUR_SERVER_HOST` with your Vajra C++ server's host name or IP (port 1234) |
| `common/extension.conf` | set `tls_hostname` to your web backend's host name or IP and port 4000 |
| `common/cert.pem` | the certificate authority certificate of your Vajra C++ server (`vajra_server/ssl/myCA.pem`) |
| `common/enrollment_secret.txt` | the enrollment secret of your Vajra C++ server (`vajra_server/enrollment_secret.txt`) |

The installer stops with a clear message if `cert.pem` or `enrollment_secret.txt` is missing.

## Install and uninstall

Run `vajra_install.bat` as Administrator. It checks the Windows version and architecture, copies
the files to `C:\Program Files\osquery`, and creates and starts the `vajra` service. Run
`vajra_uninstall.bat` as Administrator to remove it. Installer logs are written next to the script.

The agent has no remote shell and no self-update.

## Known issues

- The extensions are prebuilt binaries and their source is not in this repository. Until they are
  rebuilt without the remote shell and update code, treat them as not matching this description.
- Only the 64-bit package is provided. The installer still contains a 32-bit code path that has no
  matching `x86/` folder.
- `osqueryd.exe` is a large third-party file that should be
  downloaded at build or install time rather than stored here.

## Related repositories

- `vajra_server`: the C++ server and detection engine
- `vajranet_server`: the web console and API
- `linux_agent`: the Linux agent

Replace this list with the real repository links when they are published.

## License

MIT, see `LICENSE`. Third-party components are listed in `THIRD_PARTY.md`.
