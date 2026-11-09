<h1 align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/assets/logo-dark.svg">
    <img src=".github/assets/logo-light.svg" alt="Vajra" width="220">
  </picture>
</h1>

<p align="center">
  <b>The open-source endpoint security platform</b> for Linux and Windows, on your own servers.
</p>

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/assets/tagline-dark.svg">
    <img src=".github/assets/tagline-light.svg" alt="Detect threats. Prove compliance. Patch vulnerabilities. Control devices." width="600">
  </picture>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-8F407F?logo=opensourceinitiative&logoColor=white" alt="MIT license"></a>
  <img src="https://img.shields.io/badge/status-beta-8F407F" alt="Status: beta">
  <a href="https://github.com/VajraSecurity/vajra/actions/workflows/server-ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/VajraSecurity/vajra/server-ci.yml?branch=main&label=server%20CI&logo=githubactions&logoColor=white" alt="Server CI"></a>
  <a href="https://github.com/VajraSecurity/vajra/actions/workflows/console-ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/VajraSecurity/vajra/console-ci.yml?branch=main&label=console%20CI&logo=githubactions&logoColor=white" alt="Console CI"></a>
  <img src="https://img.shields.io/badge/Linux-agent-042277?logo=linux&logoColor=white" alt="Linux agent">
  <img src="https://img.shields.io/badge/Windows-7%E2%80%9311-042277?logo=data:image/svg%2bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHBhdGggZmlsbD0id2hpdGUiIGQ9Ik0wIDBoMTEuNHYxMS40SDB6TTEyLjYgMEgyNHYxMS40SDEyLjZ6TTAgMTIuNmgxMS40VjI0SDB6TTEyLjYgMTIuNkgyNFYyNEgxMi42eiIvPjwvc3ZnPg==" alt="Windows agent">
</p>

<p align="center">
  <a href="#quick-start">Quick start</a> ·
  <a href="docs/install.md">Install guide</a> ·
  <a href="docs/agents.md">Agents</a> ·
  <a href="docs/production.md">Production</a> ·
  <a href="https://vajranet.com">Website</a>
</p>

<p align="center">
  <img src=".github/assets/vajra_background.jpeg" alt="Vajra Background Image" width="100%">
</p>

## <img src=".github/assets/icons/why.svg" width="28" height="28" alt="" align="top"> Why Vajra

Built for teams that can't afford blind spots.

- **Complete asset visibility**: every managed Windows and Linux device accounted for,
  continuously and automatically.
- **Continuous vulnerability management**: agent-based checks on every host, plus Nessus, OpenVAS
  and Burp Suite imports, keep exposure current, not quarterly.
- **Automated compliance and audit readiness**: evidence collection runs in the background, ready
  whenever auditors ask.
- **Detect, investigate and respond**: one console for alerts, investigation and containment. Every
  action carries a stated risk level and needs your explicit sign-off.
- **On your own servers**: run Vajra entirely inside your own infrastructure and network boundary.

## <img src=".github/assets/icons/features.svg" width="28" height="28" alt="" align="top"> Features

- **Threat detection**: correlation over process, file, socket, DNS, registry, eBPF and audit
  events, with a bundled ruleset partly converted from Sigma.
- **Alerts and hunting**: triage and assignment, analytics, AI-assisted analysis, and live osquery
  SQL across every host.
- **Compliance**: snapshots, history and PDF reports, including the SEBI and IRDAI frameworks.
- **Vulnerabilities and patching**: host CVEs, Nessus, OpenVAS and Burp Suite imports, Windows patch
  jobs and signed Linux patch bundles.
- **Device control**: USB, Bluetooth, port and IP policies per device or group, plus inventory of
  programs, ports, firewall and hardware.
- **Network Security** and **Domain Reputation**.
- **Access**: roles, teams, MFA with recovery codes and an audit trail.
- **Clean removal**: uninstalling an agent or the server restores what was there before.

## <img src=".github/assets/icons/quickstart.svg" width="28" height="28" alt="" align="top"> Quick start

**Requirements:** Docker with the Compose plugin (or Ubuntu/Debian for the script install), 8 GB RAM
and about 20 GB of free disk. The first build takes around 5 minutes on an 8-core machine. Your
endpoints need to reach the server on ports 1234, 4000 and 8080.

```bash
git clone https://github.com/VajraSecurity/vajra && cd vajra
./docker/init-env.sh              # writes .env with random secrets and this machine's IP
docker compose up -d --build      # the first build compiles the C++ server
./docker/create-admin.sh          # prints the first admin's one-time password
```

Open `http://<your-ip>:8080` and sign in with the password it printed.

<details>
<summary><b>Install without Docker</b> (Ubuntu or Debian)</summary>

```bash
./install.sh                      # installs everything with sudo; prints the URLs at the end
./install.sh --host 10.0.0.5      # the same, with an address you choose
```

The first admin's one-time password is printed and saved in `admin-credentials.txt`. Use one
install method per machine: both use the same ports.

</details>

### <img src=".github/assets/icons/endpoint.svg" width="22" height="22" alt="" align="top"> Add an endpoint

Your Vajra server builds both agent packages for you. Download them from **Download Agent** in the
console sidebar. Each package already contains your server's address, its CA certificate and the enrollment secret.

| Platform | Install |
|---|---|
| Linux | Unzip, then `sudo ./vajra_install.sh -install` inside `linux_agent/` |
| Windows 7–11, 64-bit | Unzip, then run `vajra_install.bat` as administrator inside `windows_agent\` |

The host appears in the console within a minute or two.

## <img src=".github/assets/icons/docs.svg" width="28" height="28" alt="" align="top"> Documentation

| Guide | What it covers |
|---|---|
| [Install](docs/install.md) | Docker and script installs, ports, start, stop and logs |
| [Agents](docs/agents.md) | Packages, install options, removing an agent |
| [Production](docs/production.md) | HTTPS, agent mTLS, network exposure, secrets and backups |
| [Uninstall](docs/uninstall.md) | Removing the server and how packages are handled |
| [Troubleshooting](docs/troubleshooting.md) | Console problems, hosts that don't appear, Windows installer errors |

<details>
<summary><b>Repository layout</b></summary>

| Folder | What it is |
|---|---|
| [`vajranet_server/`](vajranet_server) | Web console (React) and API (Node.js) |
| [`vajra_server/`](vajra_server) | C++ server that agents enroll with, and the detection engine |
| [`linux_agent/`](linux_agent) | Linux agent installer and packaging |
| [`windows_agent/`](windows_agent) | Windows agent installer and packaging |
| [`docker/`](docker) | Helper scripts for the Docker setup |

</details>

## <img src=".github/assets/icons/faq.svg" width="28" height="28" alt="" align="top"> FAQ

<details>
<summary><b>Is Vajra free?</b></summary>

Yes. This edition is MIT licensed. Vajra Enterprise adds hardened security and professional
support; see [vajranet.com](https://vajranet.com).

</details>

<details>
<summary><b>How quickly can Vajra be deployed?</b></summary>

The server comes up with one `docker compose` command, and the first build takes about five
minutes. You then onboard endpoints in phases: install the agent package on Windows and Linux
machines one at a time or in batches, and organize them into groups with their own policies. There
is no disruptive all-at-once cutover.

</details>

<details>
<summary><b>What detection methods does Vajra use?</b></summary>

A real-time correlation engine tracks process, file, socket, DNS, registry, eBPF and audit
activity across every host against a bundled ruleset that is partly converted from Sigma, with
alerts mapped to MITRE ATT&CK. For investigating emerging attacks, you can run live osquery SQL
across all your hosts.

</details>

<details>
<summary><b>Can Vajra isolate compromised endpoints?</b></summary>

Yes. From the console, the AI assistant can propose isolating an endpoint or blocking a
suspicious port or IP. Every proposed action shows its risk level and waits for a human sign-off
before it runs, so nothing acts without your approval.

</details>

<details>
<summary><b>How does Vajra enforce hardware and network controls?</b></summary>

Device control blocks unauthorized USB and Bluetooth peripherals, and IP and port policies limit
network exposure. Policies apply per device or per group.

</details>

<details>
<summary><b>Which compliance frameworks does Vajra support?</b></summary>

CERT-In directives, the SEBI Cybersecurity and Cyber Resilience Framework (CSCRF) and IRDAI
guidelines. Vajra collects the evidence automatically and produces PDF reports for auditors.

</details>

<details>
<summary><b>What context do analysts get during an incident?</b></summary>

Each alert includes host details, the process chain, the rule it matched and the alert's history,
so analysts can triage and respond without switching tools.

</details>

<details>
<summary><b>How do I remove it?</b></summary>

Run `./docker/cleanup.sh` (Docker) or `./uninstall.sh` (script). Agents are removed on each machine
with the uninstaller in their package. See [Uninstall](docs/uninstall.md) and
[Remove an agent](docs/agents.md#remove-an-agent).

</details>

## <img src=".github/assets/icons/security.svg" width="28" height="28" alt="" align="top"> Security

Please don't open public issues for security problems. Report them privately as described in
[SECURITY.md](SECURITY.md).

> [!CAUTION]
> This open-source edition is provided as is, without warranty or support, and Vajra Security is not
> responsible for any damage or breach that comes from using it. For hardened security and support,
> use **Vajra Enterprise**: [vajranet.com](https://vajranet.com).

## <img src=".github/assets/icons/contributing.svg" width="28" height="28" alt="" align="top"> Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md), then pick an
[open issue](https://github.com/VajraSecurity/vajra/issues). Bug reports and feature requests are
welcome.

## <img src=".github/assets/icons/license.svg" width="28" height="28" alt="" align="top"> License

MIT, see [LICENSE](LICENSE). Third-party components are listed in each folder's `THIRD_PARTY.md`.

<p align="center"><img src=".github/assets/divider.svg" alt="" width="100%"></p>

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/assets/logo-dark.svg">
    <img src=".github/assets/logo-light.svg" alt="Vajra" width="70">
  </picture>
  <br>
  <sub>Built by <a href="https://vajranet.com">Vajra Security</a> ·
  <a href="SECURITY.md">Security</a> ·
  <a href="https://github.com/VajraSecurity/vajra/issues">Issues</a></sub>
</p>
