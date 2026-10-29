# Vajra features: offered and removed

What the open-source edition offers, what was removed from it, and what needs something that is
not in these repositories. Last updated 2026-10-30.

## Offered

### Agents (`linux_agent/`, `windows_agent/`)

- osquery-based telemetry collection, reporting to the C++ server over TLS (port 1234).
- Linux: full mode (`sudo`, systemd service `vajra`) and reduced mode (a single user, no root).
- Windows: 64-bit only. Service `vajra`, installed with `vajra_install.bat`.
- Live status and server-issued tasks over a WebSocket to the web backend (port 4000).
- Windows process, file, registry, DNS, socket, SSL and HTTP events, and Linux eBPF and audit events.
- ClamAV integration on Linux (`-installav`).
- Manual osqueryd upgrade on Linux (`-update-osquery`), with rollback if the agent does not come up.
- Uninstall with no token: `sudo ./vajra_install.sh -uninstall` (Linux) or `vajra_uninstall.bat` as
  administrator (Windows). If osquery was already on the machine, only Vajra's files are removed and
  the original is restored.

### Detection server (`vajra_server/`)

- C++ fleet server: enrollment, config distribution, log and event ingest, distributed queries.
- Detection and correlation engine (`engine_v2`) with a bundled ruleset (part of it converted from
  Sigma) and a rule builder service.
- PostgreSQL storage with TimescaleDB hypertables for event tables, and Kafka between the server and
  the engine.

### Web console and API (`vajranet_server/`)

- **Devices:** My Devices, node detail (programs, storage, listening ports, network, Wi-Fi, firewall
  status, BIOS, memory health), device groups and group assignment rules.
- **Alerts and hunting:** alert list, assignment and status, analytics dashboards, threat hunting
  queries, notification logs.
- **Compliance:** compliance history and snapshots, PDF reports (including the SEBI and IRDAI frameworks).
- **Vulnerability management:** host vulnerabilities and CVE data, Nessus, OpenVAS and Burp Suite
  scanner integrations, Windows patch management (jobs, maintained apps) and Linux patch bundles
  (signed bundles).
- **Policy management:** port, IP, USB and Bluetooth control, on-screen messages to a device, and a
  policy library for standing rules (per device, group or fleet).
- **File Integrity Monitoring:** policies, baselines, registry coverage and alerts (needs the FIM
  worker, see below).
- **Network** features (on-prem mode only), **Domain reputation**, **Asset identity**, **Data
  retention** policies, AI-assisted alert analysis.
- **Users and access:** roles (Super Administrator, Group Admin, viewers), teams, MFA with recovery
  codes, audit trail.
- Optional Grafana dashboards.

### Deployment

- Docker (`docker compose`) or a script install (`./install.sh`), each with matching uninstall.
- Agent packages (`linux_agent.zip`, `windows_agent.zip`) built for your server address, with its
  certificate and enrollment secret.

## Removed

| Removed | Where it was | Why / what replaced it |
|---|---|---|
| Remote shell / terminal | Agents, backend (`terminal_logs`, `terminal_activity`), console | Not part of the open-source edition |
| Agent self-update | Agents, backend, console (`agent_releases`, `node_agent_versions`, `agent_devops_component_baseline`) | Not part of the open-source edition; the agent is reinstalled from a new package |
| In-app platform updater | Backend, console (`platform_update_state`, `platform_update_dismissals`) | Not part of the open-source edition; update by pulling the code and re-running setup |
| Update-verification key | Linux installer | Went with the self-update feature |
| SIEM forwarder | C++ server (`vajra_siem_forwarder`, `vajra_engine` units, alert triggers) | Dropped by migration `0004_drop_siem_forwarder` |
| **Uninstall tokens** | Backend (`/api/nodes/uninstall-token/*`, `uninstall_tokens` table, signing keys), console (Policy Management, Uninstall Tokens), Linux installer (online and offline token check, lockout, `-lockout-status`), `common/uninstall_verify.pem`, in-app guide | Uninstalling an agent now needs only administrator or root rights, on both Linux and Windows. Removed 2026-10-30 |
| 32-bit Windows package | `windows_agent/x86/` | Only the 64-bit (`x64/`) package is shipped |
| Private keys and secrets | `common/cert.pem`, `enrollment_secret.txt`, internal IPs in the agent configs | Never shipped; the package builder fills them in for your server |

### Cleaning up an existing install

Apply `vajranet_server/backend/migrations/035_drop_removed_feature_tables.sql` to the app database
and to the fleet database to drop the tables of removed features, including `uninstall_tokens`. It is
optional and destructive (the rows are deleted).

An older install may also hold uninstall signing keys in its backend keys folder
(`backend/keys` or the `backend-keys` Docker volume), named `uninstall_*.pem`. Nothing reads them now,
so delete them. Keep `agent-ca.*` and `patch_bundle_verify.pem` in that folder, which are still used.

Old audit-trail rows with the removed actions (`UPDATE_AGENT`, `TERMINAL_START`, `TERMINAL_STOP`,
`PUBLISH_AGENT_RELEASE`, `ACTIVATE_AGENT_RELEASE`, `GENERATE_UNINSTALL_TOKEN`, `USE_UNINSTALL_TOKEN`,
`REVOKE_UNINSTALL_TOKEN`) show the generic fallback text.

## Needs something that is not in these repositories

- **FIM worker (`vajra_fim`).** The File Integrity page stores policies, baselines and alerts, but the
  worker that scans hosts is not published.
- **Rule Engine console.** `/api/rule-engine/*` and the Rule Engine pages forward to a separate console
  (`RULE_ENGINE_API_URL`) that is not published. The detection engine itself is in `vajra_server/engine_v2`.
- **Windows and Linux agent extensions.** They are prebuilt binaries (Windows) or downloaded at
  packaging time (Linux, `EXTENSION_URL`); their source is not published.
- **CVE engine.** Skipped unless `CVE_ENGINE_REPO_URL` is set.
