# Contributing to Vajra

Thanks for your interest. This guide explains how to report problems, propose changes, and get a
pull request merged. Project website: https://vajranet.com. Questions: info@vajranet.com.

By taking part you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md). **Security problems
must not be filed as public issues.** See [SECURITY.md](SECURITY.md).

## Repository layout

| Folder | What it is | Main tools |
|---|---|---|
| `vajra_server/` | C++ fleet server and detection engine | CMake, C++17, PostgreSQL, Kafka |
| `vajranet_server/` | Web console: `backend/` (Node, TypeScript, Express, TypeORM) and `frontend/` (React, Vite) | Node.js, npm |
| `linux_agent/` | Linux installer and agent configuration | Bash |
| `windows_agent/` | Windows installer and agent configuration (64-bit) | Batch |
| `docker/`, `docker-compose.yml`, `install.sh`, `uninstall.sh` | Deployment | Docker Compose |

`FEATURES.md` lists what the open-source edition includes and what was removed. Features listed as
removed will not be accepted back as contributions.

## Reporting a bug

Open an issue using the bug template. Include the component and version, your OS, the steps to
reproduce, what you expected, and what happened. Attach logs with passwords, tokens, hostnames and
IP addresses removed.

## Suggesting a feature

Open an issue using the feature template **before** writing a large change, so we can agree on the
approach first.

## Development setup

1. Fork the repository and clone your fork.
2. Run the stack: `./docker/init-env.sh` then `docker compose up --build -d` (see `README.md`).
3. Work on one component at a time. Each folder's `README.md` has its own build and run steps.

Useful checks before you push:

```bash
# shell installers
bash -n linux_agent/vajra_install.sh install.sh uninstall.sh

# backend and frontend (from vajranet_server/)
cd vajranet_server/backend  && npm ci && npm run build
cd vajranet_server/frontend && npm ci && npm run build

# server (from vajra_server/)
cmake -S . -B build && cmake --build build
```

## Pull requests

- Branch from `main`. Use a short name such as `fix/node-offline-status`.
- Keep a pull request to one change. Small is easier to review.
- Match the style of the code around you: naming, comment density, formatting.
- Describe what changed and why, and how you tested it.
- Update the README or docs when behavior changes. Add a database migration under
  `vajranet_server/backend/migrations/` for schema changes.
- Add or update tests where the component has them.
- Do not commit secrets, certificates, `.env` files, generated packages, or binaries. The
  `.gitignore` covers the usual ones, but check your diff.

### Commit messages

Use the imperative mood and a short subject line (about 70 characters), then a blank line and a body
that explains the reason for the change if it is not obvious.

```
Fix Windows enrollment config list

The list omitted the process and file event queries, so agents never
reported them.
```

## Licensing

Vajra is released under the MIT License (see `LICENSE`). By submitting a contribution you confirm
that you wrote it or have the right to submit it, and that it may be distributed under that license.
Do not copy in code under an incompatible license, and add any new third-party dependency to the
component's `THIRD_PARTY.md`.

## Getting help

Open a discussion or an issue, or write to info@vajranet.com.
