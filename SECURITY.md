# Security policy

Vajra is security software, so we take vulnerability reports seriously.

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Email **info@vajranet.com** with the subject `SECURITY: <short summary>`. Please include:

- The component (`linux_agent`, `windows_agent`, `vajra_server`, `vajranet_server`, or Docker setup).
- The version or commit you tested.
- Steps to reproduce, and the impact you expect.
- A proof of concept, if you have one. Please do not include real customer data.

We aim to acknowledge a report within **3 business days** and to send a first assessment within
**10 business days**. We will keep you updated until a fix is released, and we will credit you in the
release notes unless you prefer to stay anonymous.

## Supported versions

Security fixes go to the latest release and to the `main` branch. Older releases are not patched.

## Scope

In scope: the code in this repository, the installers, the default Docker configuration, and the
agent-to-server and console-to-server protocols.

Out of scope: vulnerabilities in third-party software we ship (osquery, PostgreSQL, Kafka and so on;
report those upstream), findings that need physical access or an already-compromised administrator
account, denial of service by traffic volume, and social engineering.

## Good-faith research

If you follow this policy, avoid accessing data that is not yours, and give us reasonable time to fix
the issue before disclosing it, we will not take legal action against you for the research.

## Deployment notes

The default Docker setup is a local, plain-HTTP setup. Before exposing Vajra to a network, put TLS in
front of it, change every generated secret, and restrict the ports (see the root `README.md`).
Website: https://vajranet.com
