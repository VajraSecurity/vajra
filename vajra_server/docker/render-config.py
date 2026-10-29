#!/usr/bin/env python3
"""Render config.json from config.template.json using the environment.

Adapted from vajra.sh's patch_config() for a non-interactive container
boot: same field-matching logic (walk every object, patch by key shape
rather than by fixed path, so it patches every section that has the shape
regardless of which top-level service owns it), minus the on-disk backup
and the generated-secret file (this container has no volume conventionally
reserved for that; pass ENROLLMENT_SECRET explicitly instead).

Usage: render-config.py <template.json> <output config.json>
Required env: SERVER_HOSTNAME, DB_HOST, DB_PORT, DB_USER, DB_PASS, DB_NAME,
KAFKA_BOOTSTRAP. Optional: ENROLLMENT_SECRET (leaves the template's
CHANGE_ME_ENROLLMENT_SECRET placeholder in place if unset/empty).
"""
import json
import os
import sys

if len(sys.argv) != 3:
    print(f"usage: {sys.argv[0]} <template.json> <output.json>", file=sys.stderr)
    sys.exit(1)

src, dst = sys.argv[1], sys.argv[2]
with open(src) as f:
    cfg = json.load(f)

host = os.environ["SERVER_HOSTNAME"]
db_host = os.environ["DB_HOST"]
db_port = int(os.environ["DB_PORT"])
db_user = os.environ["DB_USER"]
db_pass = os.environ["DB_PASS"]
kafka_bootstrap = os.environ["KAFKA_BOOTSTRAP"]
enrollment_secret = os.environ.get("ENROLLMENT_SECRET", "")


def walk(node):
    if isinstance(node, dict):
        # cert/key paths -> relative to the binaries' cwd (/app/bin), into
        # the volume gen-ssl.sh writes (/app/ssl) -- see docker/gen-ssl.sh.
        if "ssl_certificate" in node:
            node["ssl_certificate"] = f"../ssl/{host}.crt"
        if "ssl_private_key" in node:
            node["ssl_private_key"] = f"../ssl/{host}.key"
        if "dh_key" in node:
            node["dh_key"] = "../ssl/dh.pem"
        # DB credentials -> the postgres compose service. database_name is
        # deliberately left untouched (matches patch_config()): the
        # services only ever read fleet_server's db_configuration ("fleet"),
        # already correct in config.template.json.
        if node is not cfg and {"username", "database_name"} <= node.keys():
            node["username"] = db_user
            node["password"] = db_pass
            node["hostname"] = db_host
            node["port"] = db_port
        # Kafka bootstrap -> the kafka compose service (matches both
        # fleet_server.kafka_producer and rule_engine.kafka).
        if "bootstrap_servers" in node:
            node["bootstrap_servers"] = kafka_bootstrap
        # Only replace the shipped template placeholder, never an
        # operator-set value -- this must stay stable once agents enroll.
        if enrollment_secret and node.get("enrollment_secret") == "CHANGE_ME_ENROLLMENT_SECRET":
            node["enrollment_secret"] = enrollment_secret
        for v in node.values():
            walk(v)
    elif isinstance(node, list):
        for v in node:
            walk(v)


walk(cfg)
with open(dst, "w") as f:
    json.dump(cfg, f, indent=2)
    f.write("\n")
print(f"render-config.py: wrote {dst}")
