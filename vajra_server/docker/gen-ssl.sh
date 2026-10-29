#!/usr/bin/env bash
# Generate the CA + server cert + DH params vajra_server needs, into
# /app/ssl (expected to be a persistent volume). Idempotent: does nothing
# if a cert/key/dh.pem already exist for SERVER_HOSTNAME, so a container
# restart never rotates (and breaks) trust for already-enrolled agents --
# same guarantee vajra.sh's gen_ssl() gives on bare metal, minus its
# interactive --force-ssl rotation path (not meaningful in a non-interactive
# container boot; delete the volume to force regeneration instead).
set -euo pipefail

SSL_DIR="/app/ssl"
SERVER_HOSTNAME="${SERVER_HOSTNAME:-vajra-server}"
: "${SSL_PASSWORD:?SSL_PASSWORD is required}"

mkdir -p "$SSL_DIR"
cd "$SSL_DIR"

if [[ -f "${SERVER_HOSTNAME}.crt" && -f "${SERVER_HOSTNAME}.key" && -f dh.pem ]]; then
    echo "gen-ssl.sh: SSL material for ${SERVER_HOSTNAME} already present in ${SSL_DIR} -- skipping"
    exit 0
fi

if [[ ! -f myCA.pem || ! -f myCA.key ]]; then
    echo "gen-ssl.sh: creating CA"
    openssl genrsa -des3 -passout pass:"$SSL_PASSWORD" -out myCA.key 2048 2>/dev/null
    openssl req -x509 -new -nodes -key myCA.key -passin pass:"$SSL_PASSWORD" \
        -sha256 -days 3650 -out myCA.pem \
        -subj "/C=US/ST=NA/L=NA/O=Vajra/OU=CD/CN=VajraCA" 2>/dev/null
    chmod 600 myCA.key
fi

echo "gen-ssl.sh: creating server key + CSR for ${SERVER_HOSTNAME}"
openssl genrsa -out "${SERVER_HOSTNAME}.key" 2048 2>/dev/null
openssl req -new -key "${SERVER_HOSTNAME}.key" -out "${SERVER_HOSTNAME}.csr" \
    -subj "/C=US/ST=NA/L=NA/O=Vajra/OU=CD/CN=${SERVER_HOSTNAME}" 2>/dev/null

# IP vs DNS SAN: an IP address literal encoded as a dNSName SAN is invalid
# per RFC 6125 and rejected by strict TLS clients. SERVER_HOSTNAME can be a
# bare IP (e.g. SERVER_HOSTNAME=<host-ip> in docker-compose.yml/.env when no
# DNS name is set up for the container's published port).
if [[ "$SERVER_HOSTNAME" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    SAN_LINE="subjectAltName=IP:${SERVER_HOSTNAME}"
else
    SAN_LINE="subjectAltName=DNS:${SERVER_HOSTNAME}"
fi

cat > "${SERVER_HOSTNAME}.ext" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
${SAN_LINE}
EOF

echo "gen-ssl.sh: signing server certificate (825 days)"
openssl x509 -req -in "${SERVER_HOSTNAME}.csr" -CA myCA.pem -CAkey myCA.key \
    -passin pass:"$SSL_PASSWORD" -CAcreateserial -out "${SERVER_HOSTNAME}.crt" \
    -days 825 -sha256 -extfile "${SERVER_HOSTNAME}.ext" 2>/dev/null

if [[ ! -f dh.pem ]]; then
    echo "gen-ssl.sh: generating DH params (2048-bit; slow, first boot only)"
    openssl dhparam -out dh.pem 2048 2>/dev/null
fi

chmod 640 "${SERVER_HOSTNAME}.key"
rm -f "${SERVER_HOSTNAME}.csr" "${SERVER_HOSTNAME}.ext"
echo "gen-ssl.sh: SSL material ready in ${SSL_DIR}"
