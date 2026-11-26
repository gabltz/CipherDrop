#!/usr/bin/env bash
# CipherDrop CLI scripting example.
#   CIPHERDROP_SERVER=https://paste.example.com ./cipherdrop-demo.sh
# Secrets and links travel through stdin/pipes, never through command-line arguments.
set -euo pipefail

: "${CIPHERDROP_SERVER:?set CIPHERDROP_SERVER}"
CD=${CIPHERDROP_BIN:-cipherdrop}
EXTRA=()
case "$CIPHERDROP_SERVER" in http://127.0.0.1*|http://localhost*) EXTRA+=(--allow-insecure-http) ;; esac

# Create a one-time share from a generated (synthetic) secret.
secret=$(head -c 24 /dev/urandom | base64)
json=$(printf '%s' "$secret" | "$CD" "${EXTRA[@]}" --json create --ttl 15m --once --title "generated credential")
link=$(printf '%s' "$json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["url"])')
echo "share link created (send it to the recipient)" >&2

# Non-consuming status check.
printf '%s\n' "$link" | "$CD" "${EXTRA[@]}" status >&2

# Recipient side: read exactly once.
received=$(printf '%s\n' "$link" | "$CD" "${EXTRA[@]}" read)
[[ "$received" == "$secret" ]] && echo "round-trip OK" >&2

# A second read fails with exit code 3 (share unavailable).
set +e
printf '%s\n' "$link" | "$CD" "${EXTRA[@]}" read >/dev/null 2>&1
echo "second read exit code: $?" >&2
