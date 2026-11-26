#!/usr/bin/env bash
# Raw cURL against the CipherDrop API, using a payload encrypted beforehand by a
# trusted local tool (encrypt.py). cURL itself never sees plaintext.
#   CIPHERDROP_SERVER=https://paste.example.com ./create-and-consume.sh
set -euo pipefail
: "${CIPHERDROP_SERVER:?set CIPHERDROP_SERVER}"
dir=$(mktemp -d); trap 'rm -rf "$dir"' EXIT
cd "$(dirname "$0")"

printf '%s' "curl synthetic secret" | python3 encrypt.py --key-file "$dir/key" > "$dir/request.json"

auth=()
[[ -n "${CIPHERDROP_API_KEY:-}" ]] && auth=(-H "Authorization: Bearer $CIPHERDROP_API_KEY")

resp=$(curl -sS --fail-with-body ${auth[@]+"${auth[@]}"} -H 'Content-Type: application/json' \
  --data-binary @"$dir/request.json" "$CIPHERDROP_SERVER/api/v1/shares")
id=$(printf '%s' "$resp" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
url=$(printf '%s' "$resp" | python3 -c 'import json,sys; print(json.load(sys.stdin)["url"])')
echo "share link: $url#v1.$(cat "$dir/key")"

# Non-consuming status.
curl -sS "$CIPHERDROP_SERVER/api/v1/shares/$id/status"; echo

# Consume: returns ciphertext only. Do NOT retry this request automatically.
curl -sS -X POST -H 'Content-Type: application/json' --data '{}' \
  "$CIPHERDROP_SERVER/api/v1/shares/$id/consume"; echo
