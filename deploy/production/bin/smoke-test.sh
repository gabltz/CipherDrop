#!/usr/bin/env bash
# shellcheck disable=SC2015  # pass/fail always succeed, so A && pass || fail is safe
# External smoke test of a deployed CipherDrop instance (run by cipherdropctl after
# each deploy, or by hand from any machine).
#
#   deploy/production/bin/smoke-test.sh https://paste.example.com [v0.2.0]
#
# Checks: TLS + health endpoints, expected version, security headers,
# HTTP->HTTPS redirect (warning only), /metrics not public. With SMOKE_API_KEY set (a token with
# shares:create only) it also creates and consumes a one-time share using the
# cipherdrop CLI inside SMOKE_IMAGE (the deployed image, run with Docker),
# proving encryption, storage and burn-after-reading end to end.
# SMOKE_CA_CERT: extra trusted CA (PEM) for instances behind a private CA.
set -euo pipefail

url=${1:?usage: smoke-test.sh <https://host> [expected-version]}
url=${url%/}
expected=${2:-}; expected=${expected#v}
retry_for=${SMOKE_RETRY_SECONDS:-90}
failures=0
curl_opts=() cli_ca=()
if [[ -n ${SMOKE_CA_CERT:-} ]]; then
  curl_opts=(--cacert "$SMOKE_CA_CERT")
  cli_ca=(-v "$SMOKE_CA_CERT:/ca.pem:ro" -e CIPHERDROP_CA_CERT=/ca.pem)
fi
c() { curl ${curl_opts[@]+"${curl_opts[@]}"} "$@"; }

pass() { printf '  ok    %s\n' "$*"; }
fail() { printf '  FAIL  %s\n' "$*"; failures=$((failures + 1)); }

[[ $url == https://* ]] || { echo "URL must be https://"; exit 2; }
host=${url#https://}; host=${host%%/*}

echo "Smoke testing $url"

# 1. Reachable over valid TLS (retry: certificates may still be issuing).
deadline=$((SECONDS + retry_for))
until c -fs --max-time 10 -o /dev/null "$url/healthz"; do
  if (( SECONDS >= deadline )); then
    c -fsS --max-time 10 -o /dev/null "$url/healthz" || true
    fail "GET /healthz over valid TLS (gave up after ${retry_for}s)"; exit 1
  fi
  sleep 5
done
pass "GET /healthz over valid TLS"

code=$(c -sS --max-time 10 -o /dev/null -w '%{http_code}' "$url/readyz")
[[ $code == 200 ]] && pass "GET /readyz" || fail "GET /readyz returned $code"

# 2. Version.
body=$(c -fsS --max-time 10 "$url/api/v1/version")
version=$(printf '%s' "$body" | sed -n 's/.*"version":"\([^"]*\)".*/\1/p')
if [[ -z $expected ]]; then
  pass "version $version"
elif [[ $version == "$expected" ]]; then
  pass "version $version matches"
else
  fail "version is $version, expected $expected"
fi

# 3. HTTP redirects to HTTPS (the reverse proxy's job: warning only).
read -r code loc < <(c -s --max-time 10 -o /dev/null -w '%{http_code} %{redirect_url}\n' "http://$host/" || echo "000 -")
if [[ $code == 30[178] && $loc == https://* ]]; then pass "http:// redirects to https://"; else printf '  warn  http:// gave %s %s (configure a redirect in the reverse proxy)\n' "$code" "$loc"; fi

# 4. Security headers on the web UI.
headers=$(c -fsS --max-time 10 -D - -o /dev/null "$url/" | tr -d '\r' | tr '[:upper:]' '[:lower:]')
for h in strict-transport-security content-security-policy x-content-type-options x-frame-options referrer-policy; do
  grep -q "^$h:" <<< "$headers" && pass "header $h" || fail "missing header $h"
done

# 5. Metrics are not public.
code=$(c -sS --max-time 10 -o /dev/null -w '%{http_code}' "$url/metrics")
[[ $code != 200 ]] && pass "/metrics not public ($code)" || fail "/metrics is publicly readable"

# 6. Optional end-to-end round trip.
if [[ -n ${SMOKE_API_KEY:-} ]]; then
  image=${SMOKE_IMAGE:?SMOKE_IMAGE must name the deployed image for the round trip}
  cli=(docker run --rm -i --network host --entrypoint /usr/local/bin/cipherdrop -e CIPHERDROP_API_KEY ${cli_ca[@]+"${cli_ca[@]}"} "$image")
  secret="cipherdrop smoke test $(date -u +%s) $RANDOM"
  err=$(mktemp); trap 'rm -f "$err"' EXIT
  # stderr holds the revoke link: keep it out of CI logs unless creation fails.
  if link=$(printf '%s' "$secret" | CIPHERDROP_API_KEY=$SMOKE_API_KEY "${cli[@]}" --server "$url" create --once --ttl 5m 2>"$err"); then
    got=$(printf '%s\n' "$link" | "${cli[@]}" read 2>/dev/null) || got=""
    [[ $got == "$secret" ]] && pass "create + consume round trip" || fail "round trip returned the wrong payload"
    if printf '%s\n' "$link" | "${cli[@]}" read >/dev/null 2>&1; then
      fail "one-time share was readable twice"
    else
      pass "one-time share burned after reading"
    fi
  else
    sed 's/#.*//' "$err" >&2
    fail "could not create a share with SMOKE_API_KEY"
  fi
else
  echo "  skip  round trip (SMOKE_API_KEY not set)"
fi

if (( failures > 0 )); then
  echo "$failures check(s) failed"
  exit 1
fi
echo "All checks passed"
