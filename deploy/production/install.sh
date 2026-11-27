#!/usr/bin/env bash
# CipherDrop production installer — the only script to run on the host.
#
#   sudo bash install.sh --domain paste.example.com
#
# Works on Debian 12+/Ubuntu 22.04+ (amd64/arm64) with a reverse proxy on the
# same host that terminates TLS. It is safe to re-run: keys, token, .env and
# config.toml are kept (options you pass update the matching settings).
#
# What it does:
#   1. installs git, curl, jq, unzip, Docker Engine + Compose (if missing) and
#      a pinned, checksum-verified cosign
#   2. creates a read-only deploy key and waits until you add it to the repository
#   3. asks for a fine-grained GitHub token limited to "Actions: read" on the
#      repository (stored root-only in /etc/cipherdrop, used to download releases)
#   4. writes /opt/cipherdrop/.env and config.toml, picks a free Docker subnet
#   5. installs cipherdropctl and the cipherdrop-update timer (checks every 5 min)
#   6. deploys the newest verified release, and prints the reverse proxy
#      configuration to use (/opt/cipherdrop/proxy/)
#
# Nothing in GitHub can reach this host: it pulls signed releases itself.
#
# Options:
#   --domain NAME          public hostname served by the reverse proxy (asked if missing)
#   --repo OWNER/NAME      GitHub repository (default: gabltz/CipherDrop)
#   --port N               loopback port for the reverse proxy (default 8080)
#   --proxy-network NAME   the reverse proxy runs in Docker on network NAME ("" to unset)
#   --notify-url URL       ntfy/Slack/Discord/webhook URL for deploy notifications ("" to unset)
#   --channel stable|prerelease   deploy pre-release tags too (default stable)
#   --persistent true|false       SQLite-backed persistent shares (default false)
#   --token-file FILE      read the GitHub token from FILE instead of prompting
#   --reset-token          ask for a new GitHub token
#   --harden-host          also: mask hibernation, disable core dumps and swap host-wide,
#                          enable unattended security upgrades
#   --no-deploy            set everything up but do not deploy now
#   --non-interactive      never prompt (fail instead)
#   --uninstall            stop CipherDrop and remove everything this script installed
set -euo pipefail
umask 077
export DEBIAN_FRONTEND=noninteractive PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

COSIGN_VERSION=v3.1.6
declare -A COSIGN_SHA256=(
  [amd64]=318a99ade4156a0c4113aa983b46c0a0830fa7896a096c63121ee47b610a94c6
  [arm64]=bbb2ebc765f483cf9fac42da8763dddc2b55b350ee12ea0c44a520a6d6d52334
)
# https://api.github.com/meta (ssh_keys)
GITHUB_KNOWN_HOSTS='github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl
github.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg=
github.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCj7ndNxQowgcQnjshcLrqPEiiphnt+VTTvDP6mHBL9j1aNUkY4Ue1gvwnGLVlOhGeYrnZaMgRK6+PKCUXaDbC7qtbW8gIkhL7aGCsOr/C56SJMy/BCZfxd1nWzAOxSDPgVsmerOBYfNqltV9/hWCqBywINIR+5dIg6JTJ72pcEpEjcYgXkE2YEFXV1JHnsKgbLWNlhScqb2UmyRkQyytRLtL+38TGxkxCflmO+5Z8CSSNY7GidjMIZ7Q4zMjA2n1nGrlTDkzwDCsw+wqFPGQA179cnfGWOWRVruj16z6XyvxvjJwbz0wQZ75XK5tKSb7FNyeIEs4TT4jk+S4dhPeAUC5y+bDYirYgM4GC7uEnztnZyaVWQ7B381AK4Qdrwt51ZqExKbQpTUNn+EjqoTwvqNj4kqx5QUCI0ThS/YkOxJCXmPUWZbhjpCg56i+2aB6CmK2JGhn57K5mj0MNdBXA4/WnwH6XoPWJzK5Nyu2zB3nAZp+S5hpQs+p1vN1/wsjk='
DEFAULT_REPO=gabltz/CipherDrop
SUBNET_CANDIDATES=(172.30.0.0/24 172.30.100.0/24 10.203.0.0/24 10.231.17.0/24 192.168.203.0/24)

# Paths can be overridden for testing; cipherdropctl honours the same variables.
ETC=${CIPHERDROP_ETC:-/etc/cipherdrop}
DIR=${CIPHERDROP_DIR:-/opt/cipherdrop}
STATE=${CIPHERDROP_STATE_DIR:-/var/lib/cipherdrop}
LIB=${CIPHERDROP_LIB:-/usr/local/lib/cipherdrop}
export CIPHERDROP_ETC=$ETC CIPHERDROP_DIR=$DIR CIPHERDROP_STATE_DIR=$STATE CIPHERDROP_LIB=$LIB
UNSET=__unset__

domain="" repo="" port="" proxy_network=$UNSET notify=$UNSET channel="" persistent=""
token_file="" reset_token=0 harden=0 deploy=1 interactive=1 uninstall=0

say() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '    \033[33mwarning:\033[0m %s\n' "$*"; }
die() { printf '\n\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case $1 in
    --domain) domain=${2:?}; shift 2 ;;
    --repo) repo=${2:?}; shift 2 ;;
    --port) port=${2:?}; shift 2 ;;
    --proxy-network) proxy_network=${2?}; shift 2 ;;
    --notify-url) notify=${2?}; shift 2 ;;
    --channel) channel=${2:?}; shift 2 ;;
    --persistent) persistent=${2:?}; shift 2 ;;
    --token-file) token_file=${2:?}; shift 2 ;;
    --reset-token) reset_token=1; shift ;;
    --harden-host) harden=1; shift ;;
    --no-deploy) deploy=0; shift ;;
    --non-interactive) interactive=0; shift ;;
    --uninstall) uninstall=1; shift ;;
    -h | --help) sed -n '2,42s/^# \{0,1\}//p' "$0"; exit 0 ;;
    *) die "unknown option $1 (see --help)" ;;
  esac
done

[[ $(id -u) -eq 0 ]] || die "run as root: sudo bash $0 $*"
[[ -r /dev/tty ]] || interactive=0

ask() { # prompt default -> answer
  local a
  (( interactive )) || { [[ -n $2 ]] && { echo "$2"; return; }; die "missing value for: $1 (non-interactive)"; }
  read -rp "    $1${2:+ [$2]}: " a </dev/tty
  echo "${a:-$2}"
}
pause_for() { # message
  (( interactive )) || return 1
  read -rp "    $1 " _ </dev/tty
}

env_get() { [[ -f $DIR/.env ]] && sed -n "s/^$1=//p" "$DIR/.env" | tail -n 1 | sed -e "s/^'//" -e "s/'\$//" || true; }
set_env() { # key value (written verbatim)
  awk -v k="$1" -v v="$2" 'BEGIN { done = 0 }
    index($0, k "=") == 1 { print k "=" v; done = 1; next } { print }
    END { if (!done) print k "=" v }' "$DIR/.env" > "$DIR/.env.tmp"
  chmod 0600 "$DIR/.env.tmp"; mv -f "$DIR/.env.tmp" "$DIR/.env"
}

# ---------------------------------------------------------------- uninstall --
if (( uninstall )); then
  say "Uninstalling CipherDrop"
  systemctl disable --now cipherdrop-update.timer 2>/dev/null || true
  [[ -x /usr/local/bin/cipherdropctl && -f $DIR/.env ]] && /usr/local/bin/cipherdropctl down 2>/dev/null || true
  docker image ls --format '{{.Repository}}:{{.Tag}}' | grep -E '/cipherdrop:v' | xargs -r docker image rm >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/cipherdrop-update.service /etc/systemd/system/cipherdrop-update.timer /usr/local/bin/cipherdropctl
  systemctl daemon-reload 2>/dev/null || true
  rm -rf "$LIB" "$STATE" "$ETC"
  if [[ -d $DIR ]]; then
    a=n; (( interactive )) && read -rp "    Delete $DIR (config.toml with API token verifiers, .env)? [y/N] " a </dev/tty
    if [[ $a == [yY]* ]]; then rm -rf "$DIR"; info "removed $DIR"; else info "kept $DIR"; fi
  fi
  info "Docker, cosign and persistent volumes (if any: docker volume ls) were left in place."
  info "In GitHub: delete this host's deploy key and revoke its fine-grained token."
  exit 0
fi

# ------------------------------------------------------------------ checks ---
# shellcheck source=/dev/null
. /etc/os-release
[[ ${ID:-} == debian || ${ID:-} == ubuntu ]] || die "supported: Debian and Ubuntu (found ${ID:-unknown})"
arch=$(dpkg --print-architecture)
[[ -n ${COSIGN_SHA256[$arch]:-} ]] || die "unsupported architecture $arch (amd64 and arm64 are supported)"

first_run=0; [[ -f $DIR/.env ]] || first_run=1
[[ -n $repo ]] || repo=$(env_get CIPHERDROP_GITHUB_REPO)
[[ -n $repo && $repo != OWNER/* ]] || repo=$DEFAULT_REPO
[[ $repo =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die "invalid --repo $repo"
[[ -n $domain ]] || domain=$(env_get CIPHERDROP_DOMAIN)
[[ -n $domain && $domain != paste.example.com ]] || domain=$(ask "Public hostname (served by your reverse proxy)" "")
domain=${domain,,}
[[ $domain =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$ ]] || die "invalid domain '$domain'"
[[ -n $port ]] || port=$(env_get CIPHERDROP_PORT); port=${port:-8080}
{ [[ $port =~ ^[0-9]+$ ]] && (( port > 0 && port < 65536 )); } || die "invalid --port"
[[ -z $channel || $channel == stable || $channel == prerelease ]] || die "--channel must be stable or prerelease"
[[ -z $persistent || $persistent == true || $persistent == false ]] || die "--persistent must be true or false"

cat <<EOF

  CipherDrop installer
    domain      https://$domain  (reverse proxy -> http://127.0.0.1:$port)
    repository  $repo
EOF

# ---------------------------------------------------------------- packages ---
say "System packages"
pkgs=(ca-certificates curl git jq unzip util-linux openssh-client iproute2)
missing=()
for p in "${pkgs[@]}"; do dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q "ok installed" || missing+=("$p"); done
if (( ${#missing[@]} )); then
  apt-get update -q >/dev/null
  apt-get install -y -q "${missing[@]}" >/dev/null
  info "installed: ${missing[*]}"
else
  info "already installed"
fi

say "Docker"
if ! docker compose version >/dev/null 2>&1; then
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL "https://download.docker.com/linux/$ID/gpg" -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  echo "deb [arch=$arch signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/$ID ${VERSION_CODENAME:?} stable" \
    > /etc/apt/sources.list.d/docker.list
  chmod 0644 /etc/apt/sources.list.d/docker.list
  apt-get update -q >/dev/null
  apt-get install -y -q docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin >/dev/null
  if [[ ! -f /etc/docker/daemon.json ]]; then
    install -d -m 0755 /etc/docker
    printf '{\n  "log-driver": "local",\n  "log-opts": { "max-size": "10m", "max-file": "3" },\n  "live-restore": true\n}\n' > /etc/docker/daemon.json
    chmod 0644 /etc/docker/daemon.json
  fi
  systemctl enable --now docker >/dev/null 2>&1 || true
  systemctl restart docker
  info "installed $(docker --version)"
else
  info "$(docker --version), compose $(docker compose version --short)"
fi
cv=$(docker compose version --short); cv=${cv#v}
[[ $(printf '%s\n2.20.0\n' "$cv" | sort -V | head -n 1) == 2.20.0 ]] || die "Docker Compose >= 2.20 required (found $cv)"

say "cosign $COSIGN_VERSION (signature verification)"
if [[ $(cosign version --json 2>/dev/null | jq -r .gitVersion 2>/dev/null) == "$COSIGN_VERSION" ]]; then
  info "already installed"
else
  tmp=$(mktemp)
  curl -fsSL --retry 3 -o "$tmp" "https://github.com/sigstore/cosign/releases/download/$COSIGN_VERSION/cosign-linux-$arch"
  echo "${COSIGN_SHA256[$arch]}  $tmp" | sha256sum --check --strict --quiet - || { rm -f "$tmp"; die "cosign checksum mismatch"; }
  install -m 0755 "$tmp" /usr/local/bin/cosign; rm -f "$tmp"
  info "installed /usr/local/bin/cosign"
fi

install -d -m 0700 "$ETC" "$STATE"
install -d -m 0755 "$DIR" "$LIB"

# --------------------------------------------------------------- deploy key --
say "Read-only deploy key for $repo"
printf '%s\n' "$GITHUB_KNOWN_HOSTS" > "$ETC/known_hosts"; chmod 0644 "$ETC/known_hosts"
if [[ ! -s $ETC/deploy_key ]]; then
  ssh-keygen -q -t ed25519 -N "" -C "cipherdrop@$(hostname -s)" -f "$ETC/deploy_key"
  info "generated $ETC/deploy_key"
fi
export GIT_SSH_COMMAND="ssh -i $ETC/deploy_key -o IdentitiesOnly=yes -o UserKnownHostsFile=$ETC/known_hosts -o StrictHostKeyChecking=yes -o BatchMode=yes -o ConnectTimeout=20"
git_url=${CIPHERDROP_GIT_URL:-git@github.com:$repo.git}
until git ls-remote --exit-code "$git_url" HEAD >/dev/null 2>&1; do
  cat <<EOF

    Add this key to the repository (read-only):
      1. open https://github.com/$repo/settings/keys/new
      2. Title: cipherdrop $(hostname -s)    Key:

         $(cat "$ETC/deploy_key.pub")

      3. leave "Allow write access" UNCHECKED, click "Add key"
EOF
  pause_for "Press Enter once the key is added..." || die "deploy key not authorised yet; add it, then re-run"
done
info "repository access OK"

say "Fetching deployment files"
src=$STATE/src
if [[ ! -d $src/.git ]]; then
  git init -q "$src"
  git -C "$src" remote add origin "$git_url"
  git -C "$src" sparse-checkout init --cone
  git -C "$src" sparse-checkout set deploy/production
fi
git -C "$src" remote set-url origin "$git_url"
git -C "$src" fetch -q --depth 1 --filter=blob:none origin HEAD
git -C "$src" -c advice.detachedHead=false checkout -q --force FETCH_HEAD
P=$src/deploy/production
[[ -f $P/bin/cipherdropctl ]] || die "deploy/production not found on the default branch of $repo"
install -m 0755 "$P/bin/cipherdropctl" "$LIB/cipherdropctl"
install -m 0755 "$P/bin/smoke-test.sh" "$LIB/smoke-test.sh"
ln -sfn "$LIB/cipherdropctl" /usr/local/bin/cipherdropctl
install -m 0644 "$P/systemd/cipherdrop-update.service" "$P/systemd/cipherdrop-update.timer" /etc/systemd/system/
systemctl daemon-reload
info "installed cipherdropctl ($(git -C "$src" rev-parse --short HEAD))"

# ----------------------------------------------------------------- settings --
say "Settings ($DIR/.env)"

ip2int() { local IFS=.; read -r a b c d <<<"$1"; echo $(( (a << 24) | (b << 16) | (c << 8) | d )); }
overlap() { # cidr cidr
  local n1=${1%/*} l1=${1#*/} n2=${2%/*} l2=${2#*/} s1 e1 s2 e2
  s1=$(( $(ip2int "$n1") & (0xFFFFFFFF << (32 - l1)) & 0xFFFFFFFF )); e1=$(( s1 + (1 << (32 - l1)) - 1 ))
  s2=$(( $(ip2int "$n2") & (0xFFFFFFFF << (32 - l2)) & 0xFFFFFFFF )); e2=$(( s2 + (1 << (32 - l2)) - 1 ))
  (( s1 <= e2 && s2 <= e1 ))
}
used_subnets() {
  docker network ls -q | xargs -r docker network inspect -f '{{.Name}} {{range .IPAM.Config}}{{.Subnet}} {{end}}' \
    | awk '$1 != "cipherdrop_internal" { for (i = 2; i <= NF; i++) print $i }'
  ip -4 route show 2>/dev/null | awk '$1 ~ /\// { print $1 }'
}

if (( first_run )); then
  install -m 0600 "$P/env.example" "$DIR/.env"
  used=$(used_subnets | grep -E '^[0-9.]+/[0-9]+$' || true)
  subnet=""
  for cand in "${SUBNET_CANDIDATES[@]}"; do
    clash=0
    for u in $used; do overlap "$cand" "$u" && { clash=1; break; }; done
    (( clash )) || { subnet=$cand; break; }
  done
  [[ -n $subnet ]] || die "no free private /24 found for the CipherDrop network; set CIPHERDROP_SUBNET in $DIR/.env"
  set_env CIPHERDROP_SUBNET "$subnet"
  set_env CIPHERDROP_GATEWAY "${subnet%.*/*}.1"
  [[ -n $channel ]] || channel=stable
fi
set_env CIPHERDROP_DOMAIN "$domain"
set_env CIPHERDROP_PORT "$port"
set_env CIPHERDROP_GITHUB_REPO "$repo"
[[ -n ${CIPHERDROP_GIT_URL:-} ]] && set_env CIPHERDROP_GIT_URL "$CIPHERDROP_GIT_URL"
[[ -n $channel ]] && set_env CIPHERDROP_CHANNEL "$channel"
[[ -n $persistent ]] && set_env CIPHERDROP_PERSISTENT "$persistent"
[[ $notify != "$UNSET" ]] && set_env CIPHERDROP_NOTIFY_URL "$notify"
[[ $proxy_network != "$UNSET" ]] && set_env CIPHERDROP_PROXY_NETWORK "$proxy_network"

# Peers allowed to set X-Forwarded-*: the Docker gateway (loopback port forward)
# plus, for a containerised proxy, its network.
gw=$(env_get CIPHERDROP_GATEWAY)
trusted="\"$gw/32\""
pnet=$(env_get CIPHERDROP_PROXY_NETWORK)
if [[ -n $pnet ]]; then
  docker network inspect "$pnet" >/dev/null 2>&1 || die "Docker network '$pnet' (--proxy-network) does not exist"
  for s in $(docker network inspect -f '{{range .IPAM.Config}}{{.Subnet}} {{end}}' "$pnet"); do
    [[ $s =~ ^[0-9.]+/[0-9]+$ ]] && trusted+=",\"$s\""
  done
fi
set_env CIPHERDROP_TRUSTED_PROXIES "'[$trusted]'"
info "network $(env_get CIPHERDROP_SUBNET), trusted proxies [$trusted]"

if [[ ! -f $DIR/config.toml ]]; then
  sed "s|https://paste.example.com|https://$domain|" "$P/config.toml.example" > "$DIR/config.toml"
  info "created $DIR/config.toml"
fi
chown root:65532 "$DIR/config.toml"; chmod 0640 "$DIR/config.toml"
install -m 0644 "$P/env.example" "$P/config.toml.example" "$DIR/"

# ------------------------------------------------------------- GitHub token --
say "GitHub token (download releases)"
if [[ -n $token_file ]]; then
  cipherdropctl set-token < "$token_file"
elif [[ ! -s $ETC/github-token ]] || (( reset_token )); then
  cat <<EOF

    Create a fine-grained token: https://github.com/settings/personal-access-tokens/new
      Token name:         cipherdrop $(hostname -s)
      Expiration:         up to you (you get a notification when it expires;
                          then run: sudo cipherdropctl set-token)
      Resource owner:     ${repo%%/*}
      Repository access:  Only select repositories -> ${repo#*/}
      Permissions:        Repository -> Actions: Read-only   (nothing else)

EOF
  (( interactive )) || die "no GitHub token: re-run with --token-file FILE"
  until cipherdropctl set-token </dev/tty; do warn "token not accepted, try again"; done
else
  info "already configured (replace with: sudo cipherdropctl set-token)"
fi

# -------------------------------------------------------------- reverse proxy -
say "Reverse proxy configuration ($DIR/proxy/)"
install -d -m 0755 "$DIR/proxy"
if [[ -n $pnet ]]; then upstream=cipherdrop:8080; else upstream=127.0.0.1:$port; fi
for f in nginx.conf Caddyfile apache.conf traefik.yml; do
  sed -e "s|__DOMAIN__|$domain|g" -e "s|__UPSTREAM__|$upstream|g" -e "s|__FILE__|$DIR/proxy/$f|g" "$P/proxy/$f" > "$DIR/proxy/$f"
  chmod 0644 "$DIR/proxy/$f"
done
found=()
for b in nginx caddy apache2 httpd traefik haproxy; do
  if systemctl is-active --quiet "$b" 2>/dev/null || pgrep -x "$b" >/dev/null 2>&1; then found+=("$b (host)"); fi
done
while read -r img name; do
  [[ -n $img ]] && found+=("$name (container $img)")
done < <(docker ps --format '{{.Image}} {{.Names}}' | grep -Ei 'traefik|nginx|caddy|proxy-manager|haproxy|swag' || true)
if (( ${#found[@]} )); then info "detected: ${found[*]}"; else warn "no reverse proxy detected on this host"; fi
if [[ -z $pnet && ${found[*]} == *container* ]]; then
  warn "a containerised proxy cannot reach 127.0.0.1:$port on the host. Re-run with"
  warn "--proxy-network <its Docker network> (docker network ls) so it can use http://cipherdrop:8080."
fi
info "upstream: http://$upstream   (send X-Forwarded-Proto: https; stream bodies; no access log)"

# ------------------------------------------------------------ host hardening --
if (( harden )); then
  say "Host hardening"
  systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target >/dev/null 2>&1 || true
  install -d -m 0755 /etc/sysctl.d /etc/systemd/coredump.conf.d
  printf 'fs.suid_dumpable = 0\nkernel.core_pattern = |/bin/false\n' > /etc/sysctl.d/90-cipherdrop.conf
  printf '[Coredump]\nStorage=none\nProcessSizeMax=0\n' > /etc/systemd/coredump.conf.d/90-cipherdrop.conf
  chmod 0644 /etc/sysctl.d/90-cipherdrop.conf /etc/systemd/coredump.conf.d/90-cipherdrop.conf
  sysctl -q --system >/dev/null 2>&1 || true
  swapoff -a 2>/dev/null || true
  sed -i -E '/^[^#].*[[:space:]]swap[[:space:]]/ s/^/# disabled for CipherDrop: /' /etc/fstab
  apt-get install -y -q unattended-upgrades >/dev/null
  printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n' > /etc/apt/apt.conf.d/20auto-upgrades
  chmod 0644 /etc/apt/apt.conf.d/20auto-upgrades
  info "hibernation masked, core dumps and swap disabled, unattended upgrades on"
fi

# ------------------------------------------------------------------- deploy --
if (( deploy )); then
  say "Deploying the newest release"
  cipherdropctl update --now || warn "deploy did not complete (see above); the timer retries every 5 minutes"
fi
systemctl enable --now cipherdrop-update.timer >/dev/null 2>&1
info "automatic updates: cipherdrop-update.timer enabled"

say "Status"
cipherdropctl status || true
cat <<EOF

  Done. Next:
    - configure your reverse proxy with the matching file in $DIR/proxy/
      (upstream http://$upstream, TLS certificate for $domain)
    - API tokens for senders:   sudo cipherdropctl token add alice && sudo cipherdropctl restart
    - releases: push a tag vX.Y.Z; this host deploys it within ~5 minutes
    - runbook:  $src/deploy/production/README.md   (cipherdropctl --help)
EOF
