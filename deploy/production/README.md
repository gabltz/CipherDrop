# CipherDrop production runbook

CipherDrop runs on one Linux host. The host keeps itself up to date: every 5 minutes
it looks for a new release, verifies it, deploys it, checks it, and rolls back on its
own if anything fails. HTTPS is provided in one of three ways:

| Mode | When | CipherDrop listens on |
|---|---|---|
| `local` | A reverse proxy (nginx, Caddy, Apache, Traefik…) on **this** host terminates TLS | `127.0.0.1:PORT` |
| `remote` | A reverse proxy on **another** server terminates TLS (for example nginx `proxy_pass http://this-host:PORT`) | `THIS-HOST-IP:PORT`, firewalled to the proxy's IP |
| `caddy` | **No** reverse proxy: the bundled Caddy serves HTTPS with automatic certificates | ports 80/443 (Caddy) |

- **Setup:** run one script on the host (`install.sh`). It asks for the mode and the port,
  and asks you to add a deploy key and create a token. Then configure your proxy with the
  file it generates (not needed in `caddy` mode).
- **Releasing:** push a tag `vX.Y.Z`. Production updates itself within about 5 minutes.
- **GitHub never connects to the host.** It needs no secrets, SSH access or open ports.

> **Every deploy, rollback or restart deletes all active shares.** Shares live in RAM only
> (by design). Links created shortly before a release stop working. If that matters,
> release at quiet times, or use `sudo cipherdropctl pause` and deploy by hand
> (`sudo cipherdropctl deploy vX.Y.Z`) when it suits you.

Contents: [How it works](#how-it-works) · [Installation](#installation) ·
[Reverse proxy](#reverse-proxy) · [Releasing](#releasing) · [Rolling back](#rolling-back) ·
[Day-to-day operations](#day-to-day-operations) · [Monitoring and notifications](#monitoring-and-notifications) ·
[Backups](#backups) · [Security model](#security-model) · [Troubleshooting](#troubleshooting) · [Reference](#reference)

## How it works

```text
 git push origin v0.2.0
        │
        ▼
 release.yml (GitHub Actions)
   CI (full suite) ─▶ image ─▶ ghcr.io (signed) ─▶ per-arch image archives + SHA256SUMS
                                                   signed with Sigstore (keyless)
                                                   ─▶ run artifact "cipherdrop-image"
        ▲
        │ every 5 min, outbound HTTPS/SSH only
        │
 production host: cipherdrop-update.timer ─▶ cipherdropctl update
   1. newest successful release.yml run for a vX.Y.Z tag (Actions: read token)
   2. deploy/production at that tag via the read-only deploy key; its commit must equal the run's commit
   3. download the artifact; SHA256SUMS must be signed by release.yml for exactly that tag and commit
   4. check-config with the new image ─▶ start ─▶ health check ─▶ version check via X-Forwarded-Proto
   5. if https://<domain> worked before: external smoke test (TLS, headers, create + read + burn)
   any failure ─▶ previous release restored, the new release skipped, notification sent

 local:  proxy on this host (TLS)  ─▶ http://127.0.0.1:PORT ─────────────┐
 remote: proxy on another server   ─▶ http://THIS-HOST-IP:PORT (firewall) ┼─▶ cipherdrop container
 caddy:  bundled Caddy :80/:443 (TLS, automatic certificates) ────────────┘
```

The container runs with a read-only root filesystem, no capabilities and no swap, under a
256 MB memory limit. Only the proxy may set `X-Forwarded-For`/`-Proto`: the Docker gateway
(loopback port), the remote proxy's IPs, or the internal network for the bundled Caddy.
Every other client is refused with "HTTPS required".

## Installation

**Requirements:** Debian 12+ or Ubuntu 22.04+ (amd64/arm64), root access and outbound
internet. Docker is installed if missing. Existing containers and Docker settings are left
alone. For `caddy` mode, the domain's DNS must point at the host and ports 80/443 must be free
and reachable.

1. Download the script on the host and run it. Without `--mode` it asks:

   ```bash
   curl -fsSLO https://raw.githubusercontent.com/gabltz/CipherDrop/main/deploy/production/install.sh
   sudo bash install.sh --domain paste.example.com

   # or say it up front:
   bash install.sh --domain paste.example.com --mode local  --port 8080
   bash install.sh --domain paste.example.com --mode remote --proxy-ip 10.0.0.5 --port 8080
   bash install.sh --domain paste.example.com --mode caddy  --email ops@example.com
   ```

   The port is the one your proxy forwards to (nginx `proxy_pass`). The script refuses a port
   that is already in use.

2. **Deploy key.** The script prints a public key and a link
   (`github.com/<repo>/settings/keys/new`). Add the key with *Allow write access* **unchecked**,
   then press Enter.

3. **Token.** The script asks for a fine-grained token. Create it at
   <https://github.com/settings/personal-access-tokens/new>:
   - *Repository access:* only this repository
   - *Permissions:* **Actions: Read-only** and nothing else (Metadata is added automatically)
   - *Expiration:* your choice. GitHub reminds you before it expires. Replace it with `sudo cipherdropctl set-token`.

4. The script deploys the newest release. If no release exists yet, push a tag (see
   [Releasing](#releasing)) and the host deploys it within 5 minutes. In `local` and `remote`
   mode it writes ready-made proxy configurations to `/opt/cipherdrop/proxy/`.

5. Configure the [reverse proxy](#reverse-proxy) (`local`/`remote`) and check
   `sudo cipherdropctl status`. Both `local:` and `public:` should be OK.

To change the mode, port or proxy later, run the script again with the new options
(for example `--mode remote --proxy-ip 10.0.0.7`). It applies them and restarts the service.

Useful options (`bash install.sh --help` lists them all):

| Option | |
|---|---|
| `--mode local\|remote\|caddy` | How CipherDrop is reached (see the table above) |
| `--port N` | Port the proxy forwards to, default 8080 (`caddy`: internal health-check port only) |
| `--proxy-ip IP[,IP…]` | `remote`: the proxy server's IPv4 address(es) or CIDRs |
| `--bind ADDRESS` | `remote`: address to listen on (default: the one this host uses to reach the proxy; `0.0.0.0` = all) |
| `--no-firewall` | `remote`: don't restrict the port to `--proxy-ip` (use your provider's firewall instead) |
| `--email ADDRESS` | `caddy`: ACME account e-mail; `internal` uses Caddy's own CA (private networks) |
| `--proxy-network NAME` | `local`: your proxy runs **in Docker** on network `NAME` (it then uses `http://cipherdrop:8080`) |
| `--notify-url URL` | Post deploy and failure messages to ntfy, Slack, Discord or any webhook |
| `--channel prerelease` | Also deploy `vX.Y.Z-rc.N` tags |
| `--persistent true` | Enable SQLite-backed persistent shares |
| `--harden-host` | Also disable swap, hibernation and core dumps host-wide, and turn on unattended upgrades (skip this on a shared host if other services rely on swap) |
| `--uninstall` | Remove everything the script installed |

Re-running the script is safe. It keeps the key, token, `.env` and `config.toml`, and only
changes the settings you pass.

**Recommended once, in GitHub:** *Settings → Rules → Rulesets → New tag ruleset* for `v*`,
restricted to maintainers. Pushing such a tag deploys to production.

## Reverse proxy

In `local` and `remote` mode the installer writes configurations for your domain to
`/opt/cipherdrop/proxy/`: `nginx.conf`, `Caddyfile`, `apache.conf` and `traefik.yml`. Each
file starts with the commands to install it. In `remote` mode, copy the file to the proxy
server. Its upstream is already set to this host's address and port, for example:

```nginx
location / {
    proxy_pass http://10.0.0.10:8080;     # this host, --port
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
    ...
}
```

Whatever proxy you use, it must:

1. forward to the upstream shown by the installer: `http://127.0.0.1:PORT` (local),
   `http://THIS-HOST-IP:PORT` (remote) or `http://cipherdrop:8080` (local with `--proxy-network`)
2. send `X-Forwarded-Proto: https` and `X-Forwarded-For`. CipherDrop only accepts these from the
   trusted proxy addresses and rejects plain-HTTP requests otherwise
3. stream request bodies without buffering them to disk, and allow 2 MB bodies
4. keep access logs off for this site. URLs contain share ids
5. redirect HTTP to HTTPS (the smoke test warns if it doesn't)

**Remote mode network notes.** Traffic between the proxy and this host is plain HTTP. It
carries only ciphertext, but also API tokens and client metadata, so use a private network,
VLAN or VPN (WireGuard) between the two servers. The installer warns if the address is public.
The port is open only to `--proxy-ip`. Docker-published ports bypass ufw/firewalld, so
`cipherdropctl` enforces this in iptables' `DOCKER-USER` chain (see it with
`sudo cipherdropctl firewall status`). `cipherdrop-firewall.service` reapplies the rule at boot.
If your proxy's address changes, re-run `install.sh --proxy-ip NEW`.

**Caddy mode.** The bundled Caddy obtains and renews certificates itself, redirects HTTP to
HTTPS and discards access logs. Its certificates are kept in the `cipherdrop_caddy_data`
volume. If you install a web server later, switch to `local` mode (`install.sh --mode local`).

`sudo cipherdropctl smoke` checks the whole chain from outside: TLS, headers, and a one-time
share created, read and burned.

## Releasing

1. Bump `version` in `[workspace.package]` of `Cargo.toml`, run `cargo check` to update
   `Cargo.lock`, update `CHANGELOG.md`, and merge to `main`.
2. Tag and push:

   ```bash
   git switch main && git pull
   git tag -a v0.2.0 -m "v0.2.0" && git push origin v0.2.0
   ```

3. **Actions → Release** runs CI, publishes the signed image and creates the GitHub release.
   When the run succeeds, the host picks it up within 5 minutes. The result is in
   `sudo cipherdropctl history`, and also arrives as a notification if you set `--notify-url`.

If the release fails on the host, it is rolled back and skipped automatically. Fix the
problem and tag a new patch version.

Pre-release tags (`v0.2.0-rc.1`, with a matching `Cargo.toml` version) are deployed only by
hosts on the `prerelease` channel.

## Rolling back

```bash
sudo cipherdropctl rollback        # previous release, takes seconds; the current one is skipped
sudo cipherdropctl deploy v0.1.4   # any release whose artifact still exists (90 days)
```

Deploying an older release by hand **pauses** automatic updates so the host doesn't upgrade
again straight away. Run `sudo cipherdropctl resume` when you're ready. A skipped release is
never deployed automatically. Allow it again with `sudo cipherdropctl unskip vX.Y.Z`.

## Day-to-day operations

```bash
sudo cipherdropctl status          # releases, auto-update state, health, local + public check
sudo cipherdropctl logs 300        # container logs (no secrets or share ids)
sudo cipherdropctl history         # deploys, rollbacks, rejections
journalctl -u cipherdrop-update    # output of the automatic update runs
```

**API tokens for senders** (anonymous creation is off by default):

```bash
sudo cipherdropctl token add alice                       # scope shares:create
sudo cipherdropctl token add ci shares:create shares:revoke
sudo cipherdropctl restart                               # apply (drops active shares)
```

The token is printed once. Hand it over through your password manager. To revoke a token,
delete its block from `/opt/cipherdrop/config.toml` and restart.

**Changing settings:** edit `/opt/cipherdrop/.env` (domain, port, limits, channel, notifications)
or `/opt/cipherdrop/config.toml` (share policy, rate limits, tokens), then run
`sudo cipherdropctl check-config && sudo cipherdropctl restart`. `restart` validates first and
leaves the running service alone if the configuration is invalid.

**Pausing updates:** `sudo cipherdropctl pause` / `resume`, or set `CIPHERDROP_AUTO_UPDATE=false`.

**Stack and tool updates** arrive automatically. Each release brings its own
`deploy/production`. Its compose files are used for that release, so a rollback also restores
the previous compose files. `cipherdropctl`, the smoke test and the systemd units are updated
after a successful deploy and are not rolled back. Set `CIPHERDROP_AUTO_UPDATE_TOOLS=false`
to keep the installed tools.

**Persistent shares:** `bash install.sh --persistent true` (or `CIPHERDROP_PERSISTENT=true` in
`.env` followed by a restart). Grant `shares:create:persistent` only to administrator tokens,
and set up [backups](#backups).

**Stopping:** `sudo cipherdropctl pause && sudo cipherdropctl down`. Start again with
`sudo cipherdropctl restart && sudo cipherdropctl resume`.

## Monitoring and notifications

- `--notify-url` (`CIPHERDROP_NOTIFY_URL`) sends a message for every deploy, rollback, rejected
  release and expired token. It works with an ntfy topic (`https://ntfy.sh/<secret-topic>`) or a
  Slack/Discord incoming webhook.
- An external uptime monitor on `https://<domain>/healthz` (and `/readyz`) catches everything
  else, including a broken reverse proxy or certificate.
- Optional Prometheus metrics: set `[metrics] enabled = true` in `config.toml`, then
  `sudo cipherdropctl token add prometheus admin:metrics`, and scrape `https://<domain>/metrics`
  with that bearer token.
- Disk use stays flat. Logs are capped, and only the current and previous releases are kept.

## Backups

- **Default (RAM-only shares):** there is nothing to back up. To rebuild the host, keep a copy of
  `/opt/cipherdrop/.env` and `/opt/cipherdrop/config.toml`, run `install.sh` on the new host
  (new deploy key and token), and copy both files back before it deploys.
- **Persistent shares:** back up the SQLite database daily (it holds ciphertext only, but treat
  it as sensitive):

  ```bash
  install -d -m 0700 /var/backups/cipherdrop
  docker run --rm -v cipherdrop_cipherdrop_data:/data -v /var/backups/cipherdrop:/backup alpine:3 \
    sh -c 'apk add -q sqlite && sqlite3 /data/cipherdrop.sqlite3 ".backup /backup/cipherdrop-$(date +%F).sqlite3"'
  find /var/backups/cipherdrop -name '*.sqlite3' -mtime +14 -delete
  ```

## Security model

| Credential (on the host, root-only) | Can | Cannot |
|---|---|---|
| Deploy key `/etc/cipherdrop/deploy_key` | Read the repository (git) | Push, or access anything else |
| Token `/etc/cipherdrop/github-token` | Read Actions runs and download artifacts of this repository | Read code, change anything, access other repositories |

What a release must pass before it runs:

- It comes from a **successful** run of `release.yml` triggered by a `v*` tag push, and CI is part of that run.
- The tag fetched with the deploy key points at the **same commit** the run built.
- `SHA256SUMS` carries a Sigstore signature whose certificate names **this repository's
  `release.yml`, that exact tag and that commit**. The archive and `release.json` match it.
- The new image accepts the current configuration, starts healthy, serves the tagged version,
  and passes the public smoke test.

Who can release: anyone who can push a `v*` tag. Protect tags with a ruleset (see
[Installation](#installation)). Releases also update the stack files and `cipherdropctl` on the
host, so treat tag permission as root on the production host. With
`CIPHERDROP_AUTO_UPDATE_TOOLS=false` only the image updates, but compose files still come
from the release.

Rotate the token when it expires (`sudo cipherdropctl set-token`). To rotate the deploy key,
delete `/etc/cipherdrop/deploy_key*`, re-run `install.sh`, and remove the old key in GitHub.
If the host is compromised, delete its deploy key and revoke its token in GitHub, rebuild the
host, and create new API tokens. The server never had share keys, so stored ciphertext stays
unreadable.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `status` shows `public: … UNREACHABLE` | Reverse proxy not configured or not reloaded; DNS; certificate. Check with `curl -v https://<domain>/healthz` |
| `forwarded request rejected (403)` | The proxy reaches the container from an address not in `CIPHERDROP_TRUSTED_PROXIES` (for example a containerised proxy without `--proxy-network`) |
| Remote proxy gets `502`/timeouts | Wrong `--bind`/`--proxy-ip` (the proxy's source address must be in `--proxy-ip`): check `sudo cipherdropctl firewall status`, then re-run `install.sh --proxy-ip …` |
| Remote proxy gets `403 HTTPS required` | The proxy doesn't send `X-Forwarded-Proto: https`, or connects from an address not in `--proxy-ip` (with `--no-firewall`) |
| `port N is already in use` | Another service owns the port: choose another `--port` (and update `proxy_pass`) |
| `caddy` mode: no certificate | DNS doesn't point at this host, or ports 80/443 are blocked upstream: `sudo cipherdropctl logs` and `docker logs cipherdrop-caddy-1` |
| `GitHub token rejected` | Token expired or revoked: `sudo cipherdropctl set-token` |
| `git fetch … failed` | Deploy key removed from the repository, or GitHub unreachable |
| `no unexpired 'cipherdrop-image' artifact` | Release older than 90 days: tag a new patch release |
| `signature verification FAILED` / `tag … is commit …` | The artifact doesn't match the tag. Don't override this. Investigate who pushed the tag |
| `release vX rejects the current config.toml/.env` | A new release needs a config change: fix it, then `sudo cipherdropctl deploy vX` |
| `deploy failed … could not be restored` | `sudo cipherdropctl status`, `logs`, `history`; common causes: disk full (`df -h`), port taken (`ss -ltnp`) |
| Docker subnet clash after creating other networks | Set `CIPHERDROP_SUBNET`/`CIPHERDROP_GATEWAY` in `.env`, then `sudo cipherdropctl down && sudo cipherdropctl restart`, and re-run `install.sh` to refresh the trusted proxy list |

## Reference

**`cipherdropctl`** (run as root)

| Command | |
|---|---|
| `update` | Deploy the newest verified release if it is newer (run by the timer) |
| `deploy vX.Y.Z` | Deploy a specific release; pauses auto-update if it is older than the newest |
| `rollback` | Previous release; the current one is skipped |
| `status` / `logs [N]` / `history [N]` | State, logs, journal |
| `check-config` / `restart` | Validate / validate + recreate + health-check |
| `token add NAME [SCOPE...]` | New API token (printed once) |
| `smoke` | External smoke test of `https://<domain>` |
| `pause` / `resume` / `unskip vX.Y.Z` | Control automatic updates |
| `set-token` | Replace the GitHub token |
| `firewall status\|apply\|remove` | `remote` mode port restriction |
| `down` | Stop the container |

**Files on the host**

| Path | |
|---|---|
| `/opt/cipherdrop/.env` | Host settings (root 0600) |
| `/opt/cipherdrop/config.toml` | CipherDrop configuration and API token verifiers (root:65532 0640) |
| `/opt/cipherdrop/proxy/` | Generated reverse proxy configurations (`local`/`remote`) |
| `/etc/cipherdrop/` | Deploy key, GitHub token, GitHub host keys (root 0700) |
| `/var/lib/cipherdrop/` | Releases (current + previous), state, journal, smoke-test token |
| `/usr/local/bin/cipherdropctl`, `/usr/local/lib/cipherdrop/` | Tools |
| `cipherdrop-update.timer` / `.service` | Update check every 5 minutes |
| `cipherdrop-firewall.service` | Reapplies the `remote` mode port restriction at boot |
