# Security policy

## Reporting a vulnerability

Report vulnerabilities **privately** through GitHub's
[private vulnerability reporting](https://github.com/gabltz/CipherDrop/security/advisories/new)
(Security tab, then "Report a vulnerability"). Please don't open public issues, discussions
or pull requests for security problems.

Include the affected version, reproduction steps and the impact. Use synthetic data only and
never real secrets. You'll get an acknowledgement within 5 business days, and we'll agree a
disclosure date with you once a fix is available.

## Scope

In scope: the server, encryption protocol, SDKs, CLI, web interface, container image, release
pipeline (`.github/workflows/release.yml`) and the deployment tooling in `deploy/`.

Out of scope: attacks that need an already compromised client device, a malicious operator
serving modified web code (a documented limitation of browser-based encryption, see
[docs/security.md](docs/security.md)), and volumetric DDoS.

## Security review

CipherDrop has been through an internal security review: [SECURITY_AUDIT.md](SECURITY_AUDIT.md).
Every finding is fixed or documented as accepted. It has **not** been independently audited,
and no warranty is given (see [LICENSE](LICENSE)). Read [THREAT_MODEL.md](THREAT_MODEL.md)
before relying on it.

## Supported versions

Only the latest release receives security fixes. Hosts installed with
`deploy/production/install.sh` update themselves to it automatically.

## Verifying releases

Release images and the archives that production hosts download are signed keylessly with
Sigstore by `.github/workflows/release.yml` on a `v*` tag. See
[docs/quickstart.md](docs/quickstart.md) for the `cosign verify` command.
