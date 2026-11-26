# Security regression harness

Black-box checks used for the audit in `SECURITY_AUDIT.md`. Run them **only against your own local instance**, with synthetic data.

```bash
cargo build --release -p cipherdrop-server
T=$(./target/release/cipherdrop-server token generate --name audit --scope shares:create --scope shares:create:persistent --scope shares:revoke)
# Put the [[auth.tokens]] snippet into the target configs (see SECURITY_AUDIT.md § Method), then:
export AUDIT_TOKEN=$(echo "$T" | sed -n 2p | sed 's/^# //')
ONLY_RL=1 python3 tests/security/attack.py            # production-like target on :18100 (rate limits on)
PORT=18101 python3 tests/security/attack.py           # target with rate limits off (races, logic)
PORT=18102 PROBE_HOST=<second local IP> python3 tests/security/dos.py   # slowloris / slot exhaustion
```

Each check prints `PASS` or `FINDING`.
