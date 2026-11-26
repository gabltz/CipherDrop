#!/usr/bin/env python3
"""CipherDrop black-box audit harness (local target only, synthetic data)."""
import json, os, socket, sys, threading, time, urllib.request, urllib.error, http.client
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../sdk/python/src"))
import cipherdrop as cd
from cipherdrop.protocol import encode_payload

HOST, PORT = "127.0.0.1", int(os.environ.get("PORT", "18100"))
BASE = f"http://{HOST}:{PORT}"
TOKEN = os.environ.get("AUDIT_TOKEN", "")  # token with shares:create, shares:create:persistent, shares:revoke
results = []

def rec(cid, ok, title, detail=""):
    results.append((cid, ok, title, detail))
    print(f"{'PASS   ' if ok else 'FINDING'} {cid:7} {title}{' :: ' + detail if detail else ''}", flush=True)

def req(method, path, body=None, headers=None, raw=None):
    for attempt in range(50):  # tolerate connection-cap refusals during bursts
        try:
            return _req(method, path, body, headers, raw)
        except (BrokenPipeError, ConnectionResetError, ConnectionRefusedError, http.client.RemoteDisconnected):
            if raw is not None and len(raw) > 1_000_000:
                raise
            time.sleep(0.05)
    raise RuntimeError("connection repeatedly refused")

def _req(method, path, body=None, headers=None, raw=None):
    c = http.client.HTTPConnection(HOST, PORT, timeout=20)
    h = dict(headers or {})
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    if body is not None and "Content-Type" not in h:
        h["Content-Type"] = "application/json"
    c.request(method, path, body=data, headers=h)
    r = c.getresponse()
    out = (r.status, dict(r.getheaders()), r.read())
    c.close()
    return out

def share_body(**extra):
    b = cd.encrypt(os.urandom(32), encode_payload("audit synthetic"))
    b.update(extra)
    return b

def create(**extra):
    s, h, b = req("POST", "/api/v1/shares", share_body(**extra))
    assert s == 201, (s, b)
    return json.loads(b)

if os.environ.get("ONLY_RL"):
    codes = [req("GET", "/api/v1/shares/AAAAAAAAAAAAAAAAAAAAAA/status", headers={"X-Forwarded-For": f"10.0.0.{i}", "X-Real-IP": f"10.1.0.{i}", "True-Client-IP": f"1.1.1.{i}"})[0] for i in range(150)]
    rec("RL-1", 429 in codes, "spoofed client-IP headers do not bypass per-IP limit", f"first 429 at request {codes.index(429) + 1 if 429 in codes else '-'}")
    codes = [req("POST", "/api/v1/shares", share_body(), {"X-Forwarded-For": f"9.9.9.{i}"})[0] for i in range(40)]
    rec("RL-2", 429 in codes, "anonymous creation limited per IP despite spoofed XFF", f"first 429 at request {codes.index(429) + 1 if 429 in codes else '-'}")
    sys.exit(0)

# --- RECON / MISCONFIG ---
s, h, b = req("GET", "/api/v1/version")
rec("REC-1", True, "version endpoint discloses exact server version", json.loads(b)["version"])
s, h, b = req("GET", "/")
need = ["content-security-policy", "x-frame-options", "referrer-policy", "x-content-type-options", "permissions-policy"]  # HSTS only when require_https (off on this http target)
missing = [x for x in need if x not in {k.lower() for k in h}]
rec("HDR-1", not missing, "security headers on HTML", ",".join(missing) or "all present")
csp = {k.lower(): v for k, v in h.items()}["content-security-policy"]
rec("HDR-2", "unsafe-inline" not in csp and "unsafe-eval'" not in csp.replace("wasm-unsafe-eval", ""), "CSP has no unsafe-inline/unsafe-eval", csp[:80])
s, h, b = req("GET", "/docs/api/explorer")
csp2 = {k.lower(): v for k, v in h.items()}.get("content-security-policy", "")
rec("HDR-3", "wasm-unsafe-eval" not in csp2, "Swagger page CSP is minimal (no wasm-unsafe-eval needed)", csp2[:60])
s, h, b = req("GET", "/api/v1/nope")
rec("HDR-4", s == 404 and b'"code":"not_found"' in b and b"panicked" not in b, "unknown route returns problem+json without internals", str(s))

# --- AUTHN / AUTHZ (BFLA, mass assignment) ---
s, _, _ = req("GET", "/api/v1/admin/tokens", headers={"Authorization": f"Bearer {TOKEN}"})
rec("AUTH-1", s == 403, "token without admin:manage cannot list tokens (BFLA)", str(s))
for bad in ["Bearer", "Bearer ", "Basic Zm9vOmJhcg==", "Bearer cdt_" + "0" * 12 + "_" + "A" * 43, "Bearer " + TOKEN + "x", "bearer " + TOKEN]:
    s, _, _ = req("POST", "/api/v1/shares", share_body(), {"Authorization": bad})
    rec("AUTH-2", s == 401, f"malformed/invalid credential rejected, not downgraded ({bad[:14]}...)", str(s))
s, _, b = req("POST", "/api/v1/shares", share_body(storage="persistent"))
rec("AUTH-3", s in (401, 403), "anonymous cannot create persistent share", str(s))
s, _, b = req("POST", "/api/v1/shares", share_body(ttl_seconds=None))
rec("AUTH-4", s in (401, 403), "anonymous cannot create never-expiring share", str(s))
for extra in [{"id": "AAAAAAAAAAAAAAAAAAAAAA"}, {"revocation_token": "x"}, {"remaining_reads": 999}, {"created_at": 0}, {"expires_at": None}, {"owner": "admin"}]:
    s, _, _ = req("POST", "/api/v1/shares", share_body(**extra))
    rec("MASS-1", s == 400, f"mass assignment rejected: {list(extra)[0]}", str(s))

# --- INPUT HANDLING ---
good = share_body()
dup = json.dumps(good)[:-1] + ', "max_reads": 1, "max_reads": 100}'
s, _, _ = req("POST", "/api/v1/shares", raw=dup.encode(), headers={"Content-Type": "application/json"})
rec("INP-1", s == 400, "duplicate JSON keys rejected (parameter pollution)", str(s))
for ct in ["text/plain", "application/x-www-form-urlencoded", "multipart/form-data; boundary=x", "application/json-patch+json", "application/xml"]:
    s, _, _ = req("POST", "/api/v1/shares", raw=json.dumps(good).encode(), headers={"Content-Type": ct})
    rec("INP-2", s == 415, f"content-type switching rejected: {ct}", str(s))
s, _, _ = req("POST", "/api/v1/shares", raw=json.dumps(good).encode(), headers={"Content-Type": "APPLICATION/JSON; charset=utf-8"})
rec("INP-3", s == 201, "case-insensitive JSON media type accepted", str(s))
deep = b"[" * 5000 + b"]" * 5000
s, _, _ = req("POST", "/api/v1/shares", raw=deep, headers={"Content-Type": "application/json"})
rec("INP-4", s == 400, "deeply nested JSON rejected (no stack exhaustion)", str(s))
for v in [{"ttl_seconds": 2**64}, {"ttl_seconds": -1}, {"ttl_seconds": 1.5}, {"max_reads": 2**32}, {"max_reads": "1"}, {"version": 256}, {"nonce": "A" * 16 + "=="}]:
    s, _, _ = req("POST", "/api/v1/shares", share_body(**v))
    rec("INP-5", s == 400, f"type/overflow confusion rejected: {v}", str(s))
try:
    s, _, _ = req("POST", "/api/v1/shares", raw=b'{"x":"' + b"A" * 3_000_000 + b'"}', headers={"Content-Type": "application/json"})
except (ConnectionResetError, BrokenPipeError):
    s = "reset-after-early-413"
rec("INP-6", s in (413, "reset-after-early-413"), "oversized body rejected before parsing", str(s))

# --- VERB TAMPERING / OVERRIDE ---
sh = create(max_reads=3)
for m in ["PUT", "PATCH", "GET", "HEAD", "OPTIONS", "TRACE"]:
    s, _, _ = req(m, f"/api/v1/shares/{sh['id']}/consume")
    st = json.loads(req("GET", f"/api/v1/shares/{sh['id']}/status")[2])["remaining_reads"]
    rec("VERB-1", s in (405, 404, 200) and st == 3, f"{m} /consume does not consume", f"{s} remaining={st}")
s, _, _ = req("GET", f"/api/v1/shares/{sh['id']}/status", headers={"X-HTTP-Method-Override": "POST"})
s2, _, _ = req("GET", f"/api/v1/shares/{sh['id']}/consume", headers={"X-HTTP-Method-Override": "POST", "X-Method-Override": "POST"})
st = json.loads(req("GET", f"/api/v1/shares/{sh['id']}/status")[2])["remaining_reads"]
rec("VERB-2", st == 3, "method-override headers ignored", f"remaining={st}")

# --- PATH / HOST ---
for p in ["/assets/%2e%2e/%2e%2e/Cargo.toml", "/assets/..%2f..%2fCargo.toml", "/swagger/..%2f..%2f..%2fetc/passwd", "/assets/%252e%252e/Cargo.toml", "/assets/index.html%00.js"]:
    s, _, b = req("GET", p)
    rec("PATH-1", s in (400, 404) and b"[workspace]" not in b and b"root:" not in b, f"traversal blocked {p}", str(s))
s, _, b = req("POST", "/api/v1/shares", share_body(), {"Host": "evil.example", "X-Forwarded-Host": "evil.example"})
rec("HOST-1", b"evil.example" not in b, "share URL not derived from Host/X-Forwarded-Host", str(s))

# --- CORS / CSRF ---
s, h, _ = req("OPTIONS", "/api/v1/shares", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"})
rec("CORS-1", "access-control-allow-origin" not in {k.lower() for k in h}, "no CORS grant for foreign origin", str(s))
sh = create(max_reads=2)
for hdr in [{"Origin": "https://evil.example"}, {"Origin": "null"}, {"Sec-Fetch-Site": "cross-site"}]:
    s, _, _ = req("POST", f"/api/v1/shares/{sh['id']}/consume", {}, hdr)
    rec("CSRF-1", s == 403, f"cross-origin consume blocked {hdr}", str(s))
s, _, _ = req("POST", f"/api/v1/shares/{sh['id']}/consume", raw=b"", headers={"Content-Type": "text/plain"})
rec("CSRF-2", s == 415, "simple (preflight-free) consume request rejected", str(s))

# --- RACE CONDITIONS (single burst) ---
def burst(n, fn):
    barrier = threading.Barrier(n)
    def w(_):
        barrier.wait()
        return fn()
    with ThreadPoolExecutor(n) as ex:
        return list(ex.map(w, range(n)))
wins = []
for _ in range(10):
    sh = create(max_reads=1)
    res = burst(100, lambda: req("POST", f"/api/v1/shares/{sh['id']}/consume", {})[0])
    wins.append(res.count(200))
rec("RACE-1", all(w == 1 for w in wins), "100-way burst on one-time share: exactly one 200 (10 rounds)", str(wins))
sh = create(max_reads=10)
res = burst(64, lambda: json.loads(r[2]).get("remaining_reads") if (r := req("POST", f"/api/v1/shares/{sh['id']}/consume", {}))[0] == 200 else None)
got = sorted(x for x in res if x is not None)
rec("RACE-2", got == list(range(10)), "64-way burst on 10-read share: each counter value observed once", str(got))
bad = 0
for _ in range(20):
    sh = create(max_reads=1)
    rs = []
    t1 = threading.Thread(target=lambda: rs.append(("c", req("POST", f"/api/v1/shares/{sh['id']}/consume", {})[0])))
    t2 = threading.Thread(target=lambda: rs.append(("r", req("DELETE", f"/api/v1/shares/{sh['id']}", headers={"X-Revocation-Token": sh["revocation_token"]})[0])))
    t1.start(); t2.start(); t1.join(); t2.join()
    d = dict(rs)
    if not ((d["c"] == 200) ^ (d["r"] == 204)):
        bad += 1
rec("RACE-3", bad == 0, "consume vs revoke race: exactly one wins (20 rounds)", f"violations={bad}")
k = "race-key-1"
body = share_body()
res = burst(30, lambda: req("POST", "/api/v1/shares", body, {"Idempotency-Key": k}))
ids = {json.loads(b)["id"] for s, _, b in res if s == 201}
rec("RACE-4", len(ids) == 1, "idempotency key under 30-way burst creates one share", f"distinct ids={len(ids)} statuses={sorted({s for s,_,_ in res})}")

# --- BUSINESS LOGIC: password-protected share burnable without password ---
key = os.urandom(32)
pw_body = cd.encrypt(key, encode_payload("pw-protected synthetic"), "correct horse", {"memory_kib": 19456, "iterations": 2, "parallelism": 1})
pw_body["max_reads"] = 1
s, _, b = req("POST", "/api/v1/shares", pw_body)
rec("LOGIC-0", s == 400, "password share without access_verifier is refused (no ungated password shares)", str(s))
client = cd.CipherDrop(BASE, allow_insecure_http=True)
sh = client.create_secret("gated synthetic", password="correct horse", max_reads=1)
s1, _, _ = req("POST", f"/api/v1/shares/{sh['id']}/consume", {})
s2, _, _ = req("POST", f"/api/v1/shares/{sh['id']}/consume", {"access_key": cd.b64e(os.urandom(32))})
st = json.loads(req("GET", f"/api/v1/shares/{sh['id']}/status")[2])
rec("LOGIC-1", s1 == 403 and s2 == 403 and st["remaining_reads"] == 1, "link holder without password cannot burn a password share", f"no-key={s1} wrong-key={s2} remaining={st['remaining_reads']}")
codes = [req("POST", f"/api/v1/shares/{sh['id']}/consume", {"access_key": cd.b64e(os.urandom(32))})[0] for _ in range(12)]
rec("LOGIC-2", 410 in codes and codes[-1] == 404, "online password guessing destroys the share after the failure budget", str(codes))
sh = client.create_secret("timing synthetic", password="pw", max_reads=100)
st = json.loads(req("GET", f"/api/v1/shares/{sh['id']}/status")[2])
rec("LOGIC-3", st["access_protected"] and "kdf" in st, "status exposes only public KDF parameters needed to derive the access key", ",".join(sorted(st)))

print("\nSUMMARY:", sum(1 for r in results if r[1]), "pass,", sum(1 for r in results if not r[1]), "findings")
