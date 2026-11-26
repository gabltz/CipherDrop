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

def req(method, path, body=None, headers=None, raw=None, host=None):
    c = http.client.HTTPConnection(host or HOST, PORT, timeout=20)
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

# --- DOS: slowloris / connection exhaustion ---
socks = []
for i in range(1500):
    try:
        x = socket.create_connection((HOST, PORT), timeout=2)
        x.send(b"GET /healthz HTTP/1.1\r\nHost: x\r\n")  # never finish headers
        socks.append(x)
    except OSError:
        break
time.sleep(1)
try:
    s, _, _ = req("GET", "/healthz", host=os.environ.get("PROBE_HOST"))
    alive = s == 200
except Exception as e:  # noqa
    alive = False
rec("DOS-1", alive, f"other clients still served while one IP opens {len(socks)} half-open connections", "")
time.sleep(35)
closed = 0
for x in socks:
    try:
        x.settimeout(0.2)
        if x.recv(1) == b"":
            closed += 1
    except socket.timeout:
        pass
    except OSError:
        closed += 1
rec("DOS-2", closed > len(socks) * 0.9, "server reaps connections that never finish headers (header read timeout)", f"{closed}/{len(socks)} closed after 36s")
for x in socks:
    x.close()
idle = [socket.create_connection((HOST, PORT)) for _ in range(50)]
for x in idle:
    x.send(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")
time.sleep(1)
for x in idle: x.recv(4096)
time.sleep(70)
closed = 0
for x in idle:
    try:
        x.settimeout(0.2)
        if x.recv(1) == b"":
            closed += 1
    except socket.timeout:
        pass
    except OSError:
        closed += 1
rec("DOS-3", closed > 45, "idle keep-alive connections are eventually closed", f"{closed}/50 closed after 70s idle")

# Slow-body: occupy concurrency slots from one IP
def slow_body():
    x = socket.create_connection((HOST, PORT))
    x.send(b"POST /api/v1/shares HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 100000\r\n\r\n{")
    return x
hold = [slow_body() for _ in range(300)]
time.sleep(1)
s, _, b = req("GET", "/api/v1/config", host=os.environ.get("PROBE_HOST"))
rec("DOS-4", s == 200, "other clients still served while one IP holds 300 slow uploads", f"status={s}")
for x in hold: x.close()

print("\nSUMMARY:", sum(1 for r in results if r[1]), "pass,", sum(1 for r in results if not r[1]), "findings")
