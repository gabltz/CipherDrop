#!/usr/bin/env python3
"""CipherDrop Python SDK example.

    pip install ./sdk/python
    CIPHERDROP_SERVER=https://paste.example.com python3 examples/python/example.py
"""
import os
import sys

from cipherdrop import ApiError, CipherDrop

server = os.environ.get("CIPHERDROP_SERVER") or sys.exit("set CIPHERDROP_SERVER")
client = CipherDrop(server, api_key=os.environ.get("CIPHERDROP_API_KEY"),
                    allow_insecure_http=server.startswith(("http://127.0.0.1", "http://localhost")))

# Encrypted locally; only ciphertext is uploaded.
share = client.create_secret("python synthetic secret", ttl=3600, max_reads=1, title="Python example")
print("share link:", share["url"])
print("status:", client.status(share["id"]))
print("decrypted:", client.read(share["url"])["content"])
try:
    client.read(share["url"])
except ApiError as e:
    print("second read:", e.code)
