#!/usr/bin/env python3
"""Encrypts stdin into a CipherDrop create-share request for use with raw cURL.

Writes the JSON request body to stdout. The share key (base64url) is written to
the file given with --key-file (created with mode 0600), or to stderr if omitted.

    printf 'example secret' | python3 encrypt.py --key-file key.txt > request.json
"""
import argparse
import json
import os
import pathlib
import sys

# Uses the Python SDK from this repository (or `pip install ./sdk/python`).
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "sdk/python/src"))
import cipherdrop as cd  # noqa: E402
from cipherdrop.protocol import encode_payload  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--key-file")
ap.add_argument("--ttl", type=int, default=3600)
ap.add_argument("--max-reads", type=int, default=1)
a = ap.parse_args()

key = os.urandom(32)
body = cd.encrypt(key, encode_payload(sys.stdin.read()))
body["ttl_seconds"] = a.ttl
body["max_reads"] = a.max_reads
sys.stdout.write(json.dumps(body))
if a.key_file:
    fd = os.open(a.key_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(cd.b64e(key))
else:
    print(cd.b64e(key), file=sys.stderr)
