"""`python -m cipherdrop`: minimal CLI. Secrets and links are read from stdin."""

from __future__ import annotations

import argparse
import os
import sys

from .client import CipherDrop
from .protocol import ApiError, CipherDropError, DecryptionError, parse_share_link

def main() -> int:
    ap = argparse.ArgumentParser(prog="python -m cipherdrop", description="CipherDrop Python client")
    ap.add_argument("--server", default=os.environ.get("CIPHERDROP_SERVER"))
    ap.add_argument("--allow-insecure-http", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("create", help="encrypt stdin and create a share")
    c.add_argument("--ttl", type=int)
    c.add_argument("--max-reads", type=int)
    c.add_argument("--title")
    c.add_argument("--password-file")
    r = sub.add_parser("read", help="read a share link from stdin and print the secret")
    r.add_argument("--password-file")
    args = ap.parse_args()

    def pw(path: str | None) -> str | None:
        return open(path, encoding="utf-8").read().rstrip("\r\n") if path else None

    try:
        if args.cmd == "create":
            if not args.server:
                ap.error("--server or CIPHERDROP_SERVER is required")
            cd = CipherDrop(args.server, os.environ.get("CIPHERDROP_API_KEY"), args.allow_insecure_http)
            share = cd.create_secret(sys.stdin.read(), ttl=args.ttl, max_reads=args.max_reads,
                                     password=pw(args.password_file), title=args.title)
            print(share["url"])
            print(f"revoke: {share['revocation_url']}", file=sys.stderr)
        else:
            link = sys.stdin.readline().strip()
            base, _, _ = parse_share_link(link)
            server = base or args.server
            if not server:
                ap.error("short link: --server is required")
            cd = CipherDrop(server, os.environ.get("CIPHERDROP_API_KEY"), args.allow_insecure_http)
            sys.stdout.write(cd.read(link, pw(args.password_file))["content"])
        return 0
    except ApiError as e:
        print(f"error: {e}", file=sys.stderr)
        return 3 if e.status == 404 else 1
    except CipherDropError as e:
        print(f"error: {e}", file=sys.stderr)
        return 5 if isinstance(e, DecryptionError) else 2


if __name__ == "__main__":
    sys.exit(main())
