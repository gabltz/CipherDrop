"""HTTP client for the CipherDrop /api/v1 API. Encryption happens locally."""

from __future__ import annotations

import json
import secrets
import urllib.error
import urllib.request
from typing import Any

from .protocol import (
    ApiError,
    CipherDropError,
    b64e,
    decrypt,
    encode_payload,
    encrypt,
    parse_revocation_link,
    parse_share_link,
)

class CipherDrop:
    def __init__(self, base_url: str, api_key: str | None = None, allow_insecure_http: bool = False, timeout: float = 30):
        base_url = base_url.rstrip("/")
        if not base_url.startswith("https://") and not (allow_insecure_http and base_url.startswith("http://")):
            raise CipherDropError("refusing non-HTTPS base URL")
        self.base_url = base_url
        self._api_key = api_key
        self.timeout = timeout

    def _call(self, method: str, path: str, body: Any = None, headers: dict[str, str] | None = None) -> Any:
        h = {"Accept": "application/json", "User-Agent": "cipherdrop-python/0.1.0"}
        if self._api_key:
            h["Authorization"] = f"Bearer {self._api_key}"
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            h["Content-Type"] = "application/json"
        h.update(headers or {})
        req = urllib.request.Request(self.base_url + path, data=data, method=method, headers=h)
        try:
            # urllib verifies TLS certificates by default (ssl.create_default_context()).
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                raw = r.read()
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as e:
            try:
                problem = json.loads(e.read())
            except ValueError:
                problem = None
            raise ApiError(e.code, problem) from None

    def config(self) -> dict[str, Any]:
        return self._call("GET", "/api/v1/config")

    def create_secret(self, content: str, *, ttl: int | None = None, max_reads: int | None = None,
                      password: str | None = None, title: str | None = None, syntax: str | None = None) -> dict[str, Any]:
        key = secrets.token_bytes(32)
        env = encrypt(key, encode_payload(content, title, syntax), password)
        body = dict(env)
        if ttl is not None:
            body["ttl_seconds"] = ttl
        if max_reads is not None:
            body["max_reads"] = max_reads
        r = self._call("POST", "/api/v1/shares", body)
        r["url"] = f"{r['url']}#v1.{b64e(key)}"
        return r

    def read(self, link: str, password: str | None = None) -> dict[str, Any]:
        """Consume one retrieval and decrypt locally. Never retried automatically."""
        _, share_id, key = parse_share_link(link)
        if password is None and self.status(share_id).get("password_protected"):
            # Fail before consuming: a retrieval must not be burned without the password.
            raise CipherDropError("this share requires a password")
        env = self._call("POST", f"/api/v1/shares/{share_id}/consume", {})
        payload = json.loads(decrypt(key, env, password))
        if not isinstance(payload, dict) or not isinstance(payload.get("content"), str):
            raise CipherDropError("malformed payload")
        return payload

    def status(self, share_id: str) -> dict[str, Any]:
        return self._call("GET", f"/api/v1/shares/{share_id}/status")

    def revoke(self, share_id: str, revocation_token: str) -> None:
        self._call("DELETE", f"/api/v1/shares/{share_id}", headers={"X-Revocation-Token": revocation_token})

    def revoke_with_link(self, revocation_link: str) -> None:
        _, share_id, token = parse_revocation_link(revocation_link)
        self.revoke(share_id, token)
