"""CipherDrop protocol v1: encoding, envelope validation, AAD and local crypto.

Mirrors the normative Rust implementation (`crates/protocol`) and is verified
against the shared test vectors. Uses the `cryptography` package for
AES-256-GCM, HKDF-SHA256 and Argon2id.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import secrets
import unicodedata
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

VERSION = 1
ALGORITHM = "AES-256-GCM"
AAD_PREFIX = "cipherdrop/v1;alg=AES-256-GCM;kdf="
HKDF_INFO = b"cipherdrop/v1/cek/password"
HKDF_INFO_ACCESS = b"cipherdrop/v1/access"
KDF_BOUNDS = {"memory_kib": (19_456, 262_144), "iterations": (2, 10), "parallelism": (1, 4)}
DEFAULT_KDF = {"memory_kib": 65_536, "iterations": 3, "parallelism": 1}
_B64URL = re.compile(r"^[A-Za-z0-9_-]*$")


class CipherDropError(Exception):
    """Base error; messages never include secret material."""


class DecryptionError(CipherDropError):
    pass


class ApiError(CipherDropError):
    def __init__(self, status: int, problem: dict[str, Any] | None):
        self.status = status
        self.problem = problem or {}
        super().__init__(f"HTTP {status}: {self.problem.get('title', 'error')} ({self.problem.get('code', '?')})")

    @property
    def code(self) -> str | None:
        return self.problem.get("code")


# ---------------------------------------------------------------- encoding

def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def b64d(s: str, expected_len: int | None = None) -> bytes:
    """Strict, canonical unpadded base64url."""
    if not isinstance(s, str) or not _B64URL.match(s) or len(s) % 4 == 1:
        raise CipherDropError("malformed base64url")
    try:
        b = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except (binascii.Error, ValueError) as e:
        raise CipherDropError("malformed base64url") from e
    if b64e(b) != s:
        raise CipherDropError("non-canonical base64url")
    if expected_len is not None and len(b) != expected_len:
        raise CipherDropError("wrong length")
    return b


# ---------------------------------------------------------------- protocol

def build_aad(kdf: dict[str, Any] | None) -> bytes:
    if kdf is None:
        return (AAD_PREFIX + "none").encode("ascii")
    return (
        f"{AAD_PREFIX}argon2id;v=19;m={kdf['memory_kib']};t={kdf['iterations']};"
        f"p={kdf['parallelism']};salt={kdf['salt']}"
    ).encode("ascii")


def _check_kdf(kdf: dict[str, Any]) -> None:
    if set(kdf) != {"algorithm", "salt", "memory_kib", "iterations", "parallelism"} or kdf["algorithm"] != "argon2id":
        raise CipherDropError("malformed kdf")
    for k, (lo, hi) in KDF_BOUNDS.items():
        v = kdf[k]
        if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi:
            raise CipherDropError(f"kdf {k} out of bounds")
    b64d(kdf["salt"], 16)


def derive_password_keys(key: bytes, kdf: dict[str, Any], password: str) -> tuple[bytes, bytes]:
    """One Argon2id evaluation → (cek, access_key) via HKDF-SHA256 with distinct `info` strings."""
    if not password:
        raise CipherDropError("empty password")
    _check_kdf(kdf)
    salt = b64d(kdf["salt"], 16)
    pw = unicodedata.normalize("NFC", password).encode("utf-8")
    pwk = Argon2id(
        salt=salt, length=32, iterations=kdf["iterations"], lanes=kdf["parallelism"], memory_cost=kdf["memory_kib"]
    ).derive(pw)
    # HKDF-Extract once, Expand twice (same PRK) as in the specification.
    from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
    from cryptography.hazmat.primitives import hmac

    h = hmac.HMAC(salt, hashes.SHA256())
    h.update(key + pwk)
    prk = h.finalize()
    cek = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=HKDF_INFO).derive(prk)
    access = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=HKDF_INFO_ACCESS).derive(prk)
    return cek, access


def access_verifier(access_key: bytes) -> str:
    """base64url(SHA-256(access_key)), uploaded at creation."""
    d = hashes.Hash(hashes.SHA256())
    d.update(access_key)
    return b64e(d.finalize())


def derive_cek(key: bytes, kdf: dict[str, Any] | None, password: str | None) -> bytes:
    if kdf is None and password is None:
        return key
    if kdf is not None and password is None:
        raise CipherDropError("this share requires a password")
    if kdf is None:
        raise CipherDropError("this share is not password protected")
    return derive_password_keys(key, kdf, password or "")[0]


def decrypt_with_cek(cek: bytes, env: dict[str, Any]) -> bytes:
    validate_envelope(env)
    try:
        return AESGCM(cek).decrypt(b64d(env["nonce"], 12), b64d(env["ciphertext"]), build_aad(env.get("kdf")))
    except InvalidTag as e:
        raise DecryptionError("decryption failed: wrong key, wrong password, or modified data") from e


def validate_envelope(env: dict[str, Any]) -> None:
    allowed = {"version", "algorithm", "nonce", "ciphertext", "kdf", "remaining_reads", "expires_at"}
    if not set(env) <= allowed:
        raise CipherDropError("unknown envelope field")
    if env.get("version") != VERSION:
        raise CipherDropError("unsupported protocol version")
    if env.get("algorithm") != ALGORITHM:
        raise CipherDropError("unsupported algorithm")
    b64d(env["nonce"], 12)
    if len(b64d(env["ciphertext"])) < 16:
        raise CipherDropError("ciphertext too short")
    if "kdf" in env:
        _check_kdf(env["kdf"])


def encode_payload(content: str, title: str | None = None, syntax: str | None = None, pad_to: int = 256) -> bytes:
    obj: dict[str, str] = {"content": content}
    if title:
        obj["title"] = title
    if syntax:
        obj["syntax"] = syntax
    raw = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if pad_to > 0:
        raw += b" " * ((-len(raw)) % pad_to)
    return raw


def encrypt(key: bytes, plaintext: bytes, password: str | None = None, kdf_cost: dict[str, int] | None = None,
            nonce: bytes | None = None, salt: bytes | None = None) -> dict[str, Any]:
    """Encrypt plaintext. `nonce`/`salt` parameters exist only for test vectors."""
    if len(key) != 32:
        raise CipherDropError("key must be 32 bytes")
    kdf = None
    if password is not None:
        cost = kdf_cost or DEFAULT_KDF
        kdf = {"algorithm": "argon2id", "salt": b64e(salt or secrets.token_bytes(16)), **cost}
        _check_kdf(kdf)
    nonce = nonce or secrets.token_bytes(12)
    cek = derive_cek(key, kdf, password)
    ct = AESGCM(cek).encrypt(nonce, plaintext, build_aad(kdf))
    env: dict[str, Any] = {"version": VERSION, "algorithm": ALGORITHM, "nonce": b64e(nonce), "ciphertext": b64e(ct)}
    if kdf:
        env["kdf"] = kdf
    return env


def decrypt(key: bytes, env: dict[str, Any], password: str | None = None) -> bytes:
    validate_envelope(env)
    kdf = env.get("kdf")
    cek = derive_cek(key, kdf, password)
    try:
        return AESGCM(cek).decrypt(b64d(env["nonce"], 12), b64d(env["ciphertext"]), build_aad(kdf))
    except InvalidTag as e:
        raise DecryptionError("decryption failed: wrong key, wrong password, or modified data") from e


def parse_share_link(link: str) -> tuple[str | None, str, bytes]:
    """Returns (base_url, share_id, key)."""
    m = re.fullmatch(r"(?:(https?://[^#]+?))?(?:/s/)?([A-Za-z0-9_-]{22})#v1\.([A-Za-z0-9_-]{43})", link.strip())
    if not m:
        raise CipherDropError("malformed share link")
    b64d(m.group(2), 16)
    return m.group(1), m.group(2), b64d(m.group(3), 32)


def parse_revocation_link(link: str) -> tuple[str | None, str, str]:
    """Returns (base_url, share_id, revocation_token)."""
    m = re.fullmatch(r"(?:(https?://[^#]+?))?(?:/revoke/)?([A-Za-z0-9_-]{22})#v1\.([A-Za-z0-9_-]{43})", link.strip())
    if not m:
        raise CipherDropError("malformed revocation link")
    b64d(m.group(2), 16)
    b64d(m.group(3), 32)
    return m.group(1), m.group(2), m.group(3)
