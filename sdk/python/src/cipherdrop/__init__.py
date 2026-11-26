"""CipherDrop Python SDK: zero-knowledge secret sharing (protocol v1).

    from cipherdrop import CipherDrop
    client = CipherDrop("https://paste.example.com", api_key=None)
    share = client.create_secret("My secret", ttl=3600, max_reads=1)
    print(share["url"])                 # key is in the #v1. fragment, generated locally
    print(client.read(share["url"])["content"])
"""

from .client import CipherDrop
from .protocol import (
    ApiError,
    CipherDropError,
    DecryptionError,
    b64d,
    b64e,
    build_aad,
    decrypt,
    derive_cek,
    encode_payload,
    encrypt,
    parse_revocation_link,
    parse_share_link,
    validate_envelope,
)

__version__ = "0.1.0"
__all__ = [
    "ApiError", "CipherDrop", "CipherDropError", "DecryptionError", "b64d", "b64e", "build_aad",
    "decrypt", "derive_cek", "encode_payload", "encrypt", "parse_revocation_link", "parse_share_link", "validate_envelope",
]
