# cipherdrop (Python SDK)

Python client for CipherDrop. Encrypts locally (AES-256-GCM, optional Argon2id password) and uploads only ciphertext.

```bash
pip install ./sdk/python
```

```python
from cipherdrop import CipherDrop

client = CipherDrop("https://paste.example.com", api_key=None)
share = client.create_secret("My secret", ttl=3600, max_reads=1, password=None, title="optional")
print(share["url"])                      # https://…/s/{id}#v1.{key}
print(client.read(share["url"])["content"])
client.revoke_with_link(share["revocation_url"])
```

CLI: `printf 'secret' | python -m cipherdrop --server https://paste.example.com create --ttl 3600 --max-reads 1`

Tests: `python -m unittest discover -s tests` (set `CIPHERDROP_TEST_SERVER` for a live round-trip).
