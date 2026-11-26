"""Protocol vectors (offline) and optional live round-trip against CIPHERDROP_TEST_SERVER."""

import json
import os
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

import cipherdrop as cd  # noqa: E402
from cipherdrop.protocol import encode_payload  # noqa: E402

VECTORS = pathlib.Path(__file__).resolve().parents[3] / "crates/protocol/testdata/vectors.json"
DOC = json.loads(VECTORS.read_text(encoding="utf-8"))


class Vectors(unittest.TestCase):
    def test_valid(self):
        for v in DOC["vectors"]:
            with self.subTest(v["name"]):
                key, env = cd.b64d(v["key"], 32), v["envelope"]
                kdf = env.get("kdf")
                self.assertEqual(cd.build_aad(kdf).decode(), v["aad"])
                self.assertEqual(cd.derive_cek(key, kdf, v["password"]).hex(), v["cek_hex"])
                self.assertEqual(cd.decrypt(key, env, v["password"]).decode(), v["plaintext"])
                again = cd.encrypt(
                    key, v["plaintext"].encode(), v["password"],
                    {k: kdf[k] for k in ("memory_kib", "iterations", "parallelism")} if kdf else None,
                    nonce=cd.b64d(env["nonce"], 12), salt=cd.b64d(kdf["salt"], 16) if kdf else None,
                )
                self.assertEqual(again, env)

    def test_nfc(self):
        v = next(x for x in DOC["vectors"] if x["name"] == "password-nfc")
        cd.decrypt(cd.b64d(v["key"], 32), v["envelope"], "café-über")

    def test_invalid(self):
        for v in DOC["invalid"]:
            with self.subTest(v["name"]), self.assertRaises(cd.CipherDropError):
                cd.decrypt(cd.b64d(v["key"], 32), v["envelope"], v["password"])

    def test_padding_and_links(self):
        self.assertEqual(len(encode_payload("x")), 256)
        i, k = "AAECAwQFBgcICQoLDA0ODw", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
        base, sid, key = cd.parse_share_link(f"https://h.example/s/{i}#v1.{k}")
        self.assertEqual((base, sid, cd.b64e(key)), ("https://h.example", i, k))
        self.assertEqual(cd.parse_revocation_link(f"https://h.example/revoke/{i}#v1.{k}")[2], k)
        with self.assertRaises(cd.CipherDropError):
            cd.parse_share_link(f"https://h.example/s/{i}")
        with self.assertRaises(cd.CipherDropError):
            cd.CipherDrop("http://insecure.example")


@unittest.skipUnless(os.environ.get("CIPHERDROP_TEST_SERVER"), "set CIPHERDROP_TEST_SERVER for live tests")
class Live(unittest.TestCase):
    def test_roundtrip(self):
        server = os.environ["CIPHERDROP_TEST_SERVER"]
        c = cd.CipherDrop(server, allow_insecure_http=server.startswith("http://"))
        s = c.create_secret("python synthetic secret", ttl=600, max_reads=1, title="py")
        self.assertEqual(c.status(s["id"])["remaining_reads"], 1)
        p = c.read(s["url"])
        self.assertEqual((p["content"], p["title"]), ("python synthetic secret", "py"))
        with self.assertRaises(cd.ApiError) as e:
            c.read(s["url"])
        self.assertEqual(e.exception.code, "share_unavailable")
        s = c.create_secret("pw", password="synthetic pass", max_reads=2)
        # Reading without the password fails *before* consuming (status check).
        with self.assertRaises(cd.CipherDropError):
            c.read(s["url"])
        self.assertEqual(c.status(s["id"])["remaining_reads"], 2)
        self.assertEqual(c.read(s["url"], "synthetic pass")["content"], "pw")
        c.revoke_with_link(s["revocation_url"])


if __name__ == "__main__":
    unittest.main()
