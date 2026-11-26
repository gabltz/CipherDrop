// Plain JavaScript (no TypeScript) consumer test against the compiled ESM build.
// Run: npm run build && node --test test/javascript.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { CipherDrop, ShareKey, decodeEnvelope, decrypt, encryptPayload, decryptPayload } from "../dist/index.js";

const vectors = JSON.parse(readFileSync(new URL("../../../crates/protocol/testdata/vectors.json", import.meta.url), "utf8"));

test("vectors decrypt from plain JavaScript", async () => {
  for (const v of vectors.vectors) {
    const pt = await decrypt(ShareKey.fromBase64Url(v.key), decodeEnvelope(v.envelope), v.password ?? undefined);
    assert.equal(new TextDecoder().decode(pt), v.plaintext);
  }
});

test("encrypt/decrypt payload", async () => {
  const key = ShareKey.generate();
  const env = await encryptPayload(key, { content: "js synthetic", title: "t" });
  assert.equal((await decryptPayload(key, env)).content, "js synthetic");
});

test("live round-trip", { skip: !process.env.CIPHERDROP_TEST_SERVER }, async () => {
  const baseUrl = process.env.CIPHERDROP_TEST_SERVER;
  const client = new CipherDrop({ baseUrl, allowInsecureHttp: baseUrl.startsWith("http://") });
  const share = await client.createSecret("js live synthetic", { ttl: 600, maxReads: 1 });
  assert.equal((await client.read(share.url)).content, "js live synthetic");
  await assert.rejects(client.read(share.url), (e) => e.code === "share_unavailable");
});
