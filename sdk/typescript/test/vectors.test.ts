import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  ShareKey,
  b64urlDecode,
  b64urlEncode,
  buildAadString,
  decodeEnvelope,
  decrypt,
  decryptPayload,
  accessVerifier,
  deriveContentKey,
  derivePasswordKeys,
  encodeEnvelope,
  encrypt,
  encryptDeterministic,
  encryptPayload,
  parseRevocationLink,
  parseShareLink,
  type EncryptedEnvelope,
} from "../src/index.js";

const vectors = JSON.parse(
  readFileSync(fileURLToPath(new URL("../../../crates/protocol/testdata/vectors.json", import.meta.url)), "utf8"),
);

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const utf8 = (s: string) => new TextEncoder().encode(s);

describe("cross-language test vectors", () => {
  for (const v of vectors.vectors) {
    it(`valid: ${v.name}`, async () => {
      const key = ShareKey.fromBase64Url(v.key);
      const env = decodeEnvelope(v.envelope as EncryptedEnvelope);
      expect(buildAadString(env.kdf)).toBe(v.aad);
      const cek = await deriveContentKey(key, env.kdf, v.password ?? undefined);
      expect(hex(cek)).toBe(v.cek_hex);
      if (v.password) {
        const keys = await derivePasswordKeys(key, env.kdf!, v.password);
        expect(hex(keys.accessKey)).toBe(v.access_key_hex);
        expect(await accessVerifier(keys.accessKey)).toBe(v.access_verifier);
      }
      const pt = await decrypt(key, env, v.password ?? undefined);
      expect(new TextDecoder().decode(pt)).toBe(v.plaintext);
      const again = await encryptDeterministic(
        key,
        utf8(v.plaintext),
        env.nonce,
        v.password ? { password: v.password, kdf: env.kdf! } : undefined,
      );
      expect(encodeEnvelope(again)).toEqual(v.envelope);
    }, 30_000);
  }

  it("password-nfc accepts decomposed form", async () => {
    const v = vectors.vectors.find((x: { name: string }) => x.name === "password-nfc");
    const env = decodeEnvelope(v.envelope);
    const pt = await decrypt(ShareKey.fromBase64Url(v.key), env, "café-über");
    expect(new TextDecoder().decode(pt)).toBe(v.plaintext);
  }, 30_000);

  for (const v of vectors.invalid) {
    it(`invalid: ${v.name}`, async () => {
      const key = ShareKey.fromBase64Url(v.key);
      if (v.expected_error === "malformed") {
        expect(() => decodeEnvelope(v.envelope)).toThrow();
      } else {
        const env = decodeEnvelope(v.envelope);
        await expect(decrypt(key, env, v.password ?? undefined)).rejects.toThrow();
      }
    }, 30_000);
  }
});

describe("encoding", () => {
  it("is strict", () => {
    expect(b64urlEncode(new Uint8Array([0xfb, 0xff, 0, 0x10]))).toBe("-_8AEA");
    expect(() => b64urlDecode("-_8AEA==")).toThrow();
    expect(() => b64urlDecode("+/8AEA")).toThrow();
    expect(() => b64urlDecode("-_8AEB")).toThrow();
    expect(() => b64urlDecode("-_8A EA")).toThrow();
  });
});

describe("crypto", () => {
  it("roundtrips and detects tampering", async () => {
    const key = ShareKey.generate();
    const env = await encrypt(key, utf8("synthetic"));
    expect(env.nonce.length).toBe(12);
    expect(env.ciphertext.length).toBe(9 + 16);
    expect(new TextDecoder().decode(await decrypt(key, env))).toBe("synthetic");
    const t = { ...env, ciphertext: new Uint8Array(env.ciphertext) };
    t.ciphertext[0]! ^= 1;
    await expect(decrypt(key, t)).rejects.toThrow(/decryption/);
    await expect(decrypt(ShareKey.generate(), env)).rejects.toThrow();
  });

  it("password protection", async () => {
    const key = ShareKey.generate();
    const cost = { memoryKib: 19_456, iterations: 2, parallelism: 1 };
    const env = await encryptPayload(key, { content: "x", title: "t" }, { password: "pw", cost });
    await expect(decryptPayload(key, env)).rejects.toThrow(/password_required/);
    await expect(decryptPayload(key, env, "nope")).rejects.toThrow();
    expect((await decryptPayload(key, env, "pw")).title).toBe("t");
  }, 30_000);

  it("rejects weak KDF parameters", async () => {
    await expect(
      encrypt(ShareKey.generate(), utf8("x"), { password: "pw", cost: { memoryKib: 1024, iterations: 1, parallelism: 1 } }),
    ).rejects.toMatchObject({ code: "kdf_bounds" });
  });

  it("pads payloads", async () => {
    const key = ShareKey.generate();
    const env = await encryptPayload(key, { content: "short" });
    expect(env.ciphertext.length).toBe(256 + 16);
  });
});

describe("links", () => {
  const id = "AAECAwQFBgcICQoLDA0ODw";
  const k = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
  it("parses share and revocation links", () => {
    const l = parseShareLink(`https://paste.example.com/s/${id}#v1.${k}`);
    expect(l.baseUrl).toBe("https://paste.example.com");
    expect(l.shareId).toBe(id);
    expect(l.key.toBase64Url()).toBe(k);
    expect(parseShareLink(`${id}#v1.${k}`).baseUrl).toBeUndefined();
    expect(() => parseShareLink(`https://h/s/${id}`)).toThrow();
    expect(() => parseShareLink(`https://h/s/${id}#v2.${k}`)).toThrow();
    expect(parseRevocationLink(`https://h.example/revoke/${id}#v1.${k}`).token).toBe(k);
  });
});
