/**
 * Client-side encryption (protocol v1) using the Web Crypto API and a
 * bundled Argon2id WebAssembly implementation (hash-wasm).
 *
 * CEK = K                                   (no password)
 * CEK = HKDF-SHA256(salt, K ‖ Argon2id(NFC(pw), salt, m, t, p), info) (password)
 * ciphertext‖tag = AES-256-GCM(CEK, nonce, payload, AAD)
 */

import { b64urlDecodeExact, b64urlEncode, utf8Encode, wipe } from "./encoding.js";
import {
  HKDF_INFO_ACCESS,
  HKDF_INFO_PASSWORD,
  KDF_BOUNDS,
  KDF_SALT_LEN,
  KEY_LEN,
  NONCE_LEN,
  ProtocolError,
  buildAad,
  checkKdfBounds,
  decodePayload,
  encodePayload,
  type DecodedEnvelope,
  type DecodedKdf,
  type SecretPayload,
} from "./protocol.js";

function subtle(): SubtleCrypto {
  const c = globalThis.crypto;
  if (!c?.subtle) throw new Error("Web Crypto API unavailable (a secure context / HTTPS is required)");
  return c.subtle;
}

export function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  globalThis.crypto.getRandomValues(b);
  return b;
}

/** Copy into a fresh ArrayBuffer-backed view (Web Crypto requires ArrayBuffer, not SharedArrayBuffer). */
function ab(u: Uint8Array): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(new ArrayBuffer(u.length));
  out.set(u);
  return out;
}

/** A 256-bit share key. Call {@link ShareKey.wipe} when done (best effort). */
export class ShareKey {
  private constructor(private readonly bytes: Uint8Array) {}

  static generate(): ShareKey {
    return new ShareKey(randomBytes(KEY_LEN));
  }

  static fromBytes(b: Uint8Array): ShareKey {
    if (b.length !== KEY_LEN) throw new ProtocolError("malformed_url", "key must be 32 bytes");
    return new ShareKey(new Uint8Array(b));
  }

  static fromBase64Url(s: string): ShareKey {
    try {
      return new ShareKey(b64urlDecodeExact(s, KEY_LEN, "key"));
    } catch {
      throw new ProtocolError("malformed_url", "malformed key");
    }
  }

  toBase64Url(): string {
    return b64urlEncode(this.bytes);
  }

  /** @internal */
  raw(): Uint8Array {
    return this.bytes;
  }

  wipe(): void {
    this.bytes.fill(0);
  }

  toJSON(): string {
    return "<redacted>";
  }
}

export interface KdfCost {
  memoryKib: number;
  iterations: number;
  parallelism: number;
}

export const DEFAULT_KDF_COST: KdfCost = {
  memoryKib: KDF_BOUNDS.defaultMemoryKib,
  iterations: KDF_BOUNDS.defaultIterations,
  parallelism: KDF_BOUNDS.defaultParallelism,
};

/** Argon2id from hash-wasm, loaded on first use (keeps it out of the main bundle). */
async function argon2(): Promise<typeof import("hash-wasm").argon2id> {
  return (await import("hash-wasm")).argon2id;
}

export interface PasswordKeys {
  /** Content-encryption key. */
  cek: Uint8Array;
  /** Access key presented to the server on consume (never used for encryption). */
  accessKey: Uint8Array;
}

/**
 * One Argon2id evaluation → PRK = HKDF-Extract(salt, K ‖ PWK);
 * CEK = Expand(PRK, "cipherdrop/v1/cek/password"), accessKey = Expand(PRK, "cipherdrop/v1/access").
 */
export async function derivePasswordKeys(key: ShareKey, kdf: DecodedKdf, password: string): Promise<PasswordKeys> {
  checkKdfBounds(kdf);
  if (password.length === 0) throw new ProtocolError("password_required");
  const pw = utf8Encode(password.normalize("NFC"));
  let pwk: Uint8Array | undefined;
  let ikm: Uint8Array | undefined;
  try {
    pwk = await (await argon2())({
      password: pw,
      salt: kdf.salt,
      parallelism: kdf.parallelism,
      iterations: kdf.iterations,
      memorySize: kdf.memoryKib,
      hashLength: KEY_LEN,
      outputType: "binary",
    });
    ikm = new Uint8Array(2 * KEY_LEN);
    ikm.set(key.raw(), 0);
    ikm.set(pwk, KEY_LEN);
    const base = await subtle().importKey("raw", ab(ikm), "HKDF", false, ["deriveBits"]);
    const expand = async (info: string) =>
      new Uint8Array(
        await subtle().deriveBits({ name: "HKDF", hash: "SHA-256", salt: ab(kdf.salt), info: ab(utf8Encode(info)) }, base, KEY_LEN * 8),
      );
    return { cek: await expand(HKDF_INFO_PASSWORD), accessKey: await expand(HKDF_INFO_ACCESS) };
  } finally {
    wipe(pw, pwk, ikm);
  }
}

/** base64url(SHA-256(accessKey)), uploaded at creation. */
export async function accessVerifier(accessKey: Uint8Array): Promise<string> {
  return b64urlEncode(new Uint8Array(await subtle().digest("SHA-256", ab(accessKey))));
}

/** Derive the content-encryption key bytes (exported for test vectors). */
export async function deriveContentKey(key: ShareKey, kdf: DecodedKdf | undefined, password: string | undefined): Promise<Uint8Array> {
  if (!kdf && password === undefined) return new Uint8Array(key.raw());
  if (kdf && password === undefined) throw new ProtocolError("password_required");
  if (!kdf && password !== undefined) throw new ProtocolError("password_not_expected");
  if (!kdf || password === undefined) throw new ProtocolError("malformed");
  const keys = await derivePasswordKeys(key, kdf, password);
  wipe(keys.accessKey);
  return keys.cek;
}

async function aesKey(cek: Uint8Array, usage: KeyUsage): Promise<CryptoKey> {
  const buf = ab(cek);
  try {
    return await subtle().importKey("raw", buf, { name: "AES-GCM" }, false, [usage]);
  } finally {
    wipe(buf);
  }
}

/** Deterministic encryption for test vectors only. Use {@link encrypt} in applications. */
export async function encryptDeterministic(
  key: ShareKey,
  plaintext: Uint8Array,
  nonce: Uint8Array,
  password?: { password: string; kdf: DecodedKdf },
): Promise<DecodedEnvelope> {
  if (nonce.length !== NONCE_LEN) throw new ProtocolError("malformed", "nonce must be 12 bytes");
  const kdf = password?.kdf;
  const cek = await deriveContentKey(key, kdf, password?.password);
  try {
    const k = await aesKey(cek, "encrypt");
    const ct = await subtle().encrypt(
      { name: "AES-GCM", iv: ab(nonce), additionalData: ab(buildAad(kdf)), tagLength: 128 },
      k,
      ab(plaintext),
    );
    return { nonce: new Uint8Array(nonce), ciphertext: new Uint8Array(ct), ...(kdf ? { kdf } : {}) };
  } finally {
    wipe(cek);
  }
}

/** Encrypt bytes with a fresh random nonce (and salt, when a password is given). */
export async function encrypt(
  key: ShareKey,
  plaintext: Uint8Array,
  password?: { password: string; cost?: KdfCost },
): Promise<DecodedEnvelope> {
  const nonce = randomBytes(NONCE_LEN);
  if (!password) return encryptDeterministic(key, plaintext, nonce);
  const cost = password.cost ?? DEFAULT_KDF_COST;
  const kdf: DecodedKdf = { salt: randomBytes(KDF_SALT_LEN), ...cost };
  checkKdfBounds(kdf);
  return encryptDeterministic(key, plaintext, nonce, { password: password.password, kdf });
}

/** Decrypt with an already-derived content key (no second Argon2id run). */
export async function decryptWithCek(cek: Uint8Array, env: DecodedEnvelope): Promise<Uint8Array> {
  try {
    const k = await aesKey(cek, "decrypt");
    const pt = await subtle().decrypt(
      { name: "AES-GCM", iv: ab(env.nonce), additionalData: ab(buildAad(env.kdf)), tagLength: 128 },
      k,
      ab(env.ciphertext),
    );
    return new Uint8Array(pt);
  } catch {
    throw new ProtocolError("decryption", "decryption failed: wrong key, wrong password, or modified ciphertext");
  }
}

/**
 * Encrypt a payload; with a password, also return the access verifier
 * computed from the same Argon2id evaluation.
 */
export async function encryptPayloadWithAccess(
  key: ShareKey,
  payload: SecretPayload,
  options: { password?: string; cost?: KdfCost; padTo?: number } = {},
): Promise<{ envelope: DecodedEnvelope; accessVerifier?: string }> {
  if (options.password === undefined) return { envelope: await encryptPayload(key, payload, options) };
  const kdf: DecodedKdf = { salt: randomBytes(KDF_SALT_LEN), ...(options.cost ?? DEFAULT_KDF_COST) };
  const keys = await derivePasswordKeys(key, kdf, options.password);
  const bytes = encodePayload(payload, options.padTo ?? 256);
  try {
    const nonce = randomBytes(NONCE_LEN);
    const k = await aesKey(keys.cek, "encrypt");
    const ct = await subtle().encrypt({ name: "AES-GCM", iv: ab(nonce), additionalData: ab(buildAad(kdf)), tagLength: 128 }, k, ab(bytes));
    return { envelope: { nonce, ciphertext: new Uint8Array(ct), kdf }, accessVerifier: await accessVerifier(keys.accessKey) };
  } finally {
    wipe(bytes, keys.cek, keys.accessKey);
  }
}

/** Decrypt. Throws ProtocolError("decryption") on wrong key/password or tampering. */
export async function decrypt(key: ShareKey, env: DecodedEnvelope, password?: string): Promise<Uint8Array> {
  const cek = await deriveContentKey(key, env.kdf, password);
  try {
    const k = await aesKey(cek, "decrypt");
    const pt = await subtle().decrypt(
      { name: "AES-GCM", iv: ab(env.nonce), additionalData: ab(buildAad(env.kdf)), tagLength: 128 },
      k,
      ab(env.ciphertext),
    );
    return new Uint8Array(pt);
  } catch (e) {
    if (e instanceof ProtocolError) throw e;
    throw new ProtocolError("decryption", "decryption failed: wrong key, wrong password, or modified ciphertext");
  } finally {
    wipe(cek);
  }
}

export async function encryptPayload(
  key: ShareKey,
  payload: SecretPayload,
  options: { password?: string; cost?: KdfCost; padTo?: number } = {},
): Promise<DecodedEnvelope> {
  const bytes = encodePayload(payload, options.padTo ?? 256);
  try {
    return await encrypt(
      key,
      bytes,
      options.password !== undefined ? { password: options.password, ...(options.cost ? { cost: options.cost } : {}) } : undefined,
    );
  } finally {
    wipe(bytes);
  }
}

export async function decryptPayload(key: ShareKey, env: DecodedEnvelope, password?: string): Promise<SecretPayload> {
  const bytes = await decrypt(key, env, password);
  try {
    return decodePayload(bytes);
  } finally {
    wipe(bytes);
  }
}
