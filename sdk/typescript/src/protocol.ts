/**
 * CipherDrop protocol v1: types, constants, envelope validation and AAD.
 * Mirrors `crates/protocol` (the normative implementation) and is verified
 * against the shared test vectors.
 */

import { b64urlDecode, b64urlDecodeExact, b64urlEncode, utf8Encode } from "./encoding.js";

export const PROTOCOL_VERSION = 1;
export const ALGORITHM = "AES-256-GCM";
export const KEY_LEN = 32;
export const NONCE_LEN = 12;
export const TAG_LEN = 16;
export const SHARE_ID_LEN = 16;
export const REVOCATION_TOKEN_LEN = 32;
export const KDF_SALT_LEN = 16;
export const HKDF_INFO_PASSWORD = "cipherdrop/v1/cek/password";
export const AAD_PREFIX = "cipherdrop/v1;alg=AES-256-GCM;kdf=";

export const KDF_BOUNDS = {
  minMemoryKib: 19_456,
  maxMemoryKib: 262_144,
  minIterations: 2,
  maxIterations: 10,
  minParallelism: 1,
  maxParallelism: 4,
  defaultMemoryKib: 65_536,
  defaultIterations: 3,
  defaultParallelism: 1,
} as const;

export interface KdfParams {
  algorithm: "argon2id";
  salt: string;
  memory_kib: number;
  iterations: number;
  parallelism: number;
}

export interface EncryptedEnvelope {
  version: 1;
  algorithm: "AES-256-GCM";
  nonce: string;
  ciphertext: string;
  kdf?: KdfParams;
}

export interface DecodedKdf {
  salt: Uint8Array;
  memoryKib: number;
  iterations: number;
  parallelism: number;
}

export interface DecodedEnvelope {
  nonce: Uint8Array;
  ciphertext: Uint8Array;
  kdf?: DecodedKdf;
}

export type StorageBackend = "memory" | "persistent";

export interface CreateShareRequest extends EncryptedEnvelope {
  ttl_seconds?: number | null;
  max_reads?: number | null;
  storage?: StorageBackend;
}

export interface CreateShareResponse {
  id: string;
  url: string;
  created_at: string;
  expires_at: string | null;
  max_reads: number | null;
  storage: StorageBackend;
  revocation_token: string;
  revocation_url: string;
}

export interface ConsumeShareResponse extends EncryptedEnvelope {
  remaining_reads: number | null;
  expires_at: string | null;
}

export interface ShareStatusResponse {
  available: boolean;
  expires_at: string | null;
  remaining_reads: number | null;
  password_protected: boolean;
  storage: StorageBackend;
}

export interface ConfigResponse {
  public_url: string;
  protocol_versions: number[];
  max_ciphertext_bytes: number;
  default_ttl_seconds: number;
  max_ttl_seconds: number;
  default_max_reads: number;
  max_reads: number;
  allow_unlimited_reads: boolean;
  allow_permanent: boolean;
  persistent_enabled: boolean;
  anonymous_creation: boolean;
  anonymous_retrieval: boolean;
  kdf: Record<string, number>;
}

export interface Problem {
  type: string;
  title: string;
  status: number;
  detail?: string;
  code: string;
}

/** Plaintext document that is encrypted. Unknown fields are ignored on read. */
export interface SecretPayload {
  content: string;
  title?: string;
  syntax?: string;
}

export class ProtocolError extends Error {
  constructor(
    public readonly code:
      | "unsupported_version"
      | "unsupported_algorithm"
      | "malformed"
      | "kdf_bounds"
      | "too_large"
      | "decryption"
      | "password_required"
      | "password_not_expected"
      | "malformed_url"
      | "malformed_payload",
    message?: string,
  ) {
    super(message ?? code);
    this.name = "ProtocolError";
  }
}

export function checkKdfBounds(k: { memoryKib: number; iterations: number; parallelism: number }): void {
  const b = KDF_BOUNDS;
  const int = Number.isInteger;
  if (!int(k.memoryKib) || k.memoryKib < b.minMemoryKib || k.memoryKib > b.maxMemoryKib)
    throw new ProtocolError("kdf_bounds", "memory_kib out of bounds");
  if (!int(k.iterations) || k.iterations < b.minIterations || k.iterations > b.maxIterations)
    throw new ProtocolError("kdf_bounds", "iterations out of bounds");
  if (!int(k.parallelism) || k.parallelism < b.minParallelism || k.parallelism > b.maxParallelism)
    throw new ProtocolError("kdf_bounds", "parallelism out of bounds");
}

/** Strictly validate and decode a wire envelope. */
export function decodeEnvelope(env: EncryptedEnvelope, maxCiphertextLen = Number.MAX_SAFE_INTEGER): DecodedEnvelope {
  if (typeof env !== "object" || env === null) throw new ProtocolError("malformed");
  const allowed = new Set(["version", "algorithm", "nonce", "ciphertext", "kdf", "remaining_reads", "expires_at"]);
  for (const k of Object.keys(env)) if (!allowed.has(k)) throw new ProtocolError("malformed", `unknown field ${k}`);
  if (env.version !== PROTOCOL_VERSION) throw new ProtocolError("unsupported_version");
  if (env.algorithm !== ALGORITHM) throw new ProtocolError("unsupported_algorithm");
  if (typeof env.nonce !== "string" || typeof env.ciphertext !== "string") throw new ProtocolError("malformed");
  let nonce: Uint8Array;
  let ciphertext: Uint8Array;
  try {
    nonce = b64urlDecodeExact(env.nonce, NONCE_LEN, "nonce");
    if (Math.floor((env.ciphertext.length * 3) / 4) > maxCiphertextLen) throw new ProtocolError("too_large");
    ciphertext = b64urlDecode(env.ciphertext, "ciphertext");
  } catch (e) {
    if (e instanceof ProtocolError) throw e;
    throw new ProtocolError("malformed", (e as Error).message);
  }
  if (ciphertext.length < TAG_LEN) throw new ProtocolError("malformed", "ciphertext too short");
  let kdf: DecodedKdf | undefined;
  if (env.kdf !== undefined) {
    const k = env.kdf;
    const keys = Object.keys(k).sort().join(",");
    if (keys !== "algorithm,iterations,memory_kib,parallelism,salt" || k.algorithm !== "argon2id")
      throw new ProtocolError("malformed", "invalid kdf");
    let salt: Uint8Array;
    try {
      salt = b64urlDecodeExact(k.salt, KDF_SALT_LEN, "kdf.salt");
    } catch {
      throw new ProtocolError("malformed", "invalid kdf salt");
    }
    kdf = { salt, memoryKib: k.memory_kib, iterations: k.iterations, parallelism: k.parallelism };
    checkKdfBounds(kdf);
  }
  return { nonce, ciphertext, ...(kdf ? { kdf } : {}) };
}

export function encodeEnvelope(d: DecodedEnvelope): EncryptedEnvelope {
  const env: EncryptedEnvelope = {
    version: 1,
    algorithm: "AES-256-GCM",
    nonce: b64urlEncode(d.nonce),
    ciphertext: b64urlEncode(d.ciphertext),
  };
  if (d.kdf) {
    env.kdf = {
      algorithm: "argon2id",
      salt: b64urlEncode(d.kdf.salt),
      memory_kib: d.kdf.memoryKib,
      iterations: d.kdf.iterations,
      parallelism: d.kdf.parallelism,
    };
  }
  return env;
}

/** Canonical associated data (see docs/encryption.md). */
export function buildAadString(kdf?: DecodedKdf): string {
  if (!kdf) return `${AAD_PREFIX}none`;
  return `${AAD_PREFIX}argon2id;v=19;m=${kdf.memoryKib};t=${kdf.iterations};p=${kdf.parallelism};salt=${b64urlEncode(kdf.salt)}`;
}

export const buildAad = (kdf?: DecodedKdf): Uint8Array => utf8Encode(buildAadString(kdf));

/** Serialize a payload as compact JSON, space-padded to a multiple of `padTo`. */
export function encodePayload(p: SecretPayload, padTo = 256): Uint8Array {
  const obj: SecretPayload = { content: p.content };
  if (p.title !== undefined && p.title !== "") obj.title = p.title;
  if (p.syntax !== undefined && p.syntax !== "") obj.syntax = p.syntax;
  const json = utf8Encode(JSON.stringify(obj));
  if (padTo <= 0) return json;
  const target = Math.ceil(json.length / padTo) * padTo;
  const out = new Uint8Array(Math.max(target, padTo === 0 ? json.length : target)).fill(0x20);
  out.set(json);
  json.fill(0);
  return out;
}

export function decodePayload(bytes: Uint8Array): SecretPayload {
  let v: unknown;
  try {
    v = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new ProtocolError("malformed_payload");
  }
  if (typeof v !== "object" || v === null || typeof (v as SecretPayload).content !== "string")
    throw new ProtocolError("malformed_payload");
  const o = v as Record<string, unknown>;
  const out: SecretPayload = { content: o.content as string };
  if (typeof o.title === "string") out.title = o.title;
  if (typeof o.syntax === "string" && o.syntax.length <= 32) out.syntax = o.syntax;
  return out;
}
