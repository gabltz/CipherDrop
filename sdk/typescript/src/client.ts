/**
 * HTTP client for the CipherDrop /api/v1 API. All encryption happens locally
 * before any request is made; the key never leaves this process.
 */

import { ShareKey, decryptPayload, encryptPayload, type KdfCost } from "./crypto.js";
import {
  ProtocolError,
  decodeEnvelope,
  encodeEnvelope,
  type ConfigResponse,
  type ConsumeShareResponse,
  type CreateShareRequest,
  type CreateShareResponse,
  type Problem,
  type SecretPayload,
  type ShareStatusResponse,
  type StorageBackend,
} from "./protocol.js";
import { attachKey, parseRevocationLink, parseShareLink, validateRevocationToken, validateShareId } from "./url.js";

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly problem?: Problem,
  ) {
    super(problem ? `${problem.title} (${problem.code})` : `HTTP ${status}`);
    this.name = "ApiError";
  }
  get code(): string | undefined {
    return this.problem?.code;
  }
}

export interface ClientOptions {
  /** Base URL, e.g. https://paste.example.com. Use "" in the browser for same-origin. */
  baseUrl: string;
  /** API token (cdt_...). Kept in memory only. */
  apiKey?: string | undefined;
  /** Custom fetch (e.g. for proxies or testing). */
  fetch?: typeof fetch;
  /** Allow http:// base URLs (local development only). */
  allowInsecureHttp?: boolean;
}

export interface CreateOptions {
  /** Lifetime in seconds; omit for the server default. `null` = never expire (requires authorization). */
  ttl?: number | null;
  /** Maximum retrievals; omit for the server default. `null` = unlimited (if allowed). */
  maxReads?: number | null;
  password?: string;
  kdfCost?: KdfCost;
  title?: string;
  syntax?: string;
  storage?: StorageBackend;
  idempotencyKey?: string;
  /** Pad the plaintext payload to a multiple of this many bytes (default 256). */
  padTo?: number;
}

export interface CreatedShare {
  /** Complete link including the #v1.<key> fragment. Treat as a secret. */
  url: string;
  id: string;
  expiresAt: string | null;
  maxReads: number | null;
  storage: StorageBackend;
  /** Treat as a secret; do not give to recipients. */
  revocationToken: string;
  revocationUrl: string;
}

export class CipherDrop {
  private readonly base: string;
  private readonly apiKey: string | undefined;
  private readonly fetchImpl: typeof fetch;

  constructor(opts: ClientOptions) {
    const base = opts.baseUrl.replace(/\/+$/, "");
    if (base !== "") {
      const u = new URL(base);
      if (u.protocol !== "https:" && !(u.protocol === "http:" && opts.allowInsecureHttp))
        throw new Error("refusing non-HTTPS base URL (set allowInsecureHttp for local testing)");
      if (u.hash || u.search) throw new Error("base URL must not contain a query or fragment");
    }
    this.base = base;
    this.apiKey = opts.apiKey || undefined;
    this.fetchImpl = opts.fetch ?? globalThis.fetch.bind(globalThis);
  }

  private async call<T>(method: string, path: string, init: { body?: unknown; headers?: Record<string, string> } = {}): Promise<T> {
    const headers: Record<string, string> = { Accept: "application/json", ...init.headers };
    if (this.apiKey) headers.Authorization = `Bearer ${this.apiKey}`;
    let body: string | undefined;
    if (init.body !== undefined) {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify(init.body);
    }
    const res = await this.fetchImpl(`${this.base}${path}`, {
      method,
      headers,
      body,
      redirect: "error",
      referrerPolicy: "no-referrer",
      credentials: "omit",
      cache: "no-store",
    });
    if (res.ok) {
      if (res.status === 204) return undefined as T;
      return (await res.json()) as T;
    }
    let problem: Problem | undefined;
    try {
      problem = (await res.json()) as Problem;
    } catch {
      problem = undefined;
    }
    throw new ApiError(res.status, problem);
  }

  config(): Promise<ConfigResponse> {
    return this.call("GET", "/api/v1/config");
  }

  /** Encrypt `payload` locally and upload only the ciphertext. */
  async create(payload: SecretPayload, opts: CreateOptions = {}): Promise<CreatedShare> {
    const key = ShareKey.generate();
    try {
      const env = await encryptPayload(key, payload, {
        ...(opts.password !== undefined ? { password: opts.password } : {}),
        ...(opts.kdfCost ? { cost: opts.kdfCost } : {}),
        ...(opts.padTo !== undefined ? { padTo: opts.padTo } : {}),
      });
      const body: CreateShareRequest = { ...encodeEnvelope(env) };
      if (opts.ttl !== undefined) body.ttl_seconds = opts.ttl;
      if (opts.maxReads !== undefined) body.max_reads = opts.maxReads;
      if (opts.storage) body.storage = opts.storage;
      const headers: Record<string, string> = {};
      if (opts.idempotencyKey) headers["Idempotency-Key"] = opts.idempotencyKey;
      const r = await this.call<CreateShareResponse>("POST", "/api/v1/shares", { body, headers });
      return {
        url: attachKey(r.url, key),
        id: r.id,
        expiresAt: r.expires_at,
        maxReads: r.max_reads,
        storage: r.storage,
        revocationToken: r.revocation_token,
        revocationUrl: r.revocation_url,
      };
    } finally {
      key.wipe();
    }
  }

  /** Convenience wrapper sharing plain text. */
  createSecret(text: string, opts: CreateOptions = {}): Promise<CreatedShare> {
    return this.create(
      { content: text, ...(opts.title ? { title: opts.title } : {}), ...(opts.syntax ? { syntax: opts.syntax } : {}) },
      opts,
    );
  }

  /** Raw consume: atomically uses one retrieval and returns the envelope. Never retried. */
  consume(shareId: string): Promise<ConsumeShareResponse> {
    validateShareId(shareId);
    return this.call("POST", `/api/v1/shares/${shareId}/consume`, { body: {} });
  }

  /** Consume one retrieval and decrypt locally. Never retried automatically. */
  async read(link: string, password?: string): Promise<SecretPayload & { remainingReads: number | null }> {
    const l = parseShareLink(link);
    try {
      if (password === undefined && (await this.status(l.shareId)).password_protected) {
        // Fail before consuming: a retrieval must not be burned without the password.
        throw new ProtocolError("password_required");
      }
      const r = await this.consume(l.shareId);
      const env = decodeEnvelope({
        version: r.version,
        algorithm: r.algorithm,
        nonce: r.nonce,
        ciphertext: r.ciphertext,
        ...(r.kdf ? { kdf: r.kdf } : {}),
      });
      const p = await decryptPayload(l.key, env, password);
      return { ...p, remainingReads: r.remaining_reads };
    } finally {
      l.key.wipe();
    }
  }

  /** Non-consuming status. */
  status(shareIdOrLink: string): Promise<ShareStatusResponse> {
    const id = shareIdOrLink.includes("#") ? parseShareLink(shareIdOrLink).shareId : validateShareId(shareIdOrLink);
    return this.call("GET", `/api/v1/shares/${id}/status`);
  }

  /** Revoke with a revocation token, or with an API key holding shares:revoke. */
  async revoke(shareId: string, revocationToken?: string): Promise<void> {
    validateShareId(shareId);
    const headers: Record<string, string> = {};
    if (revocationToken !== undefined) headers["X-Revocation-Token"] = validateRevocationToken(revocationToken);
    await this.call<unknown>("DELETE", `/api/v1/shares/${shareId}`, { headers });
  }

  revokeWithLink(revocationLink: string): Promise<void> {
    const l = parseRevocationLink(revocationLink);
    return this.revoke(l.shareId, l.token);
  }
}
