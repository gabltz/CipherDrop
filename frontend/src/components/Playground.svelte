<script lang="ts">
  /**
   * Interactive API playground. Plaintext is ALWAYS encrypted locally before
   * any request; the request body shown is exactly what is sent. The optional
   * API token is held in memory only.
   */
  import { FlaskConical, Send } from "@lucide/svelte";
  import {
    ApiError,
    ShareKey,
    attachKey,
    decodeEnvelope,
    decryptPayload,
    encodeEnvelope,
    encryptPayload,
    parseShareLink,
    type CreateShareRequest,
  } from "@cipherdrop/sdk";

  import { describeError } from "../lib/api";

  let token = $state("");
  let plaintext = $state("Hello from the API playground (synthetic example)");
  let ttl = $state(600);
  let reads = $state(1);
  let createReq = $state("");
  let createRes = $state("");
  let link = $state("");
  let consumeLink = $state("");
  let consumeRes = $state("");
  let decrypted = $state("");
  let busy = $state(false);

  function headers(json: boolean): Record<string, string> {
    const h: Record<string, string> = {};
    if (json) h["Content-Type"] = "application/json";
    if (token.trim()) h.Authorization = `Bearer ${token.trim()}`;
    return h;
  }

  async function show(res: Response): Promise<string> {
    const text = await res.text();
    let body = text;
    try {
      body = JSON.stringify(JSON.parse(text), null, 2);
    } catch {
      /* not JSON */
    }
    return `HTTP ${res.status}\n${body}`;
  }

  async function create() {
    busy = true;
    createRes = "";
    link = "";
    const key = ShareKey.generate();
    try {
      const env = await encryptPayload(key, { content: plaintext });
      const body: CreateShareRequest = { ...encodeEnvelope(env), ttl_seconds: ttl, max_reads: reads };
      createReq = `POST /api/v1/shares\nContent-Type: application/json\n\n${JSON.stringify(body, null, 2)}`;
      const res = await fetch("/api/v1/shares", { method: "POST", headers: headers(true), body: JSON.stringify(body), credentials: "omit" });
      const out = res.clone();
      createRes = await show(res);
      if (out.ok) {
        const j = (await out.json()) as { url: string };
        link = attachKey(j.url, key);
        consumeLink = link;
      }
    } catch (e) {
      createRes = describeError(e);
    } finally {
      key.wipe();
      busy = false;
    }
  }

  async function consume() {
    busy = true;
    consumeRes = "";
    decrypted = "";
    try {
      const l = parseShareLink(consumeLink);
      const res = await fetch(`/api/v1/shares/${l.shareId}/consume`, { method: "POST", headers: headers(true), body: "{}", credentials: "omit" });
      const out = res.clone();
      consumeRes = await show(res);
      if (out.ok) {
        const j = await out.json();
        const env = decodeEnvelope({ version: j.version, algorithm: j.algorithm, nonce: j.nonce, ciphertext: j.ciphertext, ...(j.kdf ? { kdf: j.kdf } : {}) });
        decrypted = (await decryptPayload(l.key, env)).content;
      }
      l.key.wipe();
    } catch (e) {
      consumeRes = e instanceof ApiError ? consumeRes : describeError(e);
    } finally {
      busy = false;
    }
  }
</script>

<section class="pg" aria-labelledby="pg-title">
  <h2 id="pg-title"><FlaskConical size={18} /> Interactive playground</h2>
  <p>
    This playground runs against this instance. Plaintext is encrypted <strong>in your browser</strong> before the
    request is sent; the request body below is exactly what leaves your machine. Use synthetic data only.
  </p>
  <div class="row">
    <label class="label" for="pg-token">API token (optional, memory only)</label>
    <input id="pg-token" class="input mono" type="password" bind:value={token} autocomplete="off" placeholder="cdt_…" />
  </div>
  <div class="row">
    <label class="label" for="pg-pt">Plaintext (encrypted locally)</label>
    <textarea id="pg-pt" class="textarea" rows="3" bind:value={plaintext}></textarea>
  </div>
  <div class="inline">
    <label>ttl_seconds <input class="input" type="number" min="60" bind:value={ttl} /></label>
    <label>max_reads <input class="input" type="number" min="1" bind:value={reads} /></label>
    <button class="btn btn-primary" onclick={create} disabled={busy || !plaintext}><Send size={15} /> Encrypt &amp; create</button>
  </div>
  {#if createReq}<pre class="io" data-testid="pg-request">{createReq}</pre>{/if}
  {#if createRes}<pre class="io">{createRes}</pre>{/if}
  {#if link}<p class="small">Share link (key appended locally): <code>{link}</code></p>{/if}

  <div class="row">
    <label class="label" for="pg-link">Share link to consume</label>
    <input id="pg-link" class="input mono" bind:value={consumeLink} autocomplete="off" />
  </div>
  <div class="inline">
    <button class="btn" onclick={consume} disabled={busy || !consumeLink}><Send size={15} /> POST /consume &amp; decrypt locally</button>
  </div>
  {#if consumeRes}<pre class="io">{consumeRes}</pre>{/if}
  {#if decrypted}<p class="small">Decrypted locally: <code>{decrypted}</code></p>{/if}
</section>

<style>
  .pg {
    margin-top: 2.5rem;
    padding: 1.25rem;
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    background: var(--bg-elev);
    display: flex;
    flex-direction: column;
    gap: 0.8rem;
  }
  .pg h2 {
    display: flex;
    gap: 0.5rem;
    align-items: center;
    margin: 0 !important;
    padding: 0 !important;
    border: none !important;
  }
  .pg p {
    margin: 0;
  }
  .inline {
    display: flex;
    gap: 0.75rem;
    align-items: flex-end;
    flex-wrap: wrap;
  }
  .inline label {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
    font-size: 0.78rem;
    font-family: var(--font-mono);
    color: var(--text-muted);
    width: 9rem;
  }
  .io {
    margin: 0;
    background: var(--bg-sunken);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 0.75rem;
    font-size: 0.78rem;
    max-height: 18rem;
    overflow: auto;
    white-space: pre-wrap;
    word-break: break-all;
  }
  .small {
    font-size: 0.82rem;
    word-break: break-all;
  }
</style>
