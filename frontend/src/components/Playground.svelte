<script lang="ts">
  /**
   * Interactive API playground. Plaintext is always encrypted locally before
   * any request; the request body shown is exactly what is sent. The optional
   * API token is held in memory only.
   */
  import { ShareKey, attachKey, decodeEnvelope, decryptPayload, encodeEnvelope, encryptPayload, parseShareLink, type CreateShareRequest } from "@cipherdrop/sdk";

  import { describeError } from "../lib/api";

  let token = $state("");
  let plaintext = $state("Hello from the API playground (synthetic example)");
  let createReq = $state("");
  let createRes = $state("");
  let consumeLink = $state("");
  let consumeRes = $state("");
  let decrypted = $state("");
  let busy = $state(false);

  function headers(): Record<string, string> {
    const h: Record<string, string> = { "Content-Type": "application/json" };
    if (token.trim()) h.Authorization = `Bearer ${token.trim()}`;
    return h;
  }

  async function show(res: Response): Promise<string> {
    const text = await res.text();
    try {
      return `HTTP ${res.status}\n${JSON.stringify(JSON.parse(text), null, 2)}`;
    } catch {
      return `HTTP ${res.status}\n${text}`;
    }
  }

  async function create() {
    busy = true;
    const key = ShareKey.generate();
    try {
      const env = await encryptPayload(key, { content: plaintext });
      const body: CreateShareRequest = { ...encodeEnvelope(env), ttl_seconds: 600, max_reads: 1 };
      createReq = `POST /api/v1/shares\n\n${JSON.stringify(body, null, 2)}`;
      const res = await fetch("/api/v1/shares", { method: "POST", headers: headers(), body: JSON.stringify(body), credentials: "omit" });
      const copy = res.clone();
      createRes = await show(res);
      if (copy.ok) consumeLink = attachKey(((await copy.json()) as { url: string }).url, key);
    } catch (e) {
      createRes = describeError(e);
    } finally {
      key.wipe();
      busy = false;
    }
  }

  async function consume() {
    busy = true;
    decrypted = "";
    try {
      const l = parseShareLink(consumeLink);
      const res = await fetch(`/api/v1/shares/${l.shareId}/consume`, { method: "POST", headers: headers(), body: "{}", credentials: "omit" });
      const copy = res.clone();
      consumeRes = await show(res);
      if (copy.ok) {
        const j = await copy.json();
        const env = decodeEnvelope({ version: j.version, algorithm: j.algorithm, nonce: j.nonce, ciphertext: j.ciphertext, ...(j.kdf ? { kdf: j.kdf } : {}) });
        decrypted = (await decryptPayload(l.key, env)).content;
      }
      l.key.wipe();
    } catch (e) {
      consumeRes = describeError(e);
    } finally {
      busy = false;
    }
  }
</script>

<hr />
<h2 id="pg-title">Playground</h2>
<p class="small">Runs against this instance. Plaintext is encrypted in your browser first; the body below is exactly what is sent. Use synthetic data.</p>
<div class="field">
  <label for="pg-token">API token (optional, memory only)</label>
  <input id="pg-token" class="mono" type="password" bind:value={token} autocomplete="off" />
</div>
<div class="field">
  <label for="pg-pt">Plaintext</label>
  <input id="pg-pt" type="text" bind:value={plaintext} />
</div>
<p><button onclick={create} disabled={busy || !plaintext}>Encrypt &amp; create</button></p>
{#if createReq}<pre data-testid="pg-request">{createReq}</pre>{/if}
{#if createRes}<pre>{createRes}</pre>{/if}
<div class="field">
  <label for="pg-link">Share link to consume</label>
  <input id="pg-link" class="mono" type="text" bind:value={consumeLink} autocomplete="off" />
</div>
<p><button onclick={consume} disabled={busy || !consumeLink}>Consume &amp; decrypt locally</button></p>
{#if consumeRes}<pre>{consumeRes}</pre>{/if}
{#if decrypted}<p class="small">Decrypted locally: <code>{decrypted}</code></p>{/if}
