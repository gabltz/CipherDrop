<script lang="ts">
  /**
   * Secret retrieval. Loading the page only performs a non-consuming status
   * request; the ciphertext is fetched exclusively after an explicit click.
   * For password-protected shares the password is verified by the server
   * (via the derived access key) before anything is consumed, so a wrong
   * password simply asks again. The key is read from the URL fragment into
   * memory and the fragment is removed from the address bar on reveal.
   */
  import {
    ApiError,
    ProtocolError,
    ShareKey,
    b64urlEncode,
    decodeEnvelope,
    decodeKdf,
    decodePayload,
    decryptPayload,
    decryptWithCek,
    derivePasswordKeys,
    type DecodedEnvelope,
    type SecretPayload,
    type ShareStatusResponse,
  } from "@cipherdrop/sdk";
  import { onDestroy } from "svelte";

  import CopyButton from "../components/CopyButton.svelte";
  import { client, describeError, setApiToken } from "../lib/api";
  import { formatExpiry, formatReads } from "../lib/util";

  let { id }: { id: string } = $props();

  type Phase = "checking" | "ready" | "working" | "revealed" | "unavailable" | "destroyed" | "invalid" | "error" | "auth";
  let phase = $state<Phase>("checking");
  let status = $state<ShareStatusResponse | null>(null);
  let message = $state("");
  let password = $state("");
  let wrongPassword = $state(false);
  let apiToken = $state("");
  let payload = $state<SecretPayload | null>(null);
  let remaining = $state<number | null>(null);

  let key: ShareKey | null = null;
  // Legacy password shares without a server-side gate: keep ciphertext for local retries.
  let held = $state.raw<DecodedEnvelope | null>(null);

  function readKey(): ShareKey | null {
    const h = location.hash;
    if (!h.startsWith("#v1.")) return null;
    try {
      return ShareKey.fromBase64Url(h.slice(4));
    } catch {
      return null;
    }
  }

  function stripFragment() {
    if (location.hash) history.replaceState(null, "", location.pathname + location.search);
  }

  key = readKey();
  if (!key) phase = "invalid";
  else check();

  async function check() {
    try {
      status = await client().status(id);
      phase = "ready";
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) phase = "auth";
      else if (e instanceof ApiError && e.code === "share_unavailable") {
        phase = "unavailable";
        stripFragment();
      } else {
        phase = "error";
        message = describeError(e);
      }
    }
  }

  async function submitToken(e: Event) {
    e.preventDefault();
    setApiToken(apiToken);
    phase = "checking";
    await check();
  }

  function done(p: SecretPayload) {
    payload = p;
    phase = "revealed";
    password = "";
    key?.wipe();
    key = null;
    held?.ciphertext.fill(0);
    held = null;
  }

  async function reveal(e: Event) {
    e.preventDefault();
    if (!key || !status || phase === "working") return;
    if (status.password_protected && !password) return;
    phase = "working";
    wrongPassword = false;
    try {
      if (held) {
        done(await decryptPayload(key, held, password));
        return;
      }
      let accessKey: string | undefined;
      let cek: Uint8Array | undefined;
      if (status.password_protected && status.kdf) {
        const keys = await derivePasswordKeys(key, decodeKdf(status.kdf), password);
        cek = keys.cek;
        if (status.access_protected) accessKey = b64urlEncode(keys.accessKey);
        keys.accessKey.fill(0);
      }
      const r = await client().consume(id, accessKey);
      stripFragment();
      remaining = r.remaining_reads;
      const env = decodeEnvelope({ version: r.version, algorithm: r.algorithm, nonce: r.nonce, ciphertext: r.ciphertext, ...(r.kdf ? { kdf: r.kdf } : {}) });
      if (cek) {
        try {
          const bytes = await decryptWithCek(cek, env);
          done(decodePayload(bytes));
          bytes.fill(0);
        } catch (err) {
          if (!status.access_protected && err instanceof ProtocolError && err.code === "decryption") {
            held = env; // ungated legacy share: already consumed, retry locally
            wrongPassword = true;
            phase = "ready";
            return;
          }
          throw err;
        } finally {
          cek.fill(0);
        }
      } else {
        done(await decryptPayload(key, env));
      }
    } catch (err) {
      if (err instanceof ApiError && err.code === "access_denied") {
        wrongPassword = true;
        phase = "ready";
      } else if (err instanceof ApiError && err.code === "share_destroyed") {
        phase = "destroyed";
        stripFragment();
      } else if (err instanceof ApiError && err.code === "share_unavailable") {
        phase = "unavailable";
        stripFragment();
      } else if (err instanceof ProtocolError && err.code === "decryption" && held) {
        wrongPassword = true;
        phase = "ready";
      } else {
        phase = "error";
        message = describeError(err);
      }
    }
  }

  onDestroy(() => {
    key?.wipe();
    held?.ciphertext.fill(0);
  });
</script>

<svelte:head><title>Secret · CipherDrop</title></svelte:head>

{#if phase === "checking"}
  <p class="muted">Checking link…</p>
{:else if phase === "invalid"}
  <section data-testid="state-invalid">
    <h1>Incomplete link</h1>
    <p class="muted">The decryption key (after <code>#v1.</code>) is missing. Copy the entire link.</p>
  </section>
{:else if phase === "unavailable"}
  <section data-testid="state-unavailable">
    <h1>Not available</h1>
    <p class="muted">This secret has expired, was already viewed, or was revoked.</p>
    <a href="/">Create a secret</a>
  </section>
{:else if phase === "destroyed"}
  <section data-testid="state-destroyed">
    <h1>Secret destroyed</h1>
    <p class="muted">Too many wrong passwords were entered, so the secret was deleted.</p>
  </section>
{:else if phase === "error"}
  <section data-testid="state-error">
    <h1>Error</h1>
    <p class="muted">{message}</p>
  </section>
{:else if phase === "auth"}
  <form onsubmit={submitToken}>
    <h1>Authentication required</h1>
    <div class="field">
      <label for="rtoken">API token with shares:consume (kept in memory only)</label>
      <input id="rtoken" class="mono" type="password" bind:value={apiToken} autocomplete="off" />
    </div>
    <button class="primary" type="submit" disabled={!apiToken}>Continue</button>
  </form>
{:else if phase === "ready" || phase === "working"}
  <form onsubmit={reveal} data-testid="state-ready">
    <h1>You received a secret</h1>
    {#if status}
      <p class="muted small">Expires {formatExpiry(status.expires_at)} · {formatReads(status.remaining_reads)} left</p>
      {#if status.remaining_reads === 1 && !held}
        <p class="warn small" data-testid="one-time-warning">It can be viewed only once. It is deleted when you reveal it.</p>
      {/if}
    {/if}
    {#if status?.password_protected}
      <div class="field">
        <label for="pw">Password</label>
        <input id="pw" type="password" bind:value={password} autocomplete="off" data-testid="reveal-password" aria-invalid={wrongPassword} />
        {#if wrongPassword}<p class="err small" role="alert">Wrong password. Nothing was revealed; try again.</p>{/if}
      </div>
    {/if}
    <button class="primary" type="submit" disabled={phase === "working" || (status?.password_protected && !password)} data-testid="reveal">
      {phase === "working" ? "Decrypting…" : "Reveal secret"}
    </button>
  </form>
{:else if phase === "revealed" && payload}
  <section data-testid="state-revealed">
    <h1 data-testid="revealed-title">{payload.title ?? "Secret"}</h1>
    <pre data-testid="revealed-content">{payload.content}</pre>
    <div class="row">
      <CopyButton text={() => payload?.content ?? ""} testid="copy-secret" />
      <span class="muted small">{remaining === 0 ? "Deleted from the server." : remaining === null ? "" : `${formatReads(remaining)} left.`}</span>
    </div>
  </section>
{/if}
