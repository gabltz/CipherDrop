<script lang="ts">
  /**
   * Secret retrieval.
   *
   * Loading this page never consumes the share: it only performs a
   * non-consuming status request. The ciphertext is fetched exclusively via
   * POST /consume after the user clicks "Reveal secret". The key is read from
   * the URL fragment into memory and the fragment is removed from the address
   * bar (and the current history entry) at reveal time.
   */
  import { Clock, Eye, Flame, KeyRound, LockKeyhole, ShieldCheck, TriangleAlert } from "@lucide/svelte";
  import {
    ApiError,
    ProtocolError,
    ShareKey,
    decodeEnvelope,
    decryptPayload,
    type DecodedEnvelope,
    type SecretPayload,
    type ShareStatusResponse,
  } from "@cipherdrop/sdk";
  import { onDestroy } from "svelte";

  import CopyButton from "../components/CopyButton.svelte";
  import { client, describeError, setApiToken } from "../lib/api";
  import { formatExpiry, formatReads, highlight } from "../lib/util";

  let { id }: { id: string } = $props();

  type Phase = "checking" | "ready" | "revealing" | "password" | "revealed" | "unavailable" | "invalid" | "error" | "auth";

  let phase = $state<Phase>("checking");
  let status = $state<ShareStatusResponse | null>(null);
  let message = $state("");
  let password = $state("");
  let apiToken = $state("");
  let payload = $state<SecretPayload | null>(null);
  let remaining = $state<number | null>(null);
  let highlightOn = $state(true);
  let wrongPassword = $state(false);

  // Secret material held in memory only.
  let key: ShareKey | null = null;
  let envelope: DecodedEnvelope | null = null;

  function readKeyFromFragment(): ShareKey | null {
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

  key = readKeyFromFragment();
  if (!key) {
    phase = "invalid";
  } else {
    checkStatus();
  }

  async function checkStatus() {
    try {
      status = await client().status(id);
      phase = "ready";
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        phase = "auth";
      } else if (e instanceof ApiError && e.code === "share_unavailable") {
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
    await checkStatus();
  }

  async function reveal(e?: Event) {
    e?.preventDefault();
    if (!key || phase === "revealing") return;
    if (status?.password_protected && !password) return;
    phase = "revealing";
    // The link is used up (or about to be); remove the key from the address bar.
    stripFragment();
    try {
      const r = await client().consume(id);
      remaining = r.remaining_reads;
      envelope = decodeEnvelope({
        version: r.version,
        algorithm: r.algorithm,
        nonce: r.nonce,
        ciphertext: r.ciphertext,
        ...(r.kdf ? { kdf: r.kdf } : {}),
      });
    } catch (err) {
      if (err instanceof ApiError && err.code === "share_unavailable") {
        phase = "unavailable";
      } else {
        phase = "error";
        message = describeError(err);
      }
      return;
    }
    await decryptHeld();
  }

  /** Decrypt the ciphertext held in memory. Password retries do not re-consume. */
  async function decryptHeld(e?: Event) {
    e?.preventDefault();
    const env = envelope;
    if (!key || !env) return;
    if (env.kdf && !password) {
      phase = "password";
      return;
    }
    phase = "revealing";
    try {
      payload = await decryptPayload(key, env, env.kdf ? password : undefined);
      phase = "revealed";
      password = "";
      key.wipe();
      key = null;
      env.ciphertext.fill(0);
      envelope = null;
    } catch (err) {
      if (err instanceof ProtocolError && err.code === "decryption" && env.kdf) {
        wrongPassword = true;
        phase = "password";
      } else {
        phase = "error";
        message = describeError(err);
      }
    }
  }

  function hide() {
    payload = null;
    phase = "unavailable";
    message = "";
  }

  onDestroy(() => {
    key?.wipe();
    envelope?.ciphertext.fill(0);
    payload = null;
  });

  const highlighted = $derived(payload && highlightOn ? highlight(payload.content, payload.syntax) : null);

  $effect(() => {
    document.title = "Secret · CipherDrop";
  });
</script>

<div class="page">
  {#if phase === "checking"}
    <div class="card panel center" aria-busy="true"><span class="spinner"></span> Checking link…</div>
  {:else if phase === "invalid"}
    <div class="card panel" data-testid="state-invalid">
      <h1><TriangleAlert size={20} /> Incomplete link</h1>
      <p class="muted">
        This link is missing its decryption key (the part after <code>#v1.</code>). Make sure you copied the entire link.
        Some chat apps and email clients truncate long links.
      </p>
    </div>
  {:else if phase === "unavailable"}
    <div class="card panel" data-testid="state-unavailable">
      <h1><Flame size={20} /> {payload === null && message === "" && remaining === 0 ? "Secret destroyed" : "This secret is no longer available"}</h1>
      <p class="muted">
        It may have expired, been viewed the maximum number of times, or been revoked by its creator. CipherDrop
        cannot tell which: once a secret is gone, nothing about it is kept.
      </p>
      <a class="btn" href="/">Create a new secret</a>
    </div>
  {:else if phase === "error"}
    <div class="card panel" data-testid="state-error">
      <h1><TriangleAlert size={20} /> Something went wrong</h1>
      <p class="muted">{message}</p>
    </div>
  {:else if phase === "auth"}
    <form class="card panel" onsubmit={submitToken}>
      <h1><KeyRound size={20} /> Authentication required</h1>
      <p class="muted">This instance requires an API token with <code>shares:consume</code> to retrieve secrets. It is kept in memory only.</p>
      <label class="label" for="rtoken">API token</label>
      <input id="rtoken" class="input mono" type="password" bind:value={apiToken} autocomplete="off" />
      <div><button class="btn btn-primary" type="submit" disabled={!apiToken}>Continue</button></div>
    </form>
  {:else if phase === "ready" || phase === "revealing" || phase === "password"}
    <form class="card panel" onsubmit={phase === "password" ? decryptHeld : reveal} data-testid="state-ready">
      <div class="head">
        <span class="lock" aria-hidden="true"><LockKeyhole size={20} /></span>
        <div>
          <h1>Someone shared a secret with you</h1>
          <p class="muted">It will be decrypted in your browser. The server cannot read it.</p>
        </div>
      </div>
      {#if status}
        <div class="facts">
          <span class="badge"><Clock size={12} /> {formatExpiry(status.expires_at)}</span>
          <span class="badge"><Eye size={12} /> {formatReads(status.remaining_reads)} left</span>
          {#if status.password_protected}<span class="badge"><KeyRound size={12} /> Password protected</span>{/if}
        </div>
        {#if status.remaining_reads === 1 && phase !== "password"}
          <div class="callout warning" data-testid="one-time-warning">
            <Flame size={16} />
            <div>
              <strong>This secret can be viewed only once.</strong> After you reveal it, it is permanently deleted from
              the server. Make sure you are ready to copy or store it.
            </div>
          </div>
        {/if}
      {/if}
      {#if status?.password_protected || phase === "password"}
        <div>
          <label class="label" for="pw">Password</label>
          <input
            id="pw"
            class="input"
            type="password"
            bind:value={password}
            autocomplete="off"
            data-testid="reveal-password"
            aria-invalid={wrongPassword}
            aria-describedby={wrongPassword ? "pw-err" : undefined}
          />
          {#if wrongPassword}<p id="pw-err" class="hint err" role="alert">Wrong password. The secret is held in this tab's memory; try again.</p>{/if}
          {#if phase === "password" && !wrongPassword}<p class="hint">The encrypted secret was retrieved. Enter the password to decrypt it locally.</p>{/if}
        </div>
      {/if}
      <div>
        <button class="btn btn-primary btn-lg" type="submit" disabled={phase === "revealing" || ((status?.password_protected || phase === "password") && !password)} data-testid="reveal">
          {#if phase === "revealing"}<span class="spinner"></span> Decrypting…{:else if phase === "password"}<KeyRound size={16} /> Decrypt{:else}<Eye size={16} /> Reveal secret{/if}
        </button>
      </div>
    </form>
  {:else if phase === "revealed" && payload}
    <section class="card panel" data-testid="state-revealed">
      <div class="reveal-head">
        <div>
          {#if payload.title}<h1 class="title" data-testid="revealed-title">{payload.title}</h1>{:else}<h1 class="title">Secret</h1>{/if}
          <p class="muted small">
            <ShieldCheck size={13} /> Decrypted locally.
            {#if remaining === 0}This secret has now been deleted from the server.{:else if remaining !== null}{formatReads(remaining)} remaining.{/if}
          </p>
        </div>
        <div class="tools">
          {#if payload.syntax && highlight("", payload.syntax) !== null}
            <label class="switch small"><input type="checkbox" bind:checked={highlightOn} /><span class="track"></span>Highlight</label>
          {/if}
          <CopyButton text={() => payload?.content ?? ""} variant="primary" testid="copy-secret" />
        </div>
      </div>
      <!-- Plain text is rendered through Svelte text interpolation (always escaped).
           Highlighted output comes from highlight.js, which escapes its input and
           only adds <span class="hljs-*"> wrappers; the CSP additionally forbids
           inline scripts and event handlers. -->
      {#if highlighted !== null}
        <!-- eslint-disable-next-line svelte/no-at-html-tags -->
        <pre class="content" data-testid="revealed-content"><code class="hljs">{@html highlighted}</code></pre>
      {:else}
        <pre class="content" data-testid="revealed-content"><code>{payload.content}</code></pre>
      {/if}
      <div class="actions">
        <button type="button" class="btn" onclick={hide}>Hide and clear from this page</button>
        <a class="btn btn-ghost" href="/">Create your own secret</a>
      </div>
    </section>
  {/if}
</div>

<style>
  .page {
    max-width: 880px;
    margin: 0 auto;
    padding: 2.5rem 1.25rem 1rem;
  }
  .panel {
    padding: 1.5rem;
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }
  .center {
    flex-direction: row;
    align-items: center;
    justify-content: center;
    color: var(--text-muted);
  }
  h1 {
    display: flex;
    gap: 0.5rem;
    align-items: center;
    font-size: 1.3rem;
    letter-spacing: -0.02em;
    margin: 0;
  }
  .muted {
    color: var(--text-muted);
    margin: 0;
  }
  .small {
    font-size: 0.83rem;
  }
  .head {
    display: flex;
    gap: 0.9rem;
    align-items: flex-start;
  }
  .head h1 {
    margin-bottom: 0.15rem;
  }
  .lock {
    display: grid;
    place-items: center;
    width: 2.4rem;
    height: 2.4rem;
    border-radius: 10px;
    background: var(--accent-soft);
    color: var(--accent);
    flex-shrink: 0;
  }
  .facts {
    display: flex;
    gap: 0.4rem;
    flex-wrap: wrap;
  }
  .err {
    color: var(--danger);
  }
  .reveal-head {
    display: flex;
    justify-content: space-between;
    gap: 1rem;
    align-items: flex-start;
    flex-wrap: wrap;
  }
  .title {
    word-break: break-word;
  }
  .reveal-head p {
    display: flex;
    gap: 0.35rem;
    align-items: center;
    margin-top: 0.25rem;
  }
  .tools {
    display: flex;
    gap: 0.75rem;
    align-items: center;
  }
  .content {
    margin: 0;
    padding: 1rem;
    background: var(--bg-sunken);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    overflow: auto;
    max-height: 60vh;
    white-space: pre-wrap;
    word-break: break-word;
    font-size: 0.87rem;
    line-height: 1.6;
  }
  .actions {
    display: flex;
    gap: 0.5rem;
    flex-wrap: wrap;
  }
</style>
