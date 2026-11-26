<script lang="ts">
  import {
    ChevronDown,
    Clock,
    Database,
    Eye,
    EyeOff,
    Flame,
    KeyRound,
    Link,
    LockKeyhole,
    Plus,
    ShieldCheck,
    TriangleAlert,
  } from "@lucide/svelte";
  import type { ConfigResponse, CreatedShare } from "@cipherdrop/sdk";

  import CopyButton from "../components/CopyButton.svelte";
  import { client, describeError, hasApiToken, instanceConfig, setApiToken } from "../lib/api";
  import { formatDuration, formatExpiry, formatReads, LANGUAGES } from "../lib/util";

  const TTL_CHOICES = [300, 3600, 86_400, 7 * 86_400, 30 * 86_400];

  let cfg = $state<ConfigResponse | null>(null);
  let cfgError = $state("");

  let content = $state("");
  let title = $state("");
  let syntax = $state("");
  let ttl = $state<number | "never">(3600);
  let burn = $state(true);
  let maxReads = $state(3);
  let unlimited = $state(false);
  let usePassword = $state(false);
  let password = $state("");
  let showPassword = $state(false);
  let persistent = $state(false);
  let apiToken = $state("");
  let showAdvanced = $state(false);

  let busy = $state(false);
  let error = $state("");
  let created = $state<CreatedShare | null>(null);
  let showRevoke = $state(false);

  instanceConfig()
    .then((c) => {
      cfg = c;
      const choices = ttlChoices(c);
      ttl = choices.includes(c.default_ttl_seconds) ? c.default_ttl_seconds : (choices[0] ?? c.default_ttl_seconds);
      maxReads = Math.min(3, c.max_reads);
    })
    .catch((e) => (cfgError = describeError(e)));

  function ttlChoices(c: ConfigResponse): number[] {
    const all = [...TTL_CHOICES.filter((t) => t <= c.max_ttl_seconds), c.default_ttl_seconds];
    return all.filter((t, i) => all.indexOf(t) === i).sort((a, b) => a - b);
  }

  const needsToken = $derived(cfg !== null && !cfg.anonymous_creation);
  const bytes = $derived(new TextEncoder().encode(content).length);
  const tooLarge = $derived(cfg !== null && bytes + 512 > cfg.max_ciphertext_bytes);
  const canSubmit = $derived(
    cfg !== null && content.length > 0 && !tooLarge && !busy && (!usePassword || password.length > 0) && (!needsToken || apiToken.trim() !== ""),
  );

  async function submit(e?: Event) {
    e?.preventDefault();
    if (!canSubmit || !cfg) return;
    busy = true;
    error = "";
    try {
      setApiToken(apiToken || undefined);
      const share = await client().create(
        { content, ...(title ? { title } : {}), ...(syntax ? { syntax } : {}) },
        {
          ttl: ttl === "never" ? null : ttl,
          maxReads: burn ? 1 : unlimited ? null : maxReads,
          ...(usePassword ? { password } : {}),
          ...(persistent ? { storage: "persistent" as const } : {}),
        },
      );
      created = share;
      // Drop plaintext and password from memory as soon as possible.
      content = "";
      title = "";
      password = "";
    } catch (err) {
      error = describeError(err);
    } finally {
      busy = false;
    }
  }

  function reset() {
    created = null;
    showRevoke = false;
    content = "";
    title = "";
    password = "";
    usePassword = false;
    error = "";
    queueMicrotask(() => document.getElementById("secret")?.focus());
  }

  function onKeydown(e: KeyboardEvent) {
    if ((e.metaKey || e.ctrlKey) && e.key === "Enter") submit(e);
  }

  $effect(() => {
    document.title = created ? "Link created · CipherDrop" : "New secret · CipherDrop";
  });
</script>

<div class="page">
  {#if created}
    <section class="card result" aria-labelledby="done-title" data-testid="share-created">
      <div class="result-head">
        <span class="ok-icon" aria-hidden="true"><ShieldCheck size={20} /></span>
        <div>
          <h1 id="done-title">Your secure link is ready</h1>
          <p class="muted">Encrypted in this browser. The decryption key is the part after <code>#</code> and was never sent to the server.</p>
        </div>
      </div>

      <label class="label" for="share-url">Share link</label>
      <div class="url-row">
        <input id="share-url" class="input mono" readonly value={created.url} data-testid="share-url" onfocus={(e) => e.currentTarget.select()} />
        <CopyButton text={() => created?.url ?? ""} variant="primary" testid="copy-url" />
      </div>

      <dl class="facts">
        <div><dt><Clock size={14} />Expires</dt><dd>{formatExpiry(created.expiresAt)}</dd></div>
        <div>
          <dt><Eye size={14} />Retrieval limit</dt>
          <dd>{created.maxReads === 1 ? "Burns after the first view" : formatReads(created.maxReads)}</dd>
        </div>
        <div><dt><Database size={14} />Storage</dt><dd>{created.storage === "memory" ? "RAM only" : "Persistent (encrypted)"}</dd></div>
        {#if usePassword}
          <div><dt><KeyRound size={14} />Password</dt><dd>Required. Share it through a different channel</dd></div>
        {/if}
      </dl>

      <div class="callout warning">
        <TriangleAlert size={16} />
        <div>
          Anyone who has the <strong>complete link</strong> can decrypt this secret. Send it only to the intended
          recipient, preferably over a different channel than any password.
        </div>
      </div>

      <details class="revoke" bind:open={showRevoke}>
        <summary>Revocation link <span class="muted">(keep it private; do not send it to the recipient)</span></summary>
        <p class="muted small">Opening this link lets you delete the secret before it is read.</p>
        <div class="url-row">
          <input class="input mono" readonly value={created.revocationUrl} data-testid="revocation-url" onfocus={(e) => e.currentTarget.select()} />
          <CopyButton text={() => created?.revocationUrl ?? ""} />
        </div>
      </details>

      <div class="actions">
        <button type="button" class="btn btn-lg" onclick={reset} data-testid="create-another"><Plus size={16} />Create another secret</button>
      </div>
    </section>
  {:else}
    <header class="hero">
      <h1>Share a secret, safely.</h1>
      <p class="muted">
        Text is encrypted in your browser with AES-256-GCM before upload. The key lives only in the link you share.
        The server stores ciphertext in RAM and deletes it after it is read.
      </p>
    </header>

    {#if cfgError}
      <div class="callout danger" role="alert">{cfgError}</div>
    {/if}

    <form class="card form" onsubmit={submit} aria-label="Create a secret">
      <div class="field">
        <label class="sr-only" for="secret">Secret</label>
        <textarea
          id="secret"
          class="textarea editor"
          bind:value={content}
          placeholder="Paste a password, API key, private note or code snippet…"
          spellcheck="false"
          autocomplete="off"
          autocapitalize="off"
          data-gramm="false"
          onkeydown={onKeydown}
          data-testid="secret-input"
        ></textarea>
        <div class="meta">
          <span class:danger={tooLarge}>{cfg ? `${bytes.toLocaleString()} / ${cfg.max_ciphertext_bytes.toLocaleString()} bytes` : `${bytes.toLocaleString()} bytes`}</span>
          <span class="muted"><kbd>⌘</kbd>/<kbd>Ctrl</kbd> + <kbd>Enter</kbd> to create</span>
        </div>
      </div>

      <div class="grid">
        <div>
          <label class="label" for="ttl">Expires after</label>
          <select id="ttl" class="select" bind:value={ttl} data-testid="ttl">
            {#if cfg}
              {#each ttlChoices(cfg) as t (t)}<option value={t}>{formatDuration(t)}</option>{/each}
              {#if cfg.allow_permanent}<option value="never">Never (requires authorization)</option>{/if}
            {/if}
          </select>
        </div>
        <div>
          <span class="label">Burn after reading</span>
          <label class="switch">
            <input type="checkbox" bind:checked={burn} data-testid="burn" />
            <span class="track"></span>
            <span><Flame size={14} class="inline-icon" /> {burn ? "Delete after the first view" : "Allow multiple views"}</span>
          </label>
        </div>
        {#if !burn && cfg}
          <div>
            <label class="label" for="reads">Maximum views</label>
            <input id="reads" class="input" type="number" min="1" max={cfg.max_reads} bind:value={maxReads} disabled={unlimited} data-testid="max-reads" />
            {#if cfg.allow_unlimited_reads}
              <label class="check"><input type="checkbox" bind:checked={unlimited} /> Unlimited until expiry</label>
            {/if}
          </div>
        {/if}
      </div>

      <button type="button" class="disclosure" aria-expanded={showAdvanced} onclick={() => (showAdvanced = !showAdvanced)} data-testid="advanced">
        <ChevronDown size={16} class={showAdvanced ? "rot" : ""} /> More options
        <span class="muted small">title, syntax, password{cfg?.persistent_enabled ? ", storage" : ""}</span>
      </button>

      {#if showAdvanced || usePassword}
        <div class="grid">
          <div>
            <label class="label" for="title">Title <span class="muted">(optional, encrypted)</span></label>
            <input id="title" class="input" bind:value={title} maxlength="200" autocomplete="off" data-testid="title" />
          </div>
          <div>
            <label class="label" for="syntax">Syntax highlighting</label>
            <select id="syntax" class="select" bind:value={syntax}>
              {#each LANGUAGES as [v, n] (v)}<option value={v}>{n}</option>{/each}
            </select>
          </div>
          <div class="span2">
            <label class="switch">
              <input type="checkbox" bind:checked={usePassword} data-testid="use-password" />
              <span class="track"></span>
              <span><LockKeyhole size={14} /> Require an additional password</span>
            </label>
            {#if usePassword}
              <div class="pw-row">
                <label class="sr-only" for="password">Password</label>
                <input
                  id="password"
                  class="input"
                  type={showPassword ? "text" : "password"}
                  bind:value={password}
                  autocomplete="new-password"
                  placeholder="Password (never sent to the server)"
                  data-testid="password"
                />
                <button type="button" class="btn btn-icon" onclick={() => (showPassword = !showPassword)} aria-label={showPassword ? "Hide password" : "Show password"}>
                  {#if showPassword}<EyeOff size={16} />{:else}<Eye size={16} />{/if}
                </button>
              </div>
              <p class="hint">Hardened with Argon2id in your browser. The recipient needs both the link and the password.</p>
            {/if}
          </div>
          {#if cfg?.persistent_enabled}
            <div class="span2">
              <label class="switch">
                <input type="checkbox" bind:checked={persistent} />
                <span class="track"></span>
                <span><Database size={14} /> Store persistently on disk (encrypted; requires an authorized API token)</span>
              </label>
            </div>
          {/if}
        </div>
      {/if}

      {#if needsToken || persistent || ttl === "never" || hasApiToken()}
        <div>
          <label class="label" for="token">API token {#if !needsToken}<span class="muted">(optional)</span>{/if}</label>
          <input id="token" class="input mono" type="password" bind:value={apiToken} autocomplete="off" placeholder="cdt_…" data-testid="api-token" />
          <p class="hint">
            {needsToken ? "This instance requires authentication to create secrets. " : ""}Kept in this tab's memory only, never stored.
          </p>
        </div>
      {/if}

      {#if error}
        <div class="callout danger" role="alert" data-testid="create-error">{error}</div>
      {/if}

      <div class="submit-row">
        <p class="muted small enc"><ShieldCheck size={14} /> End-to-end encrypted · AES-256-GCM · zero-knowledge server</p>
        <button type="submit" class="btn btn-primary btn-lg" disabled={!canSubmit} data-testid="create-submit">
          {#if busy}<span class="spinner" aria-hidden="true"></span> Encrypting…{:else}<Link size={16} /> Create secure link{/if}
        </button>
      </div>
    </form>
  {/if}
</div>

<style>
  .page {
    max-width: 880px;
    margin: 0 auto;
    padding: 2.5rem 1.25rem 1rem;
  }
  .hero h1 {
    font-size: 1.85rem;
    letter-spacing: -0.025em;
    margin: 0 0 0.4rem;
    font-weight: 700;
  }
  .hero p {
    margin: 0 0 1.5rem;
    max-width: 640px;
  }
  .muted {
    color: var(--text-muted);
  }
  .small {
    font-size: 0.82rem;
  }
  .danger {
    color: var(--danger);
  }
  .form {
    padding: 1.25rem;
    display: flex;
    flex-direction: column;
    gap: 1.1rem;
  }
  .editor {
    min-height: 260px;
    resize: vertical;
    line-height: 1.55;
    background: var(--bg-sunken);
    border-color: var(--border);
  }
  .meta {
    display: flex;
    justify-content: space-between;
    font-size: 0.78rem;
    color: var(--text-faint);
    margin-top: 0.35rem;
  }
  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 1rem 1.25rem;
    align-items: start;
  }
  .span2 {
    grid-column: 1 / -1;
  }
  .switch {
    min-height: 2.25rem;
  }
  .check {
    display: flex;
    gap: 0.4rem;
    align-items: center;
    font-size: 0.85rem;
    margin-top: 0.4rem;
    color: var(--text-muted);
  }
  .pw-row {
    display: flex;
    gap: 0.5rem;
    margin-top: 0.6rem;
    max-width: 420px;
  }
  .disclosure {
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    align-self: flex-start;
    background: none;
    border: none;
    padding: 0.25rem 0;
    color: var(--text);
    font: inherit;
    font-weight: 550;
    font-size: 0.9rem;
    cursor: pointer;
  }
  .disclosure :global(.rot) {
    transform: rotate(180deg);
  }
  .disclosure :global(svg) {
    transition: transform 150ms var(--ease);
  }
  .submit-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 1rem;
    flex-wrap: wrap;
    padding-top: 0.25rem;
    border-top: 1px solid var(--border);
    margin-top: 0.25rem;
    padding-top: 1rem;
  }
  .enc {
    display: inline-flex;
    gap: 0.4rem;
    align-items: center;
    margin: 0;
  }
  .result {
    padding: 1.5rem;
    display: flex;
    flex-direction: column;
    gap: 1.1rem;
  }
  .result-head {
    display: flex;
    gap: 0.9rem;
    align-items: flex-start;
  }
  .result-head h1 {
    font-size: 1.35rem;
    margin: 0 0 0.2rem;
    letter-spacing: -0.02em;
  }
  .result-head p {
    margin: 0;
  }
  .ok-icon {
    display: grid;
    place-items: center;
    width: 2.4rem;
    height: 2.4rem;
    border-radius: 10px;
    background: var(--success-soft);
    color: var(--success);
    flex-shrink: 0;
  }
  .url-row {
    display: flex;
    gap: 0.5rem;
  }
  .url-row .input {
    flex: 1;
    min-width: 0;
  }
  .facts {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 0.75rem;
    margin: 0;
  }
  .facts div {
    background: var(--bg-sunken);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 0.6rem 0.75rem;
  }
  .facts dt {
    display: flex;
    gap: 0.35rem;
    align-items: center;
    font-size: 0.75rem;
    font-weight: 600;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }
  .facts dd {
    margin: 0.2rem 0 0;
    font-size: 0.9rem;
  }
  .revoke summary {
    cursor: pointer;
    font-weight: 550;
    font-size: 0.9rem;
  }
  .revoke[open] summary {
    margin-bottom: 0.5rem;
  }
  .actions {
    display: flex;
    gap: 0.5rem;
  }
  @media (max-width: 560px) {
    .url-row {
      flex-direction: column;
    }
    .page {
      padding-top: 1.5rem;
    }
  }
</style>
