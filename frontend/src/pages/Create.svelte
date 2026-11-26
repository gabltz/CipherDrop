<script lang="ts">
  import type { ConfigResponse, CreatedShare } from "@cipherdrop/sdk";

  import CopyButton from "../components/CopyButton.svelte";
  import { client, describeError, instanceConfig, setApiToken } from "../lib/api";
  import { formatDuration, formatExpiry, formatReads } from "../lib/util";

  const TTL_CHOICES = [300, 3600, 86_400, 7 * 86_400, 30 * 86_400];

  let cfg = $state<ConfigResponse | null>(null);
  let cfgError = $state("");
  let content = $state("");
  let password = $state("");
  let title = $state("");
  let ttl = $state(3600);
  let burn = $state(true);
  let maxReads = $state(3);
  let apiToken = $state("");
  let busy = $state(false);
  let error = $state("");
  let created = $state<CreatedShare | null>(null);
  let hadPassword = $state(false);

  instanceConfig()
    .then((c) => {
      cfg = c;
      ttl = c.default_ttl_seconds;
      maxReads = Math.min(3, c.max_reads);
    })
    .catch((e) => (cfgError = describeError(e)));

  function ttlChoices(c: ConfigResponse): number[] {
    const all = [...TTL_CHOICES.filter((t) => t <= c.max_ttl_seconds), c.default_ttl_seconds];
    return all.filter((t, i) => all.indexOf(t) === i).sort((a, b) => a - b);
  }

  const needsToken = $derived(cfg !== null && !cfg.anonymous_creation);
  const canSubmit = $derived(cfg !== null && content.length > 0 && !busy && (!needsToken || apiToken.trim() !== ""));

  async function submit(e: Event) {
    e.preventDefault();
    if (!canSubmit) return;
    busy = true;
    error = "";
    try {
      setApiToken(apiToken || undefined);
      created = await client().create(
        { content, ...(title ? { title } : {}) },
        { ttl, maxReads: burn ? 1 : maxReads, ...(password ? { password } : {}) },
      );
      hadPassword = password !== "";
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
    error = "";
  }

  function onKeydown(e: KeyboardEvent) {
    if ((e.metaKey || e.ctrlKey) && e.key === "Enter") submit(e);
  }
</script>

<svelte:head><title>CipherDrop</title></svelte:head>

{#if created}
  <section data-testid="share-created">
    <h1>Link created</h1>
    <div class="field">
      <label for="share-url">Share this link</label>
      <div class="row">
        <input id="share-url" class="mono" type="text" readonly value={created.url} data-testid="share-url" onfocus={(e) => e.currentTarget.select()} />
        <CopyButton text={() => created?.url ?? ""} testid="copy-url" />
      </div>
    </div>
    <p class="muted small">
      Expires {formatExpiry(created.expiresAt)} · {created.maxReads === 1 ? "deleted after first view" : formatReads(created.maxReads)}{hadPassword
        ? " · password required"
        : ""}
    </p>
    <p class="warn small">
      Anyone with the full link{hadPassword ? " and the password" : ""} can read this secret.{hadPassword
        ? " Send the password through a different channel."
        : ""}
    </p>
    <details>
      <summary>Revocation link (keep it private)</summary>
      <div class="row">
        <input class="mono" type="text" readonly value={created.revocationUrl} data-testid="revocation-url" onfocus={(e) => e.currentTarget.select()} />
        <CopyButton text={() => created?.revocationUrl ?? ""} />
      </div>
    </details>
    <button type="button" onclick={reset} data-testid="create-another">New secret</button>
  </section>
{:else}
  <form onsubmit={submit} aria-label="Create a secret">
    {#if cfgError}<p class="err" role="alert">{cfgError}</p>{/if}
    <div class="field">
      <label for="secret">Secret</label>
      <textarea id="secret" bind:value={content} spellcheck="false" autocomplete="off" onkeydown={onKeydown} data-testid="secret-input"></textarea>
    </div>

    <div class="field">
      <label for="password">Password (optional, never sent to the server)</label>
      <input id="password" type="password" bind:value={password} autocomplete="new-password" data-testid="password" />
    </div>

    <div class="field">
      <label for="ttl">Expires after</label>
      <select id="ttl" bind:value={ttl} data-testid="ttl">
        {#if cfg}{#each ttlChoices(cfg) as t (t)}<option value={t}>{formatDuration(t)}</option>{/each}{/if}
      </select>
    </div>

    <div class="field">
      <label class="check"><input type="checkbox" bind:checked={burn} data-testid="burn" /> Delete after the first view</label>
    </div>

    <details>
      <summary>More options</summary>
      {#if !burn && cfg}
        <div class="field">
          <label for="reads">Maximum views</label>
          <input id="reads" type="number" min="1" max={cfg.max_reads} bind:value={maxReads} data-testid="max-reads" />
        </div>
      {/if}
      <div class="field">
        <label for="title">Title (optional, encrypted)</label>
        <input id="title" type="text" bind:value={title} maxlength="200" autocomplete="off" data-testid="title" />
      </div>
      {#if !needsToken}
        <div class="field">
          <label for="token">API token (optional, kept in memory only)</label>
          <input id="token" class="mono" type="password" bind:value={apiToken} autocomplete="off" />
        </div>
      {/if}
    </details>

    {#if needsToken}
      <div class="field">
        <label for="token">API token (required on this instance, kept in memory only)</label>
        <input id="token" class="mono" type="password" bind:value={apiToken} autocomplete="off" data-testid="api-token" />
      </div>
    {/if}

    {#if error}<p class="err" role="alert" data-testid="create-error">{error}</p>{/if}
    <button class="primary" type="submit" disabled={!canSubmit} data-testid="create-submit">{busy ? "Encrypting…" : "Create link"}</button>
  </form>
{/if}
