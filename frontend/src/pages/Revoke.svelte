<script lang="ts">
  import { CircleCheck, Trash2, TriangleAlert } from "@lucide/svelte";
  import { ApiError, validateRevocationToken } from "@cipherdrop/sdk";

  import { client, describeError } from "../lib/api";

  let { id }: { id: string } = $props();

  let token: string | null = null;
  try {
    const h = location.hash;
    token = h.startsWith("#v1.") ? validateRevocationToken(h.slice(4)) : null;
  } catch {
    token = null;
  }

  let phase = $state<"confirm" | "busy" | "done" | "gone" | "error" | "invalid">(token ? "confirm" : "invalid");
  let message = $state("");

  async function revoke() {
    if (!token) return;
    phase = "busy";
    try {
      await client().revoke(id, token);
      phase = "done";
    } catch (e) {
      if (e instanceof ApiError && e.code === "share_unavailable") phase = "gone";
      else {
        phase = "error";
        message = describeError(e);
      }
    } finally {
      token = null;
      history.replaceState(null, "", location.pathname);
    }
  }

  $effect(() => {
    document.title = "Revoke secret · CipherDrop";
  });
</script>

<div class="page">
  <div class="card panel">
    {#if phase === "invalid"}
      <h1><TriangleAlert size={20} /> Incomplete revocation link</h1>
      <p class="muted">The revocation token after <code>#v1.</code> is missing or malformed.</p>
    {:else if phase === "confirm" || phase === "busy"}
      <h1><Trash2 size={20} /> Revoke this secret?</h1>
      <p class="muted">The encrypted secret is deleted from the server immediately and the share link stops working. This cannot be undone.</p>
      <div>
        <button class="btn btn-danger btn-lg" onclick={revoke} disabled={phase === "busy"} data-testid="revoke">
          {#if phase === "busy"}<span class="spinner"></span>{:else}<Trash2 size={16} />{/if} Revoke permanently
        </button>
      </div>
    {:else if phase === "done"}
      <h1 data-testid="revoked"><CircleCheck size={20} /> Secret revoked</h1>
      <p class="muted">The encrypted data has been deleted from the server's storage.</p>
      <div><a class="btn" href="/">Create a new secret</a></div>
    {:else if phase === "gone"}
      <h1><CircleCheck size={20} /> Nothing to revoke</h1>
      <p class="muted">The secret no longer exists: it has expired, been read, or was already revoked.</p>
    {:else}
      <h1><TriangleAlert size={20} /> Revocation failed</h1>
      <p class="muted">{message}</p>
    {/if}
  </div>
</div>

<style>
  .page {
    max-width: 640px;
    margin: 0 auto;
    padding: 2.5rem 1.25rem 1rem;
  }
  .panel {
    padding: 1.5rem;
    display: flex;
    flex-direction: column;
    gap: 0.9rem;
  }
  h1 {
    display: flex;
    gap: 0.5rem;
    align-items: center;
    font-size: 1.3rem;
    margin: 0;
    letter-spacing: -0.02em;
  }
  .muted {
    color: var(--text-muted);
    margin: 0;
  }
</style>
