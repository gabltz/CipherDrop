<script lang="ts">
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
</script>

<svelte:head><title>Revoke · CipherDrop</title></svelte:head>

{#if phase === "invalid"}
  <h1>Incomplete revocation link</h1>
{:else if phase === "confirm" || phase === "busy"}
  <h1>Revoke this secret?</h1>
  <p class="muted">It is deleted immediately and the link stops working.</p>
  <button class="primary" onclick={revoke} disabled={phase === "busy"} data-testid="revoke">Revoke</button>
{:else if phase === "done"}
  <h1 data-testid="revoked">Revoked</h1>
  <p class="muted">The secret was deleted.</p>
{:else if phase === "gone"}
  <h1>Nothing to revoke</h1>
  <p class="muted">The secret no longer exists.</p>
{:else}
  <h1>Revocation failed</h1>
  <p class="muted">{message}</p>
{/if}
