<script lang="ts">
  import type { Component } from "svelte";

  import Create from "./pages/Create.svelte";
  import NotFound from "./pages/NotFound.svelte";
  import Reveal from "./pages/Reveal.svelte";
  import Revoke from "./pages/Revoke.svelte";
  import { linkHandler, router } from "./lib/router.svelte";

  const route = $derived(router.route);
  const wide = $derived(route.name === "docs");

  // The documentation (pre-rendered HTML) is loaded only when visited.
  let Docs = $state<Component<{ slug: string }> | null>(null);
  $effect(() => {
    if (route.name === "docs" && !Docs) import("./pages/Docs.svelte").then((m) => (Docs = m.default));
  });
</script>

<svelte:document onclick={linkHandler} />

<header class:wide>
  <a class="brand" href="/">CipherDrop</a>
  <a href="/docs">Docs</a>
</header>

<main class:wide>
  {#if route.name === "create"}
    <Create />
  {:else if route.name === "reveal"}
    {#key route.id}<Reveal id={route.id} />{/key}
  {:else if route.name === "revoke"}
    {#key route.id}<Revoke id={route.id} />{/key}
  {:else if route.name === "docs"}
    {#if Docs}<Docs slug={route.slug} />{:else}<p class="muted">Loading…</p>{/if}
  {:else}
    <NotFound />
  {/if}
</main>

<footer class:wide>
  Encrypted in your browser. The server only stores ciphertext. <a href="/docs/security">Security</a>
</footer>
