<script lang="ts">
  import { BookOpen, LockKeyhole, Moon, Plus, Sun } from "@lucide/svelte";

  import Create from "./pages/Create.svelte";
  import Docs from "./pages/Docs.svelte";
  import NotFound from "./pages/NotFound.svelte";
  import Reveal from "./pages/Reveal.svelte";
  import Revoke from "./pages/Revoke.svelte";
  import { linkHandler, router } from "./lib/router.svelte";

  let theme = $state(document.documentElement.dataset.theme ?? "light");

  function toggleTheme() {
    theme = theme === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = theme;
  }

  const route = $derived(router.route);
  const isDocs = $derived(route.name === "docs");
</script>

<svelte:document onclick={linkHandler} />

<a class="skip-link" href="#main">Skip to content</a>

<header class="topbar" class:wide={isDocs}>
  <div class="inner">
    <a class="brand" href="/" aria-label="CipherDrop home">
      <span class="logo" aria-hidden="true"><LockKeyhole size={16} strokeWidth={2.25} /></span>
      <span class="name">CipherDrop</span>
    </a>
    <nav aria-label="Primary">
      <a class="btn btn-ghost" href="/" class:active={route.name === "create"}><Plus size={16} />New secret</a>
      <a class="btn btn-ghost" href="/docs" class:active={isDocs}><BookOpen size={16} />Docs</a>
      <button
        type="button"
        class="btn btn-ghost btn-icon"
        onclick={toggleTheme}
        aria-label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
      >
        {#if theme === "dark"}<Sun size={16} />{:else}<Moon size={16} />{/if}
      </button>
    </nav>
  </div>
</header>

<main id="main" tabindex="-1">
  {#if route.name === "create"}
    <Create />
  {:else if route.name === "reveal"}
    {#key route.id}<Reveal id={route.id} />{/key}
  {:else if route.name === "revoke"}
    {#key route.id}<Revoke id={route.id} />{/key}
  {:else if route.name === "docs"}
    <Docs slug={route.slug} />
  {:else}
    <NotFound />
  {/if}
</main>

{#if !isDocs}
  <footer class="foot">
    <span>End-to-end encrypted in your browser. The server only ever sees ciphertext.</span>
    <a href="/docs/security">Security model</a>
  </footer>
{/if}

<style>
  .topbar {
    position: sticky;
    top: 0;
    z-index: 20;
    background: color-mix(in srgb, var(--bg) 85%, transparent);
    backdrop-filter: saturate(1.4) blur(10px);
    border-bottom: 1px solid var(--border);
  }
  .inner {
    max-width: 880px;
    margin: 0 auto;
    padding: 0 1.25rem;
    height: 3.5rem;
    display: flex;
    align-items: center;
    justify-content: space-between;
  }
  .topbar.wide .inner {
    max-width: 1240px;
  }
  .brand {
    display: flex;
    align-items: center;
    gap: 0.55rem;
    color: var(--text);
    font-weight: 650;
    letter-spacing: -0.01em;
  }
  .brand:hover {
    text-decoration: none;
  }
  .logo {
    display: grid;
    place-items: center;
    width: 1.75rem;
    height: 1.75rem;
    border-radius: 7px;
    background: var(--text);
    color: var(--accent);
  }
  :global(:root[data-theme="dark"]) .logo {
    background: var(--accent-soft);
  }
  nav {
    display: flex;
    gap: 0.15rem;
    align-items: center;
  }
  nav .active {
    color: var(--text);
    background: var(--bg-hover);
  }
  main {
    outline: none;
    min-height: calc(100vh - 3.5rem - 4rem);
  }
  .foot {
    max-width: 880px;
    margin: 0 auto;
    padding: 1.5rem 1.25rem 2rem;
    display: flex;
    gap: 1rem;
    justify-content: space-between;
    flex-wrap: wrap;
    font-size: 0.8rem;
    color: var(--text-faint);
  }
  @media (max-width: 560px) {
    .name {
      display: none;
    }
  }
</style>
