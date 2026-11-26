<script lang="ts">
  import pages from "virtual:docs";
  import { tick } from "svelte";

  import Playground from "../components/Playground.svelte";
  import { router } from "../lib/router.svelte";
  import { copyText } from "../lib/util";

  let { slug }: { slug: string } = $props();

  const SHORT: Record<string, string> = {
    "": "Overview",
    quickstart: "Quickstart",
    api: "API",
    encryption: "Encryption",
    sdk: "SDKs",
    cli: "CLI",
    security: "Security",
    deployment: "Deployment",
    configuration: "Configuration",
  };

  const page = $derived(pages.find((p) => p.slug === slug));
  let query = $state("");
  let article = $state<HTMLElement | undefined>();

  interface Hit {
    href: string;
    page: string;
    heading: string;
    snippet: string;
    score: number;
  }

  const results = $derived.by((): Hit[] => {
    const q = query.trim().toLowerCase();
    if (q.length < 2) return [];
    const terms = q.split(/\s+/);
    const hits: Hit[] = [];
    for (const p of pages) {
      for (const s of p.sections) {
        const h = s.heading.toLowerCase();
        const t = s.text.toLowerCase();
        if (!terms.every((term) => h.includes(term) || t.includes(term))) continue;
        const score = terms.reduce((acc, term) => acc + (h.includes(term) ? 5 : 0) + (t.includes(term) ? 1 : 0), 0);
        const idx = t.indexOf(terms[0]!);
        const start = Math.max(0, idx - 50);
        const snippet = (start > 0 ? "…" : "") + s.text.slice(start, start + 140) + (s.text.length > start + 140 ? "…" : "");
        hits.push({
          href: `/docs${p.slug ? "/" + p.slug : ""}${s.id && s !== p.sections[0] ? "#" + s.id : ""}`,
          page: p.title,
          heading: s.heading,
          snippet,
          score,
        });
      }
    }
    return hits.sort((a, b) => b.score - a.score).slice(0, 12);
  });

  function onArticleClick(e: MouseEvent) {
    const btn = (e.target as Element).closest<HTMLButtonElement>("[data-copy-code]");
    if (!btn) return;
    const code = btn.parentElement?.querySelector("code")?.textContent ?? "";
    copyText(code).then((ok) => {
      btn.textContent = ok ? "Copied" : "Failed";
      setTimeout(() => (btn.textContent = "Copy"), 1500);
    });
  }

  function pick(href: string) {
    query = "";
    router.navigate(href);
  }

  $effect(() => {
    document.title = `${page?.title ?? "Not found"} · CipherDrop Docs`;
  });

  $effect(() => {
    // Scroll to a heading anchor after navigation.
    void page;
    tick().then(() => {
      if (location.hash) document.getElementById(decodeURIComponent(location.hash.slice(1)))?.scrollIntoView();
    });
  });
</script>

<nav class="docnav" aria-label="Documentation">
  {#each pages as p (p.slug)}<a
      href={`/docs${p.slug ? "/" + p.slug : ""}`}
      aria-current={p.slug === slug ? "page" : undefined}>{SHORT[p.slug] ?? p.title}</a
    >{/each}<a href="/docs/api/explorer">API explorer</a>
</nav>

<div class="field">
  <label class="sr-only" for="doc-search">Search documentation</label>
  <input id="doc-search" type="search" placeholder="Search docs" bind:value={query} autocomplete="off" data-testid="docs-search" />
</div>
{#if results.length}
  <ul class="results" data-testid="docs-results">
    {#each results as r (r.href + r.heading)}
      <li><a href={r.href} onclick={(e) => { e.preventDefault(); pick(r.href); }}>{r.heading}</a> <span class="muted small">{r.page}</span></li>
    {/each}
  </ul>
{:else if query.trim().length >= 2}
  <p class="muted small">No results.</p>
{/if}

<!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_noninteractive_element_interactions -->
<article class="prose" bind:this={article} onclick={onArticleClick}>
  {#if page}
    <!-- Documentation HTML is rendered at build time from the repository's own
         Markdown (raw HTML in Markdown is escaped by the build plugin). It never
         contains user input. -->
    <!-- eslint-disable-next-line svelte/no-at-html-tags -->
    {@html page.html}
    {#if page.slug === "api"}<Playground />{/if}
  {:else}
    <h1>Not found</h1>
    <p><a href="/docs">Documentation</a></p>
  {/if}
</article>

<style>
  .docnav {
    display: flex;
    flex-wrap: wrap;
    gap: 0.25rem 1rem;
    margin-bottom: 1rem;
    font-size: 14px;
  }
  .docnav a[aria-current="page"] {
    font-weight: 600;
    text-decoration: none;
  }
  .results {
    margin: 0 0 1rem;
    padding-left: 1.2rem;
  }
  .prose :global(h1) {
    font-size: 1.6rem;
    margin: 1.5rem 0 1rem;
  }
  .prose :global(h2) {
    font-size: 1.2rem;
    margin: 2rem 0 0.5rem;
  }
  .prose :global(h3) {
    font-size: 1rem;
    margin: 1.5rem 0 0.5rem;
  }
  .prose :global(.anchor) {
    display: none;
  }
  .prose :global(.code-block) {
    position: relative;
  }
  .prose :global(.code-lang) {
    display: none;
  }
  .prose :global(.copy-code) {
    position: absolute;
    top: 0.25rem;
    right: 0.25rem;
    padding: 0.1rem 0.5rem;
    font-size: 12px;
  }
  .prose :global(.table-wrap) {
    overflow-x: auto;
  }
  .prose :global(table) {
    border-collapse: collapse;
    width: 100%;
    font-size: 13px;
    margin-bottom: 1rem;
  }
  .prose :global(th),
  .prose :global(td) {
    border-bottom: 1px solid var(--line);
    padding: 0.35rem 0.5rem;
    text-align: left;
    vertical-align: top;
  }
  .prose :global(blockquote) {
    margin: 0 0 1rem;
    padding-left: 0.75rem;
    border-left: 2px solid var(--line);
    color: var(--muted);
  }
</style>
