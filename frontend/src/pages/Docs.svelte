<script lang="ts">
  import { ExternalLink, Search } from "@lucide/svelte";
  import pages from "virtual:docs";
  import { tick } from "svelte";

  import Playground from "../components/Playground.svelte";
  import { router } from "../lib/router.svelte";
  import { copyText } from "../lib/util";

  let { slug }: { slug: string } = $props();

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

<div class="docs">
  <aside class="side" aria-label="Documentation">
    <div class="search">
      <Search size={15} />
      <label class="sr-only" for="doc-search">Search documentation</label>
      <input id="doc-search" class="input" type="search" placeholder="Search docs" bind:value={query} autocomplete="off" data-testid="docs-search" />
    </div>
    {#if results.length}
      <ul class="results" aria-label="Search results" data-testid="docs-results">
        {#each results as r (r.href + r.heading)}
          <li>
            <a href={r.href} onclick={(e) => { e.preventDefault(); pick(r.href); }}>
              <span class="rh">{r.heading}</span>
              <span class="rp">{r.page}</span>
              <span class="rs">{r.snippet}</span>
            </a>
          </li>
        {/each}
      </ul>
    {:else if query.trim().length >= 2}
      <p class="none">No results.</p>
    {/if}
    <nav>
      {#each pages as p (p.slug)}
        <a href={`/docs${p.slug ? "/" + p.slug : ""}`} class:active={p.slug === slug} aria-current={p.slug === slug ? "page" : undefined}>{p.title}</a>
      {/each}
      <a href="/docs/api/explorer" class="ext">API explorer (Swagger UI) <ExternalLink size={12} /></a>
      <a href="/api/v1/openapi.json" class="ext" target="_blank" rel="noopener">openapi.json <ExternalLink size={12} /></a>
    </nav>
  </aside>

  <!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_noninteractive_element_interactions -->
  <article class="prose" bind:this={article} onclick={onArticleClick}>
    {#if page}
      <!-- Documentation HTML is rendered at build time from the repository's own
           Markdown (raw HTML in Markdown is escaped by the build plugin). It never
           contains user input. -->
      <!-- eslint-disable-next-line svelte/no-at-html-tags -->
      {@html page.html}
      {#if page.slug === "api"}
        <Playground />
      {/if}
    {:else}
      <h1>Page not found</h1>
      <p><a href="/docs">Back to the documentation</a></p>
    {/if}
  </article>
</div>

<style>
  .docs {
    max-width: 1240px;
    margin: 0 auto;
    display: grid;
    grid-template-columns: 250px minmax(0, 1fr);
    gap: 2.5rem;
    padding: 1.5rem 1.25rem 4rem;
  }
  .side {
    position: sticky;
    top: 4.5rem;
    align-self: start;
    max-height: calc(100vh - 5.5rem);
    overflow: auto;
    padding-right: 0.25rem;
  }
  .search {
    position: relative;
    margin-bottom: 0.75rem;
  }
  .search :global(svg) {
    position: absolute;
    left: 0.65rem;
    top: 50%;
    transform: translateY(-50%);
    color: var(--text-faint);
  }
  .search .input {
    padding-left: 2rem;
    font-size: 0.88rem;
  }
  nav {
    display: flex;
    flex-direction: column;
    gap: 1px;
  }
  nav a {
    padding: 0.38rem 0.65rem;
    border-radius: var(--radius-sm);
    color: var(--text-muted);
    font-size: 0.9rem;
  }
  nav a:hover {
    background: var(--bg-hover);
    color: var(--text);
    text-decoration: none;
  }
  nav a.active {
    background: var(--accent-soft);
    color: var(--accent);
    font-weight: 600;
  }
  nav .ext {
    display: flex;
    align-items: center;
    gap: 0.3rem;
    font-size: 0.83rem;
  }
  nav .ext:first-of-type {
    margin-top: 0.75rem;
    border-top: 1px solid var(--border);
    border-radius: 0;
    padding-top: 0.75rem;
  }
  .results {
    list-style: none;
    margin: 0 0 1rem;
    padding: 0;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: var(--bg-elev);
    overflow: hidden;
  }
  .results a {
    display: grid;
    padding: 0.5rem 0.7rem;
    border-bottom: 1px solid var(--border);
    color: var(--text);
  }
  .results li:last-child a {
    border-bottom: none;
  }
  .results a:hover {
    background: var(--bg-hover);
    text-decoration: none;
  }
  .rh {
    font-weight: 600;
    font-size: 0.85rem;
  }
  .rp {
    font-size: 0.72rem;
    color: var(--accent);
  }
  .rs {
    font-size: 0.76rem;
    color: var(--text-muted);
  }
  .none {
    font-size: 0.85rem;
    color: var(--text-faint);
  }

  /* ---- Prose ---- */
  .prose {
    min-width: 0;
    max-width: 820px;
    font-size: 0.95rem;
  }
  .prose :global(h1) {
    font-size: 2rem;
    letter-spacing: -0.025em;
    margin: 0.25rem 0 1rem;
  }
  .prose :global(h2) {
    font-size: 1.35rem;
    letter-spacing: -0.015em;
    margin: 2.25rem 0 0.75rem;
    padding-top: 1rem;
    border-top: 1px solid var(--border);
  }
  .prose :global(h3) {
    font-size: 1.08rem;
    margin: 1.75rem 0 0.5rem;
  }
  .prose :global(h4) {
    font-size: 0.95rem;
    margin: 1.25rem 0 0.4rem;
  }
  .prose :global(h2),
  .prose :global(h3),
  .prose :global(h4) {
    scroll-margin-top: 4.5rem;
  }
  .prose :global(.anchor) {
    margin-left: 0.4rem;
    color: var(--text-faint);
    opacity: 0;
    font-weight: 400;
  }
  .prose :global(h2:hover .anchor),
  .prose :global(h3:hover .anchor),
  .prose :global(h4:hover .anchor) {
    opacity: 1;
  }
  .prose :global(p),
  .prose :global(li) {
    color: color-mix(in srgb, var(--text) 88%, var(--text-muted));
  }
  .prose :global(:not(pre) > code) {
    background: var(--bg-sunken);
    border: 1px solid var(--border);
    padding: 0.05em 0.35em;
    border-radius: 5px;
    font-size: 0.85em;
    word-break: break-word;
  }
  .prose :global(.code-block) {
    position: relative;
    margin: 1rem 0;
    background: var(--bg-sunken);
    border: 1px solid var(--border);
    border-radius: var(--radius);
  }
  .prose :global(.code-block pre) {
    margin: 0;
    padding: 1rem;
    overflow: auto;
    font-size: 0.82rem;
    line-height: 1.6;
  }
  .prose :global(.code-lang) {
    position: absolute;
    top: 0.4rem;
    right: 4.5rem;
    font-size: 0.7rem;
    color: var(--text-faint);
    font-family: var(--font-mono);
  }
  .prose :global(.copy-code) {
    position: absolute;
    top: 0.35rem;
    right: 0.4rem;
    font: inherit;
    font-size: 0.72rem;
    padding: 0.15rem 0.55rem;
    border-radius: 5px;
    border: 1px solid var(--border-strong);
    background: var(--bg-elev);
    color: var(--text-muted);
    cursor: pointer;
  }
  .prose :global(.copy-code:hover) {
    color: var(--text);
  }
  .prose :global(.table-wrap) {
    overflow-x: auto;
    margin: 1rem 0;
    border: 1px solid var(--border);
    border-radius: var(--radius);
  }
  .prose :global(table) {
    border-collapse: collapse;
    width: 100%;
    font-size: 0.86rem;
  }
  .prose :global(th),
  .prose :global(td) {
    text-align: left;
    padding: 0.5rem 0.75rem;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
  }
  .prose :global(th) {
    background: var(--bg-sunken);
    font-weight: 600;
  }
  .prose :global(tr:last-child td) {
    border-bottom: none;
  }
  .prose :global(blockquote) {
    margin: 1rem 0;
    padding: 0.6rem 1rem;
    border-left: 3px solid var(--accent);
    background: var(--accent-soft);
    border-radius: 0 var(--radius-sm) var(--radius-sm) 0;
  }
  .prose :global(blockquote p) {
    margin: 0.3rem 0;
  }
  .prose :global(hr) {
    border: none;
    border-top: 1px solid var(--border);
    margin: 2rem 0;
  }
  @media (max-width: 860px) {
    .docs {
      grid-template-columns: 1fr;
      gap: 1rem;
    }
    .side {
      position: static;
      max-height: none;
    }
    nav {
      flex-direction: row;
      flex-wrap: wrap;
    }
  }
</style>
