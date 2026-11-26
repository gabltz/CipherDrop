import { readFileSync, readdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

import { svelte } from "@sveltejs/vite-plugin-svelte";
import hljs from "highlight.js";
import { Marked, type Tokens } from "marked";
import { defineConfig, type Plugin } from "vite";

const here = dirname(fileURLToPath(import.meta.url));
const docsDir = resolve(here, "../docs");
const require = createRequire(import.meta.url);

/** Documentation pages, in navigation order. Slugs map to /docs/<slug>. */
const DOC_PAGES: { slug: string; file: string }[] = [
  { slug: "", file: "index.md" },
  { slug: "quickstart", file: "quickstart.md" },
  { slug: "api", file: "api.md" },
  { slug: "encryption", file: "encryption.md" },
  { slug: "sdk", file: "sdk.md" },
  { slug: "cli", file: "cli.md" },
  { slug: "security", file: "security.md" },
  { slug: "deployment", file: "deployment.md" },
  { slug: "configuration", file: "configuration.md" },
];

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
}

function slugify(s: string): string {
  return s
    .toLowerCase()
    .replace(/<[^>]+>/g, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");
}

/**
 * Renders ../docs/*.md to HTML at build time (marked + highlight.js) and
 * exposes them as `virtual:docs`. No Markdown is parsed in the browser.
 */
function docsPlugin(): Plugin {
  const id = "virtual:docs";
  const resolved = "\0" + id;
  return {
    name: "cipherdrop-docs",
    resolveId(source) {
      return source === id ? resolved : null;
    },
    load(loadId) {
      if (loadId !== resolved) return null;
      const pages = DOC_PAGES.map(({ slug, file }) => {
        const path = resolve(docsDir, file);
        this.addWatchFile(path);
        const md = readFileSync(path, "utf8");
        const sections: { id: string; heading: string; text: string }[] = [];
        let current = { id: "", heading: "", text: "" };
        sections.push(current);
        const marked = new Marked({ gfm: true });
        marked.use({
          renderer: {
            heading({ tokens, depth }: Tokens.Heading) {
              const inner = this.parser.parseInline(tokens);
              const plain = inner.replace(/<[^>]+>/g, "");
              const hid = slugify(plain);
              current = { id: hid, heading: plain, text: "" };
              sections.push(current);
              const anchor = depth > 1 ? `<a class="anchor" href="#${hid}" aria-hidden="true">#</a>` : "";
              return `<h${depth} id="${hid}">${inner}${anchor}</h${depth}>\n`;
            },
            code({ text, lang }: Tokens.Code) {
              const language = (lang ?? "").split(/\s/)[0] ?? "";
              const html =
                language && hljs.getLanguage(language)
                  ? hljs.highlight(text, { language, ignoreIllegals: true }).value
                  : escapeHtml(text);
              current.text += " " + text;
              const label = language ? `<span class="code-lang">${escapeHtml(language)}</span>` : "";
              return `<div class="code-block">${label}<button type="button" class="copy-code" data-copy-code aria-label="Copy code">Copy</button><pre><code class="hljs">${html}</code></pre></div>\n`;
            },
            paragraph({ tokens }: Tokens.Paragraph) {
              const inner = this.parser.parseInline(tokens);
              current.text += " " + inner.replace(/<[^>]+>/g, "");
              return `<p>${inner}</p>\n`;
            },
            table(token: Tokens.Table) {
              const head = token.header.map((c) => `<th>${this.parser.parseInline(c.tokens)}</th>`).join("");
              const body = token.rows
                .map((r) => `<tr>${r.map((c) => `<td>${this.parser.parseInline(c.tokens)}</td>`).join("")}</tr>`)
                .join("");
              current.text += " " + token.rows.flat().map((c) => c.text).join(" ");
              return `<div class="table-wrap"><table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table></div>\n`;
            },
            link({ href, tokens }: Tokens.Link) {
              const inner = this.parser.parseInline(tokens);
              // Rewrite repository-relative links (foo.md) to in-app routes.
              let h = href;
              const m = /^(?:\.\/)?([a-z-]+)\.md(#.*)?$/.exec(h);
              if (m) {
                const page = DOC_PAGES.find((p) => p.file === `${m[1]}.md`);
                if (page) h = `/docs${page.slug ? "/" + page.slug : ""}${m[2] ?? ""}`;
              }
              const external = /^https?:\/\//.test(h);
              return external
                ? `<a href="${escapeHtml(h)}" rel="noopener noreferrer" target="_blank">${inner}</a>`
                : `<a href="${escapeHtml(h)}" data-internal>${inner}</a>`;
            },
            html({ text }: Tokens.HTML | Tokens.Tag) {
              // Raw HTML in docs is not allowed; render it as text.
              return escapeHtml(text);
            },
          },
        });
        const html = marked.parse(md, { async: false }) as string;
        const title = sections.find((s) => s.heading)?.heading ?? slug;
        return {
          slug,
          title,
          html,
          sections: sections
            .filter((s) => s.heading)
            .map((s) => ({ ...s, text: s.text.replace(/\s+/g, " ").trim().slice(0, 4000) })),
        };
      });
      return `export default ${JSON.stringify(pages)};`;
    },
  };
}

/** Bundles Swagger UI (from node_modules, never a CDN) under /swagger/. */
function swaggerPlugin(): Plugin {
  return {
    name: "cipherdrop-swagger",
    apply: "build",
    generateBundle() {
      const dist = dirname(require.resolve("swagger-ui-dist/package.json"));
      for (const f of ["swagger-ui-bundle.js", "swagger-ui.css"]) {
        this.emitFile({ type: "asset", fileName: `swagger/${f}`, source: readFileSync(resolve(dist, f)) });
      }
      const license = readdirSync(dist).find((f) => /^LICENSE/i.test(f));
      if (license) {
        this.emitFile({ type: "asset", fileName: "swagger/LICENSE.txt", source: readFileSync(resolve(dist, license)) });
      }
    },
  };
}

export default defineConfig({
  plugins: [svelte(), docsPlugin(), swaggerPlugin()],
  resolve: {
    alias: { "@cipherdrop/sdk": resolve(here, "../sdk/typescript/src/index.ts") },
  },
  build: {
    target: "es2022",
    outDir: "dist",
    emptyOutDir: true,
    assetsInlineLimit: 0,
    sourcemap: false,
    modulePreload: { polyfill: false },
    reportCompressedSize: true,
  },
  server: {
    proxy: { "/api": "http://127.0.0.1:8080" },
  },
});
