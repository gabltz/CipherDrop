/**
 * Minimal client-side router. The URL fragment is never inspected here; only
 * the Reveal and Revoke pages read it, once, into memory.
 */

export type Route =
  | { name: "create" }
  | { name: "reveal"; id: string }
  | { name: "revoke"; id: string }
  | { name: "docs"; slug: string }
  | { name: "notfound" };

function parse(pathname: string): Route {
  if (pathname === "/" || pathname === "") return { name: "create" };
  let m = /^\/s\/([A-Za-z0-9_-]{22})\/?$/.exec(pathname);
  if (m) return { name: "reveal", id: m[1]! };
  m = /^\/revoke\/([A-Za-z0-9_-]{22})\/?$/.exec(pathname);
  if (m) return { name: "revoke", id: m[1]! };
  m = /^\/docs(?:\/([a-z-]+))?\/?$/.exec(pathname);
  if (m) return { name: "docs", slug: m[1] ?? "" };
  return { name: "notfound" };
}

class Router {
  route = $state<Route>(parse(location.pathname));
  path = $state(location.pathname);

  constructor() {
    window.addEventListener("popstate", () => this.sync());
  }

  private sync(): void {
    this.path = location.pathname;
    this.route = parse(location.pathname);
  }

  navigate(to: string, opts: { replace?: boolean } = {}): void {
    const url = new URL(to, location.origin);
    if (url.origin !== location.origin) {
      location.assign(to);
      return;
    }
    const target = url.pathname + url.search + url.hash;
    if (opts.replace) history.replaceState(null, "", target);
    else history.pushState(null, "", target);
    this.sync();
    if (url.hash) {
      queueMicrotask(() => document.getElementById(decodeURIComponent(url.hash.slice(1)))?.scrollIntoView());
    } else {
      window.scrollTo(0, 0);
    }
  }
}

export const router = new Router();

/** Intercept same-origin link clicks for SPA navigation. */
export function linkHandler(e: MouseEvent): void {
  if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
  const a = (e.target as Element | null)?.closest?.("a");
  if (!a || a.target === "_blank" || a.hasAttribute("download")) return;
  const href = a.getAttribute("href");
  if (!href || !href.startsWith("/") || href.startsWith("//")) return;
  // The Swagger UI explorer is a separate page served by the server.
  if (href.startsWith("/docs/api/explorer")) return;
  e.preventDefault();
  router.navigate(href);
}
