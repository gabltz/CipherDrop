import { spawnSync } from "node:child_process";
import { unlinkSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

import { expect, test, type Page, type Request } from "@playwright/test";

const BASE = "http://127.0.0.1:18080";
const CLI = resolve(process.env.CIPHERDROP_CLI_BIN ?? "../../target/release/cipherdrop");

/** Records every request and console CSP violation for a page. */
function instrument(page: Page) {
  const requests: Request[] = [];
  const cspViolations: string[] = [];
  page.on("request", (r) => requests.push(r));
  page.on("console", (m) => {
    if (/Content Security Policy|Refused to/i.test(m.text())) cspViolations.push(m.text());
  });
  return { requests, cspViolations };
}

async function createInUi(page: Page, secret: string, opts: { password?: string; title?: string; syntax?: string; burn?: boolean } = {}) {
  await page.goto("/");
  await page.getByTestId("secret-input").fill(secret);
  if (opts.title || opts.password || opts.syntax) await page.getByTestId("advanced").click();
  if (opts.title) await page.getByTestId("title").fill(opts.title);
  if (opts.syntax) await page.locator("#syntax").selectOption(opts.syntax);
  if (opts.password) {
    await page.getByTestId("use-password").check({ force: true });
    await page.getByTestId("password").fill(opts.password);
  }
  if (opts.burn === false) await page.getByTestId("burn").uncheck({ force: true });
  await page.getByTestId("create-submit").click();
  await expect(page.getByTestId("share-created")).toBeVisible({ timeout: 20_000 });
  const url = await page.getByTestId("share-url").inputValue();
  const revocationUrl = await page.getByTestId("revocation-url").inputValue();
  return { url, revocationUrl };
}

function idOf(url: string): string {
  return /\/s\/([A-Za-z0-9_-]{22})/.exec(url)![1]!;
}

async function status(page: Page, id: string) {
  const r = await page.request.get(`${BASE}/api/v1/shares/${id}/status`);
  return { code: r.status(), body: r.ok() ? await r.json() : null };
}

function assertNoKeyLeak(requests: Request[], key: string) {
  for (const r of requests) {
    expect(r.url(), "key must never appear in a request URL").not.toContain(key);
    expect(r.postData() ?? "", "key must never appear in a request body").not.toContain(key);
    for (const v of Object.values(r.headers())) expect(v).not.toContain(key);
    expect(new URL(r.url()).origin, "no external requests").toBe(BASE);
  }
}

test("create in browser, page load does not consume, reveal burns the secret", async ({ page, browser }) => {
  const sender = instrument(page);
  const secret = "synthetic-secret-" + Math.random().toString(36).slice(2);
  const { url } = await createInUi(page, secret);
  expect(url).toMatch(/^http:\/\/127\.0\.0\.1:18080\/s\/[A-Za-z0-9_-]{22}#v1\.[A-Za-z0-9_-]{43}$/);
  const key = url.split("#v1.")[1]!;
  assertNoKeyLeak(sender.requests, key);
  // The plaintext was never sent either.
  for (const r of sender.requests) expect(r.postData() ?? "").not.toContain(secret);

  // Recipient in a fresh context.
  const ctx = await browser.newContext();
  const rp = await ctx.newPage();
  const recipient = instrument(rp);
  await rp.goto(url);
  await expect(rp.getByTestId("state-ready")).toBeVisible();
  await expect(rp.getByTestId("one-time-warning")).toBeVisible();
  // Reloading and HEAD requests do not consume.
  await rp.reload();
  await expect(rp.getByTestId("state-ready")).toBeVisible();
  const head = await rp.request.head(url.split("#")[0]!);
  expect(head.status()).toBe(200);
  expect((await status(rp, idOf(url))).body.remaining_reads).toBe(1);

  await rp.getByTestId("reveal").click();
  await expect(rp.getByTestId("revealed-content")).toHaveText(secret);
  expect(rp.url(), "fragment removed from address bar after reveal").not.toContain("#");
  assertNoKeyLeak(recipient.requests, key);
  expect((await status(rp, idOf(url))).code).toBe(404);

  // A second visit with the full link: unavailable.
  const rp2 = await ctx.newPage();
  await rp2.goto(url);
  await expect(rp2.getByTestId("state-unavailable")).toBeVisible();

  // No browser storage used anywhere.
  for (const p of [page, rp, rp2]) {
    const storage = await p.evaluate(async () => ({
      local: localStorage.length,
      session: sessionStorage.length,
      cookies: document.cookie,
      idb: (await indexedDB.databases()).length,
      sw: (await navigator.serviceWorker?.getRegistrations?.())?.length ?? 0,
    }));
    expect(storage).toEqual({ local: 0, session: 0, cookies: "", idb: 0, sw: 0 });
  }
  expect([...sender.cspViolations, ...recipient.cspViolations]).toEqual([]);
  await ctx.close();
});

test("untrusted content is rendered as text, never as HTML", async ({ page, browser }) => {
  const payload = `<img src=x onerror="window.__pwned=1"><script>window.__pwned=2</script><b>bold</b>`;
  for (const syntax of ["", "xml"]) {
    const { url } = await createInUi(page, payload, { title: "<i>title</i>", syntax });
    const ctx = await browser.newContext();
    const rp = await ctx.newPage();
    const { cspViolations } = instrument(rp);
    await rp.goto(url);
    await rp.getByTestId("reveal").click();
    await expect(rp.getByTestId("revealed-content")).toHaveText(payload);
    await expect(rp.getByTestId("revealed-title")).toHaveText("<i>title</i>");
    expect(await rp.locator("[data-testid=revealed-content] img, [data-testid=revealed-content] script, [data-testid=revealed-content] b").count()).toBe(0);
    expect(await rp.evaluate(() => (window as unknown as { __pwned?: number }).__pwned)).toBeUndefined();
    expect(cspViolations).toEqual([]);
    await ctx.close();
  }
});

test("password-protected share: wrong password can be retried without re-consuming", async ({ page, browser }) => {
  const { url } = await createInUi(page, "pw synthetic secret", { password: "correct horse", burn: true });
  const ctx = await browser.newContext();
  const rp = await ctx.newPage();
  await rp.goto(url);
  await expect(rp.getByTestId("reveal-password")).toBeVisible();
  await rp.getByTestId("reveal-password").fill("wrong");
  await rp.getByTestId("reveal").click();
  await expect(rp.getByText("Wrong password")).toBeVisible({ timeout: 20_000 });
  // The share was consumed exactly once; ciphertext is held in memory for the retry.
  expect((await status(rp, idOf(url))).code).toBe(404);
  await rp.getByTestId("reveal-password").fill("correct horse");
  await rp.getByTestId("reveal").click();
  await expect(rp.getByTestId("revealed-content")).toHaveText("pw synthetic secret", { timeout: 20_000 });
  await ctx.close();
});

test("incomplete link shows a clear error without contacting the server for ciphertext", async ({ page }) => {
  const { requests } = instrument(page);
  await page.goto("/s/AAAAAAAAAAAAAAAAAAAAAA");
  await expect(page.getByTestId("state-invalid")).toBeVisible();
  expect(requests.filter((r) => r.url().includes("/consume"))).toHaveLength(0);
});

test("revocation link deletes the share", async ({ page, browser }) => {
  const { url, revocationUrl } = await createInUi(page, "to be revoked");
  const ctx = await browser.newContext();
  const rp = await ctx.newPage();
  await rp.goto(revocationUrl);
  await rp.getByTestId("revoke").click();
  await expect(rp.getByTestId("revoked")).toBeVisible();
  expect(rp.url()).not.toContain("#");
  await rp.goto(url);
  await expect(rp.getByTestId("state-unavailable")).toBeVisible();
  await ctx.close();
});

test("interoperability: CLI-created share decrypts in the browser and vice versa", async ({ page, browser }) => {
  const cli = spawnSync(CLI, ["--allow-insecure-http", "--server", BASE, "create", "--ttl", "10m", "--once", "--title", "From CLI"], {
    input: "created by the CLI (synthetic)",
    encoding: "utf8",
  });
  expect(cli.status, cli.stderr).toBe(0);
  const link = cli.stdout.trim();
  const ctx = await browser.newContext();
  const rp = await ctx.newPage();
  await rp.goto(link);
  await rp.getByTestId("reveal").click();
  await expect(rp.getByTestId("revealed-content")).toHaveText("created by the CLI (synthetic)");
  await expect(rp.getByTestId("revealed-title")).toHaveText("From CLI");
  await ctx.close();

  const { url } = await createInUi(page, "created in the browser (synthetic)\nline two", { password: "pw-123", title: "From browser" });
  const pw = resolve("pw.txt");
  writeFileSync(pw, "pw-123", { mode: 0o600 });
  const read = spawnSync(CLI, ["--allow-insecure-http", "--json", "read", "--password-file", pw], { input: url, encoding: "utf8" });
  unlinkSync(pw);
  expect(read.status, read.stderr).toBe(0);
  const out = JSON.parse(read.stdout);
  expect(out.content).toBe("created in the browser (synthetic)\nline two");
  expect(out.title).toBe("From browser");
});

test("documentation site, search, playground and API explorer", async ({ page }) => {
  const { requests, cspViolations } = instrument(page);
  for (const slug of ["", "quickstart", "api", "encryption", "sdk", "cli", "security", "deployment", "configuration"]) {
    await page.goto(`/docs${slug ? "/" + slug : ""}`);
    await expect(page.locator("article h1").first()).toBeVisible();
  }
  await page.goto("/docs");
  await page.getByTestId("docs-search").fill("revocation token");
  await expect(page.getByTestId("docs-results")).toBeVisible();

  // Playground encrypts locally: the shown request body contains ciphertext, not plaintext.
  await page.goto("/docs/api");
  await page.locator("#pg-pt").fill("playground synthetic plaintext");
  await page.getByRole("button", { name: /Encrypt & create/ }).click();
  await expect(page.getByTestId("pg-request")).toContainText("ciphertext");
  await expect(page.getByTestId("pg-request")).not.toContainText("playground synthetic plaintext");
  for (const r of requests) expect(r.postData() ?? "").not.toContain("playground synthetic plaintext");

  await page.goto("/docs/api/explorer");
  await expect(page.locator(".swagger-ui .info .title")).toContainText("CipherDrop API", { timeout: 15_000 });
  await expect(page.locator(".opblock-summary-path").first()).toBeVisible();
  for (const r of requests) expect(new URL(r.url()).origin).toBe(BASE);
  expect(cspViolations).toEqual([]);
});
