import hljs from "highlight.js/lib/core";
import bash from "highlight.js/lib/languages/bash";
import csharp from "highlight.js/lib/languages/csharp";
import css from "highlight.js/lib/languages/css";
import go from "highlight.js/lib/languages/go";
import ini from "highlight.js/lib/languages/ini";
import java from "highlight.js/lib/languages/java";
import javascript from "highlight.js/lib/languages/javascript";
import json from "highlight.js/lib/languages/json";
import markdown from "highlight.js/lib/languages/markdown";
import plaintext from "highlight.js/lib/languages/plaintext";
import powershell from "highlight.js/lib/languages/powershell";
import python from "highlight.js/lib/languages/python";
import rust from "highlight.js/lib/languages/rust";
import sql from "highlight.js/lib/languages/sql";
import typescript from "highlight.js/lib/languages/typescript";
import xml from "highlight.js/lib/languages/xml";
import yaml from "highlight.js/lib/languages/yaml";

export const LANGUAGES: [string, string][] = [
  ["", "Plain text"],
  ["bash", "Shell"],
  ["csharp", "C#"],
  ["css", "CSS"],
  ["go", "Go"],
  ["ini", "INI / TOML"],
  ["java", "Java"],
  ["javascript", "JavaScript"],
  ["json", "JSON"],
  ["markdown", "Markdown"],
  ["powershell", "PowerShell"],
  ["python", "Python"],
  ["rust", "Rust"],
  ["sql", "SQL"],
  ["typescript", "TypeScript"],
  ["xml", "HTML / XML"],
  ["yaml", "YAML"],
];

for (const [name, lang] of Object.entries({
  bash, csharp, css, go, ini, java, javascript, json, markdown, plaintext, powershell, python, rust, sql, typescript, xml, yaml,
})) {
  hljs.registerLanguage(name, lang);
}

/**
 * Syntax-highlight untrusted text. highlight.js HTML-escapes its input and
 * emits only <span class="hljs-*"> wrappers, so the result contains no markup
 * from the input. Unknown languages return null (render as plain text).
 */
export function highlight(code: string, language: string | undefined): string | null {
  if (!language || !hljs.getLanguage(language)) return null;
  return hljs.highlight(code, { language, ignoreIllegals: true }).value;
}

export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

export function formatDuration(seconds: number): string {
  const units: [number, string][] = [
    [86_400, "day"],
    [3_600, "hour"],
    [60, "minute"],
    [1, "second"],
  ];
  for (const [n, name] of units) {
    if (seconds >= n && seconds % n === 0) {
      const v = seconds / n;
      return `${v} ${name}${v === 1 ? "" : "s"}`;
    }
  }
  return `${seconds} seconds`;
}

export function formatExpiry(iso: string | null): string {
  if (!iso) return "Never expires";
  const d = new Date(iso);
  const diff = Math.round((d.getTime() - Date.now()) / 1000);
  const abs = d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
  if (diff <= 0) return `Expired (${abs})`;
  const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  const rel =
    diff < 3600
      ? rtf.format(Math.round(diff / 60), "minute")
      : diff < 86_400
        ? rtf.format(Math.round(diff / 3600), "hour")
        : rtf.format(Math.round(diff / 86_400), "day");
  return `${rel} · ${abs}`;
}

export function formatReads(n: number | null): string {
  if (n === null) return "Unlimited views";
  return n === 1 ? "1 view" : `${n} views`;
}
