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
  if (!iso) return "never";
  return new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

export function formatReads(n: number | null): string {
  if (n === null) return "unlimited views";
  return n === 1 ? "1 view" : `${n} views`;
}
