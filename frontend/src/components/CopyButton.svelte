<script lang="ts">
  import { Check, Copy } from "@lucide/svelte";

  import { copyText } from "../lib/util";

  let {
    text,
    label = "Copy",
    variant = "btn",
    testid,
  }: { text: () => string; label?: string; variant?: "btn" | "primary" | "icon"; testid?: string } = $props();

  let copied = $state(false);
  let failed = $state(false);
  let timer: ReturnType<typeof setTimeout> | undefined;

  async function copy() {
    const ok = await copyText(text());
    copied = ok;
    failed = !ok;
    clearTimeout(timer);
    timer = setTimeout(() => {
      copied = false;
      failed = false;
    }, 1800);
  }
</script>

<button
  type="button"
  class="btn"
  class:btn-primary={variant === "primary"}
  class:btn-icon={variant === "icon"}
  onclick={copy}
  aria-label={variant === "icon" ? label : undefined}
  data-testid={testid}
>
  {#if copied}<Check size={16} />{:else}<Copy size={16} />{/if}
  {#if variant !== "icon"}{copied ? "Copied" : failed ? "Copy failed" : label}{/if}
</button>
<span class="sr-only" aria-live="polite">{copied ? "Copied to clipboard" : ""}</span>
