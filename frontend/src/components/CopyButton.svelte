<script lang="ts">
  import { copyText } from "../lib/util";

  let { text, label = "Copy", testid }: { text: () => string; label?: string; testid?: string } = $props();
  let state = $state<"idle" | "ok" | "fail">("idle");

  async function copy() {
    state = (await copyText(text())) ? "ok" : "fail";
    setTimeout(() => (state = "idle"), 1500);
  }
</script>

<button type="button" onclick={copy} data-testid={testid} aria-live="polite">
  {state === "ok" ? "Copied" : state === "fail" ? "Copy failed" : label}
</button>
