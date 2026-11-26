import tseslint from "typescript-eslint";
import svelte from "eslint-plugin-svelte";
import svelteConfig from "./svelte.config.js";

export default tseslint.config(
  { ignores: ["dist/**", "public/**"] },
  ...tseslint.configs.recommended,
  ...svelte.configs.recommended,
  {
    files: ["**/*.svelte", "**/*.svelte.ts"],
    languageOptions: { parserOptions: { parser: tseslint.parser, extraFileExtensions: [".svelte"], svelteConfig } },
  },
  {
    rules: {
      // Secrets must never be persisted in browser storage.
      "no-restricted-globals": ["error", "localStorage", "sessionStorage", "indexedDB"],
      "no-restricted-properties": [
        "error",
        { object: "window", property: "localStorage" },
        { object: "window", property: "sessionStorage" },
        { object: "document", property: "cookie" },
      ],
      // {@html} is permitted only for build-time documentation and highlight.js
      // output (which escapes its input); each use carries an inline justification.
      "svelte/no-at-html-tags": "error",
      "svelte/no-navigation-without-resolve": "off",
    },
  },
);
