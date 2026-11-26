import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist/**"] },
  ...tseslint.configs.strict,
  {
    rules: {
      // Index access is bounds-checked by loop conditions; with
      // noUncheckedIndexedAccess enabled, `!` documents that invariant.
      "@typescript-eslint/no-non-null-assertion": "off",
      // Secrets must never be persisted in browser storage.
      "no-restricted-globals": ["error", "localStorage", "sessionStorage", "indexedDB"],
    },
  },
);
