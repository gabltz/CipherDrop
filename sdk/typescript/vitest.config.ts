import { defineConfig } from "vitest/config";

// The plain-JavaScript consumer test (test/javascript.test.mjs) runs under node:test against dist/.
export default defineConfig({ test: { include: ["test/**/*.test.ts"] } });
