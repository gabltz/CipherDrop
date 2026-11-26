import { defineConfig, devices } from "@playwright/test";

const BIN = process.env.CIPHERDROP_SERVER_BIN ?? "../../target/release/cipherdrop-server";

export default defineConfig({
  testDir: ".",
  testMatch: /.*\.spec\.ts/,
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [["list"]],
  use: {
    baseURL: "http://127.0.0.1:18080",
    trace: "retain-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  // Set CIPHERDROP_E2E_EXTERNAL=1 to test an already running instance (e.g. the Docker image)
  // listening on 127.0.0.1:18080 with tests/e2e/server.toml-equivalent settings.
  webServer: process.env.CIPHERDROP_E2E_EXTERNAL ? undefined : {
    command: `${BIN} --config server.toml`,
    url: "http://127.0.0.1:18080/healthz",
    reuseExistingServer: false,
    timeout: 30_000,
    stdout: "pipe",
    stderr: "pipe",
  },
});
