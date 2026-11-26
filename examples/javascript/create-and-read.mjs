#!/usr/bin/env node
// CipherDrop TypeScript/JavaScript SDK example (Node.js >= 20.19).
//
//   npm run build -w @cipherdrop/sdk        # once, from the repository root
//   CIPHERDROP_SERVER=https://paste.example.com node examples/javascript/create-and-read.mjs
//
// In your own project: `npm install @cipherdrop/sdk` and import from "@cipherdrop/sdk".

import { CipherDrop } from "../../sdk/typescript/dist/index.js";

const server = process.env.CIPHERDROP_SERVER;
if (!server) {
  console.error("set CIPHERDROP_SERVER");
  process.exit(2);
}

const client = new CipherDrop({
  baseUrl: server,
  apiKey: process.env.CIPHERDROP_API_KEY,
  allowInsecureHttp: server.startsWith("http://127.0.0.1") || server.startsWith("http://localhost"),
});

// Encrypted locally; only ciphertext is uploaded.
const share = await client.createSecret("javascript synthetic secret", { ttl: 3600, maxReads: 1, title: "JS example" });
console.log("share link:", share.url);

const status = await client.status(share.id);
console.log("remaining reads before reveal:", status.remaining_reads);

const secret = await client.read(share.url); // consumes the single retrieval
console.log("decrypted:", secret.content, `(title: ${secret.title})`);

try {
  await client.read(share.url);
} catch (e) {
  console.log("second read:", e.code); // share_unavailable
}
