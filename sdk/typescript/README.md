# @cipherdrop/sdk (TypeScript and JavaScript)

Client for CipherDrop. Works in modern browsers and Node.js ≥ 20.19, from TypeScript or plain JavaScript (ESM, with type declarations). Encryption happens locally using Web Crypto, plus a bundled Argon2id WebAssembly module for optional passwords. Only ciphertext is uploaded.

```bash
npm install ./sdk/typescript     # from this repository
```

**TypeScript**

```typescript
import { CipherDrop } from "@cipherdrop/sdk";

const client = new CipherDrop({ baseUrl: "https://paste.example.com", apiKey: process.env.CIPHERDROP_API_KEY });
const share = await client.createSecret("My secret", { ttl: 3600, maxReads: 1 });
console.log(share.url);
```

**JavaScript (ESM)**

```javascript
import { CipherDrop } from "@cipherdrop/sdk";

const client = new CipherDrop({ baseUrl: "https://paste.example.com" });
const share = await client.createSecret("My secret", { ttl: 3600, maxReads: 1, password: "optional" });
const { content } = await client.read(share.url, "optional");
await client.revokeWithLink(share.revocationUrl);
```

Under CommonJS (Node ≥ 20.19), `const { CipherDrop } = require("@cipherdrop/sdk")` also works, because Node supports `require()` of ES modules.

Tests: `npm test` runs the shared vectors in TypeScript (vitest) and plain JavaScript (`node --test`). Set `CIPHERDROP_TEST_SERVER` for a live round-trip.
