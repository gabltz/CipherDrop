/**
 * Strict, canonical base64url (RFC 4648 §5) without padding.
 * Decoding rejects padding, whitespace, the standard alphabet and
 * non-canonical trailing bits.
 */

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const LOOKUP = new Int16Array(128).fill(-1);
for (let i = 0; i < ALPHABET.length; i++) LOOKUP[ALPHABET.charCodeAt(i)] = i;

export class EncodingError extends Error {
  constructor(public readonly field: string) {
    super(`field \`${field}\` is not valid unpadded base64url`);
    this.name = "EncodingError";
  }
}

export function b64urlEncode(bytes: Uint8Array): string {
  let out = "";
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8) | bytes[i + 2]!;
    out += ALPHABET[(n >> 18) & 63]! + ALPHABET[(n >> 12) & 63]! + ALPHABET[(n >> 6) & 63]! + ALPHABET[n & 63]!;
  }
  const rem = bytes.length - i;
  if (rem === 1) {
    const n = bytes[i]! << 16;
    out += ALPHABET[(n >> 18) & 63]! + ALPHABET[(n >> 12) & 63]!;
  } else if (rem === 2) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8);
    out += ALPHABET[(n >> 18) & 63]! + ALPHABET[(n >> 12) & 63]! + ALPHABET[(n >> 6) & 63]!;
  }
  return out;
}

export function b64urlDecode(input: string, field = "value"): Uint8Array {
  if (input.length % 4 === 1) throw new EncodingError(field);
  const out = new Uint8Array(Math.floor((input.length * 3) / 4));
  let o = 0;
  let acc = 0;
  let bits = 0;
  for (let i = 0; i < input.length; i++) {
    const c = input.charCodeAt(i);
    const v = c < 128 ? LOOKUP[c]! : -1;
    if (v < 0) throw new EncodingError(field);
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >> bits) & 0xff;
    }
  }
  // Canonical form: leftover bits must be zero.
  if (bits > 0 && (acc & ((1 << bits) - 1)) !== 0) throw new EncodingError(field);
  return out.subarray(0, o);
}

/** Decode into exactly `len` bytes. */
export function b64urlDecodeExact(input: string, len: number, field: string): Uint8Array {
  if (input.length !== Math.ceil((len * 4) / 3)) throw new EncodingError(field);
  const b = b64urlDecode(input, field);
  if (b.length !== len) throw new EncodingError(field);
  return b;
}

export const utf8Encode = (s: string): Uint8Array => new TextEncoder().encode(s);
export const utf8Decode = (b: Uint8Array): string => new TextDecoder("utf-8", { fatal: true }).decode(b);

/** Best-effort wipe of a byte buffer (JavaScript cannot guarantee erasure). */
export function wipe(...bufs: (Uint8Array | undefined | null)[]): void {
  for (const b of bufs) b?.fill(0);
}
