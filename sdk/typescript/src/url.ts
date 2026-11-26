/**
 * Share links:      {base}/s/{id}#v1.{key}
 * Revocation links: {base}/revoke/{id}#v1.{token}
 * The fragment is never sent to any server.
 */

import { b64urlDecodeExact } from "./encoding.js";
import { ShareKey } from "./crypto.js";
import { ProtocolError, REVOCATION_TOKEN_LEN, SHARE_ID_LEN } from "./protocol.js";

export const FRAGMENT_PREFIX = "v1.";

export function validateShareId(id: string): string {
  try {
    b64urlDecodeExact(id, SHARE_ID_LEN, "share_id");
  } catch {
    throw new ProtocolError("malformed_url", "malformed share id");
  }
  return id;
}

function splitLink(link: string, marker: string): { base?: string; id: string; secret: string } {
  const s = link.trim();
  const hash = s.indexOf("#");
  if (hash < 0) throw new ProtocolError("malformed_url", "missing #v1. fragment");
  const left = s.slice(0, hash);
  const frag = s.slice(hash + 1);
  if (!frag.startsWith(FRAGMENT_PREFIX)) throw new ProtocolError("malformed_url", "unsupported fragment version");
  const secret = frag.slice(FRAGMENT_PREFIX.length);
  const pos = left.lastIndexOf(marker);
  let base: string | undefined;
  let id: string;
  if (pos >= 0) {
    base = left.slice(0, pos);
    if (!/^https?:\/\/[^/]/.test(base)) throw new ProtocolError("malformed_url");
    id = left.slice(pos + marker.length);
  } else if (!left.includes("/") && !left.includes(":")) {
    id = left;
  } else {
    throw new ProtocolError("malformed_url");
  }
  validateShareId(id);
  return { ...(base !== undefined ? { base } : {}), id, secret };
}

export interface ShareLink {
  baseUrl?: string;
  shareId: string;
  key: ShareKey;
}

export function parseShareLink(link: string): ShareLink {
  const { base, id, secret } = splitLink(link, "/s/");
  return { ...(base !== undefined ? { baseUrl: base } : {}), shareId: id, key: ShareKey.fromBase64Url(secret) };
}

export function formatShareLink(baseUrl: string, shareId: string, key: ShareKey): string {
  return `${baseUrl.replace(/\/+$/, "")}/s/${shareId}#${FRAGMENT_PREFIX}${key.toBase64Url()}`;
}

/** Append the key fragment to the fragment-free URL returned by the server. */
export function attachKey(url: string, key: ShareKey): string {
  if (url.includes("#")) throw new ProtocolError("malformed_url", "URL already has a fragment");
  return `${url}#${FRAGMENT_PREFIX}${key.toBase64Url()}`;
}

export interface RevocationLink {
  baseUrl?: string;
  shareId: string;
  token: string;
}

export function validateRevocationToken(token: string): string {
  try {
    b64urlDecodeExact(token, REVOCATION_TOKEN_LEN, "revocation_token");
  } catch {
    throw new ProtocolError("malformed_url", "malformed revocation token");
  }
  return token;
}

export function parseRevocationLink(link: string): RevocationLink {
  const { base, id, secret } = splitLink(link, "/revoke/");
  return { ...(base !== undefined ? { baseUrl: base } : {}), shareId: id, token: validateRevocationToken(secret) };
}
