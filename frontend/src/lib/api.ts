import { ApiError, CipherDrop, ProtocolError, type ConfigResponse } from "@cipherdrop/sdk";

/**
 * Same-origin API client. An optional API token lives only in this module's
 * memory for the lifetime of the tab: it is never written to storage.
 */
let apiToken: string | undefined;

export function setApiToken(t: string | undefined): void {
  apiToken = t && t.trim() ? t.trim() : undefined;
}

export function hasApiToken(): boolean {
  return apiToken !== undefined;
}

export function client(): CipherDrop {
  return new CipherDrop({ baseUrl: "", apiKey: apiToken });
}

let configPromise: Promise<ConfigResponse> | undefined;
export function instanceConfig(): Promise<ConfigResponse> {
  configPromise ??= client()
    .config()
    .catch((e: unknown) => {
      configPromise = undefined;
      throw e;
    });
  return configPromise;
}

/** Human-readable message for any error. Never includes secret material. */
export function describeError(e: unknown): string {
  if (e instanceof ApiError) {
    switch (e.code) {
      case "share_unavailable":
        return "This secret is no longer available. It may have expired, been viewed the maximum number of times, or been revoked.";
      case "unauthorized":
        return "An API token is required on this instance.";
      case "insufficient_scope":
        return "Your API token does not have the required permission.";
      case "rate_limited":
        return "Too many requests. Please wait a minute and try again.";
      case "quota_exceeded":
        return "Your API token has reached its daily quota.";
      case "payload_too_large":
        return "The secret is too large for this instance.";
      case "capacity_exhausted":
        return "This instance is currently full. Please try again later.";
      case "feature_disabled":
        return e.problem?.detail ?? "This option is disabled on this instance.";
      default:
        return e.problem?.detail ?? e.problem?.title ?? `Request failed (HTTP ${e.status}).`;
    }
  }
  if (e instanceof ProtocolError) {
    switch (e.code) {
      case "decryption":
        return "Decryption failed. The link may be incomplete or the password is wrong.";
      case "password_required":
        return "This secret is protected by a password.";
      case "malformed_url":
        return "This link is invalid or incomplete. Make sure you copied the entire link, including the part after #.";
      case "kdf_bounds":
        return "This secret uses unsupported password-protection parameters.";
      default:
        return "The encrypted data is malformed.";
    }
  }
  if (e instanceof TypeError) return "Network error. Check your connection and try again.";
  return "Something went wrong.";
}
