//! PKCE (RFC 7636) + the random `state`/`nonce` tokens that bind an authorize
//! request to its callback. A straight port of the helpers in Proteles'
//! reference Go client (`randomURLSafeToken`, `pkceChallengeS256`).

import { base64UrlEncode, randomBytes, sha256 } from "./crypto.js";

/**
 * A fresh PKCE code verifier: `nBytes` of entropy, base64url-encoded. The
 * default of 32 bytes yields 43 characters — the minimum RFC 7636 allows
 * (43–128).
 */
export async function generateCodeVerifier(nBytes = 32): Promise<string> {
  return base64UrlEncode(await randomBytes(nBytes));
}

/** The S256 code challenge for a verifier: base64url(SHA-256(verifier)). */
export async function codeChallengeS256(verifier: string): Promise<string> {
  const data = new TextEncoder().encode(verifier);
  return base64UrlEncode(await sha256(data));
}

/** A random URL-safe token, for `state` and `nonce`. */
export async function randomToken(nBytes = 32): Promise<string> {
  return base64UrlEncode(await randomBytes(nBytes));
}

/**
 * Length-checked, best-effort constant-time string comparison for validating
 * the `state` returned by the authorization server against the one we issued.
 * JavaScript can't guarantee true constant time, but this avoids the trivial
 * early-return on the first differing byte. Empty inputs never match — a
 * missing/expired flow is treated as a failed comparison, exactly like
 * `validateState` in the Go reference.
 */
export function timingSafeEqual(a: string, b: string): boolean {
  const enc = new TextEncoder();
  const ab = enc.encode(a);
  const bb = enc.encode(b);
  if (ab.length === 0 || bb.length === 0) return false;
  const len = Math.max(ab.length, bb.length);
  let diff = ab.length ^ bb.length;
  for (let i = 0; i < len; i++) {
    diff |= (ab[i] ?? 0) ^ (bb[i] ?? 0);
  }
  return diff === 0;
}
