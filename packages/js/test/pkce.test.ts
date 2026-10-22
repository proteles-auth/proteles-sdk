import { test } from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";

import { codeChallengeS256, generateCodeVerifier, randomToken, timingSafeEqual } from "../src/pkce.ts";
import { base64UrlEncode } from "../src/crypto.ts";

const BASE64URL = /^[A-Za-z0-9_-]+$/;

test("code verifier is 43 base64url chars (32 bytes) and within RFC 7636 range", async () => {
  const v = await generateCodeVerifier();
  assert.match(v, BASE64URL);
  assert.equal(v.length, 43);
  assert.ok(v.length >= 43 && v.length <= 128);
});

test("randomToken is base64url and unique across calls", async () => {
  const a = await randomToken(16);
  const b = await randomToken(16);
  assert.match(a, BASE64URL);
  assert.notEqual(a, b);
});

test("S256 challenge matches an independent SHA-256 computation", async () => {
  const verifier = await generateCodeVerifier();
  const challenge = await codeChallengeS256(verifier);
  // Independently compute base64url(SHA-256(verifier)) via node:crypto.
  const digest = await webcrypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  const expected = base64UrlEncode(new Uint8Array(digest));
  assert.equal(challenge, expected);
});

test("S256 challenge matches the RFC 7636 Appendix B test vector", async () => {
  // RFC 7636 Appendix B fixed vector.
  const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
  const challenge = await codeChallengeS256(verifier);
  assert.equal(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
});

test("timingSafeEqual: equal strings match, mismatches and empties do not", () => {
  assert.equal(timingSafeEqual("abc123", "abc123"), true);
  assert.equal(timingSafeEqual("abc123", "abc124"), false);
  assert.equal(timingSafeEqual("abc", "abcd"), false); // differing lengths
  assert.equal(timingSafeEqual("", ""), false); // empty never matches (missing flow)
  assert.equal(timingSafeEqual("x", ""), false);
});
