import { randomBytes } from "node:crypto";
import { test } from "node:test";
import assert from "node:assert/strict";

import { base64UrlDecode, base64UrlEncode } from "../src/crypto.ts";
import { SessionCrypto } from "../src/session.ts";

/** Flips a bit in the token's final byte — which lands in the AES-GCM
 *  authentication tag. Tampering at the *byte* level matters: replacing the last
 *  base64url *character* often changes only padding bits, leaving the decoded
 *  bytes identical, so such a "tampered" token would decrypt fine. */
function tamper(token: string): string {
  const bytes = base64UrlDecode(token);
  bytes[bytes.length - 1] ^= 0xff;
  return base64UrlEncode(bytes);
}

// 32-byte key, base64.
// Generated per run: the literal this replaced is entry one of the
// published register, so the fixture and the value the register exists
// to refuse were the same string.
const KEY = randomBytes(32).toString("base64");

test("encrypt -> decrypt round-trips a structured value", async () => {
  const sc = new SessionCrypto(KEY);
  const value = { accessToken: "at", accessExpiresAt: 123, sub: "u1", nested: { a: 1 } };
  const token = await sc.decrypt(await sc.encrypt(value));
  assert.deepEqual(token, value);
});

test("ciphertext is opaque base64url (no plaintext leakage)", async () => {
  const sc = new SessionCrypto(KEY);
  const token = await sc.encrypt({ secret: "hunter2" });
  assert.match(token, /^[A-Za-z0-9_-]+$/);
  assert.ok(!token.includes("hunter2"));
});

test("two encryptions of the same value differ (random IV)", async () => {
  const sc = new SessionCrypto(KEY);
  const a = await sc.encrypt({ x: 1 });
  const b = await sc.encrypt({ x: 1 });
  assert.notEqual(a, b);
});

test("a tampered token fails to decrypt", async () => {
  const sc = new SessionCrypto(KEY);
  const token = await sc.encrypt({ x: 1 });
  await assert.rejects(() => sc.decrypt(tamper(token)));
});

test("a truncated token fails to decrypt", async () => {
  const sc = new SessionCrypto(KEY);
  const token = await sc.encrypt({ x: 1 });
  // Drop the last 4 bytes, destroying part of the GCM tag.
  const bytes = base64UrlDecode(token);
  await assert.rejects(() => sc.decrypt(base64UrlEncode(bytes.slice(0, bytes.length - 4))));
});

test("a different key cannot decrypt", async () => {
  const a = new SessionCrypto(KEY);
  const other = new SessionCrypto(randomBytes(32).toString("base64"));
  const token = await a.encrypt({ x: 1 });
  await assert.rejects(() => other.decrypt(token));
});

test("rejects a session secret that is not 32 bytes", () => {
  assert.throws(() => new SessionCrypto("c2hvcnQ=")); // "short"
});
