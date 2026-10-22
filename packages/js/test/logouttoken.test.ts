import { test } from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";

import { BACKCHANNEL_LOGOUT_EVENT, JwksCache, verifyIdToken, verifyLogoutToken } from "../src/idtoken.ts";
import { OAuthError } from "../src/errors.ts";
import type { FetchLike } from "../src/types.ts";

// Every token here is signed for the test that uses it, with a real RSA key,
// so each refusal is the rule under test and not a broken signature.

const ISSUER = "https://acme.auth.example.test";
const CLIENT = "notes-app";
const KID = "k1";

type Keys = { publicJwk: JsonWebKey; privateKey: CryptoKey };

const keys: Promise<Keys> = (async () => {
  const pair = await webcrypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  );
  return { publicJwk: await webcrypto.subtle.exportKey("jwk", pair.publicKey), privateKey: pair.privateKey };
})();

const b64u = (s: string | Uint8Array) => Buffer.from(typeof s === "string" ? new TextEncoder().encode(s) : s).toString("base64url");

async function sign(claims: Record<string, unknown>, header: Record<string, unknown> = {}): Promise<string> {
  const k = await keys;
  const h = b64u(JSON.stringify({ alg: "RS256", typ: "logout+jwt", kid: KID, ...header }));
  const p = b64u(JSON.stringify(claims));
  const sig = await webcrypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, k.privateKey, new TextEncoder().encode(`${h}.${p}`));
  return `${h}.${p}.${b64u(new Uint8Array(sig))}`;
}

async function jwks(): Promise<JwksCache> {
  const k = await keys;
  const fetch: FetchLike = async () =>
    new Response(JSON.stringify({ keys: [{ ...k.publicJwk, kid: KID, alg: "RS256", use: "sig" }] }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  return new JwksCache(`${ISSUER}/.well-known/jwks.json`, fetch);
}

/** What the Proteles server sends in a back-channel logout token. */
function claims(over: Record<string, unknown> = {}): Record<string, unknown> {
  const now = Math.floor(Date.now() / 1000);
  return {
    iss: ISSUER,
    aud: CLIENT,
    iat: now,
    exp: now + 120,
    jti: "0b8f6c4e-1d2a-4c5b-9e8f-7a6b5c4d3e2f",
    events: { [BACKCHANNEL_LOGOUT_EVENT]: {} },
    sub: "4b1c0a2e-0000-4000-8000-000000000001",
    sid: "0123456789abcdef0123456789abcdef",
    ...over,
  };
}

async function verify(token: string) {
  return verifyLogoutToken(token, { issuer: ISSUER, audience: CLIENT, jwks: await jwks() });
}

async function refused(token: string, why: RegExp) {
  await assert.rejects(verify(token), (e: unknown) => e instanceof OAuthError && why.test(e.message), String(why));
}

test("a logout token this server sends verifies, and says which session ended", async () => {
  const c = await verify(await sign(claims()));
  assert.equal(c.sid, "0123456789abcdef0123456789abcdef");
  assert.equal(c.sub, "4b1c0a2e-0000-4000-8000-000000000001");
  assert.equal(c.jti, "0b8f6c4e-1d2a-4c5b-9e8f-7a6b5c4d3e2f");
  assert.deepEqual(c.aud, [CLIENT]);
});

test("a sub alone, or a sid alone, is enough (§2.4)", async () => {
  const { sid: _sid, ...noSid } = claims();
  const { sub: _sub, ...noSub } = claims();
  assert.equal((await verify(await sign(noSid))).sid, undefined);
  assert.equal((await verify(await sign(noSub))).sub, undefined);
});

test("each of §2.6's rules refuses the token that breaks it", async () => {
  const { sub: _a, sid: _b, ...neither } = claims();
  const { jti: _c, ...noJti } = claims();
  const { iat: _d, ...noIat } = claims();
  const { exp: _e, ...noExp } = claims();
  const now = Math.floor(Date.now() / 1000);
  const cases: [Record<string, unknown>, RegExp][] = [
    [neither, /neither a sub nor a sid/],
    [noJti, /no jti/],
    [noIat, /no iat/],
    [noExp, /no exp/],
    [claims({ exp: now - 600 }), /expired/],
    [claims({ iat: now + 600 }), /in the future/],
    [claims({ events: {} }), /do not name a back-channel logout/],
    [claims({ events: { [BACKCHANNEL_LOGOUT_EVENT]: "yes" } }), /do not name a back-channel logout/],
    [claims({ events: [BACKCHANNEL_LOGOUT_EVENT] }), /do not name a back-channel logout/],
    [claims({ events: { [BACKCHANNEL_LOGOUT_EVENT]: [] } }), /do not name a back-channel logout/],
    [claims({ nonce: "n" }), /carries a nonce/],
    [claims({ nonce: null }), /carries a nonce/],
    [claims({ iss: "https://other.example.test" }), /issuer/],
    [claims({ aud: "another-app" }), /audience/],
    [claims({ aud: [CLIENT, "another-app"] }), /audience/],
  ];
  for (const [c, why] of cases) await refused(await sign(c), why);
});

test("a sub or sid of the wrong type reads as absent, not as a string", async () => {
  const c = await verify(await sign(claims({ sub: 123 })));
  assert.equal(c.sub, undefined);
  assert.equal(c.sid, "0123456789abcdef0123456789abcdef");
  await refused(await sign(claims({ sub: 123, sid: false })), /neither a sub nor a sid/);
});

test("the media type is read as RFC 7515 says: any case, application/ implied", async () => {
  for (const typ of ["LOGOUT+JWT", "application/logout+jwt"]) assert.ok(await verify(await sign(claims(), { typ })), typ);
});

test("the header must type it, and the signature must be the issuer's", async () => {
  await refused(await sign(claims(), { typ: "JWT" }), /typ/);
  await refused(await sign(claims(), { kid: undefined }), /logout token header has no kid/);
  await refused(await sign(claims(), { typ: undefined }), /typ/);
  await refused(await sign(claims(), { alg: "none" }), /only RS256/);
  const token = await sign(claims());
  const [h, , s] = token.split(".");
  const forged = `${h}.${b64u(JSON.stringify(claims({ sid: "ffffffffffffffffffffffffffffffff" })))}.${s}`;
  await refused(forged, /signature does not verify/);
});

test("an ID token is not a logout token, nor a logout token an ID token", async () => {
  const now = Math.floor(Date.now() / 1000);
  const idToken = await sign({ iss: ISSUER, aud: CLIENT, sub: "u", iat: now, exp: now + 300, sid: "s" }, { typ: "JWT" });
  await refused(idToken, /typ/);
  // And the other way: refused for its type, even by a caller with no nonce
  // and no access token to compare — the refresh path, where nothing else
  // would tell the two apart.
  for (const nonce of ["N", null]) {
    await assert.rejects(
      verifyIdToken(await sign(claims()), { issuer: ISSUER, audience: CLIENT, nonce, accessToken: null, jwks: await jwks() }),
      (e: unknown) => e instanceof OAuthError && /typed as a logout token/.test(e.message),
      String(nonce),
    );
  }
});
