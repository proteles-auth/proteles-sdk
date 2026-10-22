import { test } from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";

import { JwksCache, verifyIdToken } from "../src/idtoken.ts";
import { OAuthError } from "../src/errors.ts";
import type { FetchLike } from "../src/types.ts";

// ---------------------------------------------------------------------------
// A real RSA key, so these tests exercise the actual signature path rather than
// a stub. Nothing here is a fixture: every token below is signed for the test
// that uses it, which is what makes the negative cases mean anything.
// ---------------------------------------------------------------------------

const ISSUER = "https://auth.example.test";
const CLIENT = "test-client";
const KID = "k1";

type Keys = { publicJwk: JsonWebKey; privateKey: CryptoKey };

async function makeKeys(): Promise<Keys> {
  const pair = await webcrypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  );
  const publicJwk = await webcrypto.subtle.exportKey("jwk", pair.publicKey);
  return { publicJwk, privateKey: pair.privateKey };
}

function b64u(bytes: Uint8Array | string): string {
  const b = typeof bytes === "string" ? new TextEncoder().encode(bytes) : bytes;
  return Buffer.from(b).toString("base64url");
}

async function signToken(
  keys: Keys,
  claims: Record<string, unknown>,
  header: Record<string, unknown> = {},
): Promise<string> {
  const h = b64u(JSON.stringify({ alg: "RS256", typ: "JWT", kid: KID, ...header }));
  const p = b64u(JSON.stringify(claims));
  const sig = await webcrypto.subtle.sign(
    { name: "RSASSA-PKCS1-v1_5" },
    keys.privateKey,
    new TextEncoder().encode(`${h}.${p}`),
  );
  return `${h}.${p}.${b64u(new Uint8Array(sig))}`;
}

function jwksFetch(keys: Keys, kid = KID): { fetch: FetchLike; calls: number } {
  const state = { calls: 0 };
  const fetch: FetchLike = async () => {
    state.calls += 1;
    const jwk = { ...keys.publicJwk, kid, alg: "RS256", use: "sig" };
    return new Response(JSON.stringify({ keys: [jwk] }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };
  return { fetch, get calls() { return state.calls; } } as { fetch: FetchLike; calls: number };
}

function goodClaims(over: Record<string, unknown> = {}): Record<string, unknown> {
  const now = Math.floor(Date.now() / 1000);
  return { iss: ISSUER, aud: CLIENT, sub: "user-1", exp: now + 300, iat: now, nonce: "N", ...over };
}

async function verify(keys: Keys, token: string, over: Record<string, unknown> = {}) {
  const { fetch } = jwksFetch(keys);
  return verifyIdToken(token, {
    issuer: ISSUER,
    audience: CLIENT,
    nonce: "N",
    // `null` unless a test is about `at_hash`: the tokens below do not carry
    // one. The vectors hold the binding itself (`vectors.test.ts`).
    accessToken: null,
    jwks: new JwksCache(`${ISSUER}/.well-known/jwks.json`, fetch),
    ...over,
  });
}

async function refuses(fn: () => Promise<unknown>, contains: string) {
  await assert.rejects(fn, (err: unknown) => {
    assert.ok(err instanceof OAuthError, `expected OAuthError, got ${String(err)}`);
    assert.match(
      String((err as OAuthError).message ?? err),
      new RegExp(contains, "i"),
      `message should mention ${contains}`,
    );
    return true;
  });
}

// ---------------------------------------------------------------------------

test("a well-formed token verifies and returns its claims", async () => {
  const keys = await makeKeys();
  const claims = await verify(keys, await signToken(keys, goodClaims()));
  assert.equal(claims.sub, "user-1");
  assert.deepEqual(claims.aud, [CLIENT]);
});

test("alg none is refused before anything else is read", async () => {
  // The forgery a permissive verifier accepts: no signature at all.
  const keys = await makeKeys();
  const h = b64u(JSON.stringify({ alg: "none", kid: KID }));
  const p = b64u(JSON.stringify(goodClaims()));
  await refuses(() => verify(keys, `${h}.${p}.`), "only RS256");
});

test("alg HS256 is refused — the public key is not an HMAC secret", async () => {
  // The subtler forgery: sign with HS256 using the *public* key, which anybody
  // can fetch from the JWKS endpoint. A verifier that trusts the header's alg
  // and looks up "the key for this kid" accepts it.
  const keys = await makeKeys();
  const h = b64u(JSON.stringify({ alg: "HS256", kid: KID }));
  const p = b64u(JSON.stringify(goodClaims()));
  const secret = new TextEncoder().encode(JSON.stringify(keys.publicJwk.n));
  const hkey = await webcrypto.subtle.importKey("raw", secret, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = await webcrypto.subtle.sign("HMAC", hkey, new TextEncoder().encode(`${h}.${p}`));
  await refuses(() => verify(keys, `${h}.${p}.${b64u(new Uint8Array(mac))}`), "only RS256");
});

test("a tampered payload does not verify", async () => {
  const keys = await makeKeys();
  const token = await signToken(keys, goodClaims());
  const [h, , s] = token.split(".");
  const swapped = b64u(JSON.stringify(goodClaims({ sub: "somebody-else" })));
  await refuses(() => verify(keys, `${h}.${swapped}.${s}`), "signature does not verify");
});

test("a token signed by another key does not verify", async () => {
  const mine = await makeKeys();
  const theirs = await makeKeys();
  // Signed by `theirs`, checked against a JWKS publishing `mine`.
  const token = await signToken(theirs, goodClaims());
  await refuses(() => verify(mine, token), "signature does not verify");
});

test("the wrong issuer is refused", async () => {
  const keys = await makeKeys();
  const token = await signToken(keys, goodClaims({ iss: "https://evil.test" }));
  await refuses(() => verify(keys, token), "issuer");
});

test("a trailing slash is a mismatch, whichever side has it (M2, §5.2 #2)", async () => {
  // The server emits one spelling per tenant, with no trailing slash, and
  // normalising a slash is how two issuers become one. `OAuthClient` refuses a
  // configured slash at start-up, so this is the verifier's own half.
  const keys = await makeKeys();
  await refuses(async () => verify(keys, await signToken(keys, goodClaims()), { issuer: `${ISSUER}/` }), "issuer");
  await refuses(async () => verify(keys, await signToken(keys, goodClaims({ iss: `${ISSUER}/` }))), "issuer");
});

test("an audience that does not include this client is refused", async () => {
  const keys = await makeKeys();
  const token = await signToken(keys, goodClaims({ aud: "another-client" }));
  await refuses(() => verify(keys, token), "audience");
});

test("an array audience is accepted only as this client alone (§5.2)", async () => {
  // Several audiences would need `azp`, which this issuer never sends. A token
  // naming another client beside this one is not this client's token.
  const keys = await makeKeys();
  const claims = await verify(keys, await signToken(keys, goodClaims({ aud: [CLIENT] })));
  assert.deepEqual(claims.aud, [CLIENT]);
  await refuses(async () => verify(keys, await signToken(keys, goodClaims({ aud: ["other", CLIENT] }))), "audience");
});

test("an issuer that is not a string is refused, not coerced", async () => {
  // `String(["https://a"])` is `"https://a"`: coercing would let an array stand
  // in for the issuer.
  const keys = await makeKeys();
  await refuses(async () => verify(keys, await signToken(keys, goodClaims({ iss: [ISSUER] }))), "issuer");
});

test("at_hash binds the token to the access token it came with (M3)", async () => {
  const keys = await makeKeys();
  const digest = new Uint8Array(await webcrypto.subtle.digest("SHA-256", new TextEncoder().encode("AT")));
  const atHash = b64u(digest.subarray(0, 16));
  const token = await signToken(keys, goodClaims({ at_hash: atHash }));
  const claims = await verify(keys, token, { accessToken: "AT" });
  assert.equal(claims.sub, "user-1");
  await refuses(() => verify(keys, token, { accessToken: "another access token" }), "at_hash");
  // Held, and not in the token: refused, since the binding is the point.
  await refuses(async () => verify(keys, await signToken(keys, goodClaims()), { accessToken: "AT" }), "at_hash");
});

test("an expired token is refused", async () => {
  const keys = await makeKeys();
  const past = Math.floor(Date.now() / 1000) - 3600;
  const token = await signToken(keys, goodClaims({ exp: past }));
  await refuses(() => verify(keys, token), "expired");
});

test("a token issued in the future is refused", async () => {
  const keys = await makeKeys();
  const soon = Math.floor(Date.now() / 1000) + 3600;
  const token = await signToken(keys, goodClaims({ iat: soon }));
  await refuses(() => verify(keys, token), "future");
});

test("a mismatched nonce is refused", async () => {
  const keys = await makeKeys();
  const token = await signToken(keys, goodClaims({ nonce: "different" }));
  await refuses(() => verify(keys, token), "nonce");
});

test("a missing nonce is refused when one was expected", async () => {
  const keys = await makeKeys();
  const claims = goodClaims();
  delete claims["nonce"];
  const token = await signToken(keys, claims);
  await refuses(() => verify(keys, token), "nonce");
});

test("an empty expected nonce is an error, not a skip", async () => {
  // The check quietly not happening. A login whose nonce was lost must fail,
  // not pass.
  const keys = await makeKeys();
  const token = await signToken(keys, goodClaims());
  await refuses(() => verify(keys, token, { nonce: "" }), "no nonce was recorded");
});

test("nonce null is the only way to skip the comparison, for the refresh grant", async () => {
  // The refresh grant mints an id_token with no nonce — there is no authorize
  // request to have carried one. `null` says that explicitly.
  const keys = await makeKeys();
  const claims = goodClaims();
  delete claims["nonce"];
  const verified = await verify(keys, await signToken(keys, claims), { nonce: null });
  assert.equal(verified.sub, "user-1");
});

test("an unknown kid refetches the key set, which is what a rotation looks like", async () => {
  const keys = await makeKeys();
  let served = "old-kid";
  let calls = 0;
  const fetch: FetchLike = async () => {
    calls += 1;
    const jwk = { ...keys.publicJwk, kid: served, alg: "RS256", use: "sig" };
    return new Response(JSON.stringify({ keys: [jwk] }), { status: 200 });
  };
  const cache = new JwksCache(`${ISSUER}/.well-known/jwks.json`, fetch);

  // Warm it on the old kid.
  const oldToken = await signToken(keys, goodClaims(), { kid: "old-kid" });
  await verifyIdToken(oldToken, { issuer: ISSUER, audience: CLIENT, nonce: "N", accessToken: null, jwks: cache });
  assert.equal(calls, 1);

  // The server rotates; a token arrives naming a kid the cache has never seen.
  served = KID;
  const newToken = await signToken(keys, goodClaims(), { kid: KID });
  const claims = await verifyIdToken(newToken, { issuer: ISSUER, audience: CLIENT, nonce: "N", accessToken: null, jwks: cache });
  assert.equal(claims.sub, "user-1");
  assert.equal(calls, 2, "an unknown kid must trigger exactly one refetch");
});

test("a kid nobody publishes is an error rather than a silent pass", async () => {
  const keys = await makeKeys();
  const token = await signToken(keys, goodClaims(), { kid: "never-published" });
  await refuses(() => verify(keys, token), "no signing key");
});

test("a header with no kid is refused", async () => {
  const keys = await makeKeys();
  const h = b64u(JSON.stringify({ alg: "RS256" }));
  const p = b64u(JSON.stringify(goodClaims()));
  await refuses(() => verify(keys, `${h}.${p}.AAAA`), "no kid");
});

test("a jwks document with no usable key is refused rather than cached empty", async () => {
  const keys = await makeKeys();
  const fetch: FetchLike = async () => new Response(JSON.stringify({ keys: [] }), { status: 200 });
  const cache = new JwksCache(`${ISSUER}/.well-known/jwks.json`, fetch);
  const token = await signToken(keys, goodClaims());
  await refuses(
    () => verifyIdToken(token, { issuer: ISSUER, audience: CLIENT, nonce: "N", accessToken: null, jwks: cache }),
    "no usable RS256",
  );
});

// A key set that could not be read is not a key set that said no. A caller
// holding a freshly rotated refresh token keeps it for the first and drops it
// for the second, so the error has to say which it is — through `retryable`,
// as the token endpoint's errors do (docs/mobile-SDKs.md §10.9 item 4).
test("a key-set fetch that failed says how, and whether trying again could help", async () => {
  const keys = await makeKeys();
  const token = await signToken(keys, goodClaims());
  const cases: [string, FetchLike, { status?: number; unreachable: boolean; retryable: boolean; retryAfter?: number }][] = [
    [
      "503",
      async () => new Response("busy", { status: 503, headers: { "retry-after": "5" } }),
      { status: 503, unreachable: false, retryable: true, retryAfter: 5 },
    ],
    [
      "no answer",
      async () => {
        throw new TypeError("fetch failed");
      },
      { unreachable: true, retryable: true },
    ],
    ["404", async () => new Response("nope", { status: 404 }), { status: 404, unreachable: false, retryable: false }],
  ];
  for (const [label, fetch, want] of cases) {
    const cache = new JwksCache(`${ISSUER}/.well-known/jwks.json`, fetch);
    await assert.rejects(
      () => verifyIdToken(token, { issuer: ISSUER, audience: CLIENT, nonce: "N", accessToken: null, jwks: cache }),
      (err: unknown) => {
        assert.ok(err instanceof OAuthError, `${label}: expected OAuthError, got ${String(err)}`);
        assert.equal(err.status, want.status, `${label}: status`);
        assert.equal(err.unreachable, want.unreachable, `${label}: unreachable`);
        assert.equal(err.retryable, want.retryable, `${label}: retryable`);
        assert.equal(err.retryAfter, want.retryAfter, `${label}: retryAfter`);
        return true;
      },
    );
  }
});

test("a token verifies where globalThis.crypto is missing, as on Node 18", async () => {
  // Every package says `node >=18.12`, and Node 18 has no global `crypto`
  // unless started with --experimental-global-webcrypto. The verifier used it
  // bare for the key import, the signature and `at_hash`, so every sign-in
  // there failed on `crypto is not defined`.
  const keys = await makeKeys();
  const digest = new Uint8Array(await webcrypto.subtle.digest("SHA-256", new TextEncoder().encode("AT")));
  const token = await signToken(keys, goodClaims({ at_hash: b64u(digest.subarray(0, 16)) }));
  const { fetch } = jwksFetch(keys);
  const saved = Object.getOwnPropertyDescriptor(globalThis, "crypto");
  Object.defineProperty(globalThis, "crypto", { value: undefined, configurable: true, writable: true });
  try {
    assert.equal(typeof (globalThis as { crypto?: unknown }).crypto, "undefined", "the global really is gone");
    const claims = await verifyIdToken(token, {
      issuer: ISSUER,
      audience: CLIENT,
      nonce: "N",
      accessToken: "AT",
      jwks: new JwksCache(`${ISSUER}/.well-known/jwks.json`, fetch),
    });
    assert.equal(claims.sub, "user-1");
  } finally {
    if (saved) Object.defineProperty(globalThis, "crypto", saved);
    else delete (globalThis as { crypto?: unknown }).crypto;
  }
  assert.ok(globalThis.crypto?.subtle, "and it is back for the tests after this one");
});

/** A key-set fetch that never answers until its abort signal fires. */
function hangingKeySet(): { fetch: FetchLike; abortedAfter: () => number | undefined } {
  let ms: number | undefined;
  const fetch: FetchLike = (_url, init) =>
    new Promise((_resolve, reject) => {
      const started = Date.now();
      const signal = init?.signal ?? undefined;
      if (!signal) {
        reject(new Error("no abort signal reached the key-set fetch"));
        return;
      }
      // So that a cache which never aborts fails this test rather than hangs it.
      const backstop = setTimeout(() => reject(new Error("the key-set fetch was never aborted")), 5_000);
      signal.addEventListener("abort", () => {
        clearTimeout(backstop);
        ms = Date.now() - started;
        reject(new DOMException("aborted", "AbortError"));
      });
    });
  return { fetch, abortedAfter: () => ms };
}

test("a key-set fetch that never answers is abandoned after the timeout, as unreachable", async () => {
  // Every callback and every refresh with an ID token waits on this fetch, so a
  // key-set endpoint that accepts the connection and never answers held all of
  // them open with it.
  const keys = await makeKeys();
  const token = await signToken(keys, goodClaims());
  const { fetch, abortedAfter } = hangingKeySet();
  const cache = new JwksCache(`${ISSUER}/.well-known/jwks.json`, fetch, { timeoutMs: 250 });
  await assert.rejects(
    () => verifyIdToken(token, { issuer: ISSUER, audience: CLIENT, nonce: "N", accessToken: null, jwks: cache }),
    (err: unknown) => {
      assert.ok(err instanceof OAuthError, `expected OAuthError, got ${String(err)}`);
      assert.equal(err.unreachable, true, "no answer came");
      assert.equal(err.retryable, true, "so trying again later could help");
      return true;
    },
  );
  const ms = abortedAfter();
  assert.ok(ms !== undefined, "the fetch was never aborted — no timeout was applied");
  // Generous upper bound: this runs on a machine that also builds Rust.
  assert.ok(ms >= 200 && ms < 3000, `aborted after ${ms}ms, expected ~250ms`);
});

test("unknown kids refetch the key set at most once per interval", async () => {
  // `verifyLogoutToken` runs on an unauthenticated POST, and the key lookup
  // comes before the signature is checked. So every token naming a kid the
  // cache did not hold was one fetch to the issuer, for anybody who could reach
  // the back-channel logout route.
  const keys = await makeKeys();
  let calls = 0;
  const fetch: FetchLike = async () => {
    calls += 1;
    return new Response(JSON.stringify({ keys: [{ ...keys.publicJwk, kid: KID, alg: "RS256", use: "sig" }] }), { status: 200 });
  };
  const cache = new JwksCache(`${ISSUER}/.well-known/jwks.json`, fetch);
  const t0 = Date.now();
  const at = (ms: number) => ({ issuer: ISSUER, audience: CLIENT, nonce: "N", accessToken: null, jwks: cache, now: () => t0 + ms });
  const randomKid = () => signToken(keys, goodClaims(), { kid: crypto.randomUUID() });

  await verifyIdToken(await signToken(keys, goodClaims()), at(0));
  assert.equal(calls, 1, "the first token fills the cache");

  for (let i = 0; i < 10; i++) await refuses(async () => verifyIdToken(await randomKid(), at(1_000 + i)), "no signing key");
  const burst = await Promise.allSettled(Array.from({ length: 10 }, async () => verifyIdToken(await randomKid(), at(2_000))));
  assert.ok(burst.every((r) => r.status === "rejected"), "a kid nobody publishes is still refused");
  assert.equal(calls, 2, "twenty unknown kids, one refetch");

  // The known kid is unaffected, and costs nothing.
  assert.equal((await verifyIdToken(await signToken(keys, goodClaims()), at(3_000))).sub, "user-1");
  assert.equal(calls, 2);

  // A minute on, an unknown kid may look again — a rotation is still found.
  await refuses(async () => verifyIdToken(await randomKid(), at(61_000)), "no signing key");
  assert.equal(calls, 3, "one more refetch once the interval has passed");
});

test("made-up kids on the logout route do not hold back an ID token's new key", async () => {
  // There used to be one window for the whole cache, so a made-up kid
  // POSTed to the back-channel logout route every thirty seconds kept it
  // armed, and an ID token naming a freshly rotated key was refused until the
  // key set's TTL ran out.
  const keys = await makeKeys();
  let published = ["A"];
  let calls = 0;
  const fetch: FetchLike = async () => {
    calls += 1;
    const set = published.map((kid) => ({ ...keys.publicJwk, kid, alg: "RS256", use: "sig" }));
    return new Response(JSON.stringify({ keys: set }), { status: 200 });
  };
  const cache = new JwksCache(`${ISSUER}/.well-known/jwks.json`, fetch);
  const t0 = Date.now();

  await cache.keyFor("A", t0, "id_token");
  await refuses(() => cache.keyFor("made-up", t0 + 1_000, "logout token"), "no signing key");
  assert.equal(calls, 2, "the made-up kid spent the logout path's refetch");

  published = ["A", "B"]; // the rotation
  await cache.keyFor("B", t0 + 2_000, "id_token");
  assert.equal(calls, 3, "the ID token's new kid still refetches, and is found");

  // The control: the logout path is still held back, so the floor holds.
  await refuses(() => cache.keyFor("made-up-2", t0 + 3_000, "logout token"), "no signing key");
  assert.equal(calls, 3, "a second made-up kid inside the window fetches nothing");
});

test("a token that is not three parts is refused", async () => {
  const keys = await makeKeys();
  await refuses(() => verify(keys, "not.a.jwt.at.all"), "three-part");
  await refuses(() => verify(keys, "two.parts"), "three-part");
});
