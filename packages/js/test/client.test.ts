import { test } from "node:test";
import assert from "node:assert/strict";

import { OAuthClient } from "../src/client.ts";
import { MAX_RETRY_AFTER_SECONDS, OAuthError, parseRetryAfter } from "../src/errors.ts";
import { codeChallengeS256 } from "../src/pkce.ts";
import type { FetchLike } from "../src/types.ts";

interface Recorded {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: string;
}

/** A fetch double that records each request and returns a canned response. */
function mockFetch(respond: (rec: Recorded) => Response): { fetch: FetchLike; calls: Recorded[] } {
  const calls: Recorded[] = [];
  const fetch: FetchLike = async (url, init) => {
    const rec: Recorded = {
      url,
      method: (init?.method ?? "GET").toUpperCase(),
      headers: (init?.headers as Record<string, string>) ?? {},
      body: typeof init?.body === "string" ? init.body : "",
    };
    calls.push(rec);
    return respond(rec);
  };
  return { fetch, calls };
}

const json = (obj: unknown, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json" } });

const baseConfig = {
  issuer: "https://auth.example.com",
  clientId: "app-123",
  redirectUri: "https://app.example.com/api/auth/callback",
};

test("a configured issuer with a trailing slash is refused at construction (M2)", () => {
  // ID tokens are compared to the issuer byte for byte, and the server's `iss`
  // never ends in "/", so a configured slash would fail every sign-in later.
  assert.throws(
    () => new OAuthClient({ ...baseConfig, issuer: "https://auth.example.com/", fetch: mockFetch(() => json({})).fetch }),
    /trailing slash/,
  );
});

test("resolves conventional endpoints from the issuer", () => {
  const client = new OAuthClient({ ...baseConfig, fetch: mockFetch(() => json({})).fetch });
  assert.deepEqual(client.getEndpoints(), {
    authorization: "https://auth.example.com/oauth/authorize",
    token: "https://auth.example.com/oauth/token",
    userinfo: "https://auth.example.com/oauth/userinfo",
    revocation: "https://auth.example.com/oauth/revoke",
    jwks: "https://auth.example.com/.well-known/jwks.json",
    endSession: "https://auth.example.com/oauth/logout",
  });
});

test("endSessionUrl names the app by its ID token, or by client_id without one", () => {
  const client = new OAuthClient({ ...baseConfig, fetch: mockFetch(() => json({})).fetch });

  const withHint = new URL(
    client.endSessionUrl({ idTokenHint: "h.i.nt", postLogoutRedirectUri: "https://app.example.com/", state: "s1" }),
  );
  assert.equal(withHint.origin + withHint.pathname, "https://auth.example.com/oauth/logout");
  assert.equal(withHint.searchParams.get("id_token_hint"), "h.i.nt");
  // Not both: the server must then check they agree, and the hint already says.
  assert.equal(withHint.searchParams.get("client_id"), null);
  assert.equal(withHint.searchParams.get("post_logout_redirect_uri"), "https://app.example.com/");
  assert.equal(withHint.searchParams.get("state"), "s1");

  const bare = new URL(client.endSessionUrl());
  assert.equal(bare.searchParams.get("client_id"), "app-123");
  assert.equal(bare.searchParams.get("id_token_hint"), null);
  assert.equal(bare.searchParams.get("post_logout_redirect_uri"), null);
});

test("createAuthorizationUrl sets every required param and a valid S256 challenge", async () => {
  const client = new OAuthClient({ ...baseConfig, fetch: mockFetch(() => json({})).fetch });
  const req = await client.createAuthorizationUrl();
  const u = new URL(req.url);

  assert.equal(u.origin + u.pathname, "https://auth.example.com/oauth/authorize");
  assert.equal(u.searchParams.get("response_type"), "code");
  assert.equal(u.searchParams.get("client_id"), "app-123");
  assert.equal(u.searchParams.get("redirect_uri"), baseConfig.redirectUri);
  assert.equal(u.searchParams.get("scope"), "openid profile email");
  assert.equal(u.searchParams.get("code_challenge_method"), "S256");
  assert.equal(u.searchParams.get("state"), req.state);
  assert.equal(u.searchParams.get("nonce"), req.nonce);
  // The challenge in the URL must be the S256 hash of the returned verifier.
  assert.equal(u.searchParams.get("code_challenge"), await codeChallengeS256(req.codeVerifier));
});

test("createAuthorizationUrl passes optional prompt/login_hint/connection and scope override", async () => {
  const client = new OAuthClient({ ...baseConfig, fetch: mockFetch(() => json({})).fetch });
  const req = await client.createAuthorizationUrl({
    scopes: ["openid", "email"],
    prompt: "consent",
    loginHint: "alice@example.com",
    connection: "google",
  });
  const p = new URL(req.url).searchParams;
  assert.equal(p.get("scope"), "openid email");
  assert.equal(p.get("prompt"), "consent");
  assert.equal(p.get("login_hint"), "alice@example.com");
  assert.equal(p.get("connection"), "google");
});

test("createAuthorizationUrl sends max_age, and sends it when it is zero", async () => {
  const client = new OAuthClient({ ...baseConfig, fetch: mockFetch(() => json({})).fetch });

  const fresh = await client.createAuthorizationUrl({ maxAge: 300 });
  assert.equal(new URL(fresh.url).searchParams.get("max_age"), "300");

  // The case a truthiness check drops. `max_age=0` is not "unset" — it is
  // "authenticate them now", which is the value a caller reaches for when they
  // mean it most, and OIDC Core §3.1.2.1 gives it that meaning explicitly.
  const now = await client.createAuthorizationUrl({ maxAge: 0 });
  assert.equal(new URL(now.url).searchParams.get("max_age"), "0", "max_age=0 must reach the wire");

  // Absent when not asked for, rather than defaulted to something.
  const plain = await client.createAuthorizationUrl({});
  assert.equal(new URL(plain.url).searchParams.get("max_age"), null);
});

test("createAuthorizationUrl sends max_age as an integer", async () => {
  const client = new OAuthClient({ ...baseConfig, fetch: mockFetch(() => json({})).fetch });
  // The parameter is defined in seconds as a whole number; a caller doing
  // arithmetic on a duration can easily arrive at a fraction, and "300.7"
  // is refused by a strict server rather than rounded by it.
  const req = await client.createAuthorizationUrl({ maxAge: 300.7 });
  assert.equal(new URL(req.url).searchParams.get("max_age"), "300");
});

test("HTTP Basic form-encodes each half of the credential (RFC 6749 s2.3.1)", async () => {
  // s2.3.1: the client identifier and password are each encoded with the
  // application/x-www-form-urlencoded algorithm before the base64. For the
  // base64url credentials Proteles issues that is the identity, which is why
  // sending them raw worked; a credential containing "+", "%", a space or ":"
  // is only transmitted correctly if it is encoded.
  //
  // ":" is the one that silently corrupts rather than merely mismatching: the
  // server splits on the first colon, so an unencoded colon in the id moves the
  // boundary and both halves come out wrong.
  const { fetch, calls } = mockFetch(() =>
    json({ access_token: "at", token_type: "Bearer", expires_in: 900 }),
  );
  const client = new OAuthClient({
    ...baseConfig,
    clientId: "app:1 2",
    clientSecret: "p+ss%word",
    fetch,
  });
  await client.exchangeCode({ code: "c", codeVerifier: "v" });

  const header = calls[0]!.headers["authorization"]!;
  const decoded = Buffer.from(header.slice("Basic ".length), "base64").toString();
  assert.equal(decoded, "app%3A1+2:p%2Bss%25word");
  // And it round-trips: decoding each half recovers what was configured.
  const [id, secret] = decoded.split(":");
  assert.equal(decodeURIComponent(id!.replace(/\+/g, " ")), "app:1 2");
  assert.equal(decodeURIComponent(secret!.replace(/\+/g, " ")), "p+ss%word");
});

test("exchangeCode (confidential) uses HTTP Basic and posts the PKCE verifier", async () => {
  const { fetch, calls } = mockFetch(() =>
    json({ access_token: "at", token_type: "Bearer", expires_in: 900, refresh_token: "rt", id_token: "it", scope: "openid" }),
  );
  const client = new OAuthClient({ ...baseConfig, clientSecret: "s3cret", fetch });
  const tok = await client.exchangeCode({ code: "the-code", codeVerifier: "the-verifier" });

  assert.equal(calls.length, 1);
  const call = calls[0]!;
  assert.equal(call.url, "https://auth.example.com/oauth/token");
  assert.equal(call.method, "POST");
  // client_secret_basic: base64("app-123:s3cret")
  assert.equal(call.headers["authorization"], `Basic ${Buffer.from("app-123:s3cret").toString("base64")}`);
  const form = new URLSearchParams(call.body);
  assert.equal(form.get("grant_type"), "authorization_code");
  assert.equal(form.get("code"), "the-code");
  assert.equal(form.get("code_verifier"), "the-verifier");
  assert.equal(form.get("redirect_uri"), baseConfig.redirectUri);
  assert.equal(form.get("client_id"), null, "confidential client authenticates via the header, not the body");

  // Response is normalized to camelCase.
  assert.deepEqual(tok, {
    accessToken: "at",
    tokenType: "Bearer",
    expiresIn: 900,
    refreshToken: "rt",
    idToken: "it",
    scope: "openid",
  });
});

test("exchangeCode (public) sends no Authorization header and identifies via client_id in the body", async () => {
  const { fetch, calls } = mockFetch(() => json({ access_token: "at", token_type: "Bearer", expires_in: 900 }));
  const client = new OAuthClient({ ...baseConfig, fetch }); // no clientSecret => public
  await client.exchangeCode({ code: "c", codeVerifier: "v" });

  const call = calls[0]!;
  assert.equal(call.headers["authorization"], undefined);
  assert.equal(new URLSearchParams(call.body).get("client_id"), "app-123");
});

test("refresh posts grant_type=refresh_token and normalizes the response", async () => {
  const { fetch, calls } = mockFetch(() => json({ access_token: "at2", token_type: "Bearer", expires_in: 900, refresh_token: "rt2" }));
  const client = new OAuthClient({ ...baseConfig, clientSecret: "s3cret", fetch });
  const tok = await client.refresh("old-rt");

  const form = new URLSearchParams(calls[0]!.body);
  assert.equal(form.get("grant_type"), "refresh_token");
  assert.equal(form.get("refresh_token"), "old-rt");
  assert.equal(tok.accessToken, "at2");
  assert.equal(tok.refreshToken, "rt2");
});

test("a structured OAuth error becomes OAuthError with code + status", async () => {
  const { fetch } = mockFetch(() => json({ error: "invalid_grant", error_description: "bad code" }, 400));
  const client = new OAuthClient({ ...baseConfig, clientSecret: "s3cret", fetch });
  await assert.rejects(
    () => client.exchangeCode({ code: "c", codeVerifier: "v" }),
    (e: unknown) => {
      assert.ok(e instanceof OAuthError);
      assert.equal(e.code, "invalid_grant");
      assert.equal(e.status, 400);
      return true;
    },
  );
});

test("fetchUserInfo maps preferred_username and preserves extra claims", async () => {
  const { fetch, calls } = mockFetch(() => json({ sub: "user-1", email: "a@b.com", preferred_username: "alice", custom: "x" }));
  const client = new OAuthClient({ ...baseConfig, fetch });
  const info = await client.fetchUserInfo("the-access-token");

  assert.equal(calls[0]!.headers["authorization"], "Bearer the-access-token");
  assert.equal(info.sub, "user-1");
  assert.equal(info.email, "a@b.com");
  assert.equal(info.preferredUsername, "alice");
  assert.equal(info["custom"], "x");
});

test("fetchUserInfo throws OAuthError on a non-200", async () => {
  const { fetch } = mockFetch(() => new Response("nope", { status: 401 }));
  const client = new OAuthClient({ ...baseConfig, fetch });
  await assert.rejects(() => client.fetchUserInfo("bad"), OAuthError);
});

test("revoke never throws: a transport failure resolves, and says the server was unreachable", async () => {
  const fetch: FetchLike = async () => {
    throw new Error("network down");
  };
  const client = new OAuthClient({ ...baseConfig, clientSecret: "s3cret", fetch });
  const result = await client.revoke("some-token"); // must resolve, not reject
  assert.equal(result.ok, false);
  assert.ok(!result.ok && result.error.unreachable && result.error.retryable);
});

test("revoke reports a busy server instead of swallowing it", async () => {
  // A 503 used to be drained and forgotten: sign-out went ahead, and the
  // refresh family it meant to end stayed live for thirty days, unmentioned.
  const { fetch } = mockFetch(() => json({ error: "temporarily_unavailable" }, 503));
  const client = new OAuthClient({ ...baseConfig, clientSecret: "s3cret", fetch });
  const result = await client.revoke("some-token");
  assert.equal(result.ok, false);
  assert.ok(!result.ok);
  assert.equal(result.error.status, 503);
  assert.equal(result.error.code, "temporarily_unavailable");
  assert.equal(result.error.retryable, true);

  const done = new OAuthClient({ ...baseConfig, clientSecret: "s3cret", fetch: mockFetch(() => new Response(null, { status: 200 })).fetch });
  assert.deepEqual(await done.revoke("some-token"), { ok: true });
});

// ---------------------------------------------------------------------------
// "Come back shortly" versus "no". The token endpoint answers a full
// password pool with 503 temporarily_unavailable, and the rate limiter answers
// 429 rate_limited with a Retry-After. A caller that reads either as a refusal
// signs its user out for being busy, so the error has to say which it is.
// ---------------------------------------------------------------------------

test("503 from the token endpoint is retryable, whatever its body says", async () => {
  for (const [body, retryAfter, why] of [
    // The server's own answer to a full password pool, as it sends it.
    [
      () =>
        new Response(
          JSON.stringify({ error: "temporarily_unavailable", error_description: "the server is busy; retry shortly" }),
          { status: 503, headers: { "content-type": "application/json", "retry-after": "1" } },
        ),
      1,
      "the token endpoint's own 503 names a wait of one second",
    ],
    // A proxy's, which may name none; none is invented.
    [
      () => new Response("<html>busy</html>", { status: 503, headers: { "content-type": "text/html" } }),
      undefined,
      "a proxy's 503 that names no wait gets none",
    ],
    [() => new Response(null, { status: 503 }), undefined, "a bare 503 that names no wait gets none"],
  ] as const) {
    const client = new OAuthClient({ ...baseConfig, clientSecret: "s3cret", fetch: mockFetch(body).fetch });
    await assert.rejects(
      () => client.refresh("rt"),
      (e: unknown) => {
        assert.ok(e instanceof OAuthError);
        assert.equal(e.status, 503);
        assert.equal(e.retryable, true);
        assert.equal(e.retryAfter, retryAfter, why);
        return true;
      },
    );
  }
});

test("429 is retryable and carries its Retry-After", async () => {
  const { fetch } = mockFetch(
    () =>
      new Response(JSON.stringify({ error: "rate_limited" }), {
        status: 429,
        headers: { "content-type": "application/json", "retry-after": "7" },
      }),
  );
  const client = new OAuthClient({ ...baseConfig, clientSecret: "s3cret", fetch });
  await assert.rejects(
    () => client.refresh("rt"),
    (e: unknown) => {
      assert.ok(e instanceof OAuthError);
      assert.equal(e.status, 429);
      assert.equal(e.code, "rate_limited");
      assert.equal(e.retryable, true);
      assert.equal(e.retryAfter, 7);
      return true;
    },
  );
});

test("an unreachable token endpoint is retryable, and says so", async () => {
  const fetch: FetchLike = async () => {
    throw new TypeError("fetch failed");
  };
  const client = new OAuthClient({ ...baseConfig, clientSecret: "s3cret", fetch });
  await assert.rejects(
    () => client.refresh("rt"),
    (e: unknown) => {
      assert.ok(e instanceof OAuthError);
      assert.equal(e.status, undefined);
      assert.equal(e.unreachable, true);
      assert.equal(e.retryable, true);
      return true;
    },
  );
});

/**
 * A fetch that answers with headers at once and a body that never comes,
 * aborted the way a real `fetch` aborts one: the request's signal errors the
 * body stream. Without that tie the double would hang whatever the client did.
 */
const stalledBody: FetchLike = async (_url, init) =>
  new Response(
    new ReadableStream({
      start(controller) {
        init?.signal?.addEventListener("abort", () => controller.error(new DOMException("aborted", "AbortError")));
      },
    }),
    { status: 200, headers: { "content-type": "application/json" } },
  );

test("a token answer whose body stalls ends at the timeout, as unreachable", { timeout: 5000 }, async () => {
  // The timer used to be cleared on the headers, so a server
  // that sent them and stalled the body held the caller with no deadline.
  const client = new OAuthClient({ ...baseConfig, clientSecret: "s3cret", fetch: stalledBody, timeoutMs: 50 });
  const started = Date.now();
  await assert.rejects(
    () => client.refresh("rt"),
    (e: unknown) => e instanceof OAuthError && e.unreachable === true,
  );
  assert.ok(Date.now() - started < 2000, "within the timeout, not the test's");
  const revoked = await client.revoke("rt");
  assert.ok(!revoked.ok && revoked.error.unreachable, "revoke's answer is bounded too");
  await assert.rejects(() => client.fetchUserInfo("at"), "and userinfo's");
});

test("invalid_grant and the other refusals are not retryable", async () => {
  for (const [status, error] of [
    [400, "invalid_grant"],
    [401, "invalid_client"],
    [400, "invalid_request"],
  ] as const) {
    const client = new OAuthClient({ ...baseConfig, clientSecret: "s3cret", fetch: mockFetch(() => json({ error }, status)).fetch });
    await assert.rejects(
      () => client.refresh("rt"),
      (e: unknown) => {
        assert.ok(e instanceof OAuthError);
        assert.equal(e.code, error);
        assert.equal(e.retryable, false, `${status} ${error} is a verdict on the request, not on the moment`);
        return true;
      },
    );
  }
  // An error built without a status — a local failure, not an answer — is not
  // one to retry either.
  assert.equal(new OAuthError("id_token is not a three-part JWS", "invalid_token").retryable, false);
});

test("Retry-After is read as seconds or an HTTP-date, capped at an hour", () => {
  const now = Date.UTC(2026, 8, 28, 12, 0, 0);
  assert.equal(parseRetryAfter("7", now), 7);
  assert.equal(parseRetryAfter(" 120 ", now), 120);
  assert.equal(parseRetryAfter("86400", now), MAX_RETRY_AFTER_SECONDS, "a day is capped to an hour");
  assert.equal(parseRetryAfter(new Date(now + 30_000).toUTCString(), now), 30);
  assert.equal(parseRetryAfter(new Date(now - 30_000).toUTCString(), now), undefined, "a moment already past is no delay");
  assert.equal(parseRetryAfter("0", now), undefined);
  assert.equal(parseRetryAfter("soon", now), undefined);
  assert.equal(parseRetryAfter("-5", now), undefined);
  assert.equal(parseRetryAfter(null, now), undefined);
});

test("constructor validates required config", () => {
  const fetch = mockFetch(() => json({})).fetch;
  assert.throws(() => new OAuthClient({ ...baseConfig, issuer: "", fetch }), OAuthError);
  assert.throws(() => new OAuthClient({ ...baseConfig, clientId: "", fetch }), OAuthError);
  assert.throws(() => new OAuthClient({ ...baseConfig, redirectUri: "", fetch }), OAuthError);
});
