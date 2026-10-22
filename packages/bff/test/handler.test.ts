import { randomBytes } from "node:crypto";
import { test } from "node:test";
import assert from "node:assert/strict";

import type { FetchLike } from "@proteles/js";

import { AuthApp, ISS_MISMATCH_REPORT_INTERVAL_MS, SessionUnavailableError, cookieNames, matchesPath, safeReturnTo } from "../src/handler.ts";
import { toWebRequest } from "../src/request.ts";
import { SessionCrypto } from "../src/session.ts";
import type { ProtelesConfigInput, SessionData } from "../src/types.ts";

// Generated per run: the literal this replaced is entry one of the
// published register, so the fixture and the value the register exists
// to refuse were the same string.
const KEY = randomBytes(32).toString("base64");

const jsonResponse = (obj: unknown, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json" } });

const ISSUER = "https://auth.example.com";
const CLIENT_ID = "app-1";
const KID = "test-key";

// ---------------------------------------------------------------------------
// The mock AS now signs real ID tokens.
//
// It used to return `id_token: "IT"` — a two-character string that is not a JWT
// — and publish no JWKS, which was fine while nothing opened the token. It is
// exactly what would have made an id_token check look like it was running while
// verifying a string nobody signed, so the harness had to become real before
// the check could mean anything.
// ---------------------------------------------------------------------------

const signingKeys = await crypto.subtle.generateKey(
  { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
  true,
  ["sign", "verify"],
);
const publicJwk = await crypto.subtle.exportKey("jwk", signingKeys.publicKey);

function b64u(v: Uint8Array | string): string {
  const b = typeof v === "string" ? new TextEncoder().encode(v) : v;
  return Buffer.from(b).toString("base64url");
}

/** An id_token the SDK will actually accept, unless a test asks otherwise. */
/** `at_hash` for an access token, as the server computes it (OIDC Core §3.1.3.6). */
async function atHashOf(accessToken: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(accessToken)));
  return b64u(digest.subarray(0, digest.length / 2));
}

async function issueIdToken(over: Record<string, unknown> = {}): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const header = b64u(JSON.stringify({ alg: "RS256", typ: "JWT", kid: KID }));
  // Bound to "AT", the access token the mock server returns beside it, as the
  // server binds every ID token it mints; the BFF checks it (M3).
  const atHash = await atHashOf("AT");
  const payload = b64u(
    JSON.stringify({ iss: ISSUER, aud: CLIENT_ID, sub: "user-1", exp: now + 300, iat: now, at_hash: atHash, ...over }),
  );
  const sig = await crypto.subtle.sign(
    { name: "RSASSA-PKCS1-v1_5" },
    signingKeys.privateKey,
    new TextEncoder().encode(`${header}.${payload}`),
  );
  return `${header}.${payload}.${b64u(new Uint8Array(sig))}`;
}

/** The nonce the app sealed into the flow cookie, so the mock can echo it. */
let lastNonce: string | null = null;

/** A mock authorization server covering the token/userinfo/revoke/jwks endpoints. */
function mockAS(opts: { idToken?: () => Promise<string | undefined> } = {}) {
  const calls: { url: string; body: string; auth: string | undefined }[] = [];
  const fetch: FetchLike = async (url, init) => {
    const headers = (init?.headers as Record<string, string>) ?? {};
    calls.push({ url, body: typeof init?.body === "string" ? init.body : "", auth: headers["authorization"] });
    if (url.endsWith("/.well-known/jwks.json")) {
      return jsonResponse({ keys: [{ ...publicJwk, kid: KID, alg: "RS256", use: "sig" }] });
    }
    if (url.endsWith("/oauth/token")) {
      const isRefresh = typeof init?.body === "string" && init.body.includes("grant_type=refresh_token");
      // The refresh grant mints a token with no nonce, exactly as the server
      // does — so a refresh path that demanded one would fail here, which is
      // the point of testing against a mock that behaves like the real thing.
      const id = opts.idToken
        ? await opts.idToken()
        : await issueIdToken(isRefresh ? {} : lastNonce ? { nonce: lastNonce } : {});
      const body: Record<string, unknown> = {
        access_token: "AT",
        token_type: "Bearer",
        expires_in: 900,
        refresh_token: "RT",
        scope: "openid",
      };
      if (id !== undefined) body["id_token"] = id;
      return jsonResponse(body);
    }
    if (url.endsWith("/oauth/userinfo")) {
      return jsonResponse({ sub: "user-1", email: "alice@example.com", preferred_username: "alice" });
    }
    if (url.endsWith("/oauth/revoke")) {
      return new Response(null, { status: 200 });
    }
    return new Response("not found", { status: 404 });
  };
  return { fetch, calls };
}

function makeApp(
  overrides?: Partial<ProtelesConfigInput>,
  asOpts?: { idToken?: () => Promise<string | undefined> },
): { app: AuthApp; calls: ReturnType<typeof mockAS>["calls"] } {
  const { fetch, calls } = mockAS(asOpts);
  const app = new AuthApp({
    issuer: "https://auth.example.com",
    clientId: "app-1",
    clientSecret: "secret",
    redirectUri: "https://app.example.com/api/auth/callback",
    sessionSecret: KEY,
    cookieSecure: false,
    fetch,
    // Quiet by default here; the reporting behavior has its own tests below.
    onError: false,
    ...overrides,
  });
  return { app, calls };
}

/**
 * Records the nonce the app just sealed, so the mock AS can echo it back in the
 * `id_token` the way a real one would.
 *
 * The real server learns the nonce from the authorize *request*; this mock never
 * sees that redirect, so the test has to bridge it. Reading it out of the flow
 * cookie rather than inventing one keeps the check honest: a callback whose
 * token carries a nonce the app did not send must still fail, and does — see
 * the replay test below.
 */
async function publishNonce(flowCookie: string): Promise<void> {
  const crypto = new SessionCrypto(KEY);
  const flow = await crypto.decrypt<{ nonce: string }>(flowCookie);
  lastNonce = flow.nonce;
}

function setCookies(res: Response): string[] {
  const h = res.headers as Headers & { getSetCookie?: () => string[] };
  if (typeof h.getSetCookie === "function") return h.getSetCookie();
  // Node < ~18.14 lacks getSetCookie; multiple Set-Cookie headers come back
  // comma-joined. Split only at a comma that begins a new `name=` pair, so the
  // comma inside an `Expires=Thu, 01 Jan ...` attribute is not a false boundary.
  const merged = res.headers.get("set-cookie");
  return merged ? merged.split(/,\s*(?=[A-Za-z0-9_-]+=)/) : [];
}

function cookieValue(cookies: string[], name: string): string | undefined {
  for (const c of cookies) {
    const m = c.match(new RegExp(`^${name}=([^;]*)`));
    if (m) return decodeURIComponent(m[1]!);
  }
  return undefined;
}

const req = (url: string, init?: { method?: string; cookie?: string }) =>
  new Request(url, { method: init?.method ?? "GET", headers: init?.cookie ? { cookie: init.cookie } : undefined });

test("login redirects to the AS authorize endpoint and sets an encrypted flow cookie", async () => {
  const { app } = makeApp();
  const res = await app.handle(req("https://app.example.com/api/auth/login?returnTo=/dashboard"));

  assert.equal(res.status, 302);
  const loc = new URL(res.headers.get("location")!);
  assert.equal(loc.origin + loc.pathname, "https://auth.example.com/oauth/authorize");
  assert.equal(loc.searchParams.get("code_challenge_method"), "S256");
  assert.ok(loc.searchParams.get("state"));
  assert.equal(loc.searchParams.has("prompt"), false, "a sign-in must not open on the sign-up page");

  const flow = cookieValue(setCookies(res), "proteles_flow");
  assert.ok(flow, "flow cookie set");
  assert.match(setCookies(res).find((c) => c.startsWith("proteles_flow"))!, /HttpOnly/);
});

// --- third-party-initiated login (OpenID Connect Core 1.0 §4) --------------
//
// `/api/auth/login` is the app's `initiate_login_uri`: an invitation accepted
// at Proteles sends the invitee here as `?iss=<issuer>`, signed in.

test("a sign-in started with ?iss= naming the configured issuer is an ordinary sign-in, and reports nothing", async () => {
  const reasons: string[] = [];
  const { app } = makeApp({ onError: (reason) => reasons.push(reason) });
  const res = await app.handle(req(`https://app.example.com/api/auth/login?iss=${encodeURIComponent(ISSUER)}`));

  assert.equal(res.status, 302);
  const loc = new URL(res.headers.get("location")!);
  assert.equal(loc.origin + loc.pathname, `${ISSUER}/oauth/authorize`);
  assert.equal(loc.searchParams.get("client_id"), CLIENT_ID);
  assert.ok(loc.searchParams.get("state"));
  assert.equal(loc.searchParams.has("iss"), false, "iss is not passed on");
  assert.equal(loc.searchParams.has("prompt"), false, "nor turned into a prompt");
  // The flow is the one a plain sign-in seals, back to the default landing.
  const flow = await new SessionCrypto(KEY).decrypt<{ returnTo: string; state: string }>(
    cookieValue(setCookies(res), "proteles_flow")!,
  );
  assert.equal(flow.returnTo, "/");
  assert.equal(flow.state, loc.searchParams.get("state"));
  assert.deepEqual(reasons, [], "nothing to report");
});

test("an iss naming another issuer is never followed, and is reported without its value, at most once per interval", async (t) => {
  t.mock.timers.enable({ apis: ["Date"], now: Date.UTC(2026, 9, 18, 12) });
  const reports: [string, string][] = [];
  const { app } = makeApp({ onError: (reason, context) => reports.push([reason, context]) });
  // A stranger's value: long, and marked so any part of it reaching the report shows.
  const hostile = `https://evil.example/${"zqxjv".repeat(200)}`;
  for (const other of [hostile, "https://evil.example", `${ISSUER}/`, "https://AUTH.example.com", ""]) {
    const res = await app.handle(req(`https://app.example.com/api/auth/login?iss=${encodeURIComponent(other)}`));
    assert.equal(res.status, 302, other);
    const loc = new URL(res.headers.get("location")!);
    assert.equal(loc.origin + loc.pathname, `${ISSUER}/oauth/authorize`, `${other.slice(0, 40)}: the configured issuer, always`);
    assert.ok(cookieValue(setCookies(res), "proteles_flow"), `${other.slice(0, 40)}: a flow is started`);
  }
  assert.equal(reports.length, 1, "five mismatches inside the interval are one report");
  const [reason, context] = reports[0]!;
  assert.equal(context, "login");
  assert.ok(reason.includes(ISSUER), "it names the configured issuer, which is the app's own");
  assert.ok(!reason.includes("zqxjv") && !reason.includes("evil.example"), `nothing the link sent: ${reason}`);

  t.mock.timers.tick(ISS_MISMATCH_REPORT_INTERVAL_MS - 1);
  await app.handle(req("https://app.example.com/api/auth/login?iss=https%3A%2F%2Fevil.example"));
  assert.equal(reports.length, 1, "still inside the interval");
  t.mock.timers.tick(1);
  await app.handle(req("https://app.example.com/api/auth/login?iss=https%3A%2F%2Fevil.example"));
  assert.equal(reports.length, 2, "and once more after it");
});

test("signup asks for the sign-up page, and its flow completes at the callback as login's does", async () => {
  const { app } = makeApp();
  const res = await app.handle(req("https://app.example.com/api/auth/signup?returnTo=/welcome&connection=google"));

  assert.equal(res.status, 302);
  const loc = new URL(res.headers.get("location")!);
  assert.equal(loc.origin + loc.pathname, "https://auth.example.com/oauth/authorize");
  assert.equal(loc.searchParams.get("prompt"), "create");
  assert.equal(loc.searchParams.get("code_challenge_method"), "S256");
  // The server reads `create` first, so a connection would only steer the
  // fallback to sign-in; see `signup`.
  assert.equal(loc.searchParams.has("connection"), false, "connection is not passed on");

  // The same cookie as login's, attributes and all: only the sealed value differs.
  const flowOf = (r: Response) => setCookies(r).find((c) => c.startsWith("proteles_flow="))!;
  const attributes = (c: string) => c.slice(c.indexOf(";"));
  const login = await app.handle(req("https://app.example.com/api/auth/login"));
  assert.equal(attributes(flowOf(res)), attributes(flowOf(login)));

  // And the callback finishes it as it finishes a sign-in, back to `returnTo`.
  const flowCookie = cookieValue(setCookies(res), "proteles_flow")!;
  await publishNonce(flowCookie);
  const cbRes = await app.handle(
    req(`https://app.example.com/api/auth/callback?code=the-code&state=${encodeURIComponent(loc.searchParams.get("state")!)}`, {
      cookie: `proteles_flow=${flowCookie}`,
    }),
  );
  assert.equal(cbRes.status, 303);
  assert.equal(cbRes.headers.get("location"), "/welcome");
  assert.ok(cookieValue(setCookies(cbRes), "proteles_session"), "session cookie set");

  // `returnTo` is checked as login's is: another origin's falls back to the default.
  const foreign = await app.handle(req("https://app.example.com/api/auth/signup?returnTo=//evil.example/"));
  const sealed = await new SessionCrypto(KEY).decrypt<{ returnTo: string }>(
    cookieValue(setCookies(foreign), "proteles_flow")!,
  );
  assert.equal(sealed.returnTo, "/");
});

test("an unknown action is a 404, and starts no flow", async () => {
  const { app } = makeApp();
  for (const action of ["register", "sign-up", "signin"]) {
    const res = await app.handle(req(`https://app.example.com/api/auth/${action}`));
    assert.equal(res.status, 404, action);
    assert.deepEqual(await res.json(), { error: "not_found" });
    assert.deepEqual(setCookies(res), [], `${action} sets no cookie`);
  }
});

test("full login -> callback -> me establishes a session; browser only sees the sanitized user", async () => {
  const { app, calls } = makeApp();

  // 1. Start login.
  const loginRes = await app.handle(req("https://app.example.com/api/auth/login?returnTo=/dashboard"));
  const state = new URL(loginRes.headers.get("location")!).searchParams.get("state")!;
  const flowCookie = cookieValue(setCookies(loginRes), "proteles_flow")!;
  await publishNonce(flowCookie);

  // 2. AS redirects back with a code + our state; the flow cookie rides along.
  const cbRes = await app.handle(
    req(`https://app.example.com/api/auth/callback?code=the-code&state=${encodeURIComponent(state)}`, {
      cookie: `proteles_flow=${flowCookie}`,
    }),
  );
  assert.equal(cbRes.status, 303);
  assert.equal(cbRes.headers.get("location"), "/dashboard");

  // Token endpoint was called with the code + PKCE verifier, using Basic auth.
  const tokenCall = calls.find((c) => c.url.endsWith("/oauth/token"))!;
  assert.ok(tokenCall.auth?.startsWith("Basic "), "confidential client uses client_secret_basic");
  const form = new URLSearchParams(tokenCall.body);
  assert.equal(form.get("grant_type"), "authorization_code");
  assert.equal(form.get("code"), "the-code");
  assert.ok(form.get("code_verifier"), "PKCE verifier sent");

  const sessionCookie = cookieValue(setCookies(cbRes), "proteles_session")!;
  assert.ok(sessionCookie, "session cookie set");

  // The session cookie is opaque — no raw token leaks into it.
  assert.ok(!sessionCookie.includes("AT") || sessionCookie.length > 40);

  // 3. /api/auth/me returns only the sanitized user, never a token.
  const meRes = await app.handle(req("https://app.example.com/api/auth/me", { cookie: `proteles_session=${sessionCookie}` }));
  assert.equal(meRes.status, 200);
  const body = (await meRes.json()) as { authenticated: boolean; user?: { email?: string } };
  assert.equal(body.authenticated, true);
  assert.equal(body.user?.email, "alice@example.com");
  assert.ok(!JSON.stringify(body).includes("AT"), "no access token in the /me response");
  assert.ok(!JSON.stringify(body).includes("RT"), "no refresh token in the /me response");
});

test("the session carries amr and auth_time from the id_token, and /me hands them on", async () => {
  const authenticatedAt = Math.floor(Date.now() / 1000) - 90;
  const { app } = makeApp({}, {
    idToken: () => issueIdToken({ nonce: lastNonce, amr: ["pwd", "otp"], auth_time: authenticatedAt }),
  });

  const loginRes = await app.handle(req("https://app.example.com/api/auth/login"));
  const state = new URL(loginRes.headers.get("location")!).searchParams.get("state")!;
  const flowCookie = cookieValue(setCookies(loginRes), "proteles_flow")!;
  await publishNonce(flowCookie);

  const cbRes = await app.handle(
    req(`https://app.example.com/api/auth/callback?code=the-code&state=${encodeURIComponent(state)}`, {
      cookie: `proteles_flow=${flowCookie}`,
    }),
  );
  const sessionCookie = cookieValue(setCookies(cbRes), "proteles_session")!;

  const meRes = await app.handle(
    req("https://app.example.com/api/auth/me", { cookie: `proteles_session=${sessionCookie}` }),
  );
  const body = (await meRes.json()) as { user?: { amr?: string[]; authTime?: number } };

  // These are id_token claims, not userinfo claims. `fetchUserInfo` fills the
  // rest of the session and cannot see them, which is why they were absent
  // until the verified claims stopped being discarded.
  assert.deepEqual(body.user?.amr, ["pwd", "otp"]);
  assert.equal(body.user?.authTime, authenticatedAt);
});

test("amr and auth_time are absent, not defaulted, when the id_token omits them", async () => {
  const { app } = makeApp({}, { idToken: () => issueIdToken({ nonce: lastNonce }) });

  const loginRes = await app.handle(req("https://app.example.com/api/auth/login"));
  const state = new URL(loginRes.headers.get("location")!).searchParams.get("state")!;
  const flowCookie = cookieValue(setCookies(loginRes), "proteles_flow")!;
  await publishNonce(flowCookie);
  const cbRes = await app.handle(
    req(`https://app.example.com/api/auth/callback?code=the-code&state=${encodeURIComponent(state)}`, {
      cookie: `proteles_flow=${flowCookie}`,
    }),
  );
  const sessionCookie = cookieValue(setCookies(cbRes), "proteles_session")!;
  const meRes = await app.handle(
    req("https://app.example.com/api/auth/me", { cookie: `proteles_session=${sessionCookie}` }),
  );
  const body = (await meRes.json()) as { user?: { amr?: string[]; authTime?: number } };

  // The distinction the server draws deliberately: an empty `amr` asserts that
  // no methods were used, which is a different and false claim from "the token
  // did not say". A zero `authTime` would place the authentication in 1970.
  assert.equal(body.user?.amr, undefined, "an absent amr must not become []");
  assert.equal(body.user?.authTime, undefined, "an absent auth_time must not become 0");
});

test("callback rejects a state mismatch (CSRF) without establishing a session", async () => {
  const { app } = makeApp();
  const loginRes = await app.handle(req("https://app.example.com/api/auth/login"));
  const flowCookie = cookieValue(setCookies(loginRes), "proteles_flow")!;
  await publishNonce(flowCookie);

  const cbRes = await app.handle(
    req("https://app.example.com/api/auth/callback?code=x&state=not-the-real-state", { cookie: `proteles_flow=${flowCookie}` }),
  );
  assert.equal(cbRes.status, 303);
  assert.match(cbRes.headers.get("location")!, /proteles_error=login_failed/);
  assert.equal(cookieValue(setCookies(cbRes), "proteles_session"), undefined, "no session on failed state check");
});

test("callback surfacing an AS error param fails closed", async () => {
  const { app } = makeApp();
  const loginRes = await app.handle(req("https://app.example.com/api/auth/login"));
  const flowCookie = cookieValue(setCookies(loginRes), "proteles_flow")!;
  await publishNonce(flowCookie);
  const cbRes = await app.handle(
    req("https://app.example.com/api/auth/callback?error=access_denied", { cookie: `proteles_flow=${flowCookie}` }),
  );
  assert.equal(cbRes.status, 303);
  assert.match(cbRes.headers.get("location")!, /proteles_error/);
});

test("me transparently refreshes an expired access token (rotation-aware)", async () => {
  const { app, calls } = makeApp();
  // Forge a session whose access token expired but that has a refresh token.
  const sc = new SessionCrypto(KEY);
  const expired: SessionData = {
    accessToken: "OLD",
    refreshToken: "OLD-RT",
    accessExpiresAt: Date.now() - 1000,
    sub: "user-1",
    email: "alice@example.com",
  };
  const cookie = await sc.encrypt(expired);

  const meRes = await app.handle(req("https://app.example.com/api/auth/me", { cookie: `proteles_session=${cookie}` }));
  assert.equal(meRes.status, 200);
  assert.equal(((await meRes.json()) as { authenticated: boolean }).authenticated, true);

  // A refresh was performed and the session cookie rewritten with the new tokens.
  const refresh = calls.find((c) => new URLSearchParams(c.body).get("grant_type") === "refresh_token");
  assert.ok(refresh, "refresh_token grant was used");
  const rewritten = cookieValue(setCookies(meRes), "proteles_session")!;
  const updated = await sc.decrypt<SessionData>(rewritten);
  assert.equal(updated.accessToken, "AT");
  assert.equal(updated.refreshToken, "RT");
  assert.ok(updated.accessExpiresAt > Date.now());
});

test("requests racing one expired session share one refresh, and nobody is signed out", async () => {
  // The server spends a refresh token exactly once: of two requests presenting
  // it together, one gets invalid_grant. Before the BFF shared its refreshes,
  // that loser's response cleared the session cookie — two tabs, signed out.
  const { app, calls } = makeApp();
  const sc = new SessionCrypto(KEY);
  const cookie = await sc.encrypt({
    accessToken: "OLD",
    refreshToken: "OLD-RT",
    accessExpiresAt: Date.now() - 1000,
    sub: "user-1",
  } satisfies SessionData);
  const me = () => app.handle(req("https://app.example.com/api/auth/me", { cookie: `proteles_session=${cookie}` }));

  const racing = await Promise.all([me(), me(), me()]);
  // And one more after the fact, still carrying the old cookie, as a browser
  // does until it has stored the rotated one.
  const late = await me();

  const refreshes = calls.filter((c) => new URLSearchParams(c.body).get("grant_type") === "refresh_token");
  assert.equal(refreshes.length, 1, "one exchange for the one refresh token");
  for (const res of [...racing, late]) {
    assert.equal(((await res.json()) as { authenticated: boolean }).authenticated, true);
    const rewritten = cookieValue(setCookies(res), "proteles_session");
    assert.ok(rewritten, "every response carries the rotated session, none clears it");
    assert.equal((await sc.decrypt<SessionData>(rewritten!)).refreshToken, "RT");
  }
});

test("a failed refresh is not remembered", async () => {
  let fail = true;
  const { app, calls } = makeApp();
  const inner = (app as unknown as { client: { refresh: (rt: string) => Promise<unknown> } }).client;
  const real = inner.refresh.bind(inner);
  inner.refresh = (rt: string) => (fail ? Promise.reject(new Error("invalid_grant")) : real(rt));
  const sc = new SessionCrypto(KEY);
  const cookie = await sc.encrypt({ accessToken: "OLD", refreshToken: "OLD-RT", accessExpiresAt: Date.now() - 1000, sub: "user-1" } satisfies SessionData);
  const me = () => app.handle(req("https://app.example.com/api/auth/me", { cookie: `proteles_session=${cookie}` }));

  assert.equal(((await (await me()).json()) as { authenticated: boolean }).authenticated, false);
  fail = false;
  assert.equal(((await (await me()).json()) as { authenticated: boolean }).authenticated, true, "the next attempt refreshes afresh");
  assert.equal(calls.filter((c) => new URLSearchParams(c.body).get("grant_type") === "refresh_token").length, 1);
});

test("me with no cookie is unauthenticated", async () => {
  const { app } = makeApp();
  const res = await app.handle(req("https://app.example.com/api/auth/me"));
  assert.equal(((await res.json()) as { authenticated: boolean }).authenticated, false);
});

test("/me is never stored by a cache, signed in or not", async () => {
  // It names the person the cookie belongs to. A shared cache that kept one
  // answer would serve it to the next visitor; a browser that kept one would
  // show the signed-in user after sign-out.
  const { app } = makeApp();
  const cookie = await new SessionCrypto(KEY).encrypt({
    accessToken: "AT",
    accessExpiresAt: Date.now() + 1e6,
    sub: "user-1",
  } satisfies SessionData);
  const signedIn = await app.handle(req("https://app.example.com/api/auth/me", { cookie: `proteles_session=${cookie}` }));
  assert.equal(((await signedIn.json()) as { authenticated: boolean }).authenticated, true);
  assert.equal(signedIn.headers.get("cache-control"), "no-store");
  const signedOut = await app.handle(req("https://app.example.com/api/auth/me"));
  assert.equal(signedOut.headers.get("cache-control"), "no-store");
});

test("logout revokes the refresh token and clears the session cookie", async () => {
  const { app, calls } = makeApp();
  const sc = new SessionCrypto(KEY);
  const cookie = await sc.encrypt({ accessToken: "AT", refreshToken: "RT", accessExpiresAt: Date.now() + 1e6, sub: "u1" } satisfies SessionData);

  const res = await app.handle(req("https://app.example.com/api/auth/logout", { method: "POST", cookie: `proteles_session=${cookie}` }));
  assert.equal(res.status, 303);
  assert.ok(calls.some((c) => c.url.endsWith("/oauth/revoke")), "refresh token revoked");
  const cleared = setCookies(res).find((c) => c.startsWith("proteles_session"))!;
  assert.match(cleared, /Max-Age=0/, "session cookie cleared");
});

// ---------------------------------------------------------------------------
// Sign-out is a POST from this app's own pages.
//
// `SameSite=Lax` sends the session cookie on a top-level cross-site GET, and
// this route used to act on a GET, so any page could navigate a visitor here
// and sign them out, revoking their refresh token on the way. Fetch Metadata
// alone left a browser that sends none, and a sibling subdomain, which the
// browser marks `same-site`. A GET now gets a confirmation form, and a POST is
// checked by origin.
// ---------------------------------------------------------------------------

const APP_ORIGIN = "https://app.example.com";

async function logoutWith(
  method: string,
  headers: Record<string, string> = {},
  path = "/api/auth/logout?returnTo=/goodbye",
  options: { config?: Partial<ProtelesConfigInput>; idToken?: string } = {},
) {
  const reasons: [string, string][] = [];
  const { app, calls } = makeApp({ onError: (reason, context) => reasons.push([reason, context]), ...options.config });
  const cookie = await new SessionCrypto(KEY).encrypt({
    accessToken: "AT",
    refreshToken: "RT",
    accessExpiresAt: Date.now() + 1e6,
    sub: "u1",
    ...(options.idToken ? { idToken: options.idToken } : {}),
  } satisfies SessionData);
  const res = await app.handle(
    new Request(`${APP_ORIGIN}${path}`, { method, headers: { cookie: `proteles_session=${cookie}`, ...headers } }),
  );
  return {
    res,
    revoked: calls.some((c) => c.url.endsWith("/oauth/revoke")),
    sessionCookie: setCookies(res).find((c) => c.startsWith(`proteles_session=`)),
    reasons,
  };
}

function assertSignedOut(r: Awaited<ReturnType<typeof logoutWith>>) {
  assert.equal(r.res.status, 303);
  // On to the server's end-session endpoint (the default since 2026-10-09),
  // coming back to `returnTo` on this app's origin.
  const to = new URL(r.res.headers.get("location") ?? "");
  assert.equal(to.origin + to.pathname, "https://auth.example.com/oauth/logout");
  assert.equal(to.searchParams.get("post_logout_redirect_uri"), `${APP_ORIGIN}/goodbye`);
  assert.equal(r.revoked, true, "refresh token revoked");
  assert.match(r.sessionCookie ?? "", /Max-Age=0/, "session cookie cleared");
  assert.deepEqual(r.reasons, []);
}

function assertLeftAlone(r: Awaited<ReturnType<typeof logoutWith>>) {
  assert.equal(r.revoked, false, "the refresh token must not be revoked");
  // Clearing the cookie would be the same forced sign-out, minus the revoke.
  assert.equal(r.sessionCookie, undefined, "the session cookie must be left alone");
}

// ---------------------------------------------------------------------------
// Sign-out ends the person's session at Proteles too.
//
// Clearing only this app's cookie left the session at the server alive, so the
// next "Sign in" went straight through without a password — on a shared
// computer, the previous person. With `endSession` (the default) the 303 goes
// on to the server's end-session endpoint.
// ---------------------------------------------------------------------------

test("sign-out sends the browser on to end the session at the server, hinted by the ID token", async () => {
  const r = await logoutWith("POST", { origin: APP_ORIGIN }, undefined, { idToken: "header.payload.sig" });
  assertSignedOut(r);
  const to = new URL(r.res.headers.get("location") ?? "");
  assert.equal(to.searchParams.get("id_token_hint"), "header.payload.sig", "names the app and the person");
  assert.equal(to.searchParams.get("client_id"), null, "and not a client_id the server would then have to match");
});

test("a session without an ID token is ended at the server by client_id", async () => {
  const r = await logoutWith("POST", { origin: APP_ORIGIN });
  const to = new URL(r.res.headers.get("location") ?? "");
  assert.equal(to.searchParams.get("client_id"), "app-1");
  assert.equal(to.searchParams.get("id_token_hint"), null);
});

test("endSession: false keeps sign-out to this app, as before", async () => {
  const r = await logoutWith("POST", { origin: APP_ORIGIN }, undefined, { config: { endSession: false }, idToken: "h.p.s" });
  assert.equal(r.res.status, 303);
  assert.equal(r.res.headers.get("location"), "/goodbye");
  assert.equal(r.revoked, true);
  assert.match(r.sessionCookie ?? "", /Max-Age=0/);
  const page = await logoutWith("GET", {}, undefined, { config: { endSession: false } });
  assert.match(page.res.headers.get("content-security-policy") ?? "", /form-action 'self';/, "and its page posts only here");
});

test("PROTELES_END_SESSION=false turns it off from the environment", async () => {
  const before = process.env.PROTELES_END_SESSION;
  process.env.PROTELES_END_SESSION = "false";
  try {
    const r = await logoutWith("POST", { origin: APP_ORIGIN });
    assert.equal(r.res.headers.get("location"), "/goodbye");
  } finally {
    if (before === undefined) delete process.env.PROTELES_END_SESSION;
    else process.env.PROTELES_END_SESSION = before;
  }
});

// A GET from anywhere — a link, an image, a redirect, the app's own old
// `window.location` sign-out — signs nobody out.
for (const fetchSite of ["cross-site", "same-site", "same-origin", "none", undefined]) {
  test(`a GET sign-out (Sec-Fetch-Site ${fetchSite ?? "absent"}) gets a confirmation form and changes nothing`, async () => {
    const r = await logoutWith("GET", fetchSite === undefined ? {} : { "sec-fetch-site": fetchSite });
    assertLeftAlone(r);
    assert.equal(r.res.status, 200);
    assert.deepEqual(r.reasons, [], "a page is not a refusal worth reporting");
    const page = await r.res.text();
    assert.match(page, /<form method="post" action="\/api\/auth\/logout\?returnTo=%2Fgoodbye">/, "posts back here, returnTo and all");
    assert.match(page, /<a href="\/goodbye">Cancel<\/a>/);
  });
}

test("the confirmation cannot be framed, and posts only here and to the issuer's end-session", async () => {
  const { res } = await logoutWith("GET");
  assert.equal(res.headers.get("x-frame-options"), "DENY");
  const csp = res.headers.get("content-security-policy") ?? "";
  assert.match(csp, /frame-ancestors 'none'/);
  // The issuer's origin because a browser applies `form-action` to the 303 that
  // follows the post, and that 303 now goes to the end-session endpoint.
  assert.match(csp, /form-action 'self' https:\/\/auth\.example\.com;/);
  assert.match(res.headers.get("content-type") ?? "", /text\/html/);
  assert.equal(res.headers.get("cache-control"), "no-store");
});

test("the confirmation's returnTo is the checked one, escaped", async () => {
  const hostile = await logoutWith("GET", {}, `/api/auth/logout?returnTo=${encodeURIComponent("//evil.example")}`);
  const page = await hostile.res.text();
  assert.match(page, /action="\/api\/auth\/logout\?returnTo=%2F"/, "an off-site returnTo becomes /");
  assert.doesNotMatch(page, /evil\.example/);

  const quoted = await logoutWith("GET", {}, `/api/auth/logout?returnTo=${encodeURIComponent(`/a"b'<c>`)}`);
  const q = await quoted.res.text();
  assert.doesNotMatch(q, /"b'<c>/, "nothing from returnTo reaches the markup unescaped");

  const none = await logoutWith("GET", {}, "/api/auth/logout");
  assert.match(await none.res.text(), /action="\/api\/auth\/logout"/, "no returnTo sent, none invented");
});

test("HEAD is answered like GET, and any other method is 405", async () => {
  const head = await logoutWith("HEAD");
  assert.equal(head.res.status, 200);
  assertLeftAlone(head);
  const put = await logoutWith("PUT", { origin: APP_ORIGIN });
  assert.equal(put.res.status, 405);
  assert.equal(put.res.headers.get("allow"), "GET, HEAD, POST");
  assertLeftAlone(put);
});

// The app's own sign-out: a form post or a fetch from its pages.
test("a POST from this app's origin signs out", async () => {
  assertSignedOut(await logoutWith("POST", { origin: APP_ORIGIN, "sec-fetch-site": "same-origin" }));
  assertSignedOut(await logoutWith("POST", { origin: APP_ORIGIN }));
});

// No Origin at all is not a browser — every browser sends one on a POST. It is
// curl, a test, or a server calling this one, as Proteles' reference web app also allows.
test("a POST with no Origin signs out, unless Fetch Metadata says another site sent it", async () => {
  assertSignedOut(await logoutWith("POST"));
  assertSignedOut(await logoutWith("POST", { "sec-fetch-site": "none" }));
});

for (const [name, headers] of [
  ["another site's Origin", { origin: "https://evil.example" }],
  ["a sibling subdomain's Origin", { origin: "https://blog.example.com" }],
  ["this origin over http", { origin: "http://app.example.com" }],
  ["Sec-Fetch-Site: cross-site", { "sec-fetch-site": "cross-site" }],
  ["Sec-Fetch-Site: same-site", { "sec-fetch-site": "same-site" }],
  ["the right Origin but Sec-Fetch-Site: cross-site", { origin: APP_ORIGIN, "sec-fetch-site": "cross-site" }],
  ["Origin: null with no Fetch Metadata", { origin: "null" }],
  ["Origin: null from another site", { origin: "null", "sec-fetch-site": "cross-site" }],
] as [string, Record<string, string>][]) {
  test(`a POST with ${name} is refused: 403, nothing revoked, nothing cleared`, async () => {
    const r = await logoutWith("POST", headers);
    assertLeftAlone(r);
    assert.equal(r.res.status, 403);
    assert.equal(r.res.headers.get("x-frame-options"), "DENY");
    assert.doesNotMatch(await r.res.text(), /<form/, "no form: from a misconfigured origin it would only be refused again");
    assert.deepEqual(r.reasons.map(([, context]) => context), ["logout"], "the server hears why sign-out did nothing");
  });
}

test("the refusal names both origins, so a misconfigured redirectUri can be told from an attack", async () => {
  const { reasons } = await logoutWith("POST", { origin: "https://app.example.com:8443" });
  assert.match(reasons[0][0], /https:\/\/app\.example\.com:8443/);
  assert.match(reasons[0][0], /answers as https:\/\/app\.example\.com\b/);
});

// A browser sends `Origin: null` on the app's own form post under
// `Referrer-Policy: no-referrer`; Fetch Metadata is what tells it apart.
test("a POST with Origin: null that the browser marks same-origin signs out", async () => {
  assertSignedOut(await logoutWith("POST", { origin: "null", "sec-fetch-site": "same-origin" }));
});

// The Node path — Express, Fastify, h3 and plain `node:http` all reach the
// handler through `toWebRequest`, so the headers have to survive that copy.
for (const [name, extra, signedOut] of [
  ["another site's Origin", { origin: "https://evil.example" }, false],
  ["Sec-Fetch-Site: cross-site", { "sec-fetch-site": "cross-site" }, false],
  ["this app's Origin", { origin: APP_ORIGIN }, true],
] as [string, Record<string, string>, boolean][]) {
  test(`a POST sign-out through the Node request path with ${name} ${signedOut ? "signs out" : "revokes nothing"}`, async () => {
    const { app, calls } = makeApp();
    const cookie = await new SessionCrypto(KEY).encrypt({
      accessToken: "AT",
      refreshToken: "RT",
      accessExpiresAt: Date.now() + 1e6,
      sub: "u1",
    } satisfies SessionData);
    const res = await app.handle(
      toWebRequest({
        node: {
          req: {
            method: "POST",
            url: "/api/auth/logout",
            headers: { host: "app.example.com", cookie: `proteles_session=${cookie}`, ...extra },
          },
        },
      }),
    );
    assert.equal(res.status, signedOut ? 303 : 403);
    assert.equal(calls.some((c) => c.url.endsWith("/oauth/revoke")), signedOut);
    assert.equal(setCookies(res).some((c) => c.startsWith("proteles_session=")), signedOut);
  });
}

test("middleware redirects an unauthenticated protected request to login with returnTo", async () => {
  const { app } = makeApp();
  const mw = app.middleware();
  const res = await mw(req("https://app.example.com/dashboard/settings"));
  assert.ok(res, "protected route produced a response");
  assert.equal(res!.status, 307);
  const raw = res!.headers.get("location")!;
  // Relative on purpose — see the next test. Parsed against a base rather than
  // on its own, which is also the assertion that it *is* relative: `new
  // URL(raw)` alone would throw here, and used to be how this was written.
  assert.ok(raw.startsWith("/"), `Location must be relative, got ${raw}`);
  const loc = new URL(raw, "https://app.example.com");
  assert.equal(loc.pathname, "/api/auth/login");
  assert.equal(loc.searchParams.get("returnTo"), "/dashboard/settings");
});

test("a poisoned forwarded host cannot steer where the middleware sends the browser", async () => {
  // The request URL is only as trustworthy as whatever built it. On the Node
  // path it is built from `X-Forwarded-Host`, which nothing here can verify — so
  // an absolute `Location` derived from it lets a request header choose the
  // destination. Behind a cache keyed on URL but not on that header, one request
  // poisons the redirect served to everybody else.
  const { app } = makeApp();
  const mw = app.middleware();

  const poisoned = toWebRequest({
    node: {
      req: {
        method: "GET",
        url: "/dashboard/settings",
        headers: {
          host: "app.example.com",
          "x-forwarded-host": "evil.test",
          "x-forwarded-proto": "https",
        },
      },
    },
  });
  // The header did reach the URL — that is the whole premise. What must not
  // happen is it reaching the `Location`.
  assert.equal(new URL(poisoned.url).host, "evil.test", "the forwarded host does steer the URL");

  const res = await mw(poisoned);
  assert.ok(res, "protected route produced a response");
  const loc = res!.headers.get("location")!;
  assert.ok(!loc.includes("evil.test"), `the attacker's host reached Location: ${loc}`);
  assert.ok(loc.startsWith("/"), `Location must be relative so the browser resolves it: ${loc}`);
});

test("a stale session revalidates through a relative Location too", async () => {
  // The other of the two, and the one that carried `Response.redirect` — which
  // requires an absolute URL and is the reason it did.
  const { app } = makeApp();
  const mw = app.middleware();
  const sc = new SessionCrypto(KEY);
  const stale = await sc.encrypt({
    accessToken: "AT",
    accessExpiresAt: Date.now() - 1000,
    refreshToken: "RT",
    sub: "u1",
  } satisfies SessionData);

  const res = await mw(req("https://app.example.com/dashboard", { cookie: `proteles_session=${stale}` }));
  assert.ok(res, "a stale session is sent to revalidate");
  const loc = res!.headers.get("location")!;
  assert.ok(loc.startsWith("/api/auth/revalidate"), `expected a relative revalidate, got ${loc}`);
  assert.equal(new URL(loc, "https://app.example.com").searchParams.get("returnTo"), "/dashboard");
});

test("middleware lets auth routes and authenticated requests pass through", async () => {
  const { app } = makeApp();
  const mw = app.middleware();
  // Auth route always passes.
  assert.equal(await mw(req("https://app.example.com/api/auth/login")), undefined);

  // A valid session passes.
  const sc = new SessionCrypto(KEY);
  const cookie = await sc.encrypt({ accessToken: "AT", accessExpiresAt: Date.now() + 1e6, sub: "u1" } satisfies SessionData);
  assert.equal(await mw(req("https://app.example.com/dashboard", { cookie: `proteles_session=${cookie}` })), undefined);
});

test("safeReturnTo allows same-origin paths and blocks open redirects", () => {
  assert.equal(safeReturnTo("/dashboard"), "/dashboard");
  assert.equal(safeReturnTo("/a/b?x=1"), "/a/b?x=1");
  assert.equal(safeReturnTo("//evil.com/x"), null); // protocol-relative
  assert.equal(safeReturnTo("/\\evil.com"), null); // backslash trick
  assert.equal(safeReturnTo("https://evil.com"), null); // absolute
  assert.equal(safeReturnTo("evil"), null); // not rooted
  assert.equal(safeReturnTo(null), null);
  // Browsers strip tab, CR and LF anywhere in a URL, so each of these arrived
  // as `//evil.example` — an open redirect on every SDK customer's origin.
  assert.equal(safeReturnTo("/\t/evil.example"), null);
  assert.equal(safeReturnTo("/\n/evil.example"), null);
  assert.equal(safeReturnTo("/\r/evil.example"), null);
  assert.equal(safeReturnTo("/\t\\evil.example"), null);
  assert.equal(safeReturnTo("/\u007f/x"), null);
  // Still encoded, a tab is only a path segment on this origin.
  assert.equal(safeReturnTo("/%09/evil.example"), "/%09/evil.example");
  // What the parser normalises stays on the origin, and a space is encoded.
  assert.equal(safeReturnTo("/search?q=a b"), "/search?q=a%20b");
  assert.equal(safeReturnTo("/a/../b#frag"), "/b#frag");
});

test("safeReturnTo refuses a path the parser normalises into a protocol-relative one", () => {
  // Each starts with one slash and stays on the origin while it is parsed, but
  // dot-segment removal leaves `//evil.example` — which a browser reads as
  // another host when it comes back as a Location or an href.
  assert.equal(safeReturnTo("/.//evil.example"), null);
  assert.equal(safeReturnTo("/%2e//evil.example"), null);
  assert.equal(safeReturnTo("/a/..//evil.example"), null);
  assert.equal(safeReturnTo("/./%2E/..//evil.example/x?y#z"), null);
  // A doubled slash further in is only a path on this origin.
  assert.equal(safeReturnTo("/a//b"), "/a//b");
});

test("/revalidate never sends a fresh session to a protocol-relative Location", async () => {
  const { app } = makeApp();
  const cookie = await sealed(app);
  for (const returnTo of ["/.//evil.example", "/%2e//evil.example", "/a/..//evil.example"]) {
    const res = await app.handle(
      req(`https://app.example.com/api/auth/revalidate?returnTo=${encodeURIComponent(returnTo)}`, { cookie }),
    );
    assert.equal(res.status, 303, returnTo);
    const loc = res.headers.get("location")!;
    assert.ok(!loc.startsWith("//"), `${returnTo} must not leave the origin, got ${loc}`);
    assert.equal(loc, "/", `${returnTo} falls back to postLoginRedirect`);
  }
});

test("matchesPath: '/' is exact-only, prefixes respect segment boundaries", () => {
  // Regression: a naive startsWith made "/" match every route, so listing the
  // home page as public silently left the entire app unprotected.
  assert.equal(matchesPath("/", "/"), true);
  assert.equal(matchesPath("/dashboard", "/"), false, "'/' must not make everything public");

  assert.equal(matchesPath("/blog", "/blog"), true);
  assert.equal(matchesPath("/blog/post", "/blog"), true, "covers nested paths");
  assert.equal(matchesPath("/blogging", "/blog"), false, "must not match a partial segment");
  assert.equal(matchesPath("/public/a/b", "/public/"), true, "a trailing slash is tolerated");

  assert.equal(matchesPath("/x/y", /^\/x\//), true, "RegExp entries are tested as-is");
  assert.equal(matchesPath("/z", /^\/x\//), false);
});

test("middleware protects routes when only the home page is public", async () => {
  const { app } = makeApp();
  const mw = app.middleware({ publicPaths: ["/"] });

  assert.equal(await mw(req("https://app.example.com/")), undefined, "home is public");

  const guarded = await mw(req("https://app.example.com/dashboard"));
  assert.ok(guarded, "a protected route redirects when signed out");
  assert.equal(guarded!.status, 307);
  assert.equal(
    new URL(guarded!.headers.get("location")!, "https://app.example.com").pathname,
    "/api/auth/login",
  );
});

test("a failed callback reports a diagnostic reason server-side, never to the browser", async () => {
  // Silent auth failures are brutal to debug — a misconfigured secret or an
  // unreachable issuer should say so in the server log while the browser still
  // gets only a generic error.
  const reasons: string[] = [];
  const { app } = makeApp({ onError: (reason) => reasons.push(reason) });

  const loginRes = await app.handle(req("https://app.example.com/api/auth/login"));
  const flowCookie = cookieValue(setCookies(loginRes), "proteles_flow")!;
  await publishNonce(flowCookie);

  const res = await app.handle(
    req("https://app.example.com/api/auth/callback?code=x&state=wrong-state", {
      cookie: `proteles_flow=${flowCookie}`,
    }),
  );

  assert.equal(res.status, 303);
  const location = res.headers.get("location")!;
  assert.match(location, /proteles_error=login_failed/, "the browser gets a generic marker");
  assert.doesNotMatch(location, /state|CSRF/i, "…and no diagnostic detail");
  assert.equal(reasons.length, 1, "exactly one server-side report");
  assert.match(reasons[0]!, /state mismatch/, "with an actionable reason");
});

test("callback failure reasons distinguish the common misconfigurations", async () => {
  const reasons: string[] = [];
  const { app } = makeApp({ onError: (reason) => reasons.push(reason) });

  // No flow cookie at all.
  await app.handle(req("https://app.example.com/api/auth/callback?code=x&state=y"));
  assert.match(reasons.at(-1)!, /no proteles_flow cookie/, "missing flow cookie is named");

  // The authorization server itself reported an error.
  await app.handle(req("https://app.example.com/api/auth/callback?error=access_denied"));
  // Quoted: the value is the caller's, so it is never written raw.
  assert.match(reasons.at(-1)!, /error="access_denied"/, "the AS error is surfaced");
});

test("onError:false silences reporting entirely", async () => {
  const { app } = makeApp({ onError: false });
  // Must not throw, and must still fail closed.
  const res = await app.handle(req("https://app.example.com/api/auth/callback?code=x&state=y"));
  assert.equal(res.status, 303);
});

test("a throwing onError never breaks the auth flow", async () => {
  const { app } = makeApp({
    onError: () => {
      throw new Error("logger exploded");
    },
  });
  const res = await app.handle(req("https://app.example.com/api/auth/callback?code=x&state=y"));
  assert.equal(res.status, 303, "the redirect still happens");
});


// --- session revalidation -------------------------------------------------
//
// The defect these cover: `decryptUsableSession` used to return the session
// whenever a refresh-token *string* was present, without ever presenting it to
// the IdP. So a sealed cookie kept naming its user after the account had been
// revoked, and everything the IdP gained — session revocation, factor resets —
// stopped at the relying party's door.

/** Seals a session cookie directly, the way a previous login would have. */
async function sealed(app: AuthApp, over?: Partial<SessionData>): Promise<string> {
  const crypto = new SessionCrypto(KEY);
  const data: SessionData = {
    accessToken: "old-AT",
    refreshToken: "old-RT",
    accessExpiresAt: Date.now() + 10 * 60_000,
    sub: "user-1",
    ...over,
  };
  void app;
  return `proteles_session=${await crypto.encrypt(data)}`;
}

test("a spent access token is not a live session just because a refresh token is present", async () => {
  const { app, calls } = makeApp();
  const cookie = await sealed(app, { accessExpiresAt: Date.now() - 1 });

  const session = await app.getSession(req("https://app.example.com/dashboard", { cookie }));

  assert.equal(session, null, "the read-only accessor must not vouch for it");
  assert.equal(calls.length, 0, "and must not have called the IdP to find out");
});

test("a live access token is still served without touching the IdP", async () => {
  const { app, calls } = makeApp();
  const cookie = await sealed(app);

  const session = await app.getSession(req("https://app.example.com/dashboard", { cookie }));

  assert.ok(session, "a fresh session is usable as-is");
  assert.equal(calls.length, 0, "no round trip on the hot path");
});

test("inspectSession tells a missing session apart from a spent one", async () => {
  const { app } = makeApp();
  assert.equal((await app.inspectSession(req("https://app.example.com/x"))).kind, "none");

  const fresh = await sealed(app);
  assert.equal((await app.inspectSession(req("https://app.example.com/x", { cookie: fresh }))).kind, "fresh");

  const spent = await sealed(app, { accessExpiresAt: Date.now() - 1 });
  assert.equal((await app.inspectSession(req("https://app.example.com/x", { cookie: spent }))).kind, "stale");

  const spentNoRefresh = await sealed(app, { accessExpiresAt: Date.now() - 1, refreshToken: undefined });
  assert.equal((await app.inspectSession(req("https://app.example.com/x", { cookie: spentNoRefresh }))).kind, "dead");
});

test("resolveSession proves a spent session against the IdP and hands back the rotated cookie", async () => {
  const { app, calls } = makeApp();
  const cookie = await sealed(app, { accessExpiresAt: Date.now() - 1 });

  const written: string[] = [];
  const session = await app.resolveSession(req("https://app.example.com/dashboard", { cookie }), (c) =>
    written.push(c.header),
  );

  assert.ok(session, "the IdP renewed it");
  assert.equal(session!.accessToken, "AT");
  assert.ok(calls.some((c) => c.url.endsWith("/oauth/token")), "it actually asked");
  assert.equal(written.length, 1, "and the rotated token must be persisted, or the next use burns the family");
});

test("a session the IdP refuses is cleared rather than served", async () => {
  // What a revocation looks like from here.
  const { fetch, calls } = mockAS();
  const refusing: FetchLike = async (url, init) =>
    url.endsWith("/oauth/token")
      ? new Response(JSON.stringify({ error: "invalid_grant" }), { status: 400 })
      : fetch(url, init);
  const app = new AuthApp({
    issuer: "https://auth.example.com",
    clientId: "app-1",
    clientSecret: "secret",
    redirectUri: "https://app.example.com/api/auth/callback",
    sessionSecret: KEY,
    cookieSecure: false,
    fetch: refusing,
    onError: false,
  });
  const cookie = await sealed(app, { accessExpiresAt: Date.now() - 1 });

  const written: string[] = [];
  const session = await app.resolveSession(req("https://app.example.com/dashboard", { cookie }), (c) =>
    written.push(c.header),
  );

  assert.equal(session, null, "a refused refresh is not a session");
  assert.ok(written.some((c) => /proteles_session=;|proteles_session=$|Max-Age=0/.test(c)), "and the cookie is cleared");
  void calls;
});

test("middleware bounces a spent session through revalidate rather than to login", async () => {
  // Otherwise honesty costs the user a login every time an access token expires,
  // even though the IdP would have renewed it silently.
  const { app } = makeApp();
  const cookie = await sealed(app, { accessExpiresAt: Date.now() - 1 });
  const mw = app.middleware();

  const res = await mw(req("https://app.example.com/dashboard", { cookie }));

  assert.ok(res, "it does not pass through");
  assert.equal(res!.status, 303);
  const loc = res!.headers.get("location")!;
  assert.match(loc, /\/api\/auth\/revalidate/);
  assert.match(loc, /returnTo=%2Fdashboard/);
});

test("middleware sends a request with no session to login, not to revalidate", async () => {
  const { app } = makeApp();
  const res = await app.middleware()(req("https://app.example.com/dashboard"));
  assert.match(res!.headers.get("location")!, /\/api\/auth\/login/);
});

test("the revalidate route refreshes and returns the user where they were", async () => {
  const { app, calls } = makeApp();
  const cookie = await sealed(app, { accessExpiresAt: Date.now() - 1 });

  const res = await app.handle(
    req("https://app.example.com/api/auth/revalidate?returnTo=/dashboard", { cookie }),
  );

  assert.equal(res.status, 303);
  assert.equal(res.headers.get("location"), "/dashboard");
  assert.ok(calls.some((c) => c.url.endsWith("/oauth/token")));
  assert.ok(cookieValue(setCookies(res), "proteles_session"), "carrying the rotated session");
});

test("a session past its absolute cap cannot be renewed", async () => {
  // The cookie's Max-Age is a request to a browser; a replay with curl never
  // sees it. Without an embedded cap, looping the refresh path would renew a
  // stolen cookie forever.
  const { app, calls } = makeApp();
  const cookie = await sealed(app, {
    accessExpiresAt: Date.now() - 1,
    sessionExpiresAt: Date.now() - 1,
  });

  const written: string[] = [];
  const session = await app.resolveSession(req("https://app.example.com/dashboard", { cookie }), (c) =>
    written.push(c.header),
  );

  assert.equal(session, null);
  assert.equal(calls.length, 0, "and it is refused without asking the IdP");
});

test("a cookie that is not valid percent-encoding is read, not thrown on", async () => {
  // Somebody else's cookie on the same domain as often as an attack. It threw
  // from `decodeURIComponent`, inside an async handler nothing caught.
  const { app } = makeApp();
  const session = await app.getSession(req("https://app.example.com/", { cookie: "a=%; b=%E0%A4%A; c=ok" }));
  assert.equal(session, null);
});

test("/me refuses a session past its absolute cap, and does not refresh it", async () => {
  // The one path that skipped the cap: it refreshed and resealed, so looping
  // `/me` with a stolen cookie kept both the cookie and the IdP family alive.
  const { app, calls } = makeApp();
  const cookie = await sealed(app, {
    accessExpiresAt: Date.now() - 1,
    sessionExpiresAt: Date.now() - 1,
  });
  const res = await app.handle(req("https://app.example.com/api/auth/me", { cookie }));
  const body = (await res.json()) as { authenticated: boolean };
  assert.equal(body.authenticated, false);
  assert.equal(calls.length, 0, "no refresh was attempted");

  // The control: the same cookie before its cap is served, refreshed.
  const live = await sealed(app, { accessExpiresAt: Date.now() - 1, sessionExpiresAt: Date.now() + 60_000 });
  const ok = (await (await app.handle(req("https://app.example.com/api/auth/me", { cookie: live }))).json()) as {
    authenticated: boolean;
  };
  assert.equal(ok.authenticated, true);
});

test("refreshing does not push the absolute cap outwards", async () => {
  // A cap that every refresh extends is not a cap.
  const { app } = makeApp();
  const cap = Date.now() + 60_000;
  const cookie = await sealed(app, { accessExpiresAt: Date.now() - 1, sessionExpiresAt: cap });

  const written: { header: string }[] = [];
  await app.resolveSession(req("https://app.example.com/dashboard", { cookie }), (c) => written.push(c));

  const crypto = new SessionCrypto(KEY);
  const raw = cookieValue(written.map((c) => c.header), "proteles_session")!;
  const data = await crypto.decrypt<SessionData>(raw);
  assert.equal(data.sessionExpiresAt, cap, "the cap survives the refresh unchanged");
});

// ---------------------------------------------------------------------------
// The per-request timeout to the authorization server.
// ---------------------------------------------------------------------------
// `@proteles/js` has always accepted `timeoutMs`; this package never passed it,
// so its 10s default was unreachable for every consumer. The symptom was a
// generic `?proteles_error=login_failed` — indistinguishable from a wrong
// secret — whenever the token exchange was slower than ten seconds, which a
// cold-starting authorization server or a host busy generating a new tenant's
// keys can easily be. It looks like an authentication failure, so the
// timeout is the last thing anyone suspects. (A timed-out
// exchange now gets the page that offers a fresh sign-in, tested below.)
//
// Tested through behaviour rather than by reading the config back: a fetch that
// accepts and never answers, and an assertion on when the abort arrives. That
// is the only way to prove the value reached the client rather than merely
// being stored beside it.

/** A fetch that hangs until its abort signal fires, reporting how long it took. */
function hangingFetch(): { fetch: FetchLike; abortedAfter: () => number | undefined } {
  let ms: number | undefined;
  const fetch: FetchLike = (_url, init) =>
    new Promise((_resolve, reject) => {
      const started = Date.now();
      const signal = init?.signal as AbortSignal | undefined;
      if (!signal) throw new Error("no abort signal reached fetch — the client stopped applying a timeout");
      signal.addEventListener("abort", () => {
        ms = Date.now() - started;
        reject(new DOMException("aborted", "AbortError"));
      });
    });
  return { fetch, abortedAfter: () => ms };
}

async function timeCallback(over: Partial<ProtelesConfigInput>): Promise<number> {
  const { fetch, abortedAfter } = hangingFetch();
  const { app } = makeApp({ fetch, ...over });
  const loginRes = await app.handle(req("https://app.example.com/api/auth/login"));
  const state = new URL(loginRes.headers.get("location")!).searchParams.get("state")!;
  const flowCookie = cookieValue(setCookies(loginRes), "proteles_flow")!;
  await publishNonce(flowCookie);
  await app.handle(
    req(`https://app.example.com/api/auth/callback?code=c&state=${encodeURIComponent(state)}`, {
      cookie: `proteles_flow=${flowCookie}`,
    }),
  );
  const ms = abortedAfter();
  assert.ok(ms !== undefined, "the request was never aborted — no timeout was applied");
  return ms!;
}

test("timeoutMs bounds the call to the authorization server", async () => {
  const ms = await timeCallback({ timeoutMs: 250 });
  // Generous upper bound: this runs on a machine that also builds Rust.
  assert.ok(ms >= 200 && ms < 3000, `aborted after ${ms}ms, expected ~250ms`);
});

test("timeoutMs bounds the key-set fetch as well", async () => {
  // Every callback waits on the key set before it can check the ID token, so
  // a key-set endpoint that never answered held each one open indefinitely.
  const { fetch: server } = mockAS();
  const { fetch: hang, abortedAfter } = hangingFetch();
  const fetch: FetchLike = (url, init) => (url.endsWith("/.well-known/jwks.json") ? hang(url, init) : server(url, init));
  const { app } = makeApp({ fetch, timeoutMs: 250 });
  const loginRes = await app.handle(req("https://app.example.com/api/auth/login"));
  const state = new URL(loginRes.headers.get("location")!).searchParams.get("state")!;
  const flowCookie = cookieValue(setCookies(loginRes), "proteles_flow")!;
  await publishNonce(flowCookie);
  const res = await app.handle(
    req(`https://app.example.com/api/auth/callback?code=c&state=${encodeURIComponent(state)}`, {
      cookie: `proteles_flow=${flowCookie}`,
    }),
  );
  assert.equal(cookieValue(setCookies(res), "proteles_session"), undefined, "an unchecked ID token mints no session");
  const ms = abortedAfter();
  assert.ok(ms !== undefined, "the key-set fetch was never aborted — no timeout was applied");
  assert.ok(ms >= 200 && ms < 3000, `aborted after ${ms}ms, expected ~250ms`);
});

test("PROTELES_TIMEOUT_MS configures it from the environment", async () => {
  process.env.PROTELES_TIMEOUT_MS = "250";
  try {
    const ms = await timeCallback({});
    assert.ok(ms >= 200 && ms < 3000, `aborted after ${ms}ms, expected ~250ms`);
  } finally {
    delete process.env.PROTELES_TIMEOUT_MS;
  }
});

test("an explicit timeoutMs beats the environment", async () => {
  process.env.PROTELES_TIMEOUT_MS = "9000";
  try {
    const ms = await timeCallback({ timeoutMs: 250 });
    assert.ok(ms < 3000, `aborted after ${ms}ms — the environment won, which it must not`);
  } finally {
    delete process.env.PROTELES_TIMEOUT_MS;
  }
});

test("a nonsensical timeout is refused rather than absorbed", () => {
  // Silently falling back to the default is how a misconfiguration is found
  // during an incident instead of at boot. Zero is refused for the same reason:
  // it aborts every request instantly and looks exactly like an unreachable
  // issuer.
  for (const bad of [0, -1, Number.NaN, Number.POSITIVE_INFINITY]) {
    assert.throws(() => makeApp({ timeoutMs: bad }), /positive number of milliseconds/);
  }
  for (const bad of ["abc", "0", "-5", ""]) {
    process.env.PROTELES_TIMEOUT_MS = bad;
    try {
      if (bad === "") {
        // An empty variable is "unset" by this package's `env()`, so it falls
        // through to the default rather than throwing.
        assert.doesNotThrow(() => makeApp({}));
      } else {
        assert.throws(() => makeApp({}), /positive number of milliseconds/);
      }
    } finally {
      delete process.env.PROTELES_TIMEOUT_MS;
    }
  }
});

// ---------------------------------------------------------------------------
// ID-token verification, at the BFF
//
// The unit tests in @proteles/js cover the verifier. These cover the wiring:
// that it is actually called on the paths that matter, and hard-fails rather
// than warning. Until this shipped the nonce was minted, sent, and sealed into
// the flow cookie, and never read — so a token replayed from a different login
// of the same user was indistinguishable from this one's.
// ---------------------------------------------------------------------------

/** Runs login → callback with a mock AS that returns the given id_token. */
async function callbackWithIdToken(
  idToken: () => Promise<string | undefined>,
  overrides?: Partial<ProtelesConfigInput>,
): Promise<Response> {
  const { fetch } = mockAS({ idToken });
  const app = new AuthApp({
    issuer: ISSUER,
    clientId: CLIENT_ID,
    clientSecret: "secret",
    redirectUri: "https://app.example.com/api/auth/callback",
    sessionSecret: KEY,
    cookieSecure: false,
    fetch,
    onError: false,
    ...overrides,
  });
  const loginRes = await app.handle(req("https://app.example.com/api/auth/login?returnTo=/dashboard"));
  const state = new URL(loginRes.headers.get("location")!).searchParams.get("state")!;
  const flowCookie = cookieValue(setCookies(loginRes), "proteles_flow")!;
  await publishNonce(flowCookie);
  return app.handle(
    req(`https://app.example.com/api/auth/callback?code=c&state=${encodeURIComponent(state)}`, {
      cookie: `proteles_flow=${flowCookie}`,
    }),
  );
}

/** A callback that failed verification redirects to the error page. */
function assertRefused(res: Response, why: string) {
  assert.equal(res.status, 303, why);
  assert.notEqual(res.headers.get("location"), "/dashboard", why);
  assert.equal(cookieValue(setCookies(res), "proteles_session"), undefined, `${why}: no session may be minted`);
}

test("an id_token from a different login is refused — the nonce is finally read", async () => {
  // The replay this closes. The token is perfectly valid: signed by the right
  // key, right issuer, right audience, unexpired. Only the nonce is another
  // login's, which is exactly what a replayed token looks like.
  const res = await callbackWithIdToken(() => issueIdToken({ nonce: "a-different-logins-nonce" }));
  assertRefused(res, "a replayed id_token must not establish a session");
});

test("an id_token signed by the wrong key is refused", async () => {
  const other = await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  );
  const forge = async () => {
    const now = Math.floor(Date.now() / 1000);
    const h = b64u(JSON.stringify({ alg: "RS256", typ: "JWT", kid: KID }));
    const p = b64u(JSON.stringify({ iss: ISSUER, aud: CLIENT_ID, sub: "user-1", exp: now + 300, nonce: lastNonce }));
    const sig = await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, other.privateKey, new TextEncoder().encode(`${h}.${p}`));
    return `${h}.${p}.${b64u(new Uint8Array(sig))}`;
  };
  assertRefused(await callbackWithIdToken(forge), "a token signed by an unpublished key must not be accepted");
});

test("an id_token for another audience is refused", async () => {
  const res = await callbackWithIdToken(() => issueIdToken({ aud: "some-other-client", nonce: lastNonce }));
  assertRefused(res, "a token minted for another client must not establish a session");
});

test("a missing id_token is refused when openid was requested", async () => {
  // The skip that would look like a pass. "No token" must not read as "nothing
  // to check" when the scopes asked for one.
  const res = await callbackWithIdToken(async () => undefined);
  assertRefused(res, "openid was requested and no id_token came back");
});

test("a missing id_token is fine when openid was not requested", async () => {
  // The other half, and the reason the check is conditional: a non-OIDC caller
  // must not be broken by a verification for a token it never asked for.
  const res = await callbackWithIdToken(async () => undefined, { scopes: ["profile"] });
  assert.equal(res.status, 303);
  assert.equal(res.headers.get("location"), "/dashboard", "a non-OIDC login still completes");
});

test("a valid id_token establishes the session, and the nonce it carries is this login's", async () => {
  const res = await callbackWithIdToken(() => issueIdToken({ nonce: lastNonce }));
  assert.equal(res.status, 303);
  assert.equal(res.headers.get("location"), "/dashboard");
  assert.ok(cookieValue(setCookies(res), "proteles_session"), "a verified login mints a session");
});

test("a sign-in whose userinfo names another sub than its ID token is refused", async () => {
  // OIDC Core §5.3.2: the userinfo `sub` MUST be the ID token's, and a client
  // must not use the response otherwise. The session takes its `sub` from
  // userinfo, so without the comparison it named whoever userinfo said.
  const reasons: string[] = [];
  const res = await callbackWithIdToken(() => issueIdToken({ nonce: lastNonce, sub: "someone-else" }), {
    onError: (reason) => reasons.push(reason),
  });
  assertRefused(res, "userinfo and the ID token disagree about who signed in");
  assert.ok(reasons.some((r) => /sub/.test(r)), `the reason names the sub mismatch: ${reasons}`);
});

test("a refresh whose ID token names another sub than the session ends the session", async () => {
  // OIDC Core §12.2: an ID token from a refresh must have the same `sub` as
  // the one the session began with. Anything else is not this session.
  const { app } = makeApp(undefined, { idToken: () => issueIdToken({ sub: "someone-else" }) });
  const cookie = await sealed(app, { accessExpiresAt: Date.now() - 1 });

  const me = await app.handle(req("https://app.example.com/api/auth/me", { cookie }));
  assert.equal(((await me.json()) as { authenticated: boolean }).authenticated, false);
  assert.match(setCookies(me).find((c) => c.startsWith("proteles_session="))!, /Max-Age=0/, "/me clears the cookie");

  const written: string[] = [];
  const session = await app.resolveSession(req("https://app.example.com/dashboard", { cookie }), (c) =>
    written.push(c.header),
  );
  assert.equal(session, null, "resolveSession refuses it too");
  assert.match(written[0] ?? "", /Max-Age=0/);
});

test("a refresh whose ID token names the session's own sub carries on (the control)", async () => {
  const { app } = makeApp(undefined, { idToken: () => issueIdToken({ sub: "user-1" }) });
  const cookie = await sealed(app, { accessExpiresAt: Date.now() - 1 });
  const me = await app.handle(req("https://app.example.com/api/auth/me", { cookie }));
  assert.equal(((await me.json()) as { authenticated: boolean }).authenticated, true);
});

test("a callback's error parameter is quoted in the report", async () => {
  // The value is whoever sent the request's, and written
  // raw into the report a newline in it forged a line of the app's log.
  const reasons: string[] = [];
  const { app } = makeApp({ onError: (reason) => reasons.push(reason) });
  await app.handle(req("https://app.example.com/api/auth/callback?error=access_denied%0A%5Bproteles%5D%20forged"));
  assert.ok(reasons.some((r) => r.includes(String.raw`"access_denied\n[proteles] forged"`)), `quoted: ${JSON.stringify(reasons)}`);
  assert.ok(reasons.every((r) => !r.includes("\n")), "no raw newline reaches the report");
});

test("a refresh with no ID token ends the session when openid was asked for", async () => {
  // The check used to sit inside `if (tok.idToken)`, so
  // an answer without one kept the session and compared no `sub` at all.
  const { app } = makeApp(undefined, { idToken: async () => undefined });
  const cookie = await sealed(app, { accessExpiresAt: Date.now() - 1 });
  const me = await app.handle(req("https://app.example.com/api/auth/me", { cookie }));
  assert.equal(((await me.json()) as { authenticated: boolean }).authenticated, false);
  assert.match(setCookies(me).find((c) => c.startsWith("proteles_session="))!, /Max-Age=0/, "/me clears the cookie");
});

test("a refresh with no ID token carries on when openid was not asked for (the control)", async () => {
  const { app } = makeApp({ scopes: ["profile"] }, { idToken: async () => undefined });
  const cookie = await sealed(app, { accessExpiresAt: Date.now() - 1 });
  const me = await app.handle(req("https://app.example.com/api/auth/me", { cookie }));
  assert.equal(((await me.json()) as { authenticated: boolean }).authenticated, true);
});

// ---------------------------------------------------------------------------
// A busy authorization server is not a revoked session.
//
// The token endpoint answers a full password pool with 503
// temporarily_unavailable — the client secret went unchecked, the grant was
// never read — and the rate limiter answers 429 with a Retry-After. Every
// failed refresh used to clear the session cookie, so a busy minute signed out
// everybody whose access token expired inside it. Now those answers, and no
// answer at all, keep the cookie and its refresh token and say "try again";
// invalid_grant still ends the session exactly as before.
// ---------------------------------------------------------------------------

/** One scripted answer: the mock's normal one, a thrown network error, or a response. */
type Step = "ok" | "unreachable" | (() => Response);

const busy503 = () =>
  new Response(JSON.stringify({ error: "temporarily_unavailable", error_description: "the server is busy; retry shortly" }), {
    status: 503,
    headers: { "content-type": "application/json" },
  });
const throttled429 = () =>
  new Response(JSON.stringify({ error: "rate_limited" }), {
    status: 429,
    headers: { "content-type": "application/json", "retry-after": "7" },
  });
const invalidGrant = () =>
  new Response(JSON.stringify({ error: "invalid_grant" }), { status: 400, headers: { "content-type": "application/json" } });

/**
 * An app whose token endpoint (for code exchanges and for refreshes),
 * revocation endpoint and key set follow a script, one step per call, the last
 * step repeating. Every call still reaches the ordinary mock first, so `calls`
 * records it either way.
 */
function scriptedApp(script: { exchange?: Step[]; refresh?: Step[]; revoke?: Step[]; jwks?: Step[] }) {
  const inner = mockAS();
  const reports: { context: string; reason: string }[] = [];
  const next = { exchange: 0, refresh: 0, revoke: 0, jwks: 0 };
  const fetch: FetchLike = async (url, init) => {
    const body = typeof init?.body === "string" ? init.body : "";
    const which = url.endsWith("/oauth/revoke")
      ? "revoke"
      : url.endsWith("/.well-known/jwks.json")
        ? "jwks"
        : url.endsWith("/oauth/token") && body.includes("grant_type=refresh_token")
          ? "refresh"
          : url.endsWith("/oauth/token") && body.includes("grant_type=authorization_code")
            ? "exchange"
            : undefined;
    const answer = await inner.fetch(url, init);
    const steps = which ? script[which] : undefined;
    if (!which || !steps || steps.length === 0) return answer;
    const step = steps[Math.min(next[which]++, steps.length - 1)]!;
    if (step === "ok") return answer;
    if (step === "unreachable") throw new TypeError("fetch failed");
    return step();
  };
  const app = new AuthApp({
    issuer: ISSUER,
    clientId: CLIENT_ID,
    clientSecret: "secret",
    redirectUri: "https://app.example.com/api/auth/callback",
    sessionSecret: KEY,
    cookieSecure: false,
    fetch,
    onError: (reason, context) => reports.push({ context, reason }),
  });
  return { app, calls: inner.calls, reports };
}

/** The refresh tokens presented to the token endpoint, in order. */
function presentedRefreshTokens(calls: { body: string }[]): (string | null)[] {
  return calls
    .map((c) => new URLSearchParams(c.body))
    .filter((f) => f.get("grant_type") === "refresh_token")
    .map((f) => f.get("refresh_token"));
}

const ME = "https://app.example.com/api/auth/me";

test("503 from the token endpoint keeps the session and its refresh token, whatever the body", async () => {
  for (const [label, busy] of [
    ["temporarily_unavailable", busy503],
    ["an HTML page", () => new Response("<html>busy</html>", { status: 503, headers: { "content-type": "text/html" } })],
    ["no body", () => new Response(null, { status: 503 })],
  ] as const) {
    const { app, calls, reports } = scriptedApp({ refresh: [busy, "ok"] });
    const cookie = await sealed(app, { accessExpiresAt: Date.now() - 1 });

    const first = await app.handle(req(ME, { cookie }));
    assert.equal(first.status, 503, `${label}: /me says try again`);
    assert.equal(((await first.json()) as { error: string }).error, "temporarily_unavailable");
    assert.deepEqual(setCookies(first), [], `${label}: the session cookie is neither cleared nor rewritten`);
    assert.equal(first.headers.get("retry-after"), null, `${label}: the server named no wait, so none is invented`);
    assert.ok(reports.some((r) => r.context === "refresh"), `${label}: the deferral is reported server-side`);

    // The browser still holds the same cookie, and the next request retries.
    const second = await app.handle(req(ME, { cookie }));
    assert.equal(second.status, 200, `${label}: the next request refreshes`);
    assert.equal(((await second.json()) as { authenticated: boolean }).authenticated, true);
    assert.deepEqual(presentedRefreshTokens(calls), ["old-RT", "old-RT"], `${label}: the retry presents the refresh token the session kept`);
    const rotated = cookieValue(setCookies(second), "proteles_session")!;
    assert.equal((await new SessionCrypto(KEY).decrypt<SessionData>(rotated)).refreshToken, "RT");
  }
});

test("429 keeps the session too, and hands its Retry-After to the caller", async () => {
  const { app, calls } = scriptedApp({ refresh: [throttled429, "ok"] });
  const cookie = await sealed(app, { accessExpiresAt: Date.now() - 1 });

  const first = await app.handle(req(ME, { cookie }));
  assert.equal(first.status, 503);
  assert.equal(first.headers.get("retry-after"), "7", "the rate limiter's wait is passed through");
  assert.deepEqual(setCookies(first), [], "nothing cleared");

  const second = await app.handle(req(ME, { cookie }));
  assert.equal(((await second.json()) as { authenticated: boolean }).authenticated, true);
  assert.deepEqual(presentedRefreshTokens(calls), ["old-RT", "old-RT"]);
});

test("an unreachable authorization server keeps the session", async () => {
  const { app, calls } = scriptedApp({ refresh: ["unreachable", "ok"] });
  const cookie = await sealed(app, { accessExpiresAt: Date.now() - 1 });

  const first = await app.handle(req(ME, { cookie }));
  assert.equal(first.status, 503);
  assert.deepEqual(setCookies(first), []);

  const second = await app.handle(req(ME, { cookie }));
  assert.equal(((await second.json()) as { authenticated: boolean }).authenticated, true);
  assert.deepEqual(presentedRefreshTokens(calls), ["old-RT", "old-RT"]);
});

test("invalid_grant still ends the session (the control)", async () => {
  const { app } = scriptedApp({ refresh: [invalidGrant] });
  const cookie = await sealed(app, { accessExpiresAt: Date.now() - 1 });

  const res = await app.handle(req(ME, { cookie }));
  assert.equal(res.status, 200);
  assert.equal(((await res.json()) as { authenticated: boolean }).authenticated, false);
  const cleared = setCookies(res).find((c) => c.startsWith("proteles_session="));
  assert.ok(cleared && /Max-Age=0/.test(cleared), "a refused grant clears the cookie, as it always did");

  // And through resolveSession, which `/revalidate` uses: null and a clear, not an error.
  const written: string[] = [];
  assert.equal(await app.resolveSession(req("https://app.example.com/x", { cookie }), (c) => written.push(c.header)), null);
  assert.ok(written.some((c) => /Max-Age=0/.test(c)));
});

test("resolveSession throws SessionUnavailableError while busy, and writes nothing", async () => {
  const { app } = scriptedApp({ refresh: [throttled429, "ok"] });
  const cookie = await sealed(app, { accessExpiresAt: Date.now() - 1 });

  const written: string[] = [];
  await assert.rejects(
    () => app.resolveSession(req("https://app.example.com/x", { cookie }), (c) => written.push(c.header)),
    (e: unknown) => {
      assert.ok(e instanceof SessionUnavailableError);
      assert.equal(e.retryAfter, 7);
      return true;
    },
  );
  assert.deepEqual(written, [], "the sink is not called: the cookie the browser holds is still the session");

  const session = await app.resolveSession(req("https://app.example.com/x", { cookie }), (c) => written.push(c.header));
  assert.equal(session?.refreshToken, "RT", "and the next call refreshes");
  assert.equal(written.length, 1);
});

// The exchange went through and rotated the refresh token, but the new ID
// token could not be checked: the key-set cache is per process, cold after a
// deploy, and its one fetch failed. That used to end the session, throwing
// away the successor the process was holding — a sign-out over a network blip.
test("a key set out of reach after a refresh keeps the session, with the rotated refresh token", async () => {
  for (const [label, keySet] of [
    ["503", () => new Response("busy", { status: 503 })],
    ["no answer", "unreachable"],
  ] as const) {
    const { app, calls, reports } = scriptedApp({ jwks: [keySet, "ok"] });
    const cookie = await sealed(app, { accessExpiresAt: Date.now() - 1 });

    const first = await app.handle(req(ME, { cookie }));
    assert.equal(first.status, 503, `${label}: /me says try again`);
    const kept = cookieValue(setCookies(first), "proteles_session");
    assert.ok(kept, `${label}: the session is rewritten, because the refresh token it held is spent`);
    const successor = await new SessionCrypto(KEY).decrypt<SessionData>(kept);
    assert.equal(successor.refreshToken, "RT", `${label}: with the rotated refresh token`);
    assert.equal(successor.accessToken, "old-AT", `${label}: and the old access token, unverified exchange unused`);
    assert.ok(successor.accessExpiresAt < Date.now(), `${label}: still spent, so the next request refreshes again`);
    assert.ok(reports.some((r) => r.context === "refresh"), `${label}: the deferral is reported`);

    const second = await app.handle(req(ME, { cookie: `proteles_session=${kept}` }));
    assert.equal(second.status, 200, `${label}: the next request refreshes with the successor`);
    assert.equal(((await second.json()) as { authenticated: boolean }).authenticated, true);
    assert.deepEqual(presentedRefreshTokens(calls), ["old-RT", "RT"], `${label}: the spent token is never presented again`);
  }
});

test("resolveSession hands the sink the successor before it throws", async () => {
  const { app } = scriptedApp({ jwks: [() => new Response("busy", { status: 503 }), "ok"] });
  const cookie = await sealed(app, { accessExpiresAt: Date.now() - 1 });

  const written: string[] = [];
  await assert.rejects(
    () => app.resolveSession(req("https://app.example.com/x", { cookie }), (c) => written.push(c.header)),
    SessionUnavailableError,
  );
  assert.equal(written.length, 1, "the rotated refresh token has to reach the response");
  const kept = cookieValue(written, "proteles_session")!;
  assert.equal((await new SessionCrypto(KEY).decrypt<SessionData>(kept)).refreshToken, "RT");
});

test("/revalidate's try-again page carries the successor when the key set was out of reach", async () => {
  const { app } = scriptedApp({ jwks: [() => new Response("busy", { status: 503 }), "ok"] });
  const cookie = await sealed(app, { accessExpiresAt: Date.now() - 1 });

  const res = await app.handle(req("https://app.example.com/api/auth/revalidate?returnTo=/dashboard", { cookie }));
  assert.equal(res.status, 503);
  const kept = cookieValue(setCookies(res), "proteles_session");
  assert.ok(kept, "the page has to carry the rotated refresh token, or the next click presents a spent one");
  assert.equal((await new SessionCrypto(KEY).decrypt<SessionData>(kept)).refreshToken, "RT");
});

test("an ID token that fails verification after a refresh still ends the session (the control)", async () => {
  // A key set that answered, and does not hold the token's key: a verdict, not
  // a moment.
  const { app } = scriptedApp({ jwks: [() => jsonResponse({ keys: [{ ...publicJwk, kid: "other", alg: "RS256", use: "sig" }] })] });
  const cookie = await sealed(app, { accessExpiresAt: Date.now() - 1 });

  const res = await app.handle(req(ME, { cookie }));
  assert.equal(res.status, 200);
  assert.equal(((await res.json()) as { authenticated: boolean }).authenticated, false);
  assert.match(setCookies(res).find((c) => c.startsWith("proteles_session="))!, /Max-Age=0/);
});

test("/revalidate answers a busy server with a try-again page, not a login redirect", async () => {
  const { app } = scriptedApp({ refresh: [throttled429, "ok"] });
  const cookie = await sealed(app, { accessExpiresAt: Date.now() - 1 });
  const url = `https://app.example.com/api/auth/revalidate?returnTo=${encodeURIComponent("/dashboard?tab=a&view='x'#t'")}`;

  const busy = await app.handle(req(url, { cookie }));
  assert.equal(busy.status, 503);
  assert.equal(busy.headers.get("location"), null, "no redirect: to returnTo the middleware would bounce it straight back");
  assert.equal(busy.headers.get("retry-after"), "7");
  assert.match(busy.headers.get("content-type") ?? "", /text\/html/);
  assert.deepEqual(setCookies(busy), [], "and the cookie is left alone");
  const page = await busy.text();
  assert.match(page, /href="\/dashboard\?tab=a&#38;view=%27x%27#t&#39;"/, "the retry link goes back where the user was, escaped");
  assert.match(page, /<form method="post" action="\/api\/auth\/logout">/, "and there is a way out that does not depend on the refresh working, by POST");

  const ok = await app.handle(req(url, { cookie }));
  assert.equal(ok.status, 303);
  assert.equal(ok.headers.get("location"), "/dashboard?tab=a&view=%27x%27#t'");
  assert.ok(cookieValue(setCookies(ok), "proteles_session"), "the retry refreshed and rotated");
});

test("sign-out retries a revocation the server was too busy for", async () => {
  const { app, calls, reports } = scriptedApp({ revoke: [busy503, "ok"] });
  const cookie = await sealed(app);

  const res = await app.handle(req("https://app.example.com/api/auth/logout", { method: "POST", cookie }));
  assert.equal(res.status, 303);
  assert.equal(calls.filter((c) => c.url.endsWith("/oauth/revoke")).length, 2, "revoked on the second attempt");
  assert.deepEqual(reports.filter((r) => r.context === "logout"), [], "nothing to report when it worked");
  assert.match(setCookies(res).find((c) => c.startsWith("proteles_session="))!, /Max-Age=0/);
});

test("sign-out that still cannot revoke says so, and clears the session anyway", async () => {
  const { app, calls, reports } = scriptedApp({ revoke: [busy503] });
  const cookie = await sealed(app);

  const res = await app.handle(req("https://app.example.com/api/auth/logout", { method: "POST", cookie }));
  assert.equal(res.status, 303);
  assert.equal(calls.filter((c) => c.url.endsWith("/oauth/revoke")).length, 2, "one retry, not a loop");
  const logged = reports.filter((r) => r.context === "logout");
  assert.equal(logged.length, 1, "the lost revocation is reported, not swallowed");
  assert.match(logged[0]!.reason, /not revoked/);
  assert.match(setCookies(res).find((c) => c.startsWith("proteles_session="))!, /Max-Age=0/, "the user is signed out here regardless");
});

// Only a busy answer that came back quickly is retried. The redirect that
// clears the cookie is written after the revocation, so a retry after a
// timeout doubled sign-out to two full `timeoutMs` and the pause — long enough
// for a host with a lower request limit to cut the response off, leaving the
// user who asked to sign out signed in.
test("sign-out does not retry when no answer came", async () => {
  const { app, calls, reports } = scriptedApp({ revoke: ["unreachable", "ok"] });
  const cookie = await sealed(app);

  const res = await app.handle(req("https://app.example.com/api/auth/logout", { method: "POST", cookie }));
  assert.equal(res.status, 303);
  assert.equal(calls.filter((c) => c.url.endsWith("/oauth/revoke")).length, 1, "no answer is not a busy answer");
  assert.equal(reports.filter((r) => r.context === "logout").length, 1, "the lost revocation is reported");
  assert.match(setCookies(res).find((c) => c.startsWith("proteles_session="))!, /Max-Age=0/);
});

test("sign-out does not retry a busy answer that was slow in coming", async (t) => {
  // A gateway's 504 after its own upstream timeout: busy, but slow enough that
  // a second attempt could take as long again. The clock is moved rather than
  // waited on.
  let now = Date.now();
  t.mock.method(Date, "now", () => now);
  const slow504 = () => {
    now += 3_000;
    return new Response(null, { status: 504 });
  };
  const { app, calls, reports } = scriptedApp({ revoke: [slow504, "ok"] });
  const cookie = await sealed(app);

  const res = await app.handle(req("https://app.example.com/api/auth/logout", { method: "POST", cookie }));
  assert.equal(res.status, 303);
  assert.equal(calls.filter((c) => c.url.endsWith("/oauth/revoke")).length, 1, "a slow busy answer is not retried");
  assert.equal(reports.filter((r) => r.context === "logout").length, 1);
});

test("sign-out does not retry a revocation the server refused, but still reports it", async () => {
  const { app, calls, reports } = scriptedApp({
    revoke: [() => new Response(JSON.stringify({ error: "invalid_client" }), { status: 401 })],
  });
  const cookie = await sealed(app);

  await app.handle(req("https://app.example.com/api/auth/logout", { method: "POST", cookie }));
  assert.equal(calls.filter((c) => c.url.endsWith("/oauth/revoke")).length, 1, "a refusal is not a moment");
  assert.equal(reports.filter((r) => r.context === "logout").length, 1);
});

// ---------------------------------------------------------------------------
// A busy authorization server at sign-in's code exchange.
//
// The callback ended in `login_failed` whatever the token endpoint said, so a
// `503` from a full password pool read as a failed sign-in. It gets a page
// that says the service was busy and starts a fresh sign-in; the code itself
// is never presented again.
// ---------------------------------------------------------------------------

/** Walks the login route at `loginPath` and then the callback, as a browser does. */
async function signIn(app: AuthApp, loginPath: string): Promise<Response> {
  const loginRes = await app.handle(req(`https://app.example.com${loginPath}`));
  const state = new URL(loginRes.headers.get("location")!).searchParams.get("state")!;
  const flowCookie = cookieValue(setCookies(loginRes), "proteles_flow")!;
  await publishNonce(flowCookie);
  return app.handle(
    req(`https://app.example.com/api/auth/callback?code=the-code&state=${encodeURIComponent(state)}`, {
      cookie: `proteles_flow=${flowCookie}`,
    }),
  );
}

/** The authorization codes presented to the token endpoint, in order. */
function presentedCodes(calls: { body: string }[]): (string | null)[] {
  return calls
    .map((c) => new URLSearchParams(c.body))
    .filter((f) => f.get("grant_type") === "authorization_code")
    .map((f) => f.get("code"));
}

test("a busy server at the code exchange gets a page that starts sign-in again, not login_failed", async () => {
  for (const [label, step, retryAfter] of [
    ["503", busy503, null],
    ["429", throttled429, "7"],
    ["no answer", "unreachable", null],
  ] as const) {
    const { app, calls, reports } = scriptedApp({ exchange: [step, "ok"] });

    const res = await signIn(app, `/api/auth/login?returnTo=${encodeURIComponent("/dashboard?tab=a")}`);
    assert.equal(res.status, 503, `${label}: a busy page`);
    assert.equal(res.headers.get("location"), null, `${label}: not a redirect to login_failed`);
    assert.equal(res.headers.get("retry-after"), retryAfter, `${label}: Retry-After only when the server named one`);
    assert.match(res.headers.get("content-type") ?? "", /text\/html/);
    const page = await res.text();
    assert.match(page, /The sign-in service was busy/, `${label}: it says why`);
    const href = page.match(/href="([^"]*)"/)?.[1];
    assert.equal(href, "/api/auth/login?returnTo=%2Fdashboard%3Ftab%3Da", `${label}: and links to a fresh sign-in`);
    const cookies = setCookies(res);
    assert.match(cookies.find((c) => c.startsWith("proteles_flow="))!, /Max-Age=0/, `${label}: the flow is spent`);
    assert.equal(cookieValue(cookies, "proteles_session"), undefined, `${label}: nobody is signed in`);
    assert.deepEqual(presentedCodes(calls), ["the-code"], `${label}: the code is presented once, never retried`);
    assert.ok(
      reports.some((r) => r.context === "callback" && /busy or unreachable at the code exchange/.test(r.reason)),
      `${label}: reported server-side`,
    );

    // The link is the ordinary login route, so following it is a fresh flow,
    // which signs in once the server answers.
    const again = await signIn(app, href!);
    assert.equal(again.status, 303, `${label}: signing in again works once the server answers`);
    assert.equal(again.headers.get("location"), "/dashboard?tab=a");
    assert.ok(cookieValue(setCookies(again), "proteles_session"), `${label}: with a session`);
  }
});

test("invalid_grant at the code exchange still ends in login_failed (the control)", async () => {
  const { app, reports } = scriptedApp({ exchange: [invalidGrant] });
  const res = await signIn(app, "/api/auth/login?returnTo=%2Fdashboard");
  assert.equal(res.status, 303);
  assert.match(res.headers.get("location")!, /proteles_error=login_failed/);
  assert.ok(reports.some((r) => r.context === "callback" && /invalid_grant/.test(r.reason)));
});

// ---------------------------------------------------------------------------
// `__Host-` names whenever the cookies are Secure.
//
// Without the prefix, any host under the app's registrable domain can set
// `proteles_session` for the whole domain, and the browser sends it to the app
// as well: a sibling plants an honest sealed value of its own, and the victim
// uses the app as the attacker. A browser refuses a `__Host-` cookie from
// anywhere but the host itself, and one without `Secure` or `Path=/`, or with
// a `Domain`, so each of those is asserted rather than assumed.
// ---------------------------------------------------------------------------

test("cookieNames: __Host- names when the cookies are Secure, the plain ones when not", () => {
  assert.deepEqual(cookieNames(true), { session: "__Host-proteles_session", flow: "__Host-proteles_flow" });
  assert.deepEqual(cookieNames(false), { session: "proteles_session", flow: "proteles_flow" });
});

test("cookieNames() reads PROTELES_COOKIE_SECURE as resolveConfig does", () => {
  const was = process.env.PROTELES_COOKIE_SECURE;
  try {
    delete process.env.PROTELES_COOKIE_SECURE;
    assert.equal(cookieNames().session, "__Host-proteles_session", "unset means Secure");
    process.env.PROTELES_COOKIE_SECURE = "false";
    assert.equal(cookieNames().session, "proteles_session");
  } finally {
    if (was === undefined) delete process.env.PROTELES_COOKIE_SECURE;
    else process.env.PROTELES_COOKIE_SECURE = was;
  }
});

function assertHostPrefixed(header: string | undefined, name: string) {
  assert.ok(header?.startsWith(`${name}=`), `a ${name} cookie was set: ${header}`);
  assert.match(header!, /;\s*Secure(;|$)/i, `${name} is Secure, or the browser drops it`);
  assert.match(header!, /;\s*Path=\/(;|$)/i, `${name} is Path=/, or the browser drops it`);
  assert.doesNotMatch(header!, /;\s*Domain=/i, `${name} names no Domain, or the browser drops it`);
}

test("with Secure cookies, the app sets and clears only valid __Host- cookies", async () => {
  const { app } = makeApp({ cookieSecure: true });
  assert.deepEqual(app.cookieNames, cookieNames(true));

  const login = await app.handle(req("https://app.example.com/api/auth/login"));
  assertHostPrefixed(setCookies(login).find((c) => c.startsWith("__Host-proteles_flow=")), "__Host-proteles_flow");
  assert.equal(setCookies(login).some((c) => c.startsWith("proteles_flow=")), false, "no plain flow cookie");

  const sealed = await new SessionCrypto(KEY).encrypt({
    accessToken: "AT",
    refreshToken: "RT",
    accessExpiresAt: Date.now() + 1e6,
    sub: "u1",
  } satisfies SessionData);
  const out = await app.handle(
    req("https://app.example.com/api/auth/logout", { method: "POST", cookie: `__Host-proteles_session=${sealed}` }),
  );
  assert.equal(out.status, 303);
  assertHostPrefixed(setCookies(out).find((c) => c.startsWith("__Host-proteles_session=")), "__Host-proteles_session");
});

test("with Secure cookies, a planted plain proteles_session is not a session", async () => {
  const { app } = makeApp({ cookieSecure: true });
  const sealed = await new SessionCrypto(KEY).encrypt({
    accessToken: "AT",
    refreshToken: "RT",
    accessExpiresAt: Date.now() + 1e6,
    sub: "the-attacker",
    email: "attacker@example.com",
  } satisfies SessionData);

  const planted = await app.handle(req("https://app.example.com/api/auth/me", { cookie: `proteles_session=${sealed}` }));
  assert.equal(((await planted.json()) as { authenticated: boolean }).authenticated, false, "a sibling's plain cookie is not read");

  // The control: the same sealed value under the app's own name is a session,
  // so the refusal above is about the name and nothing else.
  const own = await app.handle(req("https://app.example.com/api/auth/me", { cookie: `__Host-proteles_session=${sealed}` }));
  assert.equal(((await own.json()) as { authenticated: boolean }).authenticated, true);
});

test("with Secure cookies, a planted plain proteles_flow cannot finish a sign-in", async () => {
  const reasons: string[] = [];
  const { app } = makeApp({ cookieSecure: true, onError: (reason) => reasons.push(reason) });
  const login = await app.handle(req("https://app.example.com/api/auth/login"));
  const flow = cookieValue(setCookies(login), "__Host-proteles_flow")!;
  const res = await app.handle(
    req("https://app.example.com/api/auth/callback?code=x&state=y", { cookie: `proteles_flow=${flow}` }),
  );
  assert.equal(cookieValue(setCookies(res), "__Host-proteles_session"), undefined, "no session was minted");
  assert.match(reasons.at(-1) ?? "", /no __Host-proteles_flow cookie/, "the missing cookie is named as the app names it");
});

