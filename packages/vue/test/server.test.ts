//! Tests for the Nuxt / h3 server bindings, including the event → Web Request
//! adapter (the one genuinely fiddly part, since h3 events aren't Requests).

import { randomBytes } from "node:crypto";
import { test } from "node:test";
import assert from "node:assert/strict";

import { SessionCrypto } from "@proteles/bff";
import type { ProtelesConfigInput, SessionData } from "@proteles/bff";

import {
  CONTEXT_USER_KEY,
  getSession,
  getUser,
  guardRequest,
  protelesAuthHandler,
  toWebRequest,
} from "../src/server/index.ts";

// Generated per run: the literal this replaced is entry one of the
// published register, so the fixture and the value the register exists
// to refuse were the same string.
const KEY = randomBytes(32).toString("base64");

const jsonResponse = (obj: unknown, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json" } });

function config(): ProtelesConfigInput {
  return {
    issuer: "https://auth.example.com",
    clientId: "app-1",
    clientSecret: "secret",
    redirectUri: "https://app.example.com/api/auth/callback",
    sessionSecret: KEY,
    cookieSecure: false,
    fetch: (async (url: string) => {
      if (url.endsWith("/oauth/token")) {
        return jsonResponse({ access_token: "AT", token_type: "Bearer", expires_in: 900, refresh_token: "RT" });
      }
      if (url.endsWith("/oauth/userinfo")) {
        return jsonResponse({ sub: "user-1", email: "alice@example.com", preferred_username: "alice" });
      }
      return new Response(null, { status: 200 });
    }) as ProtelesConfigInput["fetch"],
  };
}

/** An h3-style event backed by a Node-like request. */
function h3Event(url: string, init?: { method?: string; cookie?: string; headers?: Record<string, string> }) {
  const parsed = new URL(url);
  return {
    node: {
      req: {
        method: init?.method ?? "GET",
        url: `${parsed.pathname}${parsed.search}`,
        headers: {
          host: parsed.host,
          ...(init?.cookie ? { cookie: init.cookie } : {}),
          ...(init?.headers ?? {}),
        } as Record<string, string | string[] | undefined>,
      },
    },
    context: {} as Record<string, unknown>,
  };
}

async function signedInCookie(): Promise<string> {
  const session: SessionData = {
    accessToken: "AT",
    refreshToken: "RT",
    accessExpiresAt: Date.now() + 3_600_000,
    sub: "user-1",
    email: "alice@example.com",
    preferredUsername: "alice",
  };
  return new SessionCrypto(KEY).encrypt(session);
}

// The adapter itself (`toWebRequest`) is unit-tested in @proteles/bff, which
// owns it. Here we only assert this package re-exports it, so a Nuxt app needs
// no extra dependency.
test("toWebRequest is re-exported for Nuxt consumers", () => {
  assert.equal(typeof toWebRequest, "function");
  const req = new Request("https://app.example.com/x");
  assert.equal(toWebRequest(req), req);
});

// --- the handler ----------------------------------------------------------

test("protelesAuthHandler routes the auth actions from an h3 event", async () => {
  const cfg = config();

  const login = await protelesAuthHandler(h3Event("https://app.example.com/api/auth/login?returnTo=/dash"), cfg);
  assert.equal(login.status, 302, "login redirects to the authorization server");
  assert.ok(login.headers.get("location")?.startsWith("https://auth.example.com/oauth/authorize"));

  const signup = await protelesAuthHandler(h3Event("https://app.example.com/api/auth/signup?returnTo=/dash"), cfg);
  assert.equal(signup.status, 302, "signup redirects to the authorization server too");
  assert.equal(new URL(signup.headers.get("location")!).searchParams.get("prompt"), "create");

  const me = await protelesAuthHandler(h3Event("https://app.example.com/api/auth/me"), cfg);
  assert.equal(((await me.json()) as { authenticated: boolean }).authenticated, false);

  const logout = await protelesAuthHandler(
    h3Event("https://app.example.com/api/auth/logout", { method: "POST" }),
    cfg,
  );
  assert.equal(logout.status, 303);

  const unknown = await protelesAuthHandler(h3Event("https://app.example.com/api/auth/nope"), cfg);
  assert.equal(unknown.status, 404, "unknown actions 404");
});

test("login is the app's sign-in start address: ?iss= from an h3 event starts a sign-in at the configured issuer, whatever it names", async () => {
  // Registered as the app's `initiate_login_uri`, so Proteles sends an invitee
  // here with `iss` (OpenID Connect Core 1.0 §4). The h3 event carries the
  // query as a raw `url`, so this is the path that has to keep it.
  const reports: string[] = [];
  const onError = (_reason: string, context: string) => { reports.push(context); };
  const cfg = { ...config(), onError };
  for (const iss of ["https://auth.example.com", "https://evil.example"]) {
    const res = await protelesAuthHandler(h3Event(`https://app.example.com/api/auth/login?iss=${encodeURIComponent(iss)}`), cfg);
    assert.equal(res.status, 302, iss);
    const loc = new URL(res.headers.get("location") ?? "");
    assert.equal(loc.origin + loc.pathname, "https://auth.example.com/oauth/authorize", `${iss}: the configured issuer`);
    assert.ok(loc.searchParams.get("state"), iss);
    assert.match(res.headers.get("set-cookie") ?? "", /proteles_flow=/, `${iss}: a flow is started`);
    // The one thing `iss` changes: a mismatch is reported (bff's `login`), so
    // this is where the binding is seen to hand the query to the core.
    assert.deepEqual(reports, iss === "https://evil.example" ? ["login"] : [], `${iss}: what onError heard`);
  }
});

test("protelesAuthHandler reads the session cookie from the h3 event", async () => {
  const cfg = config();
  const me = await protelesAuthHandler(
    h3Event("https://app.example.com/api/auth/me", { cookie: `proteles_session=${await signedInCookie()}` }),
    cfg,
  );
  const body = (await me.json()) as { authenticated: boolean; user?: { email?: string } };
  assert.equal(body.authenticated, true);
  assert.equal(body.user?.email, "alice@example.com");
  assert.ok(!JSON.stringify(body).includes("AT"), "no token reaches the browser view");
});

// --- user / session / guard ----------------------------------------------

test("getUser reads the cookie, and prefers a value already on event.context", async () => {
  const cfg = config();

  const fromCookie = await getUser(
    h3Event("https://app.example.com/x", { cookie: `proteles_session=${await signedInCookie()}` }),
    cfg,
  );
  assert.equal(fromCookie?.email, "alice@example.com");
  assert.ok(!JSON.stringify(fromCookie).includes("AT"), "the public user carries no tokens");

  const event = h3Event("https://app.example.com/x");
  event.context[CONTEXT_USER_KEY] = { sub: "from-context" };
  assert.deepEqual(await getUser(event, cfg), { sub: "from-context" }, "middleware value wins");

  assert.equal(await getUser(h3Event("https://app.example.com/x"), cfg), null, "signed out -> null");
});

test("getSession is the escape hatch that does expose tokens", async () => {
  const session = await getSession(
    h3Event("https://app.example.com/x", { cookie: `proteles_session=${await signedInCookie()}` }),
    config(),
  );
  assert.equal(session?.accessToken, "AT");
});

test("guardRequest redirects protected routes and lets public ones through", async () => {
  const cfg = config();

  const guarded = await guardRequest(h3Event("https://app.example.com/dashboard"), { publicPaths: ["/"] }, cfg);
  assert.ok(guarded, "a protected route is redirected when signed out");
  assert.equal(guarded!.status, 307);
  const loc = new URL(guarded!.headers.get("location")!, "https://app.example.com");
  assert.equal(loc.pathname, "/api/auth/login");
  assert.equal(loc.searchParams.get("returnTo"), "/dashboard");

  assert.equal(
    await guardRequest(h3Event("https://app.example.com/"), { publicPaths: ["/"] }, cfg),
    undefined,
    "the home page is public",
  );
  assert.equal(
    await guardRequest(
      h3Event("https://app.example.com/dashboard", { cookie: `proteles_session=${await signedInCookie()}` }),
      { publicPaths: ["/"] },
      cfg,
    ),
    undefined,
    "a signed-in request passes",
  );
});

test("a tampered session cookie is treated as signed out", async () => {
  const out = await getUser(h3Event("https://app.example.com/x", { cookie: "proteles_session=garbage" }), config());
  assert.equal(out, null);
});

test("calls given one config object share one AuthApp, so racing requests spend a refresh token once", async () => {
  // A config object used to build a fresh AuthApp on every call, and with it a
  // fresh refresh de-duplication and key-set cache. Two requests arriving with
  // one expired access token each spent the refresh token; the server let one
  // win, and the other's invalid_grant cleared the session cookie.
  const presented: string[] = [];
  const cfg: ProtelesConfigInput = {
    ...config(),
    // No `openid`, so a refresh needs no signed ID token from this stand-in.
    scopes: "profile offline_access",
    onError: false,
    fetch: (async (url: string, init?: RequestInit) => {
      if (!url.endsWith("/oauth/token")) return new Response(null, { status: 404 });
      presented.push(new URLSearchParams(String(init?.body)).get("refresh_token")!);
      return presented.length === 1
        ? jsonResponse({ access_token: "new-AT", token_type: "Bearer", expires_in: 900, refresh_token: "new-RT" })
        : jsonResponse({ error: "invalid_grant" }, 400);
    }) as ProtelesConfigInput["fetch"],
  };
  const spent = await new SessionCrypto(KEY).encrypt({
    accessToken: "old-AT",
    refreshToken: "old-RT",
    accessExpiresAt: Date.now() - 1,
    sub: "user-1",
  } satisfies SessionData);
  const me = () =>
    protelesAuthHandler(
      new Request("https://app.example.com/api/auth/me", { headers: { cookie: `proteles_session=${spent}` } }),
      cfg,
    );

  const answers = await Promise.all([me(), me()]);
  assert.deepEqual(presented, ["old-RT"], "one exchange for the one refresh token");
  for (const res of answers) {
    assert.equal(((await res.json()) as { authenticated: boolean }).authenticated, true, "and nobody is signed out");
  }
});
