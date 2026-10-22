//! Tests for the SvelteKit server bindings. They drive real `Request` objects
//! through the handlers against a mocked authorization server, so they exercise
//! the same code a SvelteKit app runs.

import { randomBytes } from "node:crypto";
import { test } from "node:test";
import assert from "node:assert/strict";

import { SessionCrypto } from "@proteles/bff";
import type { ProtelesConfigInput, SessionData } from "@proteles/bff";

import { createAuthHandle, createAuthHandlers, getSession, getUser, LOCALS_USER_KEY } from "../src/server/index.ts";

// Generated per run: the literal this replaced is entry one of the
// published register, so the fixture and the value the register exists
// to refuse were the same string.
const KEY = randomBytes(32).toString("base64");

const jsonResponse = (obj: unknown, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json" } });

/** A mocked authorization server for the token/userinfo/revoke endpoints. */
function mockAS() {
  const calls: string[] = [];
  const fetchImpl = (async (url: string) => {
    calls.push(url);
    if (url.endsWith("/oauth/token")) {
      return jsonResponse({ access_token: "AT", token_type: "Bearer", expires_in: 900, refresh_token: "RT" });
    }
    if (url.endsWith("/oauth/userinfo")) {
      return jsonResponse({ sub: "user-1", email: "alice@example.com", preferred_username: "alice" });
    }
    return new Response(null, { status: 200 });
  }) as ProtelesConfigInput["fetch"];
  return { fetchImpl, calls };
}

function config(): ProtelesConfigInput {
  return {
    issuer: "https://auth.example.com",
    clientId: "app-1",
    clientSecret: "secret",
    redirectUri: "https://app.example.com/api/auth/callback",
    sessionSecret: KEY,
    cookieSecure: false,
    fetch: mockAS().fetchImpl,
  };
}

/** A SvelteKit-shaped event. */
function event(url: string, init?: { method?: string; cookie?: string }) {
  return {
    request: new Request(url, {
      method: init?.method ?? "GET",
      headers: init?.cookie ? { cookie: init.cookie } : undefined,
    }),
    locals: {} as Record<string, unknown>,
  };
}

async function signedInCookie(): Promise<string> {
  const sc = new SessionCrypto(KEY);
  const session: SessionData = {
    accessToken: "AT",
    refreshToken: "RT",
    accessExpiresAt: Date.now() + 3_600_000,
    sub: "user-1",
    email: "alice@example.com",
    preferredUsername: "alice",
  };
  return sc.encrypt(session);
}

test("login is the app's sign-in start address: ?iss= starts a sign-in at the configured issuer, whatever it names", async () => {
  // Registered as the app's `initiate_login_uri`, so Proteles sends an invitee
  // here with `iss` (OpenID Connect Core 1.0 §4).
  const reports: string[] = [];
  const onError = (_reason: string, context: string) => { reports.push(context); };
  const { GET } = createAuthHandlers({ ...config(), onError });
  for (const iss of ["https://auth.example.com", "https://evil.example"]) {
    const res = await GET(event(`https://app.example.com/api/auth/login?iss=${encodeURIComponent(iss)}`));
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

test("createAuthHandlers exposes GET and POST that route by path segment", async () => {
  const { GET, POST } = createAuthHandlers(config());

  const login = await GET(event("https://app.example.com/api/auth/login?returnTo=/dash"));
  assert.equal(login.status, 302, "login redirects to the authorization server");
  assert.ok(login.headers.get("location")?.startsWith("https://auth.example.com/oauth/authorize"));

  const signup = await GET(event("https://app.example.com/api/auth/signup?returnTo=/dash"));
  assert.equal(signup.status, 302, "signup redirects to the authorization server too");
  assert.equal(new URL(signup.headers.get("location")!).searchParams.get("prompt"), "create");

  const me = await GET(event("https://app.example.com/api/auth/me"));
  assert.equal(((await me.json()) as { authenticated: boolean }).authenticated, false);

  // POST goes through the same router (logout is commonly a POST).
  const logout = await POST(event("https://app.example.com/api/auth/logout", { method: "POST" }));
  assert.equal(logout.status, 303);

  const unknown = await GET(event("https://app.example.com/api/auth/nope"));
  assert.equal(unknown.status, 404, "unknown actions 404");
});

// `vite build` imports every `+server.ts` (and the hooks) while analysing the
// app, with whatever environment the build machine has. Building the AuthApp at
// import failed the quickstart's build on a machine with no session secret
// (2026-09-29); the configuration belongs to the running server.
test("the handlers and hook read their configuration on first use, not at import", async () => {
  const saved = Object.entries(process.env).filter(([k]) => k.startsWith("PROTELES_"));
  for (const [k] of saved) delete process.env[k];
  try {
    const { GET } = createAuthHandlers();
    const handle = createAuthHandle(undefined, { publicPaths: ["/"] });
    await assert.rejects(
      GET({ request: new Request("https://app.example.com/api/auth/me") }),
      /missing required configuration: PROTELES_ISSUER/,
      "the first request is where a missing variable is reported",
    );
    await assert.rejects(
      handle({ event: { request: new Request("https://app.example.com/"), locals: {} }, resolve: () => new Response("page") }),
      /missing required configuration/,
    );
  } finally {
    for (const [k, v] of saved) process.env[k] = v;
  }
});

test("createAuthHandle populates locals with the user and calls resolve", async () => {
  const handle = createAuthHandle(config());
  const ev = event("https://app.example.com/dashboard", { cookie: `proteles_session=${await signedInCookie()}` });

  let resolved = false;
  const res = await handle({
    event: ev,
    resolve: async () => {
      resolved = true;
      return new Response("page");
    },
  });

  assert.ok(resolved, "the request continued to the route");
  assert.equal(await res.text(), "page");
  assert.deepEqual(ev.locals[LOCALS_USER_KEY], {
    sub: "user-1",
    email: "alice@example.com",
    preferredUsername: "alice",
  });
});

test("createAuthHandle sets locals to null when signed out, and does not guard by default", async () => {
  const handle = createAuthHandle(config());
  const ev = event("https://app.example.com/dashboard");

  const res = await handle({ event: ev, resolve: async () => new Response("page") });
  assert.equal(await res.text(), "page", "no guard unless publicPaths/protect is given");
  assert.equal(ev.locals[LOCALS_USER_KEY], null);
});

test("createAuthHandle guards routes when publicPaths is given", async () => {
  const handle = createAuthHandle(config(), { publicPaths: ["/"] });

  // A protected route while signed out -> redirect to login with returnTo.
  const res = await handle({
    event: event("https://app.example.com/dashboard/settings"),
    resolve: async () => new Response("should not render"),
  });
  assert.equal(res.status, 307);
  const loc = new URL(res.headers.get("location")!, "https://app.example.com");
  assert.equal(loc.pathname, "/api/auth/login");
  assert.equal(loc.searchParams.get("returnTo"), "/dashboard/settings");

  // A public route passes through.
  const pub = await handle({
    event: event("https://app.example.com/"),
    resolve: async () => new Response("home"),
  });
  assert.equal(await pub.text(), "home");

  // A signed-in request to a protected route passes through.
  const authed = await handle({
    event: event("https://app.example.com/dashboard", { cookie: `proteles_session=${await signedInCookie()}` }),
    resolve: async () => new Response("dash"),
  });
  assert.equal(await authed.text(), "dash");
});

test("getUser prefers locals, and falls back to the cookie when the hook is absent", async () => {
  const cfg = config();

  // With the hook installed, locals is authoritative (no extra decryption).
  const withLocals = event("https://app.example.com/x");
  withLocals.locals[LOCALS_USER_KEY] = { sub: "from-locals" };
  assert.deepEqual(await getUser(withLocals, cfg), { sub: "from-locals" });

  // Without the hook, it decrypts the cookie.
  const noHook = event("https://app.example.com/x", { cookie: `proteles_session=${await signedInCookie()}` });
  assert.equal((await getUser(noHook, cfg))?.email, "alice@example.com");

  // Signed out -> null.
  assert.equal(await getUser(event("https://app.example.com/x"), cfg), null);
});

test("getUser never exposes tokens, while getSession does (server-side only)", async () => {
  const cfg = config();
  const ev = event("https://app.example.com/x", { cookie: `proteles_session=${await signedInCookie()}` });

  const user = await getUser(ev, cfg);
  assert.ok(!JSON.stringify(user).includes("AT"), "the public user carries no access token");
  assert.ok(!JSON.stringify(user).includes("RT"), "the public user carries no refresh token");

  const session = await getSession(ev, cfg);
  assert.equal(session?.accessToken, "AT", "getSession is the escape hatch that does expose tokens");
});

test("a tampered session cookie is treated as signed out", async () => {
  const cfg = config();
  const ev = event("https://app.example.com/x", { cookie: "proteles_session=not-a-valid-token" });
  assert.equal(await getUser(ev, cfg), null);
});
