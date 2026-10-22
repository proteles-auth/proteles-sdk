//! Tests for the Fastify plugin.
//!
//! Fastify owns its reply object, so the cases that matter are the ones where
//! that ownership changes the answer: cookies going through `reply.header`
//! one at a time, routes registered rather than intercepted, and the session
//! hook skipping the auth paths it would otherwise resolve twice.

import { randomBytes } from "node:crypto";
import { test } from "node:test";
import assert from "node:assert/strict";

import Fastify from "fastify";

import { SessionCrypto, SessionUnavailableError as CoreSessionUnavailableError } from "@proteles/bff";
import type { ProtelesConfigInput, SessionData } from "@proteles/bff";

import * as fastifyPackage from "../src/index.ts";
import { protelesPlugin, requireAuth, sendReply, sessionOf, userOf } from "../src/index.ts";
import type { FastifyReplyLike, FastifyRequestLike } from "../src/index.ts";

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
    onError: false,
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

/** A reply that records what Fastify would have been told, including every
 *  `set-cookie` separately — which is the point of several of these tests. */
function fakeReply() {
  const cookies: string[] = [];
  const headers: Record<string, string> = {};
  const reply = {
    status: 200,
    payload: undefined as unknown,
    cookies,
    headers,
    code(status: number) {
      reply.status = status;
      return reply;
    },
    header(name: string, value: string) {
      if (name.toLowerCase() === "set-cookie") cookies.push(value);
      else headers[name.toLowerCase()] = value;
      return reply;
    },
    send(payload?: unknown) {
      reply.payload = payload;
      return reply;
    },
  };
  return reply as typeof reply & FastifyReplyLike;
}

function fakeReq(
  url: string,
  opts: { method?: string; cookie?: string; accept?: string; xhr?: boolean; forwardedHost?: string } = {},
): FastifyRequestLike {
  const headers: Record<string, string> = { host: "app.example.com" };
  if (opts.cookie) headers.cookie = opts.cookie;
  if (opts.accept) headers.accept = opts.accept;
  if (opts.xhr) headers["x-requested-with"] = "XMLHttpRequest";
  if (opts.forwardedHost) headers["x-forwarded-host"] = opts.forwardedHost;
  return { raw: { method: opts.method ?? "GET", url, headers }, headers };
}

/** A stand-in Fastify instance that records its registrations. A nested
 *  `register` is handed the same instance, so every route lands in one map;
 *  the tests under real Fastify below are the ones about scopes. */
function fakeFastify() {
  const routes = new Map<string, (req: FastifyRequestLike, reply: FastifyReplyLike) => unknown>();
  const parsers = new Set<string>();
  let onRequest: ((req: FastifyRequestLike, reply: FastifyReplyLike) => Promise<void> | void) | undefined;
  const fake = {
    routes,
    parsers,
    get onRequest() {
      return onRequest;
    },
    all(path: string, handler: (req: FastifyRequestLike, reply: FastifyReplyLike) => unknown) {
      routes.set(path, handler);
    },
    addHook(_name: "onRequest", hook: (req: FastifyRequestLike, reply: FastifyReplyLike) => Promise<void> | void) {
      onRequest = hook;
    },
    register(plugin: (instance: typeof fake) => Promise<void>) {
      return plugin(fake);
    },
    hasContentTypeParser(contentType: string) {
      return parsers.has(contentType);
    },
    addContentTypeParser(contentType: string) {
      parsers.add(contentType);
    },
  };
  return fake;
}

async function signedInCookie(): Promise<string> {
  return new SessionCrypto(KEY).encrypt({
    accessToken: "AT",
    accessExpiresAt: Date.now() + 1e6,
    sub: "user-1",
    email: "alice@example.com",
    preferredUsername: "alice",
  } satisfies SessionData);
}

test("the plugin registers the auth routes rather than intercepting them", async () => {
  // Writing to `reply.raw` behind Fastify's back leaves the framework believing
  // the request is still open. Real routes are how it knows it answered.
  const fastify = fakeFastify();
  await protelesPlugin(fastify, { proteles: config() });
  assert.deepEqual([...fastify.routes.keys()].sort(), ["/api/auth", "/api/auth/*"]);
});

test("each Set-Cookie is sent as its own header", async () => {
  // Fastify's `headers({...})` object cannot hold duplicate keys, so folding
  // them produces a session cookie the browser rejects — and the flow completes
  // with the user signed out and nothing in any log saying why.
  const fastify = fakeFastify();
  await protelesPlugin(fastify, { proteles: config() });
  const reply = fakeReply();
  await fastify.routes.get("/api/auth/*")!(fakeReq("/api/auth/login"), reply);
  assert.ok(reply.cookies.length >= 1, "the login flow sets at least one cookie");
  for (const c of reply.cookies) {
    assert.ok(!c.includes(", "), `cookies must not be folded together: ${c}`);
  }
});

test("sendReply carries status, headers and body across", async () => {
  const reply = fakeReply();
  const response = new Response("hello", {
    status: 418,
    headers: { "content-type": "text/plain", "set-cookie": "a=1" },
  });
  await sendReply(reply, response);
  assert.equal(reply.status, 418);
  assert.equal(reply.headers["content-type"], "text/plain");
  assert.deepEqual(reply.cookies, ["a=1"]);
  assert.equal(reply.payload, "hello");
});

test("the onRequest hook attaches the session, and skips the auth paths", async () => {
  const fastify = fakeFastify();
  await protelesPlugin(fastify, { proteles: config() });

  const req = fakeReq("/dashboard", { cookie: `proteles_session=${await signedInCookie()}` });
  await fastify.onRequest!(req, fakeReply());
  assert.equal(sessionOf(req)?.sub, "user-1");
  assert.equal(userOf(req)?.email, "alice@example.com");

  // The auth routes resolve their own session; doing it again in the hook is a
  // second decrypt per request for a value nothing reads.
  const authReq = fakeReq("/api/auth/login");
  await fastify.onRequest!(authReq, fakeReply());
  assert.equal(sessionOf(authReq), null);
});

test("requireAuth lets a signed-in request through and refuses an anonymous one", async () => {
  const guard = requireAuth(config());

  const ok = fakeReq("/dashboard", { cookie: `proteles_session=${await signedInCookie()}` });
  assert.equal(await guard(ok, fakeReply()), undefined, "a session passes with no reply");

  const reply = fakeReply();
  await guard(fakeReq("/dashboard/settings?tab=2", { accept: "text/html,*/*" }), reply);
  assert.equal(reply.status, 302);
  const location = reply.headers["location"];
  assert.ok(location.startsWith("/"), `Location must be relative, got ${location}`);
  assert.equal(new URL(location, "https://app.example.com").searchParams.get("returnTo"), "/dashboard/settings?tab=2");
});

test("a forwarded host cannot choose where a signed-out browser lands", async () => {
  const guard = requireAuth(config());
  const reply = fakeReply();
  await guard(fakeReq("/dashboard", { accept: "text/html", forwardedHost: "evil.test" }), reply);
  assert.ok(!reply.headers["location"].includes("evil.test"), reply.headers["location"]);
});

test("requireAuth answers an XHR with 401 rather than a login page", async () => {
  const guard = requireAuth(config());
  for (const opts of [{ xhr: true }, { accept: "application/json" }]) {
    const reply = fakeReply();
    await guard(fakeReq("/api/things", opts), reply);
    assert.equal(reply.status, 401, `expected 401 for ${JSON.stringify(opts)}`);
    assert.deepEqual(JSON.parse(reply.payload as string), { error: "unauthenticated" });
  }
});

test("a browser navigation is not mistaken for an XHR", async () => {
  const guard = requireAuth(config());
  const reply = fakeReply();
  await guard(
    fakeReq("/dashboard", { accept: "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8" }),
    reply,
  );
  assert.equal(reply.status, 302);
});

// ---------------------------------------------------------------------------
// A spent access token is not a signed-out user. See the same block in
// @proteles/express's tests: the guard never refreshed, so the core's busy
// handling never reached it.
// ---------------------------------------------------------------------------

/** A config whose token endpoint answers refreshes from `answer`. No `openid`,
 *  so a refresh needs no signed ID token from this stand-in. */
function refreshConfig(answer: () => Response): ProtelesConfigInput {
  return {
    ...config(),
    scopes: "profile offline_access",
    fetch: (async (url: string) => {
      if (url.endsWith("/oauth/token")) return answer();
      return new Response(null, { status: 404 });
    }) as ProtelesConfigInput["fetch"],
  };
}

const refreshed = () =>
  jsonResponse({ access_token: "new-AT", token_type: "Bearer", expires_in: 900, refresh_token: "new-RT" });

async function spentCookie(): Promise<string> {
  return new SessionCrypto(KEY).encrypt({
    accessToken: "old-AT",
    refreshToken: "old-RT",
    accessExpiresAt: Date.now() - 1,
    sub: "user-1",
  } satisfies SessionData);
}

const sessionCookies = (reply: { cookies: string[] }) => reply.cookies.filter((c) => c.startsWith("proteles_session="));

test("requireAuth sends a browser whose session only needs a refresh through /revalidate", async () => {
  const guard = requireAuth(refreshConfig(refreshed));
  const reply = fakeReply();
  await guard(fakeReq("/dashboard?tab=2", { accept: "text/html,*/*", cookie: `proteles_session=${await spentCookie()}` }), reply);
  assert.equal(reply.status, 303);
  const location = reply.headers["location"];
  assert.ok(location.startsWith("/"), `Location must be relative, got ${location}`);
  const parsed = new URL(location, "https://app.example.com");
  assert.equal(parsed.pathname, "/api/auth/revalidate", "not /login: the refresh token may still be good");
  assert.equal(parsed.searchParams.get("returnTo"), "/dashboard?tab=2");
});

test("requireAuth refreshes a JSON caller's spent session in place", async () => {
  const guard = requireAuth(refreshConfig(refreshed));
  const req = fakeReq("/api/things", { xhr: true, cookie: `proteles_session=${await spentCookie()}` });
  const reply = fakeReply();
  assert.equal(await guard(req, reply), undefined, "the refreshed caller continues to the handler");
  assert.equal(sessionOf(req)?.accessToken, "new-AT");
  const written = sessionCookies(reply);
  assert.equal(written.length, 1, "the rotated session goes out with this reply");
  const sealed = decodeURIComponent(written[0]!.split(";")[0]!.slice("proteles_session=".length));
  assert.equal((await new SessionCrypto(KEY).decrypt<SessionData>(sealed)).refreshToken, "new-RT");
});

test("requireAuth answers a JSON caller 503 while the authorization server is busy", async () => {
  const throttled = () =>
    new Response(JSON.stringify({ error: "rate_limited" }), {
      status: 429,
      headers: { "content-type": "application/json", "retry-after": "7" },
    });
  const guard = requireAuth(refreshConfig(throttled));
  const reply = fakeReply();
  await guard(fakeReq("/api/things", { xhr: true, cookie: `proteles_session=${await spentCookie()}` }), reply);
  assert.equal(reply.status, 503, "not 401: the user is still signed in");
  assert.equal(reply.headers["retry-after"], "7");
  assert.equal((JSON.parse(reply.payload as string) as { error: string }).error, "temporarily_unavailable");
  assert.deepEqual(sessionCookies(reply), [], "the cookie is left exactly as it was");
});

test("a refused refresh is still a 401 for a JSON caller, and clears the cookie", async () => {
  const invalidGrant = () => jsonResponse({ error: "invalid_grant" }, 400);
  const guard = requireAuth(refreshConfig(invalidGrant));
  const reply = fakeReply();
  await guard(fakeReq("/api/things", { xhr: true, cookie: `proteles_session=${await spentCookie()}` }), reply);
  assert.equal(reply.status, 401);
  assert.match(sessionCookies(reply)[0] ?? "", /Max-Age=0/);
});

test("two guards refreshing one session at once spend its refresh token once", async () => {
  // See the same test in @proteles/express: an AuthApp shares a token exchange
  // only among its own requests, and every requireAuth() makes one.
  const presented: string[] = [];
  const answer = () => (presented.length === 1 ? refreshed() : jsonResponse({ error: "invalid_grant" }, 400));
  const cfg = refreshConfig(answer);
  const inner = cfg.fetch!;
  cfg.fetch = (async (url: string, init?: RequestInit) => {
    if (url.endsWith("/oauth/token")) presented.push(new URLSearchParams(String(init?.body)).get("refresh_token")!);
    return inner(url, init);
  }) as ProtelesConfigInput["fetch"];

  const fastify = fakeFastify();
  await protelesPlugin(fastify, { proteles: cfg });
  const guards = [requireAuth(cfg), requireAuth(cfg)];
  const cookie = `proteles_session=${await spentCookie()}`;
  const reqs = [fakeReq("/api/a", { xhr: true, cookie }), fakeReq("/api/b", { xhr: true, cookie })];
  for (const r of reqs) await fastify.onRequest!(r, fakeReply());

  const replies = [fakeReply(), fakeReply()];
  const outcomes = await Promise.all(guards.map((g, i) => g(reqs[i]!, replies[i]!)));
  assert.deepEqual(presented, ["old-RT"], "one exchange, shared");
  assert.deepEqual(outcomes, [undefined, undefined], "both requests continue to their handlers");
  for (const reply of replies) {
    assert.doesNotMatch(sessionCookies(reply)[0] ?? "", /Max-Age=0/, "and neither clears the session");
  }
});

test("SessionUnavailableError is re-exported beside AuthApp", () => {
  assert.equal((fastifyPackage as Record<string, unknown>)["SessionUnavailableError"], CoreSessionUnavailableError);
});

// ---------------------------------------------------------------------------
// Under real Fastify.
//
// The stand-in above calls the plugin with itself, which is not what
// `app.register` does: Fastify hands an ordinary plugin a child instance, and
// a hook added there runs only for routes added there. And stock Fastify has
// no parser for the form post every SDK sign-out sends. Neither shows up
// without the framework.
// ---------------------------------------------------------------------------

const APP_HOST = { host: "app.example.com" };

test("under app.register, an app route sees the session the plugin's hook resolved", async () => {
  const app = Fastify();
  await app.register(protelesPlugin, { proteles: config() });
  app.get("/", async (req) => ({ sub: sessionOf(req as never)?.sub ?? null, email: userOf(req as never)?.email ?? null }));

  const signedIn = await app.inject({
    method: "GET",
    url: "/",
    headers: { ...APP_HOST, cookie: `proteles_session=${await signedInCookie()}` },
  });
  assert.equal(signedIn.statusCode, 200);
  assert.deepEqual(signedIn.json(), { sub: "user-1", email: "alice@example.com" });

  const anonymous = await app.inject({ method: "GET", url: "/", headers: APP_HOST });
  assert.deepEqual(anonymous.json(), { sub: null, email: null });
  await app.close();
});

test("under app.register, the sign-in and sign-up routes are both served", async () => {
  const app = Fastify();
  await app.register(protelesPlugin, { proteles: config() });
  for (const [path, prompt] of [["/api/auth/login", null], ["/api/auth/signup", "create"]] as const) {
    const res = await app.inject({ method: "GET", url: `${path}?returnTo=/dashboard`, headers: APP_HOST });
    assert.equal(res.statusCode, 302, path);
    const to = new URL(res.headers.location as string);
    assert.equal(to.origin + to.pathname, "https://auth.example.com/oauth/authorize", path);
    assert.equal(to.searchParams.get("prompt"), prompt, path);
  }
  await app.close();
});

test("under app.register, the login route is the app's sign-in start address: ?iss= starts a sign-in at the configured issuer, whatever it names", async () => {
  // Registered as the app's `initiate_login_uri`, so Proteles sends an invitee
  // here with `iss` (OpenID Connect Core 1.0 §4). Through real Fastify, so the
  // query reaches the core as the browser sent it.
  const app = Fastify();
  const reports: string[] = [];
  const onError = (_reason: string, context: string) => { reports.push(context); };
  await app.register(protelesPlugin, { proteles: { ...config(), onError } });
  for (const iss of ["https://auth.example.com", "https://evil.example"]) {
    const res = await app.inject({ method: "GET", url: `/api/auth/login?iss=${encodeURIComponent(iss)}`, headers: APP_HOST });
    assert.equal(res.statusCode, 302, iss);
    const to = new URL(res.headers.location as string);
    assert.equal(to.origin + to.pathname, "https://auth.example.com/oauth/authorize", `${iss}: the configured issuer`);
    assert.ok(to.searchParams.get("state"), iss);
    const cookies = ([] as string[]).concat((res.headers["set-cookie"] as string | string[] | undefined) ?? []);
    assert.ok(cookies.some((c) => c.startsWith("proteles_flow=")), `${iss}: a flow is started`);
    // The one thing `iss` changes: a mismatch is reported (bff's `login`), so
    // this is where the binding is seen to hand the query to the core.
    assert.deepEqual(reports, iss === "https://evil.example" ? ["login"] : [], `${iss}: what onError heard`);
  }
  await app.close();
});

test("under app.register, requireAuth passes a session and redirects a signed-out browser", async () => {
  const app = Fastify();
  await app.register(protelesPlugin, { proteles: config() });
  app.get("/dashboard", { preHandler: requireAuth(config()) as never }, async (req) => `hello ${sessionOf(req as never)?.sub}`);

  const ok = await app.inject({
    method: "GET",
    url: "/dashboard",
    headers: { ...APP_HOST, cookie: `proteles_session=${await signedInCookie()}` },
  });
  assert.equal(ok.statusCode, 200);
  assert.equal(ok.body, "hello user-1");

  const out = await app.inject({ method: "GET", url: "/dashboard", headers: { ...APP_HOST, accept: "text/html" } });
  assert.equal(out.statusCode, 302);
  assert.equal(new URL(out.headers.location as string, "https://app.example.com").pathname, "/api/auth/login");
  await app.close();
});

test("under app.register, two guards refreshing one session at once spend its refresh token once", async () => {
  // The guards refresh through the plugin's AuthApp only when its hook ran on
  // the request; with the hook fenced into the plugin's own scope, each guard
  // fell back to its own, and the second exchange met invalid_grant.
  const presented: string[] = [];
  const answer = () => (presented.length === 1 ? refreshed() : jsonResponse({ error: "invalid_grant" }, 400));
  const cfg = refreshConfig(answer);
  const inner = cfg.fetch!;
  cfg.fetch = (async (url: string, init?: RequestInit) => {
    if (url.endsWith("/oauth/token")) presented.push(new URLSearchParams(String(init?.body)).get("refresh_token")!);
    return inner(url, init);
  }) as ProtelesConfigInput["fetch"];

  const app = Fastify();
  await app.register(protelesPlugin, { proteles: cfg });
  app.get("/api/a", { preHandler: requireAuth(cfg) as never }, async () => "a");
  app.get("/api/b", { preHandler: requireAuth(cfg) as never }, async () => "b");
  const headers = { ...APP_HOST, "x-requested-with": "XMLHttpRequest", cookie: `proteles_session=${await spentCookie()}` };

  const [a, b] = await Promise.all([
    app.inject({ method: "GET", url: "/api/a", headers }),
    app.inject({ method: "GET", url: "/api/b", headers }),
  ]);
  assert.deepEqual(presented, ["old-RT"], "one exchange, shared");
  assert.deepEqual([a.statusCode, b.statusCode], [200, 200], "both requests reach their handlers");
  await app.close();
});

/** The sign-out every SDK button sends: an empty form post from this origin. */
async function signOutPost(app: ReturnType<typeof Fastify>) {
  return app.inject({
    method: "POST",
    url: "/api/auth/logout",
    headers: {
      ...APP_HOST,
      origin: "https://app.example.com",
      "content-type": "application/x-www-form-urlencoded",
      cookie: `proteles_session=${await signedInCookie()}`,
    },
    payload: "",
  });
}

test("under app.register, a form-posted sign-out is answered, not refused with 415", async () => {
  const app = Fastify();
  await app.register(protelesPlugin, { proteles: config() });
  const res = await signOutPost(app);
  assert.equal(res.statusCode, 303, res.body);
  const cleared = ([] as string[]).concat(res.headers["set-cookie"] ?? []);
  assert.ok(cleared.some((c) => /^proteles_session=;.*Max-Age=0/.test(c)), `the session is cleared: ${cleared}`);
  await app.close();
});

test("an app's own form parser is kept, whether registered before the plugin or after it", async () => {
  // What @fastify/formbody does: a parser added through a plugin that is not
  // encapsulated, so it covers the whole app.
  const formbody = Object.assign(
    async (f: ReturnType<typeof Fastify>) => {
      f.addContentTypeParser("application/x-www-form-urlencoded", { parseAs: "string" }, async (_req: unknown, body: string | Buffer) =>
        Object.fromEntries(new URLSearchParams(String(body))),
      );
    },
    { [Symbol.for("skip-override")]: true },
  );
  for (const order of ["before", "after"] as const) {
    const app = Fastify();
    if (order === "before") await app.register(formbody);
    await app.register(protelesPlugin, { proteles: config() });
    if (order === "after") await app.register(formbody);
    app.post("/form", async (req) => req.body);
    await app.ready();

    const form = await app.inject({
      method: "POST",
      url: "/form",
      headers: { ...APP_HOST, "content-type": "application/x-www-form-urlencoded" },
      payload: "a=1&b=two",
    });
    assert.deepEqual(form.json(), { a: "1", b: "two" }, `${order}: the app's parser parses the app's forms`);
    assert.equal((await signOutPost(app)).statusCode, 303, `${order}: and sign-out still works`);
    await app.close();
  }
});
