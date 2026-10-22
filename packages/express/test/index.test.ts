//! Tests for the Express bindings.
//!
//! The interesting cases are the ones where Express differs from the Web
//! `Request` world the core is written against: a router mounted somewhere
//! other than the root, a `Set-Cookie` that must survive as several headers,
//! and a caller who wants JSON rather than a login page.

import { randomBytes } from "node:crypto";
import { once } from "node:events";
import { request as httpRequest } from "node:http";
import type { IncomingHttpHeaders, Server } from "node:http";
import type { AddressInfo } from "node:net";
import { test } from "node:test";
import assert from "node:assert/strict";

import express from "express";

import { SessionCrypto, SessionUnavailableError as CoreSessionUnavailableError } from "@proteles/bff";
import type { ProtelesConfigInput, SessionData } from "@proteles/bff";

import * as expressPackage from "../src/index.ts";
import { protelesAuth, requireAuth, sessionOf, userOf } from "../src/index.ts";
import type { ExpressRequestLike, ExpressResponseLike } from "../src/index.ts";

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

/** A recording stand-in for `res`, with the header semantics Node has. */
function fakeRes(): ExpressResponseLike & { headers: Record<string, string | string[]>; body?: string; ended: boolean } {
  const headers: Record<string, string | string[]> = {};
  return {
    statusCode: 200,
    headers,
    ended: false,
    setHeader(name: string, value: string | string[]) {
      headers[name.toLowerCase()] = value;
    },
    getHeader(name: string) {
      return headers[name.toLowerCase()];
    },
    end(chunk?: string) {
      this.body = chunk;
      this.ended = true;
    },
  };
}

function fakeReq(
  url: string,
  opts: { method?: string; cookie?: string; accept?: string; xhr?: boolean; mountedAt?: string } = {},
): ExpressRequestLike {
  const headers: Record<string, string> = { host: "app.example.com" };
  if (opts.cookie) headers.cookie = opts.cookie;
  if (opts.accept) headers.accept = opts.accept;
  if (opts.xhr) headers["x-requested-with"] = "XMLHttpRequest";
  return {
    method: opts.method ?? "GET",
    // What Express does when a router is mounted: `url` is stripped of the
    // mount path, `originalUrl` is not.
    url: opts.mountedAt ? url.slice(opts.mountedAt.length) || "/" : url,
    originalUrl: url,
    headers,
  };
}

async function signedInCookie(): Promise<string> {
  const sc = new SessionCrypto(KEY);
  return sc.encrypt({
    accessToken: "AT",
    accessExpiresAt: Date.now() + 1e6,
    sub: "user-1",
    email: "alice@example.com",
    preferredUsername: "alice",
  } satisfies SessionData);
}

test("the auth routes are served, and everything else is passed on", async () => {
  const mw = protelesAuth(config());

  const authRes = fakeRes();
  let called = false;
  await mw(fakeReq("/api/auth/login"), authRes, () => {
    called = true;
  });
  assert.equal(called, false, "an auth route must not fall through to the app");
  assert.equal(authRes.statusCode, 302, "login redirects to the authorization server");

  const appRes = fakeRes();
  let passed = false;
  await mw(fakeReq("/dashboard"), appRes, () => {
    passed = true;
  });
  assert.equal(passed, true, "an app route continues");
  assert.equal(appRes.ended, false, "and nothing was written to it");
});

test("the login route is the app's sign-in start address: ?iss= starts a sign-in at the configured issuer, whatever it names", async () => {
  // Registered as the app's `initiate_login_uri`, so Proteles sends an invitee
  // here with `iss` (OpenID Connect Core 1.0 §4). The binding has to hand the
  // query through untouched, and `iss` must never choose where the browser goes.
  const reports: string[] = [];
  const onError = (_reason: string, context: string) => { reports.push(context); };
  const mw = protelesAuth({ ...config(), onError });
  for (const iss of ["https://auth.example.com", "https://evil.example"]) {
    const res = fakeRes();
    let fellThrough = false;
    await mw(fakeReq(`/api/auth/login?iss=${encodeURIComponent(iss)}`), res, () => {
      fellThrough = true;
    });
    assert.equal(fellThrough, false, iss);
    assert.equal(res.statusCode, 302, iss);
    const loc = new URL(String(res.headers["location"]));
    assert.equal(loc.origin + loc.pathname, "https://auth.example.com/oauth/authorize", `${iss}: the configured issuer`);
    assert.ok(loc.searchParams.get("state"), iss);
    const cookies = ([] as string[]).concat(res.headers["set-cookie"] ?? []);
    assert.ok(cookies.some((c) => c.startsWith("proteles_flow=")), `${iss}: a flow is started`);
    // The one thing `iss` changes: a mismatch is reported (bff's `login`), so
    // this is where the binding is seen to hand the query to the core.
    assert.deepEqual(reports, iss === "https://evil.example" ? ["login"] : [], `${iss}: what onError heard`);
  }
});

test("a mounted router still recognises its own auth paths", async () => {
  // Express rewrites `req.url` relative to the mount point. Reading that instead
  // of `originalUrl` makes `/api/auth/login` arrive as `/auth/login`, which is
  // not the base path — the auth routes fall through to the app and 404, and
  // `returnTo` is built from a path that does not exist.
  const mw = protelesAuth(config());
  const res = fakeRes();
  let fellThrough = false;
  await mw(fakeReq("/api/auth/login", { mountedAt: "/api" }), res, () => {
    fellThrough = true;
  });
  assert.equal(fellThrough, false, "the mounted router must still see its own path");
  assert.equal(res.statusCode, 302);
});

test("several Set-Cookie values survive as separate headers", async () => {
  // The auth routes set more than one cookie in a single response. Folded into
  // one comma-joined value, browsers accept only the first — so the flow
  // completes, the redirect happens, and the user lands signed out with nothing
  // in any log saying why.
  const mw = protelesAuth(config());
  const res = fakeRes();
  await mw(fakeReq("/api/auth/login"), res, () => {});
  const cookies = res.headers["set-cookie"];
  assert.ok(Array.isArray(cookies), `Set-Cookie must be an array, got ${typeof cookies}`);
});

test("the session is attached to the request, and read back", async () => {
  const mw = protelesAuth(config());
  const req = fakeReq("/dashboard", { cookie: `proteles_session=${await signedInCookie()}` });
  await mw(req, fakeRes(), () => {});
  assert.equal(sessionOf(req)?.sub, "user-1");
  assert.equal(userOf(req)?.preferredUsername, "alice");
  assert.ok(!JSON.stringify(userOf(req)).includes("AT"), "the public user carries no tokens");
});

test("requireAuth lets a signed-in request through", async () => {
  const guard = requireAuth(config());
  const req = fakeReq("/dashboard", { cookie: `proteles_session=${await signedInCookie()}` });
  const res = fakeRes();
  let allowed = false;
  await guard(req, res, () => {
    allowed = true;
  });
  assert.equal(allowed, true);
  assert.equal(res.ended, false);
});

test("requireAuth redirects a signed-out browser, relatively, with returnTo", async () => {
  const guard = requireAuth(config());
  const res = fakeRes();
  await guard(fakeReq("/dashboard/settings?tab=2", { accept: "text/html,*/*" }), res, () => {
    assert.fail("a signed-out browser must not reach the handler");
  });
  assert.equal(res.statusCode, 302);
  const location = res.headers["location"] as string;
  assert.ok(location.startsWith("/"), `Location must be relative, got ${location}`);
  const parsed = new URL(location, "https://app.example.com");
  assert.equal(parsed.pathname, "/api/auth/login");
  assert.equal(parsed.searchParams.get("returnTo"), "/dashboard/settings?tab=2");
});

test("a forwarded host cannot choose where a signed-out browser lands", async () => {
  const guard = requireAuth(config());
  const req = fakeReq("/dashboard", { accept: "text/html" });
  req.headers["x-forwarded-host"] = "evil.test";
  const res = fakeRes();
  await guard(req, res, () => assert.fail("unreachable"));
  const location = res.headers["location"] as string;
  assert.ok(!location.includes("evil.test"), `the attacker's host reached Location: ${location}`);
});

test("requireAuth answers an XHR with 401 rather than a login page", async () => {
  // A caller asking for data that is redirected to a login page receives HTML
  // where it expected JSON, and reports "the API returned garbage" rather than
  // "I am signed out".
  const guard = requireAuth(config());

  for (const opts of [{ xhr: true }, { accept: "application/json" }]) {
    const res = fakeRes();
    await guard(fakeReq("/api/things", opts), res, () => assert.fail("unreachable"));
    assert.equal(res.statusCode, 401, `expected 401 for ${JSON.stringify(opts)}`);
    assert.deepEqual(JSON.parse(res.body!), { error: "unauthenticated" });
  }
});

test("a browser navigation is not mistaken for an XHR", async () => {
  // The Accept header a browser actually sends mentions JSON further down the
  // list. Matching on "includes application/json" alone would 401 every
  // navigation, and the user would see a JSON error instead of a login page.
  const guard = requireAuth(config());
  const res = fakeRes();
  await guard(
    fakeReq("/dashboard", { accept: "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8" }),
    res,
    () => assert.fail("unreachable"),
  );
  assert.equal(res.statusCode, 302, "a navigation gets the redirect, not a 401");
});

test("a failure inside the middleware reaches next(err), not an unhandled rejection", async () => {
  // Express 4 drops the promise an async middleware returns, and Node exits on
  // an unhandled rejection: one bad request took the whole app down. Whatever
  // throws must arrive at the app's error handler instead.
  const exploding = new Proxy({} as Record<string, string>, {
    ownKeys() {
      throw new Error("boom");
    },
  });
  for (const mw of [protelesAuth(config()), requireAuth(config())]) {
    let passed: unknown;
    const req: ExpressRequestLike = { method: "GET", url: "/dashboard", headers: exploding };
    await mw(req, fakeRes(), (err?: unknown) => {
      passed = err;
    });
    assert.ok(passed instanceof Error && passed.message === "boom", `next(err) received ${String(passed)}`);
  }
});

// ---------------------------------------------------------------------------
// A spent access token is not a signed-out user.
//
// The guard read every session whose access token had expired as signed out.
// A browser went to /login and silently back through the authorization server,
// and while that server was busy the code exchange met the same 503 and ended
// in `login_failed`; a JSON caller got 401. The busy handling in the core never
// reached this guard, because nothing here ever refreshed.
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

function sessionCookies(res: { headers: Record<string, string | string[]> }): string[] {
  const v = res.headers["set-cookie"];
  const all = v === undefined ? [] : Array.isArray(v) ? v : [v];
  return all.filter((c) => c.startsWith("proteles_session="));
}

test("requireAuth sends a browser whose session only needs a refresh through /revalidate", async () => {
  const guard = requireAuth(refreshConfig(refreshed));
  const res = fakeRes();
  await guard(
    fakeReq("/dashboard?tab=2", { accept: "text/html,*/*", cookie: `proteles_session=${await spentCookie()}` }),
    res,
    () => assert.fail("a spent session must be proven before the handler runs"),
  );
  assert.equal(res.statusCode, 303);
  const location = res.headers["location"] as string;
  assert.ok(location.startsWith("/"), `Location must be relative, got ${location}`);
  const parsed = new URL(location, "https://app.example.com");
  assert.equal(parsed.pathname, "/api/auth/revalidate", "not /login: the refresh token may still be good");
  assert.equal(parsed.searchParams.get("returnTo"), "/dashboard?tab=2");
});

test("requireAuth refreshes a JSON caller's spent session in place, keeping other cookies", async () => {
  const guard = requireAuth(refreshConfig(refreshed));
  const req = fakeReq("/api/things", { xhr: true, cookie: `proteles_session=${await spentCookie()}` });
  const res = fakeRes();
  res.setHeader("set-cookie", ["other=1; Path=/"]);
  let allowed = false;
  await guard(req, res, () => {
    allowed = true;
  });
  assert.equal(allowed, true, "the refreshed caller reaches the handler");
  assert.equal(sessionOf(req)?.accessToken, "new-AT");
  const written = sessionCookies(res);
  assert.equal(written.length, 1, "the rotated session goes out with this response");
  const sealed = decodeURIComponent(written[0]!.split(";")[0]!.slice("proteles_session=".length));
  assert.equal((await new SessionCrypto(KEY).decrypt<SessionData>(sealed)).refreshToken, "new-RT");
  assert.ok((res.headers["set-cookie"] as string[]).includes("other=1; Path=/"), "a cookie set earlier is kept");
});

test("requireAuth answers a JSON caller 503 while the authorization server is busy", async () => {
  const throttled = () =>
    new Response(JSON.stringify({ error: "rate_limited" }), {
      status: 429,
      headers: { "content-type": "application/json", "retry-after": "7" },
    });
  const guard = requireAuth(refreshConfig(throttled));
  const res = fakeRes();
  await guard(fakeReq("/api/things", { xhr: true, cookie: `proteles_session=${await spentCookie()}` }), res, () =>
    assert.fail("unreachable"),
  );
  assert.equal(res.statusCode, 503, "not 401: the user is still signed in");
  assert.equal(res.headers["retry-after"], "7");
  assert.equal((JSON.parse(res.body!) as { error: string }).error, "temporarily_unavailable");
  assert.deepEqual(sessionCookies(res), [], "the cookie is left exactly as it was");
});

test("a refused refresh is still a 401 for a JSON caller, and clears the cookie", async () => {
  const invalidGrant = () => jsonResponse({ error: "invalid_grant" }, 400);
  const guard = requireAuth(refreshConfig(invalidGrant));
  const res = fakeRes();
  await guard(fakeReq("/api/things", { xhr: true, cookie: `proteles_session=${await spentCookie()}` }), res, () =>
    assert.fail("unreachable"),
  );
  assert.equal(res.statusCode, 401);
  assert.match(sessionCookies(res)[0] ?? "", /Max-Age=0/);
});

test("two guards refreshing one session at once spend its refresh token once", async () => {
  // Each `requireAuth()` has its own AuthApp, and an AuthApp shares a token
  // exchange only among its own requests. Two XHRs to two guarded routes with
  // one expired token each spent it; the server lets one win, the other got
  // invalid_grant, and its response cleared the cookie.
  const presented: string[] = [];
  const answer = () => {
    const winner = presented.length === 1;
    return winner ? refreshed() : jsonResponse({ error: "invalid_grant" }, 400);
  };
  const cfg = refreshConfig(answer);
  const inner = cfg.fetch!;
  cfg.fetch = (async (url: string, init?: RequestInit) => {
    if (url.endsWith("/oauth/token")) presented.push(new URLSearchParams(String(init?.body)).get("refresh_token")!);
    return inner(url, init);
  }) as ProtelesConfigInput["fetch"];

  const mw = protelesAuth(cfg);
  const guards = [requireAuth(cfg), requireAuth(cfg)];
  const cookie = `proteles_session=${await spentCookie()}`;
  const reqs = [fakeReq("/api/a", { xhr: true, cookie }), fakeReq("/api/b", { xhr: true, cookie })];
  for (const r of reqs) await mw(r, fakeRes(), () => {});

  const ress = [fakeRes(), fakeRes()];
  const reached = [false, false];
  await Promise.all(
    guards.map((g, i) =>
      g(reqs[i]!, ress[i]!, () => {
        reached[i] = true;
      }),
    ),
  );
  assert.deepEqual(presented, ["old-RT"], "one exchange, shared");
  assert.deepEqual(reached, [true, true], "both requests reach their handlers");
  for (const res of ress) assert.doesNotMatch(sessionCookies(res)[0] ?? "", /Max-Age=0/, "and neither clears the session");
});

test("SessionUnavailableError is re-exported beside AuthApp", () => {
  // `resolveSession` throws it, and an app that depends on this package alone
  // must be able to catch it without adding @proteles/bff.
  assert.equal((expressPackage as Record<string, unknown>)["SessionUnavailableError"], CoreSessionUnavailableError);
});

// ---------------------------------------------------------------------------
// Under real Express.
//
// Everything above runs against a recording stand-in for `req` and `res`,
// which is the same mental model as the code it tests. This goes through a
// real `express()` app on a real socket, so that what Express itself does to a
// request — no body parser, promise-returning middleware, its own `res` — is
// in the loop.
// ---------------------------------------------------------------------------

/** One request to a listening app, answered without following redirects. */
async function call(
  server: Server,
  path: string,
  opts: { method?: string; headers?: Record<string, string>; body?: string } = {},
): Promise<{ status: number; headers: IncomingHttpHeaders; body: string }> {
  const { port } = server.address() as AddressInfo;
  return new Promise((resolve, reject) => {
    const r = httpRequest(
      { host: "127.0.0.1", port, path, method: opts.method ?? "GET", headers: { host: "app.example.com", ...opts.headers } },
      (res) => {
        let body = "";
        res.setEncoding("utf8");
        res.on("data", (chunk: string) => (body += chunk));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body }));
      },
    );
    r.on("error", reject);
    r.end(opts.body);
  });
}

test("under a real express() app, the auth routes answer and requireAuth guards", async (t) => {
  const app = express();
  app.use(protelesAuth(config()) as never);
  app.get("/open", (req, res) => {
    res.json({ sub: sessionOf(req as never)?.sub ?? null });
  });
  app.get("/dashboard", requireAuth(config()) as never, (req, res) => {
    res.send(`hello ${userOf(req as never)?.preferredUsername}`);
  });
  const server = app.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => server.close());
  const cookie = `proteles_session=${await signedInCookie()}`;

  const login = await call(server, "/api/auth/login?returnTo=/dashboard");
  assert.equal(login.status, 302);
  assert.equal(new URL(login.headers.location!).origin, "https://auth.example.com", "sign-in goes to the issuer");

  const signup = await call(server, "/api/auth/signup?returnTo=/dashboard");
  assert.equal(signup.status, 302);
  assert.equal(new URL(signup.headers.location!).searchParams.get("prompt"), "create", "sign-up asks for the sign-up page");

  const me = await call(server, "/api/auth/me", { headers: { cookie } });
  assert.equal(me.status, 200);
  assert.equal((JSON.parse(me.body) as { user: { sub: string } }).user.sub, "user-1");

  // The form post every SDK sign-out button sends, to an app with no body parser.
  const logout = await call(server, "/api/auth/logout", {
    method: "POST",
    headers: { cookie, origin: "https://app.example.com", "content-type": "application/x-www-form-urlencoded" },
    body: "",
  });
  assert.equal(logout.status, 303);
  const cleared = ([] as string[]).concat(logout.headers["set-cookie"] ?? []);
  assert.ok(cleared.some((c) => /^proteles_session=;.*Max-Age=0/.test(c)), `the session is cleared: ${cleared}`);

  assert.deepEqual(JSON.parse((await call(server, "/open", { headers: { cookie } })).body), { sub: "user-1" });

  const guarded = await call(server, "/dashboard?tab=2", { headers: { accept: "text/html" } });
  assert.equal(guarded.status, 302);
  const location = new URL(guarded.headers.location!, "https://app.example.com");
  assert.equal(location.pathname, "/api/auth/login");
  assert.equal(location.searchParams.get("returnTo"), "/dashboard?tab=2");

  const allowed = await call(server, "/dashboard", { headers: { cookie } });
  assert.equal(allowed.status, 200);
  assert.equal(allowed.body, "hello alice");
});
