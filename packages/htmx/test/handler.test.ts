//! Tests for the htmx-aware auth surface. The behaviour that matters is the
//! difference between an htmx caller and a plain browser request, so nearly every
//! case is asserted both ways.

import { randomBytes } from "node:crypto";
import { test } from "node:test";
import assert from "node:assert/strict";

import { SessionCrypto } from "@proteles/bff";
import type { ProtelesConfigInput, SessionData } from "@proteles/bff";

import {
  attachUser,
  CONTEXT_USER_KEY,
  getSession,
  getUser,
  guardRequest,
  protelesAuthHandler,
  requireUser,
} from "../src/handler.ts";

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

/** A request as htmx would send it, or as the browser would. */
function req(
  url: string,
  opts: { htmx?: boolean; boosted?: boolean; current?: string; method?: string; cookie?: string } = {},
) {
  const headers: Record<string, string> = {};
  if (opts.htmx) headers["hx-request"] = "true";
  if (opts.boosted) headers["hx-boosted"] = "true";
  if (opts.current) headers["hx-current-url"] = opts.current;
  if (opts.cookie) headers["cookie"] = opts.cookie;
  return new Request(url, { method: opts.method ?? "GET", headers });
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

// --- the auth routes ------------------------------------------------------

test("login: htmx gets HX-Redirect, a browser gets a real 302 — both keep the flow cookie", async () => {
  const cfg = config();

  const viaHtmx = await protelesAuthHandler(req("https://app.example.com/api/auth/login", { htmx: true }), cfg);
  assert.equal(viaHtmx.status, 200, "htmx must not receive a 3xx it would follow with XHR");
  assert.ok(viaHtmx.headers.get("hx-redirect")?.startsWith("https://auth.example.com/oauth/authorize"));
  assert.match(viaHtmx.headers.get("set-cookie") ?? "", /proteles_flow=/, "flow cookie still set");

  const viaBrowser = await protelesAuthHandler(req("https://app.example.com/api/auth/login"), cfg);
  assert.equal(viaBrowser.status, 302, "a full page load gets an ordinary redirect");
  assert.ok(viaBrowser.headers.get("location")?.startsWith("https://auth.example.com/oauth/authorize"));
  assert.match(viaBrowser.headers.get("set-cookie") ?? "", /proteles_flow=/);
});

test("login is the app's sign-in start address: ?iss= starts a sign-in at the configured issuer, whatever it names", async () => {
  // Registered as the app's `initiate_login_uri`, so Proteles sends an invitee
  // here with `iss` (OpenID Connect Core 1.0 §4): a full page load, not htmx.
  const reports: string[] = [];
  const onError = (_reason: string, context: string) => { reports.push(context); };
  const cfg = { ...config(), onError };
  for (const iss of ["https://auth.example.com", "https://evil.example"]) {
    const res = await protelesAuthHandler(req(`https://app.example.com/api/auth/login?iss=${encodeURIComponent(iss)}`), cfg);
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

test("signup: the same as login, to an authorization request asking for the sign-up page", async () => {
  const cfg = config();

  const viaHtmx = await protelesAuthHandler(req("https://app.example.com/api/auth/signup", { htmx: true }), cfg);
  assert.equal(viaHtmx.status, 200, "htmx must not receive a 3xx it would follow with XHR");
  const to = new URL(viaHtmx.headers.get("hx-redirect") ?? "");
  assert.equal(to.origin + to.pathname, "https://auth.example.com/oauth/authorize");
  assert.equal(to.searchParams.get("prompt"), "create");
  assert.match(viaHtmx.headers.get("set-cookie") ?? "", /proteles_flow=/, "flow cookie still set");

  const viaBrowser = await protelesAuthHandler(req("https://app.example.com/api/auth/signup"), cfg);
  assert.equal(viaBrowser.status, 302, "a full page load gets an ordinary redirect");
  assert.equal(new URL(viaBrowser.headers.get("location")!).searchParams.get("prompt"), "create");
});

test("logout via hx-post gets HX-Redirect and still clears the session", async () => {
  // Logout is nearly always an hx-post; a 303 here would have htmx swap the
  // post-logout page into a fragment.
  const cfg = config();
  const res = await protelesAuthHandler(
    req("https://app.example.com/api/auth/logout", {
      htmx: true,
      method: "POST",
      cookie: `proteles_session=${await signedInCookie()}`,
    }),
    cfg,
  );
  assert.equal(res.status, 200);
  // On to the server's end-session endpoint (the default since 2026-10-09),
  // asking to come back to this app's home.
  const to = new URL(res.headers.get("hx-redirect") ?? "");
  assert.equal(to.origin + to.pathname, "https://auth.example.com/oauth/logout");
  assert.equal(to.searchParams.get("post_logout_redirect_uri"), "https://app.example.com/");
  assert.match(res.headers.get("set-cookie") ?? "", /proteles_session=;|Max-Age=0/, "session cleared");
});

test("with endSession: false, logout's HX-Redirect stays on this app", async () => {
  const res = await protelesAuthHandler(
    req("https://app.example.com/api/auth/logout", {
      htmx: true,
      method: "POST",
      cookie: `proteles_session=${await signedInCookie()}`,
    }),
    { ...config(), endSession: false },
  );
  assert.equal(res.status, 200);
  assert.equal(res.headers.get("hx-redirect"), "/");
});

test("me returns JSON unchanged for htmx (it is not a redirect)", async () => {
  const cfg = config();
  const res = await protelesAuthHandler(
    req("https://app.example.com/api/auth/me", { htmx: true, cookie: `proteles_session=${await signedInCookie()}` }),
    cfg,
  );
  assert.equal(res.status, 200);
  const body = (await res.json()) as { authenticated: boolean; user?: { email?: string } };
  assert.equal(body.authenticated, true);
  assert.equal(body.user?.email, "alice@example.com");
  assert.ok(!JSON.stringify(body).includes("AT"), "no token reaches the browser");
});

test("an unknown auth action still 404s", async () => {
  const res = await protelesAuthHandler(req("https://app.example.com/api/auth/bogus", { htmx: true }), config());
  assert.equal(res.status, 404);
});

// --- route guarding ------------------------------------------------------

test("guardRequest bounces an htmx fragment request with HX-Redirect", async () => {
  // The bug this prevents: without it, htmx would swap the *login page* into
  // whatever hx-target asked for, and the address bar would never change.
  const res = await guardRequest(
    req("https://app.example.com/dashboard", { htmx: true, current: "https://app.example.com/reports?q=1" }),
    { publicPaths: ["/"] },
    config(),
  );
  assert.ok(res, "a protected route is guarded");
  assert.equal(res!.status, 200);
  const target = new URL(res!.headers.get("hx-redirect")!, "https://app.example.com");
  assert.equal(target.pathname, "/api/auth/login");
  // The page the fragment was for, not the fragment: signing in ends in a
  // navigation to returnTo, and a fragment as a page is a bare scrap of HTML.
  assert.equal(target.searchParams.get("returnTo"), "/reports?q=1");
});

test("guardRequest returns a boosted navigation to its own URL", async () => {
  const res = await guardRequest(
    req("https://app.example.com/dashboard", { htmx: true, boosted: true, current: "https://app.example.com/" }),
    { publicPaths: ["/"] },
    config(),
  );
  const target = new URL(res!.headers.get("hx-redirect")!, "https://app.example.com");
  assert.equal(target.searchParams.get("returnTo"), "/dashboard", "a boosted link is the page");
});

test("guardRequest uses an ordinary redirect for a normal navigation", async () => {
  const res = await guardRequest(req("https://app.example.com/dashboard"), { publicPaths: ["/"] }, config());
  assert.equal(res!.status, 307);
  assert.equal(new URL(res!.headers.get("location")!, "https://app.example.com").pathname, "/api/auth/login");
});

test("guardRequest lets public paths and signed-in requests through", async () => {
  const cfg = config();
  assert.equal(await guardRequest(req("https://app.example.com/", { htmx: true }), { publicPaths: ["/"] }, cfg), undefined);
  assert.equal(
    await guardRequest(
      req("https://app.example.com/dashboard", { htmx: true, cookie: `proteles_session=${await signedInCookie()}` }),
      { publicPaths: ["/"] },
      cfg,
    ),
    undefined,
    "a signed-in fragment request proceeds",
  );
});

// --- requireUser, the per-route guard ------------------------------------

test("requireUser returns the user when signed in", async () => {
  const result = await requireUser(
    req("https://app.example.com/fragment", { htmx: true, cookie: `proteles_session=${await signedInCookie()}` }),
    config(),
  );
  assert.equal(result.response, undefined, "no redirect needed");
  assert.equal(result.user?.email, "alice@example.com");
  assert.ok(!JSON.stringify(result.user).includes("AT"), "the public user carries no tokens");
});

test("requireUser returns an HX-Redirect for an anonymous htmx request", async () => {
  const result = await requireUser(
    req("https://app.example.com/fragment", { htmx: true, current: "https://app.example.com/page?tab=2" }),
    config(),
  );
  assert.equal(result.user, undefined);
  assert.equal(result.response!.status, 200);
  const target = new URL(result.response!.headers.get("hx-redirect")!, "https://app.example.com");
  assert.equal(target.pathname, "/api/auth/login");
  assert.equal(target.searchParams.get("returnTo"), "/page?tab=2", "returns to the page, path and query");
});

test("requireUser returns to postLoginRedirect when the current page is unknown or foreign", async () => {
  // HX-Current-URL is a request header. Only its path is ever used, and only
  // from this app's configured origin.
  for (const current of [undefined, "https://evil.example/page", "not a url", "https://app.example.com.evil.example/x"]) {
    const result = await requireUser(req("https://app.example.com/fragment", { htmx: true, current }), config());
    const target = new URL(result.response!.headers.get("hx-redirect")!, "https://app.example.com");
    assert.equal(target.searchParams.get("returnTo"), "/", `current=${current}`);
  }
});

test("requireUser returns a plain redirect for an anonymous full page load", async () => {
  const result = await requireUser(req("https://app.example.com/fragment?tab=2"), config());
  assert.equal(result.response!.status, 307);
  const target = new URL(result.response!.headers.get("location")!, "https://app.example.com");
  assert.equal(target.pathname, "/api/auth/login");
  assert.equal(target.searchParams.get("returnTo"), "/fragment?tab=2", "a navigation is the page itself");
});

test("a poisoned forwarded host reaches neither HX-Redirect nor Location", async () => {
  // `hx-redirect` is its own sink: htmx assigns it to `window.location`, so an
  // absolute value there sends the browser wherever the header said — and this
  // package is reached through `toWebRequest`, which builds the URL from
  // `X-Forwarded-Host` on the Node path.
  const poisoned = {
    node: {
      req: {
        method: "GET",
        url: "/fragment?tab=2",
        headers: {
          host: "app.example.com",
          "x-forwarded-host": "evil.test",
          "hx-request": "true",
        },
      },
    },
  } as never;

  const result = await requireUser(poisoned, config());
  const hx = result.response!.headers.get("hx-redirect") ?? "";
  assert.ok(!hx.includes("evil.test"), `the attacker's host reached HX-Redirect: ${hx}`);
  assert.ok(hx.startsWith("/"), `HX-Redirect must be relative: ${hx}`);
});

// --- user/session plumbing ----------------------------------------------

test("getUser reads the cookie; attachUser caches it on a context bag", async () => {
  const cfg = config();
  const cookie = `proteles_session=${await signedInCookie()}`;

  assert.equal((await getUser(new Request("https://app.example.com/x", { headers: { cookie } }), cfg))?.email, "alice@example.com");

  const event = { node: { req: { method: "GET", url: "/x", headers: { host: "app.example.com", cookie } } }, context: {} as Record<string, unknown> };
  const user = await attachUser(event, cfg);
  assert.equal(event.context[CONTEXT_USER_KEY], user, "cached on the bag");

  event.context[CONTEXT_USER_KEY] = { sub: "cached" };
  assert.deepEqual(await getUser(event, cfg), { sub: "cached" }, "the cached value wins");
});

test("getSession is the escape hatch that exposes tokens", async () => {
  const session = await getSession(
    new Request("https://app.example.com/x", { headers: { cookie: `proteles_session=${await signedInCookie()}` } }),
    config(),
  );
  assert.equal(session?.accessToken, "AT");
});

test("a tampered session cookie is treated as signed out", async () => {
  const result = await requireUser(
    req("https://app.example.com/fragment", { htmx: true, cookie: "proteles_session=garbage" }),
    config(),
  );
  assert.ok(result.response, "falls back to the login redirect");
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
