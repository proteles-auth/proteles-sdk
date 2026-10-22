//! Tests for the Alpine AJAX-aware auth surface.
//!
//! The behaviour that matters is the difference between an Alpine AJAX caller
//! and a plain browser navigation, so nearly every case is asserted both ways —
//! and the Alpine side is asserted for *where* the answer lands, not only that
//! one came back. A 401 whose body Alpine cannot address swaps nothing, which
//! looks to the user exactly like the click doing nothing.

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

// Generated per run rather than a literal: a fixed one would be a published
// secret, and this repository refuses those on every path.
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

/** A request as Alpine AJAX would send it, or as the browser would. */
function req(
  url: string,
  opts: { alpine?: boolean; targets?: string; referer?: string; method?: string; cookie?: string } = {},
) {
  const headers: Record<string, string> = {};
  if (opts.alpine) headers["x-alpine-request"] = "true";
  if (opts.targets) headers["x-alpine-target"] = opts.targets;
  if (opts.referer) headers["referer"] = opts.referer;
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

test("login is the app's sign-in start address: ?iss= starts a sign-in at the configured issuer, whatever it names", async () => {
  // Registered as the app's `initiate_login_uri`, so Proteles sends an invitee
  // here with `iss` (OpenID Connect Core 1.0 §4): a full page load.
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

test("login stays a real redirect even for an Alpine caller", async () => {
  // The deliberate difference from @proteles/htmx. There is no response header
  // that makes Alpine navigate — its own reference says `fetch` follows every
  // redirect transparently — so there is nothing to rewrite a 302 *to*. Leaving
  // it a redirect is what keeps the browser-navigation case correct, and the
  // README's one markup rule (no `x-target` on the sign-in control) is what
  // keeps the Alpine case from arising.
  const cfg = config();

  const viaAlpine = await protelesAuthHandler(
    req("https://app.example.com/api/auth/login", { alpine: true }),
    cfg,
  );
  assert.equal(viaAlpine.status, 302);
  assert.ok(viaAlpine.headers.get("location")?.startsWith("https://auth.example.com/oauth/authorize"));
  assert.match(viaAlpine.headers.get("set-cookie") ?? "", /proteles_flow=/, "flow cookie still set");

  const viaBrowser = await protelesAuthHandler(req("https://app.example.com/api/auth/login"), cfg);
  assert.equal(viaBrowser.status, 302, "and a full page load is unchanged");

  // Same destination for both — only `state` and `nonce` differ, being fresh
  // per request. Compared on origin+path rather than the whole URL, because
  // asserting the query would be asserting that two random values collided.
  const dest = (r: Response) => {
    const u = new URL(r.headers.get("location")!, "https://app.example.com");
    return `${u.origin}${u.pathname}`;
  };
  assert.equal(dest(viaAlpine), dest(viaBrowser));
  assert.equal(dest(viaBrowser), "https://auth.example.com/oauth/authorize");
});

test("signup stays a real redirect too, to an authorization request asking for the sign-up page", async () => {
  const res = await protelesAuthHandler(req("https://app.example.com/api/auth/signup", { alpine: true }), config());
  assert.equal(res.status, 302);
  const to = new URL(res.headers.get("location")!);
  assert.equal(to.origin + to.pathname, "https://auth.example.com/oauth/authorize");
  assert.equal(to.searchParams.get("prompt"), "create");
  assert.match(res.headers.get("set-cookie") ?? "", /proteles_flow=/, "flow cookie set");
});

test("logout clears the session for an Alpine caller too", async () => {
  const cfg = config();
  const res = await protelesAuthHandler(
    req("https://app.example.com/api/auth/logout", {
      alpine: true,
      method: "POST",
      cookie: `proteles_session=${await signedInCookie()}`,
    }),
    cfg,
  );
  assert.match(res.headers.get("set-cookie") ?? "", /proteles_session=;|Max-Age=0/, "session cleared");
});

test("me returns JSON unchanged (it is not a redirect)", async () => {
  const cfg = config();
  const res = await protelesAuthHandler(
    req("https://app.example.com/api/auth/me", {
      alpine: true,
      cookie: `proteles_session=${await signedInCookie()}`,
    }),
    cfg,
  );
  assert.equal(res.status, 200);
  const body = (await res.json()) as { authenticated: boolean; user?: { email?: string } };
  assert.equal(body.authenticated, true);
  assert.equal(body.user?.email, "alice@example.com");
  assert.ok(!JSON.stringify(body).includes("AT"), "no token reaches the browser");
});

// --- guarding -------------------------------------------------------------

test("guardRequest answers an Alpine caller with a target-addressed 401", async () => {
  const cfg = config();
  const res = await guardRequest(
    req("https://app.example.com/dashboard", { alpine: true, targets: "profile", referer: "https://app.example.com/home?x=1" }),
    undefined,
    cfg,
  );
  assert.ok(res, "an unauthenticated request must be stopped");
  assert.equal(res.status, 401, "the status is what x-target.4xx and ajax:error key on");
  assert.equal(res.headers.get("cache-control"), "no-store");

  const body = await res.text();
  assert.match(body, /<div id="profile">/, "the body has to address the id Alpine asked for");
  // Back to the page the fragment was for: signing in ends in a navigation to
  // returnTo, and the fragment as a page is a bare <div>.
  assert.match(body, /\/api\/auth\/login\?returnTo=%2Fhome%3Fx%3D1/);
  assert.ok(!res.headers.get("location"), "a redirect here would be followed by fetch and merged");
});

test("guardRequest still redirects a browser navigation", async () => {
  // The control. If the Alpine branch were taken for everything, a plain page
  // load would render a bare fragment instead of going to the login page.
  const cfg = config();
  const res = await guardRequest(req("https://app.example.com/dashboard"), undefined, cfg);
  assert.ok(res);
  assert.ok(res.status >= 300 && res.status < 400, `expected a redirect, got ${res.status}`);
  assert.ok(res.headers.get("location"));
});

test("guardRequest lets a signed-in request through, either way", async () => {
  const cfg = config();
  const cookie = `proteles_session=${await signedInCookie()}`;
  assert.equal(
    await guardRequest(req("https://app.example.com/dashboard", { alpine: true, cookie }), undefined, cfg),
    undefined,
  );
  assert.equal(await guardRequest(req("https://app.example.com/dashboard", { cookie }), undefined, cfg), undefined);
});

test("guardRequest honours publicPaths", async () => {
  const cfg = config();
  assert.equal(
    await guardRequest(
      req("https://app.example.com/about", { alpine: true }),
      { publicPaths: ["/about"] },
      cfg,
    ),
    undefined,
  );
});

// --- requireUser ----------------------------------------------------------

test("requireUser returns the user when there is one", async () => {
  const cfg = config();
  const auth = await requireUser(
    req("https://app.example.com/profile", { alpine: true, cookie: `proteles_session=${await signedInCookie()}` }),
    undefined,
    cfg,
  );
  assert.equal(auth.response, undefined);
  assert.equal(auth.user?.email, "alice@example.com");
  assert.ok(!("accessToken" in (auth.user as object)), "the public user carries no tokens");
});

test("requireUser addresses every target the caller named", async () => {
  const cfg = config();
  const auth = await requireUser(
    req("https://app.example.com/profile", { alpine: true, targets: "profile sidebar" }),
    undefined,
    cfg,
  );
  assert.ok(auth.response);
  const body = await auth.response.text();
  assert.match(body, /<div id="profile">/);
  assert.match(body, /<div id="sidebar">/);
});

test("requireUser's copy is overridable", async () => {
  const cfg = config();
  const auth = await requireUser(
    req("https://app.example.com/profile", { alpine: true, targets: "profile" }),
    { message: "Please sign in to see this.", linkText: "Continue" },
    cfg,
  );
  const body = await auth.response!.text();
  assert.match(body, /Please sign in to see this\./);
  assert.match(body, />Continue</);
});

test("an Alpine caller signs in back to its page, and to postLoginRedirect when the page is unknown or foreign", async () => {
  const cfg = config();
  const cases: [string | undefined, string][] = [
    ["https://app.example.com/reports", "%2Freports"],
    [undefined, "%2F"],
    ["https://evil.example/reports", "%2F"],
    ["https://app.example.com.evil.example/x", "%2F"],
    ["not a url", "%2F"],
  ];
  for (const [referer, returnTo] of cases) {
    const auth = await requireUser(
      req("https://app.example.com/fragments/secret", { alpine: true, targets: "secret", referer }),
      undefined,
      cfg,
    );
    assert.match(await auth.response!.text(), new RegExp(`returnTo=${returnTo}"`), `referer=${referer}`);
  }
  // Replacing the whole document is a page load: it keeps its own URL.
  const top = await requireUser(
    req("https://app.example.com/profile", { alpine: true, targets: "_top", referer: "https://app.example.com/" }),
    undefined,
    cfg,
  );
  assert.match(await top.response!.text(), /returnTo=%2Fprofile"/);
});

test("requireUser redirects a browser navigation", async () => {
  const cfg = config();
  const auth = await requireUser(req("https://app.example.com/profile"), undefined, cfg);
  assert.equal(auth.response?.status, 307);
  assert.match(auth.response!.headers.get("location") ?? "", /\/api\/auth\/login\?returnTo=%2Fprofile/);
});

// --- session helpers ------------------------------------------------------

test("getUser returns the sanitized user and getSession the tokens", async () => {
  const cfg = config();
  const r = req("https://app.example.com/x", { cookie: `proteles_session=${await signedInCookie()}` });
  assert.equal((await getUser(r, cfg))?.sub, "user-1");
  assert.equal((await getSession(r, cfg))?.accessToken, "AT", "the server-side view keeps the tokens");
  assert.equal(await getUser(req("https://app.example.com/x"), cfg), null);
});

test("attachUser caches on a context bag and getUser reuses it", async () => {
  const cfg = config();
  const event = {
    node: { req: { headers: { cookie: `proteles_session=${await signedInCookie()}` }, url: "/x" } },
    context: {} as Record<string, unknown>,
  };
  const user = await attachUser(event as never, cfg);
  assert.equal(user?.sub, "user-1");
  assert.equal((event.context as Record<string, unknown>)[CONTEXT_USER_KEY], user);

  // Reused rather than re-derived: the cached value is returned even after the
  // cookie is gone, which is what proves it was a cache hit.
  event.node.req.headers.cookie = "";
  assert.equal((await getUser(event as never, cfg))?.sub, "user-1");
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
