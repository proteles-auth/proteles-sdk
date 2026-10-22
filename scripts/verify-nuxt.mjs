// Live integration check for @proteles/vue: drives the Nuxt/h3 server bindings
// through a full login -> callback -> me -> guard -> logout loop against a
// running oauth-server, then server-renders the published Vue components
// against the resulting session.
//
// Nuxt itself needs a newer Node than this repo's toolchain, but the bindings
// take h3-shaped events (or Web Requests) and return Responses, so this
// exercises the exact code a Nuxt app runs — including the event-to-Request
// adapter — with no mocks. It plays the browser for the AS-side login, then
// feeds the issued code back in.
//
// Env: SDK_ISSUER, SDK_CLIENT_ID, SDK_CLIENT_SECRET, SDK_USERNAME, SDK_PASSWORD,
//      SDK_APP_ORIGIN (default http://localhost:3300), SDK_SESSION_SECRET.
// Exit code is non-zero on any failed assertion.

import { randomBytes } from "node:crypto";
import assert from "node:assert/strict";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { createSSRApp, defineComponent, h } from "vue";
import { renderToString } from "@vue/server-renderer";
import { leavingPageTarget } from "./leaving-page.mjs";

import {
  CONTEXT_USER_KEY,
  getSession,
  getUser,
  guardRequest,
  protelesAuthHandler,
} from "../packages/vue/dist/server/index.js";

// Default to 127.0.0.1: Node 18's fetch prefers IPv6 ::1, which an IPv4-bound
// server refuses.
const ISSUER = process.env.SDK_ISSUER || "http://127.0.0.1:8080";
const CLIENT_ID = process.env.SDK_CLIENT_ID;
const CLIENT_SECRET = process.env.SDK_CLIENT_SECRET;
const USERNAME = process.env.SDK_USERNAME;
const PASSWORD = process.env.SDK_PASSWORD;
const APP_ORIGIN = process.env.SDK_APP_ORIGIN || "http://localhost:3300";
const SESSION_SECRET = process.env.SDK_SESSION_SECRET || randomBytes(32).toString("base64");
const REDIRECT_URI = `${APP_ORIGIN}/api/auth/callback`;

for (const [name, value] of Object.entries({
  SDK_CLIENT_ID: CLIENT_ID,
  SDK_CLIENT_SECRET: CLIENT_SECRET,
  SDK_USERNAME: USERNAME,
  SDK_PASSWORD: PASSWORD,
})) {
  if (!value) {
    console.error(`missing required env ${name}`);
    process.exit(2);
  }
}

const ok = (msg) => console.log(`  ✓ ${msg}`);

const config = {
  issuer: ISSUER,
  clientId: CLIENT_ID,
  clientSecret: CLIENT_SECRET,
  redirectUri: REDIRECT_URI,
  sessionSecret: SESSION_SECRET,
  cookieSecure: false,
  scopes: "openid profile email offline_access",
};

// --- Set-Cookie helpers (Node 18.12 lacks Headers.getSetCookie) -------------
function readSetCookies(res) {
  const h_ = res.headers;
  if (typeof h_.getSetCookie === "function") return h_.getSetCookie();
  const merged = h_.get("set-cookie");
  // Split only at a comma starting a new `name=` pair, so the comma inside an
  // `Expires=Thu, 01 Jan …` attribute is not a false boundary.
  return merged ? merged.split(/,\s*(?=[A-Za-z0-9_-]+=)/) : [];
}
function cookieValueFrom(res, name) {
  for (const c of readSetCookies(res)) {
    const m = c.match(new RegExp(`^${name}=([^;]*)`));
    if (m) return decodeURIComponent(m[1]);
  }
  return undefined;
}

// --- The "browser" for the AS-side login ------------------------------------
// node:http (not fetch) because undici's `redirect: "manual"` yields an opaque
// response with no status/Location, while node:http exposes both plus
// set-cookie as an array.
const jar = new Map();
function applyJar(setCookies) {
  for (const sc of setCookies) {
    const pair = sc.split(";")[0];
    const eq = pair.indexOf("=");
    if (eq === -1) continue;
    const name = pair.slice(0, eq).trim();
    const value = pair.slice(eq + 1).trim();
    if (/max-age=0|expires=Thu, 01 Jan 1970/i.test(sc)) jar.delete(name);
    else jar.set(name, value);
  }
}
/**
 * @param {string} urlStr
 * @param {object} [options]
 * @param {string} [options.method]
 * @param {string} [options.body] Already-encoded body; sending one implies
 *   form-encoded, which is all any call site here posts.
 */
function browser(urlStr, { method = "GET", body } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(urlStr);
    /** @type {import("node:http").OutgoingHttpHeaders} */
    const headers = {};
    const ch = [...jar.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
    if (ch) headers.cookie = ch;
    if (body) {
      headers["content-type"] = "application/x-www-form-urlencoded";
      headers["content-length"] = Buffer.byteLength(body);
    }
    const req = http.request(
      { hostname: u.hostname, port: u.port || 80, path: `${u.pathname}${u.search}`, method, headers },
      (res) => {
        let data = "";
        res.setEncoding("utf8");
        res.on("data", (c) => (data += c));
        res.on("end", () => {
          applyJar(res.headers["set-cookie"] || []);
          resolve({ status: res.statusCode, location: res.headers["location"] ?? leavingPageTarget(res.statusCode, data),
            leavingPage: leavingPageTarget(res.statusCode, data) !== undefined, body: data });
        });
      },
    );
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}

/**
 * An h3-shaped event, exactly as Nuxt/Nitro would hand it to a handler — a Node
 * request plus a `context` bag. Using this (rather than a Web Request) means the
 * adapter is exercised for real.
 *
 * @param {string} url
 * @param {object} [options]
 * @param {string} [options.method]
 * @param {string} [options.cookie] Raw `cookie` request header value; omitted
 *   entirely when absent, so the event looks anonymous.
 */
function h3Event(url, { method = "GET", cookie } = {}) {
  const parsed = new URL(url);
  return {
    node: {
      req: {
        method,
        url: `${parsed.pathname}${parsed.search}`,
        headers: { host: parsed.host, ...(cookie ? { cookie } : {}) },
      },
    },
    context: {},
  };
}

/** Renders the *published* components from dist against a live session. */
async function renderPublishedComponents(user) {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const dist = path.join(here, "..", "packages", "vue", "dist");
  const { SignedIn, SignedOut, UserButton } = await import(path.join(dist, "components.js"));
  const { PROTELES_AUTH } = await import(path.join(dist, "context.js"));
  const { createAuth } = await import(path.join(dist, "auth.js"));

  const auth = createAuth({ initialUser: user, fetch: async () => new Response("{}") });
  const App = defineComponent({
    setup() {
      return () =>
        h("div", null, [
          h(SignedIn, null, { default: () => h("span", { "data-t": "in" }, "IN") }),
          h(SignedOut, null, { default: () => h("span", { "data-t": "out" }, "OUT") }),
          h(UserButton),
        ]);
    },
  });
  const app = createSSRApp(App);
  app.provide(PROTELES_AUTH, auth);
  return (await renderToString(app)).replace(/<!--.*?-->/g, "");
}

async function main() {
  // 1. The Nuxt route handler starts the login (driven by an h3 event).
  const loginRes = await protelesAuthHandler(
    h3Event(`${APP_ORIGIN}/api/auth/login?returnTo=/dashboard`),
    config,
  );
  assert.equal(loginRes.status, 302, "the h3 handler redirects to the AS");
  const authorizeUrl = loginRes.headers.get("location");
  const flowCookie = cookieValueFrom(loginRes, "proteles_flow");
  assert.ok(authorizeUrl?.startsWith(`${ISSUER}/oauth/authorize`), "authorize URL points at the AS");
  assert.ok(flowCookie, "an encrypted flow cookie was set");
  const state = new URL(authorizeUrl).searchParams.get("state");
  const authorizePath = authorizeUrl.slice(ISSUER.length);
  ok("Nuxt /api/auth/login built a PKCE authorize URL + encrypted flow cookie (via the h3 adapter)");

  // 2. AS-side login (playing the browser).
  let res = await browser(authorizeUrl);
  assert.equal(res.status, 303, "unauthenticated authorize bounces to login");
  res = await browser(`${ISSUER}${res.location}`);
  assert.equal(res.status, 200, "AS login page renders");
  const csrf = jar.get("__Host-login_csrf");
  assert.ok(csrf, "AS issued a login CSRF cookie");

  const form = new URLSearchParams();
  form.set("username", USERNAME);
  form.set("password", PASSWORD);
  form.set("redirect", authorizePath);
  form.set("csrf", csrf);
  res = await browser(`${ISSUER}/login`, { method: "POST", body: form.toString() });
  // A completed sign-in leaves through the server's page, not a 303.
  assert.ok(res.leavingPage, `AS accepted the credentials and sent the browser on (HTTP ${res.status})`);
  ok(`authenticated ${USERNAME} at the authorization server`);

  // 3. Authorize again, now authenticated -> a code for our callback.
  res = await browser(`${ISSUER}${res.location}`);
  assert.equal(res.status, 303, "authenticated authorize issues a redirect");
  const cbParams = new URL(res.location).searchParams;
  const code = cbParams.get("code");
  assert.ok(res.location.startsWith(REDIRECT_URI), "AS redirected to the app callback");
  assert.ok(code, "the AS issued an authorization code");
  assert.equal(cbParams.get("state"), state, "state round-tripped unchanged");
  ok("authorization server issued a code to the Nuxt callback route");

  // 4. The callback handler completes the exchange.
  const cbRes = await protelesAuthHandler(
    h3Event(`${REDIRECT_URI}?code=${encodeURIComponent(code)}&state=${encodeURIComponent(state)}`, {
      cookie: `proteles_flow=${flowCookie}`,
    }),
    config,
  );
  assert.equal(cbRes.status, 303, "callback redirects after the token exchange");
  assert.equal(cbRes.headers.get("location"), "/dashboard", "callback returns to the requested path");
  const sessionCookie = cookieValueFrom(cbRes, "proteles_session");
  assert.ok(sessionCookie, "an encrypted session cookie was set");
  ok("Nuxt callback exchanged the code and set an encrypted session cookie");

  // 5. /api/auth/me returns the sanitized user, no tokens.
  const meRes = await protelesAuthHandler(
    h3Event(`${APP_ORIGIN}/api/auth/me`, { cookie: `proteles_session=${sessionCookie}` }),
    config,
  );
  const me = await meRes.json();
  assert.equal(me.authenticated, true, "me reports authenticated");
  const identity = me.user?.preferredUsername ?? me.user?.email ?? me.user?.sub;
  assert.ok(identity, "me returned a user identity");
  const meText = JSON.stringify(me);
  assert.ok(!/eyJ/.test(meText) && !meText.includes(sessionCookie), "no token/JWT leaked to the browser view");
  ok(`/api/auth/me returned the user (${identity}) and leaked no token`);

  // 6. The middleware pattern: getUser fills context, getSession exposes tokens.
  const mwEvent = h3Event(`${APP_ORIGIN}/dashboard`, { cookie: `proteles_session=${sessionCookie}` });
  mwEvent.context[CONTEXT_USER_KEY] = await getUser(mwEvent, config);
  assert.equal(mwEvent.context[CONTEXT_USER_KEY]?.sub, me.user.sub, "context.protelesUser is populated");
  assert.equal((await getUser(mwEvent, config))?.sub, me.user.sub, "a second getUser reuses the context value");
  const session = await getSession(mwEvent, config);
  assert.ok(session?.accessToken, "getSession exposes the access token server-side");
  ok("server middleware populated context.protelesUser (and getSession exposed the token)");

  // 7. guardRequest allows the authenticated request and blocks the anonymous one.
  assert.equal(
    await guardRequest(mwEvent, { publicPaths: ["/"] }, config),
    undefined,
    "an authenticated protected route passes",
  );
  const guarded = await guardRequest(h3Event(`${APP_ORIGIN}/dashboard`), { publicPaths: ["/"] }, config);
  assert.ok(guarded, "an anonymous protected route is redirected");
  assert.equal(guarded.status, 307);
  // Parsed against the app origin, because the guard sends a *relative*
  // Location on purpose — an absolute one derived from the request URL would
  // let `X-Forwarded-Host` choose where the browser goes. Parsing it bare, as
  // this did, is also the assertion that it is relative: `new URL(rel)` throws.
  const loginLocation = guarded.headers.get("location");
  assert.ok(loginLocation.startsWith("/"), `the guard must redirect relatively, got ${loginLocation}`);
  assert.equal(new URL(loginLocation, APP_ORIGIN).pathname, "/api/auth/login", "…to the login route");
  ok("guardRequest allowed the signed-in request and bounced the anonymous one");

  // 8. The published Vue components render against this live session.
  const html = await renderPublishedComponents(me.user);
  assert.match(html, /data-t="in"/, "SignedIn renders for the live session");
  assert.doesNotMatch(html, /data-t="out"/, "SignedOut is hidden");
  assert.match(html, new RegExp(`user-label">${identity}<`), "UserButton shows the live user");
  assert.ok(!html.includes(sessionCookie), "no session material rendered into the markup");
  ok(`published Vue components rendered the live session (UserButton shows "${identity}")`);

  // 9. Logout revokes and clears; the session stops working.
  const outRes = await protelesAuthHandler(
    h3Event(`${APP_ORIGIN}/api/auth/logout`, { method: "POST", cookie: `proteles_session=${sessionCookie}` }),
    config,
  );
  assert.equal(outRes.status, 303, "logout redirects");
  const cleared = readSetCookies(outRes).find((c) => c.startsWith("proteles_session"));
  assert.ok(cleared && /Max-Age=0/.test(cleared), "logout cleared the session cookie");
  const meAfter = await protelesAuthHandler(h3Event(`${APP_ORIGIN}/api/auth/me`), config);
  assert.equal((await meAfter.json()).authenticated, false, "no session remains after logout");
  ok("Nuxt logout revoked the refresh token and cleared the session");
}

main()
  .then(() => console.log("Nuxt/Vue SDK live integration: all checks passed"))
  .catch((e) => {
    console.error(`Nuxt/Vue SDK live integration FAILED: ${e.message}`);
    process.exit(1);
  });
