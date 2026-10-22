// Live integration check for @proteles/htmx.
//
// htmx auth is entirely a server concern — the interesting behaviour is which
// headers come back — so unlike the browser-only Alpine SDK, this is fully
// scriptable. It stands up the example's backend and drives a real login over
// HTTP against a running oauth-server, asserting at each step that an htmx caller
// gets `HX-Redirect` where a browser gets a 3xx.
//
// The bug being guarded against: htmx follows redirects with XHR, so a protected
// fragment answered with `302 → /api/auth/login` swaps the *login page* into the
// hx-target and the address bar never changes.
//
// Env: SDK_ISSUER, SDK_CLIENT_ID, SDK_CLIENT_SECRET, SDK_USERNAME, SDK_PASSWORD,
//      SDK_APP_PORT (default 3600), SDK_SESSION_SECRET.

import { randomBytes } from "node:crypto";
import assert from "node:assert/strict";
import http from "node:http";
import { leavingPageTarget } from "./leaving-page.mjs";

import {
  getUser,
  guardRequest,
  protelesAuthHandler,
  requireUser,
  sendNodeResponse,
} from "../packages/htmx/dist/index.js";

// 127.0.0.1, not localhost: Node 18's fetch prefers IPv6 ::1, which an
// IPv4-bound authorization server refuses.
const ISSUER = process.env.SDK_ISSUER || "http://127.0.0.1:8080";
const CLIENT_ID = process.env.SDK_CLIENT_ID;
const CLIENT_SECRET = process.env.SDK_CLIENT_SECRET;
const USERNAME = process.env.SDK_USERNAME;
const PASSWORD = process.env.SDK_PASSWORD;
const APP_PORT = Number(process.env.SDK_APP_PORT || 3600);
const APP_ORIGIN = `http://127.0.0.1:${APP_PORT}`;
const SESSION_SECRET = process.env.SDK_SESSION_SECRET || randomBytes(32).toString("base64");

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
  redirectUri: `${APP_ORIGIN}/api/auth/callback`,
  sessionSecret: SESSION_SECRET,
  cookieSecure: false,
  scopes: "openid profile email offline_access",
  onError: (reason, context) => console.log(`    (server diagnostic) ${context}: ${reason}`),
};

// --- cookie jar + raw HTTP -------------------------------------------------
const jar = new Map();
function applyJar(setCookies = []) {
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
 * A raw HTTP request against the app or the authorization server.
 *
 * @param {string} urlStr
 * @param {object} [options]
 * @param {string} [options.method]
 * @param {string} [options.body] Already-encoded body; sending one implies
 *   form-encoded, which is all any call site here posts.
 * @param {boolean} [options.htmx] Send `HX-Request`, i.e. pose as an htmx XHR
 *   rather than a browser navigation. This is the whole distinction under test.
 */
function request(urlStr, { method = "GET", body, htmx = false } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(urlStr);
    /** @type {import("node:http").OutgoingHttpHeaders} */
    const headers = {};
    const cookie = [...jar.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
    if (cookie) headers.cookie = cookie;
    if (htmx) headers["hx-request"] = "true";
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
          resolve({
            status: res.statusCode,
            location: res.headers["location"] ?? leavingPageTarget(res.statusCode, data),
            leavingPage: leavingPageTarget(res.statusCode, data) !== undefined,
            hxRedirect: res.headers["hx-redirect"],
            body: data,
            setCookies: res.headers["set-cookie"] || [],
          });
        });
      },
    );
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}

/** The example's backend, in the parts that matter. */
function startAppServer() {
  const server = http.createServer(async (req, res) => {
    const event = { node: { req } };
    const url = new URL(req.url ?? "/", APP_ORIGIN);

    if (url.pathname.startsWith("/api/auth/")) {
      return sendNodeResponse(res, await protelesAuthHandler(event, config));
    }
    if (url.pathname === "/dashboard") {
      const redirect = await guardRequest(event, { publicPaths: ["/"] }, config);
      if (redirect) return sendNodeResponse(res, redirect);
      const user = await getUser(event, config);
      res.statusCode = 200;
      res.setHeader("content-type", "text/html");
      return res.end(`<h1>Dashboard</h1><p>${user?.email ?? user?.sub}</p>`);
    }
    if (url.pathname === "/fragments/secret") {
      const auth = await requireUser(event, config);
      if (auth.response) return sendNodeResponse(res, auth.response);
      res.statusCode = 200;
      res.setHeader("content-type", "text/html");
      return res.end(`<p>secret for ${auth.user.email}</p>`);
    }
    res.statusCode = 200;
    res.setHeader("content-type", "text/html");
    res.end("<p>home</p>");
  });
  return new Promise((resolve) => server.listen(APP_PORT, "127.0.0.1", () => resolve(server)));
}

async function main() {
  const server = await startAppServer();
  try {
    // 1. THE headline behaviour: a protected fragment requested by htmx while
    //    anonymous must NOT get a redirect XHR would follow.
    const anonFragment = await request(`${APP_ORIGIN}/fragments/secret`, { htmx: true });
    assert.equal(anonFragment.status, 200, "htmx gets 200, not a 3xx");
    assert.ok(anonFragment.hxRedirect, "…with an HX-Redirect header");
    assert.equal(new URL(anonFragment.hxRedirect, APP_ORIGIN).pathname, "/api/auth/login");
    assert.equal(anonFragment.location, undefined, "and no Location for XHR to follow");
    assert.doesNotMatch(anonFragment.body, /<form|password/i, "no login HTML that could be swapped in");
    ok("anonymous htmx fragment → HX-Redirect (not a swappable login page)");

    // 2. The same route, requested as a plain navigation, gets a real redirect.
    const anonBrowser = await request(`${APP_ORIGIN}/fragments/secret`);
    assert.equal(anonBrowser.status, 307, "a browser navigation gets a normal redirect");
    assert.equal(new URL(anonBrowser.location, APP_ORIGIN).pathname, "/api/auth/login");
    assert.equal(anonBrowser.hxRedirect, undefined);
    ok("the same route → ordinary 307 for a full page load");

    // 3. A protected page guarded by guardRequest, both ways.
    const pageHtmx = await request(`${APP_ORIGIN}/dashboard`, { htmx: true });
    assert.equal(pageHtmx.status, 200);
    assert.ok(pageHtmx.hxRedirect, "guardRequest is htmx-aware too");
    const pageBrowser = await request(`${APP_ORIGIN}/dashboard`);
    assert.equal(pageBrowser.status, 307);
    ok("guardRequest bounces htmx with HX-Redirect and browsers with 307");

    // 4. Sign in for real. The login route via htmx must also use HX-Redirect,
    //    and must still set the encrypted flow cookie.
    const login = await request(`${APP_ORIGIN}/api/auth/login?returnTo=%2F`, { htmx: true });
    assert.equal(login.status, 200, "htmx login is not a 3xx");
    const authorizeUrl = login.hxRedirect;
    assert.ok(authorizeUrl?.startsWith(`${ISSUER}/oauth/authorize`), "HX-Redirect points at the AS");
    assert.ok(jar.has("proteles_flow"), "the flow cookie survived the conversion");
    ok("htmx login → HX-Redirect to the authorization server, flow cookie intact");

    // 5. Complete the AS-side login (a real browser navigation, not htmx).
    const authorizePath = authorizeUrl.slice(ISSUER.length);
    let res = await request(authorizeUrl);
    assert.equal(res.status, 303, "unauthenticated authorize bounces to login");
    res = await request(`${ISSUER}${res.location}`);
    assert.equal(res.status, 200, "AS login page renders");
    const csrf = jar.get("__Host-login_csrf");
    assert.ok(csrf, "AS issued a CSRF cookie");

    const form = new URLSearchParams();
    form.set("username", USERNAME);
    form.set("password", PASSWORD);
    form.set("redirect", authorizePath);
    form.set("csrf", csrf);
    res = await request(`${ISSUER}/login`, { method: "POST", body: form.toString() });
    // A completed sign-in leaves through the server's page, not a 303.
    assert.ok(res.leavingPage, `credentials accepted and the browser sent on (HTTP ${res.status})`);
    res = await request(`${ISSUER}${res.location}`);
    assert.equal(res.status, 303, "authorize issued a code");
    ok(`authenticated ${USERNAME} at the authorization server`);

    // 6. The callback is a real browser navigation, so it keeps its 303.
    const callback = await request(res.location);
    assert.equal(callback.status, 303, "the callback stays an ordinary redirect");
    assert.equal(callback.location, "/", "…back to the app");
    assert.equal(callback.setCookies.length, 2, "session set and flow cleared, as two headers");
    assert.ok(jar.has("proteles_session"), "session cookie accepted");
    ok("callback completed the exchange with an ordinary redirect (it is not an htmx request)");

    // 7. Now the protected fragment renders instead of redirecting.
    const fragment = await request(`${APP_ORIGIN}/fragments/secret`, { htmx: true });
    assert.equal(fragment.status, 200);
    assert.equal(fragment.hxRedirect, undefined, "no redirect needed once signed in");
    assert.match(fragment.body, /secret for/, "the fragment rendered");
    assert.ok(!/eyJ|accessToken/.test(fragment.body), "no token in the HTML");
    ok("signed-in htmx fragment rendered its HTML, with no token in it");

    // 8. Logout via hx-post → HX-Redirect, session cleared.
    const logout = await request(`${APP_ORIGIN}/api/auth/logout`, { method: "POST", htmx: true });
    assert.equal(logout.status, 200, "hx-post logout is not a 3xx");
    assert.ok(logout.hxRedirect, "…it is an HX-Redirect");
    assert.ok(!jar.has("proteles_session"), "session cookie cleared");
    const after = await request(`${APP_ORIGIN}/fragments/secret`, { htmx: true });
    assert.ok(after.hxRedirect, "the fragment is protected again");
    ok("hx-post logout → HX-Redirect, session cleared, fragment protected again");
  } finally {
    server.close();
  }
}

main()
  .then(() => console.log("htmx SDK live integration: all checks passed"))
  .catch((e) => {
    console.error(`htmx SDK live integration FAILED: ${e.message}`);
    process.exit(1);
  });
