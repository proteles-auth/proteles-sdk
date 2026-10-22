// Live integration check for @proteles/alpine-ajax.
//
// Alpine AJAX auth is entirely a server concern — the interesting behaviour is
// what comes back — so this is fully scriptable. It stands up the example's
// backend and drives a real login over HTTP against a running oauth-server.
//
// The bug being guarded against is the same one htmx has: `fetch` follows
// redirects transparently, so a protected fragment answered with
// `302 → /api/auth/login` gets the *login page* merged into the x-target and the
// address bar never changes.
//
// The fix is NOT the same. Alpine AJAX reads no response header that would make
// the browser navigate — its reference says so outright — so where the htmx
// verifier asserts `HX-Redirect`, this one asserts a 401 whose body carries the
// id from `X-Alpine-Target`. That is what Alpine can actually put somewhere,
// because it merges bodies on error statuses too.
//
// Env: SDK_ISSUER, SDK_CLIENT_ID, SDK_CLIENT_SECRET, SDK_USERNAME, SDK_PASSWORD,
//      SDK_APP_PORT (default 3700), SDK_SESSION_SECRET.

import { randomBytes } from "node:crypto";
import assert from "node:assert/strict";
import http from "node:http";

import { sendNodeResponse } from "../packages/bff/dist/index.js";
import { leavingPageTarget } from "./leaving-page.mjs";
import {
  getUser,
  guardRequest,
  protelesAuthHandler,
  requireUser,
} from "../packages/alpine-ajax/dist/index.js";

// 127.0.0.1, not localhost: Node 18's fetch prefers IPv6 ::1, which an
// IPv4-bound authorization server refuses.
const ISSUER = process.env.SDK_ISSUER || "http://127.0.0.1:8080";
const CLIENT_ID = process.env.SDK_CLIENT_ID;
const CLIENT_SECRET = process.env.SDK_CLIENT_SECRET;
const USERNAME = process.env.SDK_USERNAME;
const PASSWORD = process.env.SDK_PASSWORD;
const APP_PORT = Number(process.env.SDK_APP_PORT || 3700);
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
 * @param {string} urlStr
 * @param {object} [options]
 * @param {string} [options.method]
 * @param {string} [options.body] Already-encoded body; sending one implies
 *   form-encoded, which is all any call site here posts.
 * @param {boolean} [options.alpine] Send the headers Alpine AJAX sends, i.e.
 *   ask for the fragment branch rather than a browser navigation.
 * @param {string} [options.targets] Verbatim `X-Alpine-Target` value: one id,
 *   or several separated by spaces. Only sent when `alpine` is set.
 */
function request(urlStr, { method = "GET", body, alpine = false, targets } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(urlStr);
    /** @type {import("node:http").OutgoingHttpHeaders} */
    const headers = {};
    const cookie = [...jar.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
    if (cookie) headers.cookie = cookie;
    // Both headers, because the package reads both: `isAlpineRequest` gates on
    // the first and `alpineTargets` parses the second. Carried over from
    // `verify-htmx.mjs` as `if (htmx) headers["hx-request"]`, which referenced
    // an identifier this module never declares — so in strict mode the very
    // first `request()` threw `ReferenceError: htmx is not defined` and the
    // script died before its first assertion. It also sent htmx's header, which
    // this package does not read, so renaming alone would have left every
    // guarded fragment answering 307 instead of 401.
    if (alpine) {
      headers["x-alpine-request"] = "true";
      if (targets) headers["x-alpine-target"] = targets;
    }
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
      // Three arguments, not two. `requireUser` here is
      // `(source, options?, input?)` — the middle slot is the sign-in
      // fragment's message and link text, which is the whole reason this
      // package exists and which htmx's equivalent has no room for. Passing
      // `config` second put it where `options` goes, so `input` was undefined,
      // `appFor` fell back to environment variables that are not set, and every
      // guarded request died inside the BFF with "missing required
      // configuration". `guardRequest` two lines up already gets this right.
      const auth = await requireUser(event, undefined, config);
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
    // 1. THE headline behaviour. A protected fragment requested by Alpine while
    //    anonymous must not be a redirect `fetch` would follow — and the body
    //    must carry the id the caller asked for, or Alpine fires `ajax:missing`
    //    and swaps nothing, which looks like the click doing nothing.
    const anonFragment = await request(`${APP_ORIGIN}/fragments/secret`, {
      alpine: true,
      targets: "secret",
    });
    assert.equal(anonFragment.status, 401, "an Alpine caller gets a real 401, not a 3xx");
    assert.equal(anonFragment.location, undefined, "and no Location for fetch to follow");
    assert.match(anonFragment.body, /<div id="secret">/, "addressed to the requested target");
    assert.match(anonFragment.body, /\/api\/auth\/login/, "…carrying a sign-in link");
    assert.doesNotMatch(anonFragment.body, /x-target/, "the sign-in link is a navigation, not AJAX");
    assert.doesNotMatch(anonFragment.body, /<form|password/i, "no login form to be merged in");
    ok("anonymous Alpine fragment → 401 addressed to #secret (not a swappable login page)");

    // 2. Two ids named, two ids answered.
    const twoTargets = await request(`${APP_ORIGIN}/fragments/secret`, {
      alpine: true,
      targets: "secret sidebar",
    });
    assert.match(twoTargets.body, /<div id="secret">/);
    assert.match(twoTargets.body, /<div id="sidebar">/);
    ok("every id in X-Alpine-Target is addressed");

    // 3. The same route as a plain navigation still gets a real redirect. The
    //    control: if the Alpine branch were taken for everything, a page load
    //    would render a bare fragment instead of going to sign in.
    const anonBrowser = await request(`${APP_ORIGIN}/fragments/secret`);
    assert.equal(anonBrowser.status, 307, "a browser navigation gets a normal redirect");
    assert.equal(new URL(anonBrowser.location, APP_ORIGIN).pathname, "/api/auth/login");
    ok("the same route → ordinary 307 for a full page load");

    // 4. guardRequest, both ways.
    const pageAlpine = await request(`${APP_ORIGIN}/dashboard`, { alpine: true, targets: "app" });
    assert.equal(pageAlpine.status, 401, "guardRequest is Alpine-aware too");
    assert.match(pageAlpine.body, /<div id="app">/);
    const pageBrowser = await request(`${APP_ORIGIN}/dashboard`);
    assert.ok(pageBrowser.status >= 300 && pageBrowser.status < 400, "a navigation is redirected");
    ok("guardRequest answers Alpine with an addressed 401 and browsers with a redirect");

    // 5. Sign in for real. The login route keeps its redirect even for an Alpine
    //    caller — there is nothing to rewrite it to, and the README's rule is
    //    that this control is never an AJAX control.
    const login = await request(`${APP_ORIGIN}/api/auth/login?returnTo=%2F`);
    assert.equal(login.status, 302, "login is an ordinary redirect");
    const authorizeUrl = login.location;
    assert.ok(authorizeUrl?.startsWith(`${ISSUER}/oauth/authorize`), "…to the authorization server");
    assert.ok(jar.has("proteles_flow"), "the flow cookie was set");
    ok("login → 302 to the authorization server, flow cookie set");

    // 6. Complete the AS-side login.
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

    // 7. The callback, a real browser navigation.
    const callback = await request(res.location);
    assert.equal(callback.status, 303, "the callback is an ordinary redirect");
    assert.equal(callback.location, "/", "…back to the app");
    assert.ok(jar.has("proteles_session"), "session cookie accepted");
    ok("callback completed the exchange and set the session");

    // 8. Now the protected fragment renders instead of being refused.
    const fragment = await request(`${APP_ORIGIN}/fragments/secret`, {
      alpine: true,
      targets: "secret",
    });
    assert.equal(fragment.status, 200);
    assert.match(fragment.body, /secret for/, "the fragment rendered");
    assert.ok(!/eyJ|accessToken/.test(fragment.body), "no token in the HTML");
    ok("signed-in Alpine fragment rendered its HTML, with no token in it");

    // 9. Logout, then the fragment is protected again — which is what proves
    //    step 8 passed because of the session rather than because the guard
    //    stopped working.
    const logout = await request(`${APP_ORIGIN}/api/auth/logout`, { method: "POST" });
    assert.ok(logout.status >= 300 && logout.status < 400, "logout redirects");
    assert.ok(!jar.has("proteles_session"), "session cookie cleared");
    const after = await request(`${APP_ORIGIN}/fragments/secret`, { alpine: true, targets: "secret" });
    assert.equal(after.status, 401, "the fragment is protected again");
    ok("logout cleared the session and the fragment is refused again");
  } finally {
    server.close();
  }
}

main()
  .then(() => console.log("alpine-ajax SDK live integration: all checks passed"))
  .catch((e) => {
    console.error(`alpine-ajax SDK live integration FAILED: ${e.message}`);
    process.exit(1);
  });
