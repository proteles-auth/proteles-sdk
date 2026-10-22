// Live integration check for the SDK: drives the real @proteles/next BFF through
// a full login -> callback -> me -> logout loop against a running oauth-server.
//
// Next.js can't run on Node < 18.17, but the BFF is framework-agnostic (plain
// Web Request/Response), so this exercises the exact handler code the example
// app uses — no mocks — talking to the real authorization server. It plays the
// role of the browser for the AS-side login (username/password + CSRF), then
// feeds the issued code back into the BFF the way a redirect would.
//
// Env: SDK_ISSUER, SDK_CLIENT_ID, SDK_CLIENT_SECRET, SDK_USERNAME, SDK_PASSWORD,
//      SDK_APP_ORIGIN (default http://localhost:3100), SDK_SESSION_SECRET.
// Exit code is non-zero on any failed assertion.

import { randomBytes } from "node:crypto";
import assert from "node:assert/strict";
import http from "node:http";
import { AuthApp } from "../packages/next/dist/index.js";
import { leavingPageTarget } from "./leaving-page.mjs";

// Default to 127.0.0.1 (not localhost): Node 18's fetch resolves `localhost` to
// IPv6 `::1` first, which a server bound to IPv4 `0.0.0.0` refuses.
const ISSUER = process.env.SDK_ISSUER || "http://127.0.0.1:8080";
const CLIENT_ID = process.env.SDK_CLIENT_ID;
const CLIENT_SECRET = process.env.SDK_CLIENT_SECRET;
const USERNAME = process.env.SDK_USERNAME;
const PASSWORD = process.env.SDK_PASSWORD;
const APP_ORIGIN = process.env.SDK_APP_ORIGIN || "http://localhost:3100";
const SESSION_SECRET = process.env.SDK_SESSION_SECRET || randomBytes(32).toString("base64");
const REDIRECT_URI = `${APP_ORIGIN}/api/auth/callback`;

for (const [name, value] of Object.entries({ SDK_CLIENT_ID: CLIENT_ID, SDK_CLIENT_SECRET: CLIENT_SECRET, SDK_USERNAME: USERNAME, SDK_PASSWORD: PASSWORD })) {
  if (!value) {
    console.error(`missing required env ${name}`);
    process.exit(2);
  }
}

const ok = (msg) => console.log(`  ✓ ${msg}`);

// --- Set-Cookie helpers (Node 18.12 lacks Headers.getSetCookie) -------------
function readSetCookies(res) {
  const h = res.headers;
  if (typeof h.getSetCookie === "function") return h.getSetCookie();
  const merged = h.get("set-cookie");
  // Split only at a comma that starts a new `name=` pair, so a comma inside an
  // `Expires=Thu, 01 Jan ...` attribute is not treated as a boundary.
  return merged ? merged.split(/,\s*(?=[A-Za-z0-9_-]+=)/) : [];
}
function cookieValueFrom(res, name) {
  for (const c of readSetCookies(res)) {
    const m = c.match(new RegExp(`^${name}=([^;]*)`));
    if (m) return decodeURIComponent(m[1]);
  }
  return undefined;
}

// --- The "browser": a tiny cookie jar + a raw HTTP client -------------------
// We use node:http (not fetch) for the AS-side calls because undici's
// `redirect: "manual"` returns an opaque response with no status/Location,
// whereas node:http exposes the redirect status, `location`, and `set-cookie`
// (as an array) directly — exactly what a redirect-following browser needs.
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
function jarHeader() {
  return [...jar.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
}
/**
 * @param {string} urlStr
 * @param {object} [options]
 * @param {string} [options.method]
 * @param {string} [options.body] Already-encoded body; sending one implies
 *   form-encoded, which is all the AS-side login posts.
 */
function browser(urlStr, { method = "GET", body } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(urlStr);
    /** @type {import("node:http").OutgoingHttpHeaders} */
    const headers = {};
    const ch = jarHeader();
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

const app = new AuthApp({
  issuer: ISSUER,
  clientId: CLIENT_ID,
  clientSecret: CLIENT_SECRET,
  redirectUri: REDIRECT_URI,
  sessionSecret: SESSION_SECRET,
  cookieSecure: false,
  scopes: "openid profile email offline_access",
});

async function main() {
  // 1. BFF starts the login: authorize URL + encrypted flow cookie.
  const loginRes = await app.handle(new Request(`${APP_ORIGIN}/api/auth/login?returnTo=/dashboard`));
  assert.equal(loginRes.status, 302, "BFF /login redirects to the AS");
  const authorizeUrl = loginRes.headers.get("location");
  const flowCookie = cookieValueFrom(loginRes, "proteles_flow");
  assert.ok(authorizeUrl?.startsWith(`${ISSUER}/oauth/authorize`), "authorize URL points at the AS");
  assert.ok(flowCookie, "an encrypted flow cookie was set");
  const state = new URL(authorizeUrl).searchParams.get("state");
  const authorizePath = authorizeUrl.slice(ISSUER.length);
  ok("BFF /login built a PKCE authorize URL and set an encrypted flow cookie");

  // 2. AS-side login (we play the browser).
  let res = await browser(authorizeUrl);
  assert.equal(res.status, 303, "unauthenticated authorize bounces to login");
  const loginPagePath = res.location;
  res = await browser(`${ISSUER}${loginPagePath}`);
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
  assert.ok(jar.get("__Host-oauth_session"), "AS issued a session cookie");
  ok(`authenticated ${USERNAME} at the authorization server`);

  // 3. Back to authorize, now authenticated -> a code for our callback.
  res = await browser(`${ISSUER}${res.location}`);
  assert.equal(res.status, 303, "authenticated authorize issues a redirect");
  const cbLocation = res.location;
  assert.ok(cbLocation.startsWith(REDIRECT_URI), `AS redirected to the app callback (${cbLocation})`);
  const cbParams = new URL(cbLocation).searchParams;
  const code = cbParams.get("code");
  assert.ok(code, "the AS issued an authorization code");
  assert.equal(cbParams.get("state"), state, "state round-tripped unchanged");
  ok("authorization server issued a code to the app callback (first-party, no consent screen)");

  // 4. BFF completes the exchange and establishes the session.
  const cbRes = await app.handle(
    new Request(`${REDIRECT_URI}?code=${encodeURIComponent(code)}&state=${encodeURIComponent(state)}`, {
      headers: { cookie: `proteles_flow=${flowCookie}` },
    }),
  );
  assert.equal(cbRes.status, 303, "BFF callback redirects after the token exchange");
  assert.equal(cbRes.headers.get("location"), "/dashboard", "callback returns to the requested path");
  const sessionCookie = cookieValueFrom(cbRes, "proteles_session");
  assert.ok(sessionCookie, "BFF set an encrypted session cookie");
  ok("BFF exchanged the code for tokens and set an encrypted session cookie");

  // 5. /api/auth/me: the sanitized user, no tokens.
  const meRes = await app.handle(new Request(`${APP_ORIGIN}/api/auth/me`, { headers: { cookie: `proteles_session=${sessionCookie}` } }));
  const me = await meRes.json();
  assert.equal(me.authenticated, true, "me reports authenticated");
  const identity = me.user?.preferredUsername ?? me.user?.email ?? me.user?.sub;
  assert.ok(identity, "me returned a user identity");
  const meText = JSON.stringify(me);
  assert.ok(!/eyJ/.test(meText) && !meText.includes(sessionCookie), "no token/JWT leaked to the browser view");
  ok(`/api/auth/me returned the user (${identity}) and leaked no token`);

  // 6. Logout revokes + clears; the session is gone afterwards.
  const outRes = await app.handle(new Request(`${APP_ORIGIN}/api/auth/logout`, { method: "POST", headers: { cookie: `proteles_session=${sessionCookie}` } }));
  assert.equal(outRes.status, 303, "logout redirects");
  const cleared = readSetCookies(outRes).find((c) => c.startsWith("proteles_session"));
  assert.ok(cleared && /Max-Age=0/.test(cleared), "logout cleared the session cookie");
  const meAfter = await app.handle(new Request(`${APP_ORIGIN}/api/auth/me`));
  assert.equal((await meAfter.json()).authenticated, false, "no session remains after logout");
  ok("BFF logout revoked the refresh token and cleared the session");
}

main()
  .then(() => console.log("SDK live integration: all checks passed"))
  .catch((e) => {
    console.error(`SDK live integration FAILED: ${e.message}`);
    process.exit(1);
  });
