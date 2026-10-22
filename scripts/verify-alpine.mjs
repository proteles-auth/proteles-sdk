// Live integration check for @proteles/alpine.
//
// Alpine is browser-only — it can't even be imported in Node — so this script
// verifies the two halves that *are* scriptable, and the package README points at
// the browser for the rest:
//
//   1. The server side, over real HTTP. It stands up the example's exact backend
//      (a plain node:http server using @proteles/bff's toWebRequest +
//      sendNodeResponse) and drives a full login -> callback -> me -> logout loop
//      against a running oauth-server, with cookies crossing the wire. This is
//      the only verifier that exercises the Node-response path, including the two
//      Set-Cookie headers the callback must emit.
//   2. The published browser bundle: self-contained, assigns the global, and
//      registers itself with Alpine on `alpine:init`.
//
// Env: SDK_ISSUER, SDK_CLIENT_ID, SDK_CLIENT_SECRET, SDK_USERNAME, SDK_PASSWORD,
//      SDK_APP_PORT (default 3500), SDK_SESSION_SECRET.
// Exit code is non-zero on any failed assertion.

import { randomBytes } from "node:crypto";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { AuthApp, sendNodeResponse, toWebRequest } from "../packages/bff/dist/index.js";
import { leavingPageTarget } from "./leaving-page.mjs";

// Default to 127.0.0.1: Node 18's fetch prefers IPv6 ::1, which an IPv4-bound
// server refuses — the exact trap the example's .env.example warns about.
const ISSUER = process.env.SDK_ISSUER || "http://127.0.0.1:8080";
const CLIENT_ID = process.env.SDK_CLIENT_ID;
const CLIENT_SECRET = process.env.SDK_CLIENT_SECRET;
const USERNAME = process.env.SDK_USERNAME;
const PASSWORD = process.env.SDK_PASSWORD;
const APP_PORT = Number(process.env.SDK_APP_PORT || 3500);
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

// --- a shared cookie jar for both origins ----------------------------------
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
 * A raw HTTP request that records Set-Cookie headers verbatim.
 *
 * @param {string} urlStr
 * @param {object} [options]
 * @param {string} [options.method]
 * @param {string} [options.body] Already-encoded body; sending one implies
 *   form-encoded, which is all any call site here posts.
 */
function request(urlStr, { method = "GET", body } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(urlStr);
    /** @type {import("node:http").OutgoingHttpHeaders} */
    const headers = {};
    const cookie = [...jar.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
    if (cookie) headers.cookie = cookie;
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
          const setCookies = res.headers["set-cookie"] || [];
          applyJar(setCookies);
          resolve({ status: res.statusCode, location: res.headers["location"] ?? leavingPageTarget(res.statusCode, data),
            leavingPage: leavingPageTarget(res.statusCode, data) !== undefined, body: data, setCookies });
        });
      },
    );
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}

/** The example's backend, verbatim in spirit: node:http + @proteles/bff. */
function startAppServer() {
  const app = new AuthApp({
    issuer: ISSUER,
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    redirectUri: `${APP_ORIGIN}/api/auth/callback`,
    sessionSecret: SESSION_SECRET,
    cookieSecure: false,
    scopes: "openid profile email offline_access",
    onError: (reason, context) => console.log(`    (server diagnostic) ${context}: ${reason}`),
  });

  const server = http.createServer(async (req, res) => {
    if ((req.url ?? "").startsWith("/api/auth/")) {
      const response = await app.handle(toWebRequest({ node: { req } }));
      await sendNodeResponse(res, response);
      return;
    }
    res.statusCode = 200;
    res.setHeader("content-type", "text/html");
    res.end("<!doctype html><p>alpine quickstart stand-in</p>");
  });

  return new Promise((resolve) => server.listen(APP_PORT, "127.0.0.1", () => resolve(server)));
}

function checkBundle() {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const bundlePath = path.join(here, "..", "packages", "alpine", "dist", "proteles-alpine.js");
  assert.ok(fs.existsSync(bundlePath), "the browser bundle is built");
  const source = fs.readFileSync(bundlePath, "utf8");

  assert.doesNotMatch(source, /(^|\n)\s*import\s+[^(]/, "bundle has no top-level imports");
  assert.doesNotMatch(source, /(^|\n)\s*export\s/, "bundle has no export statements");

  // Evaluate it against a fake window/document, as a CDN <script> would.
  const listeners = {};
  const plugins = [];
  const win = { Alpine: { plugin: (p) => plugins.push(p) } };
  const doc = { addEventListener: (ev, cb) => ((listeners[ev] ??= []).push(cb)) };
  new Function("window", "document", "globalThis", source)(win, doc, win);

  assert.equal(typeof win.protelesAuth, "function", "bundle assigns window.protelesAuth");
  (listeners["alpine:init"] ?? []).forEach((cb) => cb());
  assert.equal(plugins.length, 1, "bundle registers itself with Alpine on alpine:init");
  const store = plugins[0].store;
  assert.equal(store.isAuthenticated, false, "a fresh store starts signed out");
  assert.equal(store.basePath, "/api/auth", "and points at the default BFF path");
  return (fs.statSync(bundlePath).size / 1024).toFixed(1);
}

async function main() {
  // --- 1. the published browser bundle -----------------------------------
  const kb = checkBundle();
  ok(`published browser bundle is self-contained, self-registering, and ${kb}kb`);

  // --- 2. the server side, over real HTTP --------------------------------
  const server = await startAppServer();
  try {
    let res = await request(`${APP_ORIGIN}/api/auth/login?returnTo=%2F`);
    assert.equal(res.status, 302, "the Node BFF starts the login");
    assert.ok(jar.has("proteles_flow"), "flow cookie crossed the wire");
    const authorizeUrl = res.location;
    assert.ok(authorizeUrl?.startsWith(`${ISSUER}/oauth/authorize`), "redirects to the AS");
    const authorizePath = authorizeUrl.slice(ISSUER.length);
    ok("Node BFF (toWebRequest + sendNodeResponse) issued the PKCE redirect and flow cookie");

    res = await request(authorizeUrl);
    assert.equal(res.status, 303, "unauthenticated authorize bounces to login");
    res = await request(`${ISSUER}${res.location}`);
    assert.equal(res.status, 200, "AS login page renders");
    const csrf = jar.get("__Host-login_csrf");
    assert.ok(csrf, "AS issued a login CSRF cookie");

    const form = new URLSearchParams();
    form.set("username", USERNAME);
    form.set("password", PASSWORD);
    form.set("redirect", authorizePath);
    form.set("csrf", csrf);
    res = await request(`${ISSUER}/login`, { method: "POST", body: form.toString() });
    // A completed sign-in leaves through the server's page, not a 303.
    assert.ok(res.leavingPage, `AS accepted the credentials and sent the browser on (HTTP ${res.status})`);
    ok(`authenticated ${USERNAME} at the authorization server`);

    res = await request(`${ISSUER}${res.location}`);
    assert.equal(res.status, 303, "authorize issues a code");
    const callbackUrl = res.location;
    assert.ok(callbackUrl.startsWith(`${APP_ORIGIN}/api/auth/callback`), "…to the app callback");

    res = await request(callbackUrl);
    assert.equal(res.status, 303, "callback completed the exchange");
    assert.equal(res.location, "/", "and returned to the app");
    // The callback must set the session AND clear the flow cookie — as two
    // separate Set-Cookie headers, which is what sendNodeResponse exists for.
    assert.equal(res.setCookies.length, 2, `expected 2 Set-Cookie headers, got ${res.setCookies.length}`);
    assert.ok(res.setCookies.some((c) => c.startsWith("proteles_session=")), "session cookie set");
    assert.ok(
      res.setCookies.some((c) => c.startsWith("proteles_flow=") && /Max-Age=0/.test(c)),
      "flow cookie cleared",
    );
    assert.ok(jar.has("proteles_session"), "session cookie accepted by the jar");
    assert.ok(!jar.has("proteles_flow"), "flow cookie removed by the jar");
    ok("callback set the session and cleared the flow cookie as two separate headers");

    res = await request(`${APP_ORIGIN}/api/auth/me`);
    const me = JSON.parse(res.body);
    assert.equal(me.authenticated, true, "me reports authenticated");
    const identity = me.user?.preferredUsername ?? me.user?.email ?? me.user?.sub;
    assert.ok(identity, "me returned a user identity");
    assert.ok(!/eyJ|accessToken|refreshToken/.test(res.body), "no token leaked to the browser view");
    ok(`/api/auth/me returned the user (${identity}) over real HTTP and leaked no token`);

    res = await request(`${APP_ORIGIN}/api/auth/logout`, { method: "POST" });
    assert.equal(res.status, 303, "logout redirects");
    assert.ok(!jar.has("proteles_session"), "session cookie cleared");
    res = await request(`${APP_ORIGIN}/api/auth/me`);
    assert.equal(JSON.parse(res.body).authenticated, false, "no session remains after logout");
    ok("logout revoked the refresh token and cleared the session");
  } finally {
    server.close();
  }
}

main()
  .then(() => console.log("Alpine SDK live integration: all checks passed"))
  .catch((e) => {
    console.error(`Alpine SDK live integration FAILED: ${e.message}`);
    process.exit(1);
  });
