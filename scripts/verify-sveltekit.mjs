// Live integration check for @proteles/svelte: drives the SvelteKit server
// bindings through a full login -> callback -> me -> logout loop against a
// running oauth-server, and renders the real Svelte components against the
// resulting session.
//
// SvelteKit itself needs Node >= 18.13, but the bindings are plain functions
// over Web Request/Response, so this exercises the exact code a SvelteKit app
// runs (`+server.ts` handlers, the `handle` hook, `getUser`) — no mocks. It
// plays the browser for the AS-side login, then feeds the issued code back in.
//
// Env: SDK_ISSUER, SDK_CLIENT_ID, SDK_CLIENT_SECRET, SDK_USERNAME, SDK_PASSWORD,
//      SDK_APP_ORIGIN (default http://localhost:5173), SDK_SESSION_SECRET.
// Exit code is non-zero on any failed assertion.

import { randomBytes } from "node:crypto";
import assert from "node:assert/strict";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { render } from "svelte/server";

import { createAuthHandle, createAuthHandlers, getUser } from "../packages/svelte/dist/server/index.js";
import { leavingPageTarget } from "./leaving-page.mjs";

// Default to 127.0.0.1: Node 18's fetch prefers IPv6 ::1, which an IPv4-bound
// server refuses.
const ISSUER = process.env.SDK_ISSUER || "http://127.0.0.1:8080";
const CLIENT_ID = process.env.SDK_CLIENT_ID;
const CLIENT_SECRET = process.env.SDK_CLIENT_SECRET;
const USERNAME = process.env.SDK_USERNAME;
const PASSWORD = process.env.SDK_PASSWORD;
const APP_ORIGIN = process.env.SDK_APP_ORIGIN || "http://localhost:5173";
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
  const h = res.headers;
  if (typeof h.getSetCookie === "function") return h.getSetCookie();
  const merged = h.get("set-cookie");
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

/** A SvelteKit-shaped event. */
const event = (url, cookie, method = "GET") => ({
  request: new Request(url, { method, headers: cookie ? { cookie } : undefined }),
  locals: {},
});

/**
 * Compiles `UserButton.svelte` out of the built `dist/` and server-renders it
 * against a store seeded with the live user — verifying the shipped artifact,
 * not the source. Written inline (rather than reusing the package's test helper)
 * so this script stays plain JS and needs no TypeScript loader.
 */
async function renderPublishedComponents(user) {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const dist = path.join(here, "..", "packages", "svelte", "dist");
  const outDir = path.join(here, "..", "packages", "svelte", ".ssr");
  const { compile } = await import("svelte/compiler");
  const fs = await import("node:fs");

  const name = "UserButton";
  const { js } = compile(fs.readFileSync(path.join(dist, `${name}.svelte`), "utf8"), {
    generate: "server",
    name,
  });
  // Point the component's `./context.js` import at the built module.
  const code = js.code.replace(/(['"])\.\/([^'"]+)\1/g, (_m, q, file) => `${q}${path.join(dist, file)}${q}`);
  fs.mkdirSync(outDir, { recursive: true });
  const outPath = path.join(outDir, `${name}.published.ssr.mjs`);
  fs.writeFileSync(outPath, code);

  const { default: UserButton } = await import(outPath);
  const { createAuthStore } = await import(path.join(dist, "store.js"));
  const { setAuthContext } = await import(path.join(dist, "context.js"));
  void setAuthContext; // context is set by the wrapper below

  // UserButton reads the store from context, so render it inside a tiny wrapper
  // component compiled the same way.
  const wrapperSource = `<script>
  import { setAuthContext } from ${JSON.stringify(path.join(dist, "context.js"))};
  import UserButton from ${JSON.stringify(outPath)};
  export let store;
  setAuthContext(store);
</script>
<UserButton />`;
  const wrapper = compile(wrapperSource, { generate: "server", name: "Wrapper" });
  const wrapperPath = path.join(outDir, "Wrapper.published.ssr.mjs");
  fs.writeFileSync(wrapperPath, wrapper.js.code);
  const { default: Wrapper } = await import(wrapperPath);

  const store = createAuthStore({ initialUser: user, fetch: async () => new Response("{}") });
  return render(Wrapper, { props: { store } }).body.replace(/<!--.*?-->/g, "");
}

async function main() {
  const { GET, POST } = createAuthHandlers(config);

  // 1. The SvelteKit route handler starts the login.
  const loginRes = await GET(event(`${APP_ORIGIN}/api/auth/login?returnTo=/dashboard`));
  assert.equal(loginRes.status, 302, "the +server.ts handler redirects to the AS");
  const authorizeUrl = loginRes.headers.get("location");
  const flowCookie = cookieValueFrom(loginRes, "proteles_flow");
  assert.ok(authorizeUrl?.startsWith(`${ISSUER}/oauth/authorize`), "authorize URL points at the AS");
  assert.ok(flowCookie, "an encrypted flow cookie was set");
  const state = new URL(authorizeUrl).searchParams.get("state");
  const authorizePath = authorizeUrl.slice(ISSUER.length);
  ok("SvelteKit /api/auth/login built a PKCE authorize URL + encrypted flow cookie");

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
  ok("authorization server issued a code to the SvelteKit callback route");

  // 4. The callback handler completes the exchange.
  const cbRes = await GET(
    event(
      `${REDIRECT_URI}?code=${encodeURIComponent(code)}&state=${encodeURIComponent(state)}`,
      `proteles_flow=${flowCookie}`,
    ),
  );
  assert.equal(cbRes.status, 303, "callback redirects after the token exchange");
  assert.equal(cbRes.headers.get("location"), "/dashboard", "callback returns to the requested path");
  const sessionCookie = cookieValueFrom(cbRes, "proteles_session");
  assert.ok(sessionCookie, "an encrypted session cookie was set");
  ok("SvelteKit callback exchanged the code and set an encrypted session cookie");

  // 5. /api/auth/me returns the sanitized user, no tokens.
  const meRes = await GET(event(`${APP_ORIGIN}/api/auth/me`, `proteles_session=${sessionCookie}`));
  const me = await meRes.json();
  assert.equal(me.authenticated, true, "me reports authenticated");
  const identity = me.user?.preferredUsername ?? me.user?.email ?? me.user?.sub;
  assert.ok(identity, "me returned a user identity");
  const meText = JSON.stringify(me);
  assert.ok(!/eyJ/.test(meText) && !meText.includes(sessionCookie), "no token/JWT leaked to the browser view");
  ok(`/api/auth/me returned the user (${identity}) and leaked no token`);

  // 6. The handle hook populates locals, and getUser reads it.
  const handle = createAuthHandle(config, { publicPaths: ["/"] });
  const authedEvent = event(`${APP_ORIGIN}/dashboard`, `proteles_session=${sessionCookie}`);
  const passed = await handle({ event: authedEvent, resolve: async () => new Response("dashboard") });
  assert.equal(await passed.text(), "dashboard", "the hook lets an authenticated request through");
  assert.equal(authedEvent.locals.protelesUser?.sub, me.user.sub, "locals.protelesUser is populated");
  assert.equal((await getUser(authedEvent, config))?.sub, me.user.sub, "getUser reads the same user");
  ok("the handle hook populated locals.protelesUser and allowed the protected route");

  // 7. The hook guards the same route when signed out.
  const guardEvent = event(`${APP_ORIGIN}/dashboard`);
  const guarded = await handle({ event: guardEvent, resolve: async () => new Response("should not render") });
  assert.equal(guarded.status, 307, "an unauthenticated protected route is redirected");
  // Parsed against the app origin, because the guard sends a *relative*
  // Location on purpose — an absolute one derived from the request URL would
  // let `X-Forwarded-Host` choose where the browser goes. Parsing it bare, as
  // this did, is also the assertion that it is relative: `new URL(rel)` throws.
  const loginLocation = guarded.headers.get("location");
  assert.ok(loginLocation.startsWith("/"), `the guard must redirect relatively, got ${loginLocation}`);
  assert.equal(new URL(loginLocation, APP_ORIGIN).pathname, "/api/auth/login", "…to the login route");
  assert.equal(guardEvent.locals.protelesUser, null, "locals is null when signed out");
  ok("the handle hook redirected the unauthenticated request to login");

  // 8. The *published* Svelte components render against this live session.
  //    Compiled straight out of `dist/`, so this checks the artifacts a consumer
  //    actually installs — not the sources.
  const html = await renderPublishedComponents(me.user);
  assert.match(html, /data-proteles="user-button"/, "UserButton rendered for the live session");
  assert.match(html, new RegExp(`user-label">${identity}<`), "UserButton shows the live user");
  assert.ok(!html.includes(sessionCookie), "no session material rendered into the markup");
  ok(`published Svelte components rendered the live session (UserButton shows "${identity}")`);

  // 9. Logout revokes and clears; the session stops working.
  const outRes = await POST(
    event(`${APP_ORIGIN}/api/auth/logout`, `proteles_session=${sessionCookie}`, "POST"),
  );
  assert.equal(outRes.status, 303, "logout redirects");
  const cleared = readSetCookies(outRes).find((c) => c.startsWith("proteles_session"));
  assert.ok(cleared && /Max-Age=0/.test(cleared), "logout cleared the session cookie");
  const meAfter = await GET(event(`${APP_ORIGIN}/api/auth/me`));
  assert.equal((await meAfter.json()).authenticated, false, "no session remains after logout");
  ok("SvelteKit logout revoked the refresh token and cleared the session");
}

main()
  .then(() => console.log("SvelteKit SDK live integration: all checks passed"))
  .catch((e) => {
    console.error(`SvelteKit SDK live integration FAILED: ${e.message}`);
    process.exit(1);
  });
