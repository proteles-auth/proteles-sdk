//! Tests for the Next.js bindings. The BFF behavior itself is covered in
//! `@proteles/bff`; what matters here is that this package's wrappers are wired
//! correctly and that its public surface stays intact for consumers (the
//! quickstart example and `scripts/verify-live.mjs` both import from here).

import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";

import { SessionUnavailableError as CoreSessionUnavailableError } from "@proteles/bff";
import type { ProtelesConfigInput } from "@proteles/bff";

import {
  AuthApp,
  authMiddleware,
  createAuthHandlers,
  createAuthMiddleware,
  matchesPath,
  safeReturnTo,
  cookieNames,
  SessionCrypto,
} from "../src/index.ts";
import * as nextPackage from "../src/index.ts";

// Generated per run: the literal this replaced is entry one of the
// published register, so the fixture and the value the register exists
// to refuse were the same string.
const KEY = randomBytes(32).toString("base64");

// These tests run with cookieSecure off, so the plain name.
const SESSION_COOKIE = cookieNames(false).session;

function config(): ProtelesConfigInput {
  return {
    issuer: "https://auth.example.com",
    clientId: "app-1",
    clientSecret: "secret",
    redirectUri: "https://app.example.com/api/auth/callback",
    sessionSecret: KEY,
    cookieSecure: false,
    fetch: (async () => new Response("{}", { headers: { "content-type": "application/json" } })) as typeof fetch,
  };
}

test("the core surface consumers rely on is re-exported", () => {
  // Named explicitly: these are what the example app and the live verifier use.
  for (const [name, value] of Object.entries({ AuthApp, SessionCrypto, safeReturnTo, matchesPath })) {
    assert.equal(typeof value, "function", `${name} is re-exported`);
  }
  assert.equal(typeof cookieNames, "function", "cookieNames is re-exported");
  assert.deepEqual(cookieNames(true), { session: "__Host-proteles_session", flow: "__Host-proteles_flow" });
  assert.equal("SESSION_COOKIE" in nextPackage, false, "the constant is gone, so a caller of it fails to compile");
  // `resolveSession` on the re-exported `AuthApp` throws it while the
  // authorization server is busy; a Next app that depends on this package
  // alone has to be able to catch it by class.
  assert.equal(
    (nextPackage as Record<string, unknown>)["SessionUnavailableError"],
    CoreSessionUnavailableError,
    "SessionUnavailableError is re-exported",
  );
});

test("createAuthHandlers returns GET and POST that share one router", async () => {
  const { GET, POST } = createAuthHandlers(config());
  assert.equal(typeof GET, "function");
  assert.equal(typeof POST, "function");

  const login = await GET(new Request("https://app.example.com/api/auth/login"));
  assert.equal(login.status, 302);
  assert.ok(login.headers.get("location")?.startsWith("https://auth.example.com/oauth/authorize"));

  const signup = await GET(new Request("https://app.example.com/api/auth/signup"));
  assert.equal(signup.status, 302);
  assert.equal(new URL(signup.headers.get("location")!).searchParams.get("prompt"), "create");

  const me = await POST(new Request("https://app.example.com/api/auth/me", { method: "POST" }));
  assert.equal(((await me.json()) as { authenticated: boolean }).authenticated, false);

  const unknown = await GET(new Request("https://app.example.com/api/auth/bogus"));
  assert.equal(unknown.status, 404);
});

test("the login route is the app's sign-in start address: ?iss= starts a sign-in at the configured issuer, whatever it names", async () => {
  // Registered as the app's `initiate_login_uri`, so Proteles sends an invitee
  // here with `iss` (OpenID Connect Core 1.0 §4), and the middleware lets it
  // through to the handler like any auth route.
  const reports: string[] = [];
  const onError = (_reason: string, context: string) => { reports.push(context); };
  const { GET } = createAuthHandlers({ ...config(), onError });
  const mw = createAuthMiddleware({ ...config(), onError: false }, { publicPaths: ["/"] });
  for (const iss of ["https://auth.example.com", "https://evil.example"]) {
    const url = `https://app.example.com/api/auth/login?iss=${encodeURIComponent(iss)}`;
    assert.equal(await mw(new Request(url)), undefined, `${iss}: the middleware passes it`);
    const res = await GET(new Request(url));
    assert.equal(res.status, 302, iss);
    const loc = new URL(res.headers.get("location")!);
    assert.equal(loc.origin + loc.pathname, "https://auth.example.com/oauth/authorize", `${iss}: the configured issuer`);
    assert.ok(loc.searchParams.get("state"), iss);
    assert.ok((res.headers.get("set-cookie") ?? "").includes("proteles_flow="), `${iss}: a flow is started`);
    // The one thing `iss` changes: a mismatch is reported (bff's `login`), so
    // this is where the binding is seen to hand the query to the core.
    assert.deepEqual(reports, iss === "https://evil.example" ? ["login"] : [], `${iss}: what onError heard`);
  }
});

test("createAuthMiddleware guards protected routes and lets public ones through", async () => {
  const mw = createAuthMiddleware(config(), { publicPaths: ["/"] });

  assert.equal(await mw(new Request("https://app.example.com/")), undefined, "home is public");
  assert.equal(
    await mw(new Request("https://app.example.com/api/auth/login")),
    undefined,
    "auth routes always pass",
  );

  const guarded = await mw(new Request("https://app.example.com/dashboard"));
  assert.ok(guarded, "a protected route redirects when signed out");
  assert.equal(guarded!.status, 307);
  const loc = new URL(guarded!.headers.get("location")!, "https://app.example.com");
  assert.equal(loc.pathname, "/api/auth/login");
  assert.equal(loc.searchParams.get("returnTo"), "/dashboard");
});

// Next's middleware adapter parses a returned `Location` with `new URL(location)`
// and no base, so the core's relative redirects were a `TypeError: Invalid URL`
// and a 500 on every guarded request (the quickstart under Next 14.2,
// 2026-09-29). Both of the middleware's redirects must leave this package
// absolute, and absolute against the configured origin: the request below
// claims another host, as a forged `X-Forwarded-Host` would make it.
test("the middleware's redirects are absolute, against the configured origin", async () => {
  const mw = createAuthMiddleware(config(), { publicPaths: ["/"] });

  const login = await mw(new Request("https://attacker.example/dashboard?tab=2"));
  assert.equal(login?.status, 307);
  assert.equal(
    login?.headers.get("location"),
    "https://app.example.com/api/auth/login?returnTo=%2Fdashboard%3Ftab%3D2",
  );

  const stale = await new SessionCrypto(KEY).encrypt({
    accessToken: "AT",
    accessExpiresAt: Date.now() - 1000,
    refreshToken: "RT",
    sub: "user-1",
  });
  const revalidate = await mw(
    new Request("https://attacker.example/dashboard", { headers: { cookie: `${SESSION_COOKIE}=${stale}` } }),
  );
  assert.equal(revalidate?.status, 303);
  assert.equal(
    revalidate?.headers.get("location"),
    "https://app.example.com/api/auth/revalidate?returnTo=%2Fdashboard",
  );
});

test("the zero-config authMiddleware redirects absolutely too", async () => {
  const saved = { ...process.env };
  Object.assign(process.env, {
    PROTELES_ISSUER: "https://auth.example.com",
    PROTELES_CLIENT_ID: "app-1",
    PROTELES_APP_URL: "https://app.example.com",
    PROTELES_SESSION_SECRET: KEY,
  });
  try {
    const res = await authMiddleware(new Request("https://attacker.example/settings"));
    assert.equal(res?.status, 307);
    assert.equal(res?.headers.get("location"), "https://app.example.com/api/auth/login?returnTo=%2Fsettings");
  } finally {
    for (const k of Object.keys(process.env)) if (!(k in saved)) delete process.env[k];
  }
});

test("an AuthApp built through this package round-trips a session cookie", async () => {
  const app = new AuthApp(config());
  const sc = new SessionCrypto(KEY);
  const cookie = await sc.encrypt({
    accessToken: "AT",
    accessExpiresAt: Date.now() + 3_600_000,
    sub: "user-1",
    email: "alice@example.com",
  });

  const res = await app.handle(
    new Request("https://app.example.com/api/auth/me", { headers: { cookie: `${SESSION_COOKIE}=${cookie}` } }),
  );
  const body = (await res.json()) as { authenticated: boolean; user?: { email?: string } };
  assert.equal(body.authenticated, true);
  assert.equal(body.user?.email, "alice@example.com");
  assert.ok(!JSON.stringify(body).includes("AT"), "no token reaches the browser view");
});

// ---------------------------------------------------------------------------
// The peer range admits no Next.js release affected by CVE-2025-29927.
//
// Those releases let one request header skip middleware entirely, so an app
// that guards its routes with `authMiddleware` alone was open on every one of
// them. The range was `>=14`, which admitted them all. The fixed releases are
// 14.2.25 and 15.2.3.
//
// Deliberately narrow, like rule 4 of `npm-publish-readiness.mjs`: this reads
// `^x.y.z` and `>=x[.y[.z]]` alternatives joined by `||`, and fails on anything
// else rather than guessing at semver it does not implement. `>=14` is readable
// on purpose, so the range this replaced fails for admitting 14.2.24 rather
// than for being unreadable.
// ---------------------------------------------------------------------------

type Version = [number, number, number];

/** `x.y.z`, or `x` / `x.y` with the missing parts read as zero (as `>=14` means 14.0.0). */
function parseVersion(v: string): Version {
  const m = /^(\d+)(?:\.(\d+))?(?:\.(\d+))?$/.exec(v);
  assert.ok(m, `"${v}" is not a version this check reads`);
  return [Number(m[1]), Number(m[2] ?? 0), Number(m[3] ?? 0)];
}

function compare(a: Version, b: Version): number {
  return a[0] - b[0] || a[1] - b[1] || a[2] - b[2];
}

/** Whether `version` satisfies `range`, for ranges built only from `^x.y.z` (x >= 1) and `>=x[.y[.z]]`. */
function admits(range: string, version: string): boolean {
  const v = parseVersion(version);
  return range.split("||").some((alt) => {
    const a = alt.trim();
    const caret = /^\^(\d+\.\d+\.\d+)$/.exec(a);
    if (caret) {
      const floor = parseVersion(caret[1]!);
      assert.ok(floor[0] >= 1, `"${a}": a caret below 1.0.0 has different rules, which this check does not implement`);
      return v[0] === floor[0] && compare(v, floor) >= 0;
    }
    const atLeast = /^>=(\d+(?:\.\d+){0,2})$/.exec(a);
    if (atLeast) return compare(v, parseVersion(atLeast[1]!)) >= 0;
    assert.fail(`"${a}" in "${range}" is not a ^x.y.z or >=x[.y[.z]] alternative this check reads`);
  });
}

function manifest(relative: string): { dependencies?: Record<string, string>; peerDependencies?: Record<string, string> } {
  return JSON.parse(readFileSync(fileURLToPath(new URL(relative, import.meta.url)), "utf8"));
}

test("the next peer range admits no release affected by CVE-2025-29927", () => {
  const range = manifest("../package.json").peerDependencies?.["next"];
  assert.ok(range, "@proteles/next declares a next peer range");
  // The last vulnerable release on each line this package supports, and the
  // first 15.x, which was vulnerable too.
  for (const vulnerable of ["14.0.0", "14.2.24", "15.0.0", "15.2.2"]) {
    assert.equal(admits(range, vulnerable), false, `${range} must not admit next@${vulnerable}`);
  }
  for (const fixed of ["14.2.25", "14.2.30", "15.2.3", "15.5.0", "16.0.0"]) {
    assert.equal(admits(range, fixed), true, `${range} should admit next@${fixed}`);
  }
});

test("the Next.js quickstart asks for a next the peer range admits", () => {
  // The example installs its own `next`, so its range is what a reader copying
  // it gets. Its floor has to be a release this package accepts, or the
  // quickstart teaches the vulnerable version.
  const range = manifest("../package.json").peerDependencies?.["next"]!;
  const wanted = manifest("../../../examples/nextjs-quickstart/package.json").dependencies?.["next"];
  const floor = /^\^(\d+\.\d+\.\d+)$/.exec(wanted ?? "");
  assert.ok(floor, `the quickstart's next range "${wanted}" is not the ^x.y.z this check reads`);
  assert.equal(admits(range, floor[1]!), true, `the quickstart's floor next@${floor[1]} is outside ${range}`);
});

test("the Next.js quickstart links every @proteles package it installs, not only the ones it imports", () => {
  // The quickstart installs this package from `file:`, so it runs the local
  // build. This package depends on `@proteles/bff` by version, and a dependency
  // the example does not also link is not pinned to this checkout: npm may take
  // it from the registry, which serves a different build, or fail the install
  // while the workspace carries a version not yet on npm. The other quickstarts
  // link bff; this one did not.
  const example = "../../../examples/nextjs-quickstart/";
  const deps = manifest(`${example}package.json`).dependencies ?? {};
  const linked = (name: string) => deps[name]?.startsWith("file:") === true;
  assert.ok(linked("@proteles/next"), "the quickstart links @proteles/next");

  const unlinked: string[] = [];
  const seen = new Set<string>();
  const walk = (name: string): void => {
    if (seen.has(name)) return;
    seen.add(name);
    const target = deps[name]!.slice("file:".length);
    for (const dep of Object.keys(manifest(`${example}${target}/package.json`).dependencies ?? {})) {
      if (!dep.startsWith("@proteles/")) continue;
      if (linked(dep)) walk(dep);
      else unlinked.push(`${dep} (for ${name})`);
    }
  };
  for (const name of Object.keys(deps).filter((n) => n.startsWith("@proteles/") && linked(n))) walk(name);
  assert.deepEqual(unlinked, [], "@proteles packages the quickstart would resolve from npm");
});
