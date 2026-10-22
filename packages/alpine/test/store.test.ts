import { test } from "node:test";
import assert from "node:assert/strict";

import { createAuthStore } from "../src/store.ts";

const json = (obj: unknown, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json" } });

const noFetch = (async () => json({})) as typeof fetch;

test("initialUser seeds state: undefined = loading, null = signed out, object = signed in", () => {
  assert.equal(createAuthStore({ fetch: noFetch }).isLoading, true, "undefined initialUser starts loading");
  const out = createAuthStore({ initialUser: null, fetch: noFetch });
  assert.equal(out.isLoading, false);
  assert.equal(out.isAuthenticated, false);
  const inn = createAuthStore({ initialUser: { sub: "u1", email: "a@b.com" }, fetch: noFetch });
  assert.equal(inn.isAuthenticated, true);
  assert.equal(inn.user?.email, "a@b.com");
});

test("isAuthenticated is a getter, so it follows later writes to user", () => {
  // Alpine wraps the store in its own reactivity and reads properties off it, so
  // this must be a live getter rather than a value computed once at creation.
  const store = createAuthStore({ initialUser: null, fetch: noFetch });
  assert.equal(store.isAuthenticated, false);
  store.user = { sub: "u1" };
  assert.equal(store.isAuthenticated, true, "recomputed from the current user");
  store.user = null;
  assert.equal(store.isAuthenticated, false);
});

test("reload fetches /api/auth/me and updates user + isLoading", async () => {
  const urls: string[] = [];
  const store = createAuthStore({
    fetch: (async (url: string) => {
      urls.push(String(url));
      return json({ authenticated: true, user: { sub: "u1", preferredUsername: "alice" } });
    }) as unknown as typeof fetch,
  });

  assert.equal(store.isLoading, true);
  await store.reload();
  assert.equal(urls[0], "/api/auth/me");
  assert.equal(store.user?.preferredUsername, "alice");
  assert.equal(store.isLoading, false);
});

test("reload corrects a stale seeded user when the server says signed out", async () => {
  const store = createAuthStore({
    initialUser: { sub: "stale" },
    fetch: (async () => json({ authenticated: false })) as typeof fetch,
  });
  await store.reload();
  assert.equal(store.user, null);
  assert.equal(store.isAuthenticated, false);
});

// A busy `/me` is not a sign-out. Since the BFF keeps a session through a busy
// authorization server, `/me` answers 503 for it with the cookie intact; read as
// signed out, that flipped the UI to the signed-out state until the next `/me`
// got through. The timers are mocked, so the retries are stepped through rather
// than waited out.

/** A fetch answering from a script, one step per call, the last repeating. */
function scripted(...steps: (Response | "offline")[]): { fetch: typeof fetch; calls: () => number } {
  let n = 0;
  const fetchImpl = (async () => {
    const step = steps[Math.min(n++, steps.length - 1)]!;
    if (step === "offline") throw new TypeError("fetch failed");
    return step.clone();
  }) as unknown as typeof fetch;
  return { fetch: fetchImpl, calls: () => n };
}

/** Lets a retry the mocked clock just fired run to its end. */
async function settle(): Promise<void> {
  for (let i = 0; i < 10; i++) await new Promise((resolve) => setImmediate(resolve));
}

test("a busy /me keeps the user and asks again after its Retry-After; a following 200 recovers", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const busy = new Response(JSON.stringify({ error: "temporarily_unavailable" }), {
    status: 503,
    headers: { "content-type": "application/json", "retry-after": "5" },
  });
  const me = scripted(busy, json({ authenticated: true, user: { sub: "u1", email: "new@b.com" } }));
  const auth = createAuthStore({ initialUser: { sub: "u1", email: "a@b.com" }, fetch: me.fetch });

  await auth.reload();
  assert.equal(auth.user?.email, "a@b.com", "a 503 keeps the user");
  assert.equal(auth.isAuthenticated, true);
  assert.equal(auth.isLoading, false);
  assert.equal(auth.isUnavailable, true, "and says the service could not answer");

  t.mock.timers.tick(4_999);
  await settle();
  assert.equal(me.calls(), 1, "not asked again before the Retry-After");
  t.mock.timers.tick(1);
  await settle();
  assert.equal(me.calls(), 2, "then asked once");
  assert.equal(auth.isUnavailable, false, "a following 200 recovers");
  assert.equal(auth.user?.email, "new@b.com", "and its answer is taken");
});

test("a 401 still signs out, and nothing is retried (the control)", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const me = scripted(new Response(null, { status: 401 }));
  const auth = createAuthStore({ initialUser: { sub: "u1" }, fetch: me.fetch });

  await auth.reload();
  assert.equal(auth.user, null);
  assert.equal(auth.isAuthenticated, false);
  assert.equal(auth.isUnavailable, false);
  t.mock.timers.tick(60_000);
  await settle();
  assert.equal(me.calls(), 1);
});

test("a first load with no answer stays loading and backs off until one comes", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const me = scripted("offline", "offline", json({ authenticated: false }));
  const auth = createAuthStore({ fetch: me.fetch });

  await auth.reload(); // must not reject
  assert.equal(auth.isLoading, true, "neither signed in nor signed out is known yet");
  assert.equal(auth.isUnavailable, true);
  assert.equal(auth.user, null);

  t.mock.timers.tick(2_000);
  await settle();
  assert.equal(me.calls(), 2, "the first retry comes after 2 s");
  assert.equal(auth.isLoading, true);
  t.mock.timers.tick(3_999);
  await settle();
  assert.equal(me.calls(), 2, "the second waits longer");
  t.mock.timers.tick(1);
  await settle();
  assert.equal(me.calls(), 3);
  assert.equal(auth.isLoading, false);
  assert.equal(auth.isUnavailable, false);
  assert.equal(auth.isAuthenticated, false, "and the answer, signed out, is taken");
});

test("an answer that comes before the retry is due cancels the retry", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const me = scripted("offline", json({ authenticated: true, user: { sub: "u1" } }));
  const auth = createAuthStore({ fetch: me.fetch });

  await auth.reload(); // no answer: a retry is due in 2 s
  await auth.reload(); // but the app asks again first, and gets one
  t.mock.timers.tick(60_000);
  await settle();
  assert.equal(me.calls(), 2, "the pending retry was dropped");
  assert.equal(auth.isUnavailable, false);
});

test("init() revalidates by default, and can be turned off", async () => {
  let calls = 0;
  const counting = (async () => {
    calls++;
    return json({ authenticated: false });
  }) as typeof fetch;

  createAuthStore({ fetch: counting }).init();
  await new Promise((r) => setTimeout(r, 0));
  assert.equal(calls, 1, "init() fetches by default");

  calls = 0;
  createAuthStore({ fetch: counting, revalidateOnInit: false }).init();
  await new Promise((r) => setTimeout(r, 0));
  assert.equal(calls, 0, "revalidateOnInit:false skips it");
});

test("creating the store never fetches on its own (init is the trigger)", () => {
  let calls = 0;
  createAuthStore({
    fetch: (async () => {
      calls++;
      return json({});
    }) as typeof fetch,
  });
  assert.equal(calls, 0);
});

test("signIn navigates to the login route", () => {
  const navigated: string[] = [];
  const store = createAuthStore({
    initialUser: null,
    fetch: noFetch,
    navigate: (url) => navigated.push(url),
    currentPath: () => "/dashboard?tab=1",
  });

  store.signIn();
  assert.equal(navigated[0], "/api/auth/login?returnTo=%2Fdashboard%3Ftab%3D1", "defaults returnTo to the current path");
  store.signIn({ returnTo: "/settings", connection: "google" });
  assert.equal(navigated[1], "/api/auth/login?returnTo=%2Fsettings&connection=google");
});

test("signUp navigates to the sign-up route with returnTo", () => {
  const navigated: string[] = [];
  const store = createAuthStore({
    initialUser: null,
    fetch: noFetch,
    navigate: (url) => navigated.push(url),
    currentPath: () => "/pricing?plan=pro",
  });

  store.signUp();
  assert.equal(navigated[0], "/api/auth/signup?returnTo=%2Fpricing%3Fplan%3Dpro", "defaults returnTo to the current path");

  store.signUp({ returnTo: "/welcome" });
  assert.equal(navigated[1], "/api/auth/signup?returnTo=%2Fwelcome");
});

test("signOut posts to the logout route, and navigates nowhere", () => {
  const navigated: string[] = [];
  const posted: string[] = [];
  const store = createAuthStore({
    initialUser: null,
    fetch: noFetch,
    navigate: (url) => navigated.push(url),
    post: (url) => posted.push(url),
  });
  store.signOut();
  assert.equal(posted[0], "/api/auth/logout");
  store.signOut({ returnTo: "/bye" });
  assert.equal(posted[1], "/api/auth/logout?returnTo=%2Fbye");
  assert.deepEqual(navigated, [], "a GET to the logout route only shows a confirmation");
});

test("a custom basePath is honored everywhere", async () => {
  const urls: string[] = [];
  const navigated: string[] = [];
  const store = createAuthStore({
    basePath: "/custom/auth/",
    fetch: (async (url: string) => {
      urls.push(String(url));
      return json({ authenticated: false });
    }) as unknown as typeof fetch,
    navigate: (url) => navigated.push(url),
    currentPath: () => undefined,
  });

  assert.equal(store.basePath, "/custom/auth", "trailing slash stripped");
  await store.reload();
  store.signIn();
  store.signUp();
  assert.equal(urls[0], "/custom/auth/me");
  assert.equal(navigated[0], "/custom/auth/login");
  assert.equal(navigated[1], "/custom/auth/signup");
});
