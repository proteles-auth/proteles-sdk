import { test } from "node:test";
import assert from "node:assert/strict";

import { createAuthStore, createStoppableAuthStore } from "../src/store.ts";
import type { AuthState } from "../src/types.ts";

const json = (obj: unknown, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json" } });

/** Collects every value the store publishes. */
function track(store: { subscribe: (run: (v: AuthState) => void) => () => void }) {
  const seen: AuthState[] = [];
  const unsub = store.subscribe((v) => seen.push({ ...v }));
  return { seen, unsub };
}

test("subscribe immediately publishes the current state (Svelte store contract)", () => {
  const store = createAuthStore({ initialUser: null, fetch: (async () => json({})) as typeof fetch });
  const { seen, unsub } = track(store);
  assert.equal(seen.length, 1, "subscriber called synchronously on subscribe");
  assert.deepEqual(seen[0], { user: null, isLoading: false, isAuthenticated: false, isUnavailable: false });
  unsub();
});

test("unsubscribing stops further updates", async () => {
  const store = createAuthStore({
    initialUser: null,
    fetch: (async () => json({ authenticated: true, user: { sub: "u1" } })) as typeof fetch,
  });
  const { seen, unsub } = track(store);
  unsub();
  await store.reload();
  assert.equal(seen.length, 1, "no updates after unsubscribe");
});

test("initialUser seeds the state: undefined = loading, null = signed out, object = signed in", () => {
  const f = (async () => json({})) as typeof fetch;

  const unknown = createAuthStore({ fetch: f });
  const { seen: s1 } = track(unknown);
  assert.equal(s1[0]!.isLoading, true, "undefined initialUser starts in the loading state");
  assert.equal(s1[0]!.isAuthenticated, false);

  const out = createAuthStore({ initialUser: null, fetch: f });
  const { seen: s2 } = track(out);
  assert.equal(s2[0]!.isLoading, false, "a known signed-out user is not loading");

  const inn = createAuthStore({ initialUser: { sub: "u1", email: "a@b.com" }, fetch: f });
  const { seen: s3 } = track(inn);
  assert.deepEqual(s3[0], {
    user: { sub: "u1", email: "a@b.com" },
    isLoading: false,
    isAuthenticated: true,
    isUnavailable: false,
  });
});

test("reload fetches /api/auth/me and publishes the user", async () => {
  const urls: string[] = [];
  const fetchImpl = (async (url: string) => {
    urls.push(String(url));
    return json({ authenticated: true, user: { sub: "u1", email: "a@b.com", preferredUsername: "alice" } });
  }) as unknown as typeof fetch;

  const store = createAuthStore({ fetch: fetchImpl });
  const { seen } = track(store);
  await store.reload();

  assert.equal(urls[0], "/api/auth/me");
  const last = seen.at(-1)!;
  assert.equal(last.isAuthenticated, true);
  assert.equal(last.isLoading, false);
  assert.equal(last.user?.preferredUsername, "alice");
});

test("reload clears the user (and loading) when the server says signed out", async () => {
  const store = createAuthStore({
    initialUser: { sub: "stale" },
    fetch: (async () => json({ authenticated: false })) as typeof fetch,
  });
  const { seen } = track(store);
  await store.reload();
  const last = seen.at(-1)!;
  assert.equal(last.user, null, "a stale seeded user is corrected by revalidation");
  assert.equal(last.isAuthenticated, false);
  assert.equal(last.isLoading, false);
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

/** A fetch that answers `503`, each time only once `answer()` is called: the
 *  answer is in flight until then. */
function held(): { fetch: typeof fetch; calls: () => number; answer: () => void } {
  let n = 0;
  let release = (): void => {};
  const fetchImpl = (async () => {
    n++;
    await new Promise<void>((resolve) => (release = resolve));
    return new Response(null, { status: 503 });
  }) as unknown as typeof fetch;
  return { fetch: fetchImpl, calls: () => n, answer: () => release() };
}

/** The store's current value. */
function now(store: { subscribe: (run: (v: AuthState) => void) => () => void }): AuthState {
  let value: AuthState | undefined;
  store.subscribe((v) => (value = v))();
  return value!;
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
  assert.equal(now(auth).user?.email, "a@b.com", "a 503 keeps the user");
  assert.equal(now(auth).isAuthenticated, true);
  assert.equal(now(auth).isLoading, false);
  assert.equal(now(auth).isUnavailable, true, "and says the service could not answer");

  t.mock.timers.tick(4_999);
  await settle();
  assert.equal(me.calls(), 1, "not asked again before the Retry-After");
  t.mock.timers.tick(1);
  await settle();
  assert.equal(me.calls(), 2, "then asked once");
  assert.equal(now(auth).isUnavailable, false, "a following 200 recovers");
  assert.equal(now(auth).user?.email, "new@b.com", "and its answer is taken");
});

test("a 401 still signs out, and nothing is retried (the control)", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const me = scripted(new Response(null, { status: 401 }));
  const auth = createAuthStore({ initialUser: { sub: "u1" }, fetch: me.fetch });

  await auth.reload();
  assert.equal(now(auth).user, null);
  assert.equal(now(auth).isAuthenticated, false);
  assert.equal(now(auth).isUnavailable, false);
  t.mock.timers.tick(60_000);
  await settle();
  assert.equal(me.calls(), 1);
});

test("a first load with no answer stays loading and backs off until one comes", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const me = scripted("offline", "offline", json({ authenticated: false }));
  const auth = createAuthStore({ fetch: me.fetch });

  await auth.reload(); // must not reject
  assert.equal(now(auth).isLoading, true, "neither signed in nor signed out is known yet");
  assert.equal(now(auth).isUnavailable, true);
  assert.equal(now(auth).user, null);

  t.mock.timers.tick(2_000);
  await settle();
  assert.equal(me.calls(), 2, "the first retry comes after 2 s");
  assert.equal(now(auth).isLoading, true);
  t.mock.timers.tick(3_999);
  await settle();
  assert.equal(me.calls(), 2, "the second waits longer");
  t.mock.timers.tick(1);
  await settle();
  assert.equal(me.calls(), 3);
  assert.equal(now(auth).isLoading, false);
  assert.equal(now(auth).isUnavailable, false);
  assert.equal(now(auth).isAuthenticated, false, "and the answer, signed out, is taken");
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
  assert.equal(now(auth).isUnavailable, false);
});

// Retries belong to whoever owns the store. `<AuthProvider>` stops its store
// when it is destroyed, so calling `stop` by hand here is the provider going
// away; `components.test.ts` checks that the provider does call it.

test("stopping the store drops the pending retry", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const me = scripted(new Response(null, { status: 503 }));
  const { store: auth, stop } = createStoppableAuthStore({ initialUser: { sub: "u1" }, fetch: me.fetch });

  await auth.reload();
  t.mock.timers.tick(2_000);
  await settle();
  assert.equal(me.calls(), 2, "it asks again until stopped");
  stop();
  t.mock.timers.tick(60_000);
  await settle();
  assert.equal(me.calls(), 2, "and not after");
});

test("a busy answer that arrives after the store is stopped schedules nothing", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const me = held();
  const { store: auth, stop } = createStoppableAuthStore({ initialUser: { sub: "u1" }, fetch: me.fetch });

  const asking = auth.reload();
  stop();
  me.answer();
  await asking;
  assert.equal(now(auth).isUnavailable, true, "the answer was read");
  t.mock.timers.tick(60_000);
  await settle();
  assert.equal(me.calls(), 1, "but nothing asked again after it");
});

test("signIn navigates to the login route with returnTo and connection", () => {
  const navigated: string[] = [];
  const store = createAuthStore({
    initialUser: null,
    fetch: (async () => json({})) as typeof fetch,
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
    fetch: (async () => json({})) as typeof fetch,
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
    fetch: (async () => json({})) as typeof fetch,
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

test("the store never fetches on creation (SSR-safe)", () => {
  let calls = 0;
  createAuthStore({
    fetch: (async () => {
      calls++;
      return json({});
    }) as typeof fetch,
  });
  assert.equal(calls, 0, "creating the store must not hit the network");
});
