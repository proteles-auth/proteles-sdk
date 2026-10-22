import { test } from "node:test";
import assert from "node:assert/strict";
import { effectScope, nextTick, watch } from "vue";

import { createAuth } from "../src/auth.ts";

const json = (obj: unknown, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json" } });

const noFetch = (async () => json({})) as typeof fetch;

test("initialUser seeds state: undefined = loading, null = signed out, object = signed in", () => {
  const unknown = createAuth({ fetch: noFetch });
  assert.equal(unknown.isLoading.value, true, "undefined initialUser starts loading");
  assert.equal(unknown.isAuthenticated.value, false);

  const out = createAuth({ initialUser: null, fetch: noFetch });
  assert.equal(out.isLoading.value, false, "a known signed-out user is not loading");
  assert.equal(out.isAuthenticated.value, false);

  const inn = createAuth({ initialUser: { sub: "u1", email: "a@b.com" }, fetch: noFetch });
  assert.equal(inn.isLoading.value, false);
  assert.equal(inn.isAuthenticated.value, true);
  assert.equal(inn.user.value?.email, "a@b.com");
});

test("isAuthenticated is a computed that tracks the user ref", async () => {
  const auth = createAuth({ initialUser: null, fetch: noFetch });
  const seen: boolean[] = [];
  watch(auth.isAuthenticated, (v) => seen.push(v));

  auth.user.value = { sub: "u1" };
  await nextTick();
  assert.deepEqual(seen, [true], "flipping the user notifies watchers");

  auth.user.value = null;
  await nextTick();
  assert.deepEqual(seen, [true, false]);
});

test("reload fetches /api/auth/me and publishes the user reactively", async () => {
  const urls: string[] = [];
  const fetchImpl = (async (url: string) => {
    urls.push(String(url));
    return json({ authenticated: true, user: { sub: "u1", email: "a@b.com", preferredUsername: "alice" } });
  }) as unknown as typeof fetch;

  const auth = createAuth({ fetch: fetchImpl });
  assert.equal(auth.isLoading.value, true);
  await auth.reload();

  assert.equal(urls[0], "/api/auth/me");
  assert.equal(auth.isLoading.value, false);
  assert.equal(auth.isAuthenticated.value, true);
  assert.equal(auth.user.value?.preferredUsername, "alice");
});

test("reload corrects a stale seeded user when the server says signed out", async () => {
  const auth = createAuth({
    initialUser: { sub: "stale" },
    fetch: (async () => json({ authenticated: false })) as typeof fetch,
  });
  await auth.reload();
  assert.equal(auth.user.value, null);
  assert.equal(auth.isAuthenticated.value, false);
  assert.equal(auth.isLoading.value, false);
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

test("a busy /me keeps the user and asks again after its Retry-After; a following 200 recovers", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const busy = new Response(JSON.stringify({ error: "temporarily_unavailable" }), {
    status: 503,
    headers: { "content-type": "application/json", "retry-after": "5" },
  });
  const me = scripted(busy, json({ authenticated: true, user: { sub: "u1", email: "new@b.com" } }));
  const auth = createAuth({ initialUser: { sub: "u1", email: "a@b.com" }, fetch: me.fetch });

  await auth.reload();
  assert.equal(auth.user.value?.email, "a@b.com", "a 503 keeps the user");
  assert.equal(auth.isAuthenticated.value, true);
  assert.equal(auth.isLoading.value, false);
  assert.equal(auth.isUnavailable.value, true, "and says the service could not answer");

  t.mock.timers.tick(4_999);
  await settle();
  assert.equal(me.calls(), 1, "not asked again before the Retry-After");
  t.mock.timers.tick(1);
  await settle();
  assert.equal(me.calls(), 2, "then asked once");
  assert.equal(auth.isUnavailable.value, false, "a following 200 recovers");
  assert.equal(auth.user.value?.email, "new@b.com", "and its answer is taken");
});

test("a 401 still signs out, and nothing is retried (the control)", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const me = scripted(new Response(null, { status: 401 }));
  const auth = createAuth({ initialUser: { sub: "u1" }, fetch: me.fetch });

  await auth.reload();
  assert.equal(auth.user.value, null);
  assert.equal(auth.isAuthenticated.value, false);
  assert.equal(auth.isUnavailable.value, false);
  t.mock.timers.tick(60_000);
  await settle();
  assert.equal(me.calls(), 1);
});

test("a first load with no answer stays loading and backs off until one comes", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const me = scripted("offline", "offline", json({ authenticated: false }));
  const auth = createAuth({ fetch: me.fetch });

  await auth.reload(); // must not reject
  assert.equal(auth.isLoading.value, true, "neither signed in nor signed out is known yet");
  assert.equal(auth.isUnavailable.value, true);
  assert.equal(auth.user.value, null);

  t.mock.timers.tick(2_000);
  await settle();
  assert.equal(me.calls(), 2, "the first retry comes after 2 s");
  assert.equal(auth.isLoading.value, true);
  t.mock.timers.tick(3_999);
  await settle();
  assert.equal(me.calls(), 2, "the second waits longer");
  t.mock.timers.tick(1);
  await settle();
  assert.equal(me.calls(), 3);
  assert.equal(auth.isLoading.value, false);
  assert.equal(auth.isUnavailable.value, false);
  assert.equal(auth.isAuthenticated.value, false, "and the answer, signed out, is taken");
});

test("an answer that comes before the retry is due cancels the retry", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const me = scripted("offline", json({ authenticated: true, user: { sub: "u1" } }));
  const auth = createAuth({ fetch: me.fetch });

  await auth.reload(); // no answer: a retry is due in 2 s
  await auth.reload(); // but the app asks again first, and gets one
  t.mock.timers.tick(60_000);
  await settle();
  assert.equal(me.calls(), 2, "the pending retry was dropped");
  assert.equal(auth.isUnavailable.value, false);
});

// Retries belong to whoever made the auth object. `<AuthProvider>` makes it in
// `setup()`, inside the component's scope, and unmounting stops that scope, so
// stopping one by hand here is the provider going away.

test("disposing the scope that made it drops the pending retry", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const me = scripted(new Response(null, { status: 503 }));
  const scope = effectScope();
  const auth = scope.run(() => createAuth({ initialUser: { sub: "u1" }, fetch: me.fetch }))!;

  await auth.reload();
  t.mock.timers.tick(2_000);
  await settle();
  assert.equal(me.calls(), 2, "it asks again while its scope lives");
  scope.stop();
  t.mock.timers.tick(60_000);
  await settle();
  assert.equal(me.calls(), 2, "and not once the scope has gone");
});

test("a busy answer that arrives after its scope is disposed schedules nothing", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const me = held();
  const scope = effectScope();
  const auth = scope.run(() => createAuth({ initialUser: { sub: "u1" }, fetch: me.fetch }))!;

  const asking = auth.reload();
  scope.stop();
  me.answer();
  await asking;
  assert.equal(auth.isUnavailable.value, true, "the answer was read");
  t.mock.timers.tick(60_000);
  await settle();
  assert.equal(me.calls(), 1, "but nothing asked again after it");
});

test("signIn navigates to the login route with returnTo and connection", () => {
  const navigated: string[] = [];
  const auth = createAuth({
    initialUser: null,
    fetch: noFetch,
    navigate: (url) => navigated.push(url),
    currentPath: () => "/dashboard?tab=1",
  });

  auth.signIn();
  assert.equal(navigated[0], "/api/auth/login?returnTo=%2Fdashboard%3Ftab%3D1", "defaults returnTo to the current path");

  auth.signIn({ returnTo: "/settings", connection: "google" });
  assert.equal(navigated[1], "/api/auth/login?returnTo=%2Fsettings&connection=google");
});

test("signUp navigates to the sign-up route with returnTo", () => {
  const navigated: string[] = [];
  const auth = createAuth({
    initialUser: null,
    fetch: noFetch,
    navigate: (url) => navigated.push(url),
    currentPath: () => "/pricing?plan=pro",
  });

  auth.signUp();
  assert.equal(navigated[0], "/api/auth/signup?returnTo=%2Fpricing%3Fplan%3Dpro", "defaults returnTo to the current path");

  auth.signUp({ returnTo: "/welcome" });
  assert.equal(navigated[1], "/api/auth/signup?returnTo=%2Fwelcome");
});

test("signOut posts to the logout route, and navigates nowhere", () => {
  const navigated: string[] = [];
  const posted: string[] = [];
  const auth = createAuth({
    initialUser: null,
    fetch: noFetch,
    navigate: (url) => navigated.push(url),
    post: (url) => posted.push(url),
  });

  auth.signOut();
  assert.equal(posted[0], "/api/auth/logout");
  auth.signOut({ returnTo: "/bye" });
  assert.equal(posted[1], "/api/auth/logout?returnTo=%2Fbye");
  assert.deepEqual(navigated, [], "a GET to the logout route only shows a confirmation");
});

test("a custom basePath is honored everywhere", async () => {
  const urls: string[] = [];
  const navigated: string[] = [];
  const auth = createAuth({
    basePath: "/custom/auth/",
    fetch: (async (url: string) => {
      urls.push(String(url));
      return json({ authenticated: false });
    }) as unknown as typeof fetch,
    navigate: (url) => navigated.push(url),
    currentPath: () => undefined,
  });

  assert.equal(auth.basePath, "/custom/auth", "trailing slash stripped");
  await auth.reload();
  auth.signIn();
  auth.signUp();
  assert.equal(urls[0], "/custom/auth/me");
  assert.equal(navigated[0], "/custom/auth/login");
  assert.equal(navigated[1], "/custom/auth/signup");
});

test("creating the auth object never fetches (SSR-safe)", () => {
  let calls = 0;
  createAuth({
    fetch: (async () => {
      calls++;
      return json({});
    }) as typeof fetch,
  });
  assert.equal(calls, 0, "construction must not hit the network");
});
