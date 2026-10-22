import { test } from "node:test";
import assert from "node:assert/strict";

import { createRetry, fetchSession, loadSession } from "../src/session.ts";
import type { SessionState } from "../src/session.ts";

function mockFetch(response: Response | (() => Promise<Response>)): { fn: typeof fetch; urls: string[] } {
  const urls: string[] = [];
  const fn = (async (input: RequestInfo | URL, init?: RequestInit) => {
    urls.push(String(input));
    void init;
    return typeof response === "function" ? response() : response;
  }) as typeof fetch;
  return { fn, urls };
}

const json = (obj: unknown, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json" } });

test("fetchSession returns the authenticated user from /api/auth/me", async () => {
  const { fn, urls } = mockFetch(json({ authenticated: true, user: { sub: "u1", email: "a@b.com" } }));
  const result = await fetchSession("/api/auth", fn);
  assert.equal(urls[0], "/api/auth/me");
  assert.deepEqual(result, { authenticated: true, user: { sub: "u1", email: "a@b.com" } });
});

test("fetchSession returns signed-out when the server says so", async () => {
  const { fn } = mockFetch(json({ authenticated: false }));
  assert.deepEqual(await fetchSession("/api/auth", fn), { authenticated: false, user: null });
});

test("fetchSession treats a refusal as signed-out: a 401, or a 404 from a wrong basePath", async () => {
  for (const status of [401, 404]) {
    const { fn } = mockFetch(new Response("nope", { status }));
    assert.deepEqual(await fetchSession("/api/auth", fn), { authenticated: false, user: null }, `${status}`);
  }
});

// Since the BFF keeps a session through a busy authorization server, `/me`
// answers 503 for it, with the cookie intact. Read as signed out, that showed
// the signed-out state to users who were still signed in.
test("fetchSession reads a busy /me as unavailable, not signed out, with its Retry-After", async () => {
  const busy = new Response(
    JSON.stringify({ error: "temporarily_unavailable", message: "The sign-in service is busy. Try again shortly." }),
    { status: 503, headers: { "content-type": "application/json", "retry-after": "7" } },
  );
  assert.deepEqual(await fetchSession("/api/auth", mockFetch(busy).fn), {
    authenticated: false,
    user: null,
    unavailable: true,
    retryAfter: 7,
  });

  const throttled = new Response(null, { status: 429, headers: { "retry-after": "86400" } });
  assert.equal((await fetchSession("/api/auth", mockFetch(throttled).fn)).retryAfter, 3600, "capped at an hour");

  for (const status of [408, 500, 502, 504]) {
    const result = await fetchSession("/api/auth", mockFetch(new Response("<html>", { status })).fn);
    assert.deepEqual(result, { authenticated: false, user: null, unavailable: true }, `${status}, and no wait invented`);
  }
});

test("fetchSession never throws on a network error, and says it could not tell", async () => {
  const fn = (async () => {
    throw new Error("offline");
  }) as unknown as typeof fetch;
  assert.deepEqual(await fetchSession("/api/auth", fn), { authenticated: false, user: null, unavailable: true });
});

test("the retry waits for Retry-After when the server named one, else backs off from 2 s to 30 s", (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const retry = createRetry();
  let runs = 0;
  const run = () => {
    runs += 1;
  };
  const expectRunAfter = (ms: number, what: string) => {
    const before = runs;
    t.mock.timers.tick(ms - 1);
    assert.equal(runs, before, `${what}: not before ${ms} ms`);
    t.mock.timers.tick(1);
    assert.equal(runs, before + 1, `${what}: at ${ms} ms`);
  };

  retry.schedule(run, 7);
  expectRunAfter(7_000, "Retry-After: 7");
  for (const ms of [4_000, 8_000, 16_000, 30_000, 30_000]) {
    retry.schedule(run);
    expectRunAfter(ms, "backoff");
  }

  retry.cancel();
  retry.schedule(run);
  expectRunAfter(2_000, "an answer in between starts the backoff again");

  retry.schedule(run);
  retry.schedule(run);
  t.mock.timers.tick(60_000);
  assert.equal(runs, 8, "a second schedule replaces the first rather than adding to it");

  retry.schedule(run);
  retry.cancel();
  t.mock.timers.tick(60_000);
  assert.equal(runs, 8, "cancel drops the pending retry");
});

// `<AuthProvider>` is `loadSession` plus React state. Its effects cannot run in
// Node without a DOM, so the loop is tested here, with a plain variable for the
// state and the timers mocked; what the provider adds is only the wiring.

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

/** A provider's worth of state around `loadSession`. */
function provider(fetchImpl: typeof fetch, initial: SessionState, keepTrying = () => true, isCurrent = () => true) {
  let state = initial;
  const options = {
    basePath: "/api/auth",
    fetchImpl,
    update: (next: (prev: SessionState) => SessionState) => {
      state = next(state);
    },
    retry: createRetry(),
    isCurrent,
    keepTrying,
  };
  return { load: () => loadSession(options), state: () => state };
}

test("a busy /me keeps the user and asks again after its Retry-After; a following 200 recovers", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const busy = new Response(JSON.stringify({ error: "temporarily_unavailable" }), {
    status: 503,
    headers: { "content-type": "application/json", "retry-after": "5" },
  });
  const me = scripted(busy, json({ authenticated: true, user: { sub: "u1", email: "new@b.com" } }));
  const auth = provider(me.fetch, { user: { sub: "u1", email: "a@b.com" }, isLoading: false, isUnavailable: false });

  await auth.load();
  assert.deepEqual(
    auth.state(),
    { user: { sub: "u1", email: "a@b.com" }, isLoading: false, isUnavailable: true },
    "a 503 keeps the user",
  );

  t.mock.timers.tick(4_999);
  await settle();
  assert.equal(me.calls(), 1, "not asked again before the Retry-After");
  t.mock.timers.tick(1);
  await settle();
  assert.equal(me.calls(), 2, "then asked once");
  assert.deepEqual(
    auth.state(),
    { user: { sub: "u1", email: "new@b.com" }, isLoading: false, isUnavailable: false },
    "a following 200 recovers",
  );
});

test("a 401 still signs out, and nothing is retried (the control)", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const me = scripted(new Response(null, { status: 401 }));
  const auth = provider(me.fetch, { user: { sub: "u1" }, isLoading: false, isUnavailable: false });

  await auth.load();
  assert.deepEqual(auth.state(), { user: null, isLoading: false, isUnavailable: false });
  t.mock.timers.tick(60_000);
  await settle();
  assert.equal(me.calls(), 1);
});

test("a first load with no answer stays loading and backs off until one comes", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const me = scripted("offline", "offline", json({ authenticated: false }));
  const auth = provider(me.fetch, { user: null, isLoading: true, isUnavailable: false });

  await auth.load(); // must not reject
  assert.deepEqual(
    auth.state(),
    { user: null, isLoading: true, isUnavailable: true },
    "neither signed in nor out is known yet",
  );

  t.mock.timers.tick(2_000);
  await settle();
  assert.equal(me.calls(), 2, "the first retry comes after 2 s");
  assert.equal(auth.state().isLoading, true);
  t.mock.timers.tick(3_999);
  await settle();
  assert.equal(me.calls(), 2, "the second waits longer");
  t.mock.timers.tick(1);
  await settle();
  assert.equal(me.calls(), 3);
  assert.deepEqual(
    auth.state(),
    { user: null, isLoading: false, isUnavailable: false },
    "and the answer, signed out, is taken",
  );
});

test("an answer that comes before the retry is due cancels the retry", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const me = scripted("offline", json({ authenticated: true, user: { sub: "u1" } }));
  const auth = provider(me.fetch, { user: null, isLoading: true, isUnavailable: false });

  await auth.load(); // no answer: a retry is due in 2 s
  await auth.load(); // but the app asks again first, and gets one
  t.mock.timers.tick(60_000);
  await settle();
  assert.equal(me.calls(), 2, "the pending retry was dropped");
  assert.equal(auth.state().isUnavailable, false);
});

test("nothing is scheduled once the provider has stopped wanting answers (unmounted)", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const me = scripted("offline");
  const auth = provider(me.fetch, { user: { sub: "u1" }, isLoading: false, isUnavailable: false }, () => false);

  await auth.load();
  t.mock.timers.tick(60_000);
  await settle();
  assert.equal(me.calls(), 1, "no poll of a busy server for nobody");
});

test("an answer that no longer belongs to the state is dropped, busy or not", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const signedIn = { user: { sub: "u1" }, isLoading: false, isUnavailable: false };
  for (const answer of [new Response(null, { status: 401 }), new Response(null, { status: 503 })]) {
    const me = scripted(answer);
    const auth = provider(me.fetch, signedIn, () => true, () => false);
    await auth.load();
    t.mock.timers.tick(60_000);
    await settle();
    assert.deepEqual(auth.state(), signedIn, `a ${answer.status} for a basePath the provider has left changes nothing`);
    assert.equal(me.calls(), 1, "and schedules nothing");
  }
});
