import { test } from "node:test";
import assert from "node:assert/strict";

import { createRetry, fetchSession } from "../src/session.ts";

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
