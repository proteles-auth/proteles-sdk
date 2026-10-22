//! SSR render tests for the real `.svelte` components — compiled with the Svelte
//! compiler and rendered with `svelte/server`, no bundler and no jsdom.

import { test } from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { render } from "svelte/server";

import { clean, compileAndImport } from "./ssr.ts";
import { createAuthStore } from "../src/store.ts";
import type { AuthStore, AuthUser } from "../src/types.ts";

const here = path.dirname(fileURLToPath(import.meta.url));
const src = (name: string) => path.join(here, "..", "src", name);

const COMPONENTS = [
  "SignedIn.svelte",
  "SignedOut.svelte",
  "Protect.svelte",
  "SignInButton.svelte",
  "SignOutButton.svelte",
  "SignUpButton.svelte",
  "UserButton.svelte",
  "AuthProvider.svelte",
].map(src);

const Harness = (await compileAndImport(path.join(here, "fixtures", "Harness.svelte"), COMPONENTS)) as never;
const AuthProvider = (await compileAndImport(src("AuthProvider.svelte"), [])) as never;
const ProviderProbe = (await compileAndImport(path.join(here, "fixtures", "ProviderProbe.svelte"), [
  src("AuthProvider.svelte"),
  path.join(here, "fixtures", "Capture.svelte"),
])) as never;

const noFetch = (async () => new Response("{}", { headers: { "content-type": "application/json" } })) as typeof fetch;

/** A store fixed in a given state, without touching the network. */
function storeFor(state: "signedIn" | "signedOut" | "loading", user?: AuthUser) {
  if (state === "loading") return createAuthStore({ fetch: noFetch }); // initialUser undefined => isLoading
  if (state === "signedIn") return createAuthStore({ initialUser: user ?? { sub: "u1" }, fetch: noFetch });
  return createAuthStore({ initialUser: null, fetch: noFetch });
}

const renderHarness = (state: "signedIn" | "signedOut" | "loading", user?: AuthUser) =>
  clean(render(Harness, { props: { store: storeFor(state, user) } }).body);

test("signed in: SignedIn and Protect show content, SignedOut hides", () => {
  const html = renderHarness("signedIn", { sub: "u1", email: "a@b.com", preferredUsername: "alice" });
  assert.match(html, /data-t="in"/, "SignedIn renders its children");
  assert.doesNotMatch(html, /data-t="out"/, "SignedOut renders nothing");
  assert.match(html, /data-t="allow"/, "Protect renders its children");
  assert.doesNotMatch(html, /data-t="deny"/, "Protect does not render the fallback");
});

test("signed out: SignedOut shows, SignedIn hides, Protect shows the fallback", () => {
  const html = renderHarness("signedOut");
  assert.doesNotMatch(html, /data-t="in"/);
  assert.match(html, /data-t="out"/);
  assert.doesNotMatch(html, /data-t="allow"/);
  assert.match(html, /data-t="deny"/, "Protect falls back when signed out");
});

test("loading: neither SignedIn nor SignedOut renders, and Protect stays empty", () => {
  const html = renderHarness("loading");
  assert.doesNotMatch(html, /data-t="in"/, "no signed-in flash before /me resolves");
  assert.doesNotMatch(html, /data-t="out"/, "no signed-out flash before /me resolves");
  assert.doesNotMatch(html, /data-t="allow"/);
  assert.doesNotMatch(html, /data-t="deny"/, "Protect renders nothing at all while loading");
});

test("SignInButton renders a button with custom children and class", () => {
  const html = renderHarness("signedOut");
  assert.match(html, /<button[^>]*class="cta"[^>]*>\s*Continue\s*<\/button>/);
});

test("SignUpButton renders its default label and class", () => {
  assert.match(renderHarness("signedOut"), /<button[^>]*class="join"[^>]*>\s*Sign up\s*<\/button>/);
});

test("SignOutButton renders its default label", () => {
  const html = renderHarness("signedOut");
  assert.match(html, /Sign out/);
});

test("UserButton shows the user's label and hides entirely when signed out", () => {
  const signedIn = renderHarness("signedIn", { sub: "u1", email: "a@b.com", preferredUsername: "alice" });
  assert.match(signedIn, /data-proteles="user-button"/);
  assert.match(signedIn, /data-proteles="user-label">alice</, "prefers preferredUsername");
  assert.match(signedIn, /data-proteles="user-signout"/);

  const signedOut = renderHarness("signedOut");
  assert.doesNotMatch(signedOut, /data-proteles="user-button"/, "renders nothing without a user");
});

test("UserButton falls back to email, then sub", () => {
  assert.match(renderHarness("signedIn", { sub: "u1", email: "a@b.com" }), /user-label">a@b\.com</);
  assert.match(renderHarness("signedIn", { sub: "just-sub" }), /user-label">just-sub</);
});

test("UserButton passes through its class", () => {
  assert.match(renderHarness("signedIn"), /class="chip"/);
});

test("AuthProvider renders during SSR without touching the network", () => {
  // AuthProvider builds its own store internally, so stub the *global* fetch to
  // prove nothing is requested while server-rendering (onMount never runs).
  const realFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = (async () => {
    calls++;
    return new Response("{}", { headers: { "content-type": "application/json" } });
  }) as typeof fetch;
  try {
    const body = render(AuthProvider, { props: { initialUser: { sub: "u1" } } }).body;
    assert.equal(typeof body, "string", "provider renders");
    assert.equal(calls, 0, "no network during server rendering");
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("<AuthProvider> stops its store asking a busy /me once it is destroyed", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const realFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = (async () => {
    calls++;
    return new Response(null, { status: 503 });
  }) as typeof fetch;
  try {
    let store: AuthStore | undefined;
    // `onDestroy` is the one lifecycle hook Svelte runs on the server, after
    // the render, so rendering is enough to see the provider go.
    void render(ProviderProbe, { props: { basePath: "/probe", capture: (s: AuthStore) => (store = s) } }).body;
    assert.equal(store?.basePath, "/probe", "the probe holds the provider's own store");
    await store!.reload();
    t.mock.timers.tick(60_000);
    await settle();
    assert.equal(calls, 1, "a store whose provider has gone asks once, and not again");

    // The control: a store no provider owns does ask again.
    await createAuthStore({ basePath: "/probe" }).reload();
    t.mock.timers.tick(2_000);
    await settle();
    assert.equal(calls, 3);
  } finally {
    globalThis.fetch = realFetch;
  }
});

/** Lets a `/me` the mocked clock just fired run to its end. */
async function settle(): Promise<void> {
  for (let i = 0; i < 10; i++) await new Promise((resolve) => setImmediate(resolve));
}

test("a component used outside <AuthProvider> throws an actionable error", async () => {
  const SignedIn = (await compileAndImport(src("SignedIn.svelte"), [])) as never;
  // NOTE: `render()` is lazy — the component body only executes when `.body` is
  // read, so the assertion must read it or nothing would run at all.
  assert.throws(
    () => render(SignedIn, { props: {} }).body,
    /getAuth\(\) must be called inside an <AuthProvider>/,
    "missing provider must fail loudly, not render silently",
  );
});
