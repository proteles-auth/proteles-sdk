import { test } from "node:test";
import assert from "node:assert/strict";

import { protelesAuth } from "../src/plugin.ts";
import type { AuthStore } from "../src/types.ts";
import { createStubAlpine, stubElement } from "./stub-alpine.ts";

const json = (obj: unknown, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json" } });

const noFetch = (async () => json({ authenticated: false })) as typeof fetch;

test("registers the store, the magic, and both directives", () => {
  const Alpine = createStubAlpine();
  Alpine.store("noop"); // ensure a read of a missing store is harmless
  protelesAuth({ initialUser: null, fetch: noFetch, revalidateOnInit: false })(Alpine);

  assert.ok(Alpine.store("proteles"), "the store is registered under its default name");
  assert.deepEqual(Alpine.registeredMagics, ["auth"]);
  assert.deepEqual(Alpine.registeredDirectives.sort(), ["signed-in", "signed-out"]);
});

test("store and magic names are configurable", () => {
  const Alpine = createStubAlpine();
  protelesAuth({
    storeName: "myauth",
    magicName: "session",
    initialUser: null,
    fetch: noFetch,
    revalidateOnInit: false,
  })(Alpine);

  assert.ok(Alpine.store("myauth"), "registered under the custom name");
  assert.equal(Alpine.store("proteles"), undefined, "not registered under the default");
  assert.deepEqual(Alpine.registeredMagics, ["session"]);
});

test("$auth resolves to the registered (reactive) store, not the raw object", async () => {
  const Alpine = createStubAlpine();
  const plugin = protelesAuth({
    initialUser: null,
    fetch: (async () => json({ authenticated: true, user: { sub: "u1" } })) as typeof fetch,
    revalidateOnInit: false,
  });
  plugin(Alpine);

  const magicStore = Alpine.readMagic("auth") as AuthStore;
  assert.equal(magicStore, Alpine.store("proteles"), "$auth is the store Alpine registered");
  assert.notEqual(magicStore, plugin.store, "…which is the reactive wrapper, not the raw object");

  // Mutating through the magic must be visible on the store, and vice versa.
  await magicStore.reload();
  assert.equal((Alpine.store("proteles") as AuthStore).user?.sub, "u1");
});

test("the plugin exposes the raw store for direct access", () => {
  const plugin = protelesAuth({ initialUser: { sub: "u1" }, fetch: noFetch, revalidateOnInit: false });
  assert.equal(plugin.store.user?.sub, "u1");
  assert.equal(plugin.store.isAuthenticated, true);
});

test("Alpine's init() hook revalidates on registration", async () => {
  let calls = 0;
  const Alpine = createStubAlpine();
  protelesAuth({
    fetch: (async () => {
      calls++;
      return json({ authenticated: true, user: { sub: "u1" } });
    }) as typeof fetch,
  })(Alpine);

  // The stub calls init() exactly as Alpine does when a store is registered.
  await new Promise((r) => setTimeout(r, 0));
  assert.equal(calls, 1, "init() triggered one revalidation");
  const store = Alpine.store("proteles") as AuthStore;
  assert.equal(store.user?.sub, "u1");
  assert.equal(store.isLoading, false);
});

test("revalidateOnInit:false skips the request (for a page that already seeded the user)", async () => {
  let calls = 0;
  const Alpine = createStubAlpine();
  protelesAuth({
    initialUser: { sub: "seeded" },
    revalidateOnInit: false,
    fetch: (async () => {
      calls++;
      return json({ authenticated: false });
    }) as typeof fetch,
  })(Alpine);

  await new Promise((r) => setTimeout(r, 0));
  assert.equal(calls, 0, "no network on init");
  assert.equal((Alpine.store("proteles") as AuthStore).user?.sub, "seeded");
});

// --- the visibility directives -------------------------------------------

/** Registers the plugin in a given state and returns the store + Alpine stub. */
function setup(state: "signedIn" | "signedOut" | "loading") {
  const Alpine = createStubAlpine();
  const options =
    state === "loading"
      ? { fetch: noFetch, revalidateOnInit: false } // initialUser undefined => isLoading
      : { initialUser: state === "signedIn" ? { sub: "u1" } : null, fetch: noFetch, revalidateOnInit: false };
  protelesAuth(options)(Alpine);
  return { Alpine, store: Alpine.store("proteles") as AuthStore };
}

test("x-signed-in shows only when authenticated, x-signed-out only when not", () => {
  for (const [state, expectIn, expectOut] of [
    ["signedIn", "", "none"],
    ["signedOut", "none", ""],
  ] as const) {
    const { Alpine } = setup(state);
    const inEl = stubElement();
    const outEl = stubElement();
    Alpine.runDirective("signed-in", inEl);
    Alpine.runDirective("signed-out", outEl);
    assert.equal(inEl.style.display, expectIn, `${state}: x-signed-in`);
    assert.equal(outEl.style.display, expectOut, `${state}: x-signed-out`);
  }
});

test("while loading, BOTH directives hide — no flash of the wrong UI", () => {
  const { Alpine } = setup("loading");
  const inEl = stubElement();
  const outEl = stubElement();
  Alpine.runDirective("signed-in", inEl);
  Alpine.runDirective("signed-out", outEl);
  assert.equal(inEl.style.display, "none", "signed-in content stays hidden");
  assert.equal(outEl.style.display, "none", "signed-out content stays hidden too");
});

test("an element is hidden before the effect runs, not after (flash prevention)", () => {
  // The ordering is the whole point: if the directive only set `display` inside
  // its effect, the element would be visible until that first run. Record every
  // write to `display` and assert "none" comes first — even for a signed-in user,
  // where the effect's own conclusion is to show the element.
  const Alpine = createStubAlpine();
  protelesAuth({ initialUser: { sub: "u1" }, fetch: noFetch, revalidateOnInit: false })(Alpine);

  const writes: string[] = [];
  const recordingEl = {
    style: {
      _display: "flex",
      get display() {
        return this._display;
      },
      set display(v: string) {
        this._display = v;
        writes.push(v);
      },
    },
  };

  Alpine.runDirective("signed-in", recordingEl as never);

  assert.deepEqual(writes, ["none", "flex"], "hidden first, then revealed by the effect");
  assert.equal(recordingEl.style.display, "flex", "ends visible for a signed-in user");
});

test("the directives track store changes (signing in reveals signed-in content)", async () => {
  const Alpine = createStubAlpine();
  protelesAuth({
    initialUser: null,
    revalidateOnInit: false,
    fetch: (async () => json({ authenticated: true, user: { sub: "u1" } })) as typeof fetch,
  })(Alpine);

  const inEl = stubElement();
  const outEl = stubElement();
  Alpine.runDirective("signed-in", inEl);
  Alpine.runDirective("signed-out", outEl);
  assert.equal(inEl.style.display, "none", "starts hidden while signed out");
  assert.equal(outEl.style.display, "");

  await (Alpine.store("proteles") as AuthStore).reload();
  assert.equal(inEl.style.display, "", "revealed after the store reports a user");
  assert.equal(outEl.style.display, "none", "and the signed-out branch hides");
});

test("a directive preserves a meaningful original display value", () => {
  const { Alpine } = setup("signedIn");
  const el = stubElement("flex");
  Alpine.runDirective("signed-in", el);
  assert.equal(el.style.display, "flex", "restores the element's own display, not a bare ''");
});
