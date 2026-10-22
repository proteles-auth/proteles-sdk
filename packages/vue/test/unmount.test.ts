//! Unmounting: what `<AuthProvider>` and the plugin do when they go.
//! `renderToString` never mounts, so these use a renderer whose "elements" are
//! plain objects — enough for Vue to run a component's whole life in Node,
//! `onMounted` to unmount.
//!
//! A file of their own because a `setup()` that throws under `renderToString`,
//! as one in `components.test.ts` does on purpose, leaves Vue believing it is
//! still in a server setup, and from then on it drops every `onMounted` it is
//! given.

import { test } from "node:test";
import assert from "node:assert/strict";
import { createRenderer, defineComponent } from "vue";

import { AuthProvider } from "../src/components.ts";
import { protelesAuth } from "../src/context.ts";

interface Box {
  children: Box[];
  parent: Box | null;
}

const boxes = createRenderer<Box, Box>({
  createElement: () => ({ children: [], parent: null }),
  createText: () => ({ children: [], parent: null }),
  createComment: () => ({ children: [], parent: null }),
  setText: () => {},
  setElementText: () => {},
  patchProp: () => {},
  insert(child, parent, anchor) {
    child.parent = parent;
    const at = anchor ? parent.children.indexOf(anchor) : -1;
    parent.children.splice(at < 0 ? parent.children.length : at, 0, child);
  },
  remove(child) {
    const siblings = child.parent?.children;
    siblings?.splice(siblings.indexOf(child), 1);
    child.parent = null;
  },
  parentNode: (node) => node.parent,
  nextSibling(node) {
    const siblings = node.parent?.children;
    return siblings?.[siblings.indexOf(node) + 1] ?? null;
  },
});

/** Lets a `/me` and whatever it scheduled run to their end. */
async function settle(): Promise<void> {
  for (let i = 0; i < 10; i++) await new Promise((resolve) => setImmediate(resolve));
}

/** Answers every `/me` with `503` through the global fetch, which is the one
 *  `<AuthProvider>` and the plugin use, and counts the calls. */
function busyEverywhere(): { calls: () => number; restore: () => void } {
  const realFetch = globalThis.fetch;
  let n = 0;
  globalThis.fetch = (async () => {
    n++;
    return new Response(null, { status: 503 });
  }) as typeof fetch;
  return { calls: () => n, restore: () => (globalThis.fetch = realFetch) };
}

test("an unmounted <AuthProvider> stops asking a busy /me", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const me = busyEverywhere();
  try {
    const app = boxes.createApp(AuthProvider);
    app.mount({ children: [], parent: null });
    await settle();
    assert.equal(me.calls(), 1, "it asked on mount");
    t.mock.timers.tick(2_000);
    await settle();
    assert.equal(me.calls(), 2, "and again after the busy answer, while mounted");

    app.unmount();
    t.mock.timers.tick(60_000);
    await settle();
    assert.equal(me.calls(), 2, "but not once it has gone");
  } finally {
    me.restore();
  }
});

test("the protelesAuth plugin stops asking a busy /me when its app unmounts", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const me = busyEverywhere();
  try {
    const plugin = protelesAuth();
    const app = boxes.createApp(defineComponent({ render: () => null }));
    app.use(plugin);
    app.mount({ children: [], parent: null });
    await plugin.auth.reload(); // `install` asks only in a browser
    t.mock.timers.tick(2_000);
    await settle();
    assert.equal(me.calls(), 2, "it asks again after the busy answer while the app is up");

    app.unmount();
    t.mock.timers.tick(60_000);
    await settle();
    assert.equal(me.calls(), 2, "but not once the app has gone");
  } finally {
    me.restore();
  }
});
