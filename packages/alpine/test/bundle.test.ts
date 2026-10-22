//! Tests the *built* browser bundle — the artifact a no-build Alpine page loads
//! from a CDN `<script src>`. If it isn't self-contained, or doesn't assign the
//! global, or doesn't register itself on `alpine:init`, that whole audience is
//! broken no matter how well the source behaves.
//!
//! The bundle is evaluated in a tiny fake-window sandbox rather than a real
//! browser (Alpine itself can't load in Node); the genuine end-to-end check runs
//! in an actual browser and is described in the package README.

import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const bundlePath = path.join(here, "..", "dist", "proteles-alpine.js");

const bundleExists = fs.existsSync(bundlePath);
const source = bundleExists ? fs.readFileSync(bundlePath, "utf8") : "";

/** Evaluates the bundle against a fake window/document, returning both. */
function evaluateBundle(options?: unknown) {
  const listeners: Record<string, (() => void)[]> = {};
  const plugins: unknown[] = [];
  const win: Record<string, unknown> = {};
  if (options !== undefined) win["protelesAuthOptions"] = options;
  win["Alpine"] = { plugin: (p: unknown) => plugins.push(p) };

  const doc = {
    addEventListener(event: string, cb: () => void) {
      (listeners[event] ??= []).push(cb);
    },
  };

  // `new Function` keeps the bundle out of this module's scope entirely, so the
  // only globals it can see are the ones passed in.
  const run = new Function("window", "document", "globalThis", source);
  run(win, doc, win);

  return {
    win,
    plugins,
    fireAlpineInit: () => (listeners["alpine:init"] ?? []).forEach((cb) => cb()),
    alpineInitListeners: () => (listeners["alpine:init"] ?? []).length,
  };
}

test("the built bundle exists (run `npm run build` first)", () => {
  assert.ok(bundleExists, `expected a bundle at ${bundlePath}`);
});

test("the bundle is self-contained — no bare import/export or require", { skip: !bundleExists }, () => {
  // A CDN <script> can't resolve module specifiers, so any survivor is fatal.
  assert.doesNotMatch(source, /(^|\n)\s*import\s+[^(]/, "no top-level import statements");
  assert.doesNotMatch(source, /(^|\n)\s*export\s/, "no export statements");
  assert.doesNotMatch(source, /\brequire\s*\(\s*["'][a-z@]/i, "no bare requires");
});

test("the bundle assigns window.protelesAuth", { skip: !bundleExists }, () => {
  const { win } = evaluateBundle();
  assert.equal(typeof win["protelesAuth"], "function", "the global factory is exposed");
});

test("the bundle registers itself with Alpine on alpine:init", { skip: !bundleExists }, () => {
  const ctx = evaluateBundle();
  assert.equal(ctx.alpineInitListeners(), 1, "one alpine:init listener");
  assert.equal(ctx.plugins.length, 0, "nothing registered before the event");

  ctx.fireAlpineInit();
  assert.equal(ctx.plugins.length, 1, "the plugin is handed to Alpine.plugin()");
  assert.equal(typeof ctx.plugins[0], "function", "and it is a plugin function");
});

test("the bundle forwards window.protelesAuthOptions to the plugin", { skip: !bundleExists }, () => {
  const ctx = evaluateBundle({ basePath: "/custom/auth", revalidateOnInit: false });
  ctx.fireAlpineInit();
  const plugin = ctx.plugins[0] as { store: { basePath: string } };
  assert.equal(plugin.store.basePath, "/custom/auth", "options reached the store");
});

test("setting protelesAuthOptions to null opts out of auto-registration", { skip: !bundleExists }, () => {
  const ctx = evaluateBundle(null);
  ctx.fireAlpineInit();
  assert.equal(ctx.plugins.length, 0, "the page wires the plugin up itself");
  assert.equal(typeof ctx.win["protelesAuth"], "function", "but the factory is still available");
});

test("the bundle stays small enough to be a comfortable CDN include", { skip: !bundleExists }, () => {
  const kb = Buffer.byteLength(source) / 1024;
  assert.ok(kb < 20, `bundle is ${kb.toFixed(1)}kb, expected well under 20kb`);
});
