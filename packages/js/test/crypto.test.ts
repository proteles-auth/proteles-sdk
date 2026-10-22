import { test } from "node:test";
import assert from "node:assert/strict";

import { randomBytes } from "../src/crypto.ts";

/**
 * Calls `start` with `globalThis.crypto` and/or `globalThis.process` replaced,
 * and puts the originals back before returning. Only the synchronous part of
 * `start` sees the replacements — which is where the runtime is inspected: the
 * async functions under test run up to their first `await` before this returns.
 */
function withGlobals<T>(globals: { crypto?: unknown; process?: unknown }, start: () => T): T {
  const saved = new Map(
    Object.keys(globals).map((k) => [k, Object.getOwnPropertyDescriptor(globalThis, k)] as const),
  );
  for (const [k, v] of Object.entries(globals)) {
    Object.defineProperty(globalThis, k, { value: v, configurable: true, writable: true });
  }
  try {
    return start();
  } finally {
    for (const [k, d] of saved) {
      if (d) Object.defineProperty(globalThis, k, d);
      else delete (globalThis as Record<string, unknown>)[k];
    }
  }
}

// A browser page that is not a secure context (plain http, not localhost) has
// `crypto.getRandomValues` but no `crypto.subtle`, and no Node.
const insecureBrowserCrypto = { getRandomValues: <A>(a: A) => a };

test("a browser page without crypto.subtle is told it needs a secure context, not handed a failed import", async () => {
  const pending = withGlobals({ crypto: insecureBrowserCrypto, process: undefined }, () => randomBytes(8));
  await assert.rejects(pending, /crypto\.subtle.*secure context: serve the page over https, or from localhost/);
});

test("Node without globalThis.crypto.subtle (Node 18) still falls back to node:crypto", async () => {
  // The control for the test above: the same missing `subtle`, but in Node,
  // must not be refused.
  const pending = withGlobals({ crypto: insecureBrowserCrypto }, () => randomBytes(8));
  const bytes = await pending;
  assert.equal(bytes.length, 8);
});
