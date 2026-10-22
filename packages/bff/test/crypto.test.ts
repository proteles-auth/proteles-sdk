import { test } from "node:test";
import assert from "node:assert/strict";

import { randomBytes, subtle } from "../src/crypto.ts";

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

const noSubtle = { getRandomValues: <A>(a: A) => a };

test("a runtime with no crypto.subtle that is not Node gets an error naming what is missing", async () => {
  await assert.rejects(
    withGlobals({ crypto: noSubtle, process: undefined }, () => subtle()),
    /crypto\.subtle\) is unavailable in this runtime/,
  );
  await assert.rejects(
    withGlobals({ crypto: noSubtle, process: undefined }, () => randomBytes(8)),
    /crypto\.subtle\) is unavailable in this runtime/,
  );
});

test("Node without globalThis.crypto.subtle (Node 18) still falls back to node:crypto", async () => {
  // The control: the same missing `subtle`, but in Node, must not be refused.
  const s = await withGlobals({ crypto: noSubtle }, () => subtle());
  assert.equal(typeof s.digest, "function");
  const bytes = await withGlobals({ crypto: noSubtle }, () => randomBytes(8));
  assert.equal(bytes.length, 8);
});
