//! Every module that needs React's client runtime must open with "use client".
//!
//! Next's App Router treats a module with no directive, imported from a Server
//! Component, as server code. `context.ts` had none, `app/layout.tsx` imports
//! `AuthProvider` from this package's index, and `next build` failed on the
//! `createContext` call: "You're importing a component that needs
//! createContext. It only works in a Client Component" (the quickstart under
//! Next 14.2, 2026-09-29). Nothing outside a Next build notices, so this scans
//! the sources for it.

import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const src = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "src");

// React's client-only APIs, and this package's own hooks built on them.
const CLIENT_ONLY =
  /\b(createContext|useState|useEffect|useLayoutEffect|useContext|useMemo|useCallback|useRef|useReducer|useSyncExternalStore|useAuth|useUser)\b/;

/** The source with comments removed, so a mention in prose does not count. */
function code(text: string): string {
  return text.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'`])\/\/.*$/gm, "$1");
}

test('every module that needs the client runtime says "use client" first', () => {
  const needsClient: string[] = [];
  for (const file of fs.readdirSync(src).filter((f) => /\.tsx?$/.test(f) && f !== "index.ts")) {
    const text = fs.readFileSync(path.join(src, file), "utf8");
    // Declaring one of the package's hooks is not using it; `hooks.ts` is
    // flagged anyway, by the `useContext` it calls.
    if (!CLIENT_ONLY.test(code(text))) continue;
    needsClient.push(file);
    assert.match(text, /^"use client";\n/, `${file} uses the client runtime but does not open with "use client"`);
  }
  // The positive control: a scan that matched nothing would pass as well.
  for (const known of ["AuthProvider.tsx", "components.tsx", "context.ts", "hooks.ts"]) {
    assert.ok(needsClient.includes(known), `the scan should have found ${known}`);
  }
});
