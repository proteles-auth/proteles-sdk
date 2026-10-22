// Give the generated component declarations the import they reference.
//
// `svelte-package` (svelte2tsx) emits, for every component:
//
//     export default SignInButton;
//     type SignInButton = SvelteComponent<…>;          // <- bare, unimported
//     declare const SignInButton: $$__sveltets_2_IsomorphicComponent<…>;
//
// The `SvelteComponent` on the second line names nothing. Further down the same
// file the generator writes `import("svelte").SvelteComponent<…>`, which is
// fine — an inline import type — so the file looks like it imports the name
// when grepped, and does not.
//
// For a consumer that is eight `error TS2304: Cannot find name
// 'SvelteComponent'`, raised from inside `node_modules`, on nothing worse than
// `import { createAuthStore } from "@proteles/svelte"` — the barrel re-exports
// all eight components, so any import at all pulls them in. It is invisible to
// anyone with `skipLibCheck: true`, which most SvelteKit templates set and
// TypeScript itself does not.
//
// This is current upstream behaviour, not a stale toolchain: `@sveltejs/package`
// is pinned at ^2.3.7 and resolves to 2.5.8, which is the latest published
// version. So it is patched here rather than waited out.
//
// The import is prepended rather than the dangling line deleted, because
// `export default X` exports both the type and the value, and dropping the type
// alias would quietly narrow what `import type X from "@proteles/svelte/…"`
// means for anyone already relying on it.
//
// Idempotent, and it fails rather than guesses: if the generator stops emitting
// the bare reference, this says so instead of silently doing nothing, because a
// no-op post-build step that nobody notices is how a build step rots.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const DIST = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../dist");
const IMPORT = 'import { SvelteComponent } from "svelte";';

// `SvelteComponent<` not preceded by `import("svelte").` — i.e. the bare use.
const BARE = /(?<!import\("svelte"\)\.)\bSvelteComponent\s*</;

if (!fs.existsSync(DIST)) {
  console.error(`fix-component-dts: no dist/ at ${DIST} — run svelte-package first`);
  process.exit(1);
}

const files = fs.readdirSync(DIST).filter((f) => f.endsWith(".svelte.d.ts"));
if (files.length === 0) {
  console.error("fix-component-dts: no *.svelte.d.ts in dist/ — the build produced no components");
  process.exit(1);
}

let patched = 0;
let already = 0;
let clean = 0;

for (const f of files) {
  const p = path.join(DIST, f);
  const src = fs.readFileSync(p, "utf8");

  if (src.startsWith(IMPORT)) { already++; continue; }
  if (!BARE.test(src)) { clean++; continue; }

  fs.writeFileSync(p, `${IMPORT}\n${src}`);
  patched++;
}

// If nothing needed the import and nothing already had it, the generator's
// output shape changed. That is good news, but it means this step is dead code
// and should be deleted rather than left to imply it is doing something.
if (patched === 0 && already === 0) {
  console.error(
    `fix-component-dts: all ${files.length} declarations are already free of the bare ` +
    `SvelteComponent reference. svelte2tsx appears to have been fixed upstream — ` +
    `delete this script and the build step that calls it.`,
  );
  process.exit(1);
}

console.log(
  `fix-component-dts: ${patched} patched, ${already} already had the import, ${clean} did not need it`,
);
