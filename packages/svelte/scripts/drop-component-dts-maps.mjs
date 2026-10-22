// Remove the declaration maps of the generated component declarations.
//
// With `declarationMap` on (tsconfig.base.json says why the packages ship maps
// and `src/`), `svelte-package` writes a `.d.ts.map` beside every declaration.
// For the `.ts` modules those are tsc's own and resolve into the shipped
// `src/`. For the components they do not: svelte2tsx first turns
// `SignInButton.svelte` into an intermediate `SignInButton.svelte.js`, tsc
// declares *that*, and the map it writes names
//
//     "sources": ["../src/SignInButton.svelte.js"]
//
// a file that exists nowhere, with positions in the intermediate rather than
// in the `.svelte` file a reader would want. Pointing it at the `.svelte`
// instead would resolve and be wrong: the line numbers are svelte2tsx's. And
// `fix-component-dts.mjs` prepends a line to each of these declarations, which
// would shift every mapping by one even if they were right.
//
// So the component maps are removed, with the `//# sourceMappingURL` comment
// that names them: a map that cannot resolve is the dangling kind the
// workspace stopped shipping. An editor's "go to definition" on a component
// lands in its `.d.ts`, as it would with the broken map.
//
// Like fix-component-dts.mjs it fails rather than guesses: if the generator
// ever writes a component map whose sources resolve, this says so instead of
// deleting a good map, because that is the sign this step should go.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const DIST = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../dist");

if (!fs.existsSync(DIST)) {
  console.error(`drop-component-dts-maps: no dist/ at ${DIST} — run svelte-package first`);
  process.exit(1);
}

const maps = fs.readdirSync(DIST).filter((f) => f.endsWith(".svelte.d.ts.map"));
if (maps.length === 0) {
  console.error(
    "drop-component-dts-maps: no *.svelte.d.ts.map in dist/ — svelte-package no longer writes " +
      "component declaration maps (is declarationMap still on?). Delete this script and its build step.",
  );
  process.exit(1);
}

let dropped = 0;
for (const f of maps) {
  const mapPath = path.join(DIST, f);
  const map = JSON.parse(fs.readFileSync(mapPath, "utf8"));
  const resolvable = (map.sources ?? []).every((s) => fs.existsSync(path.resolve(DIST, map.sourceRoot ?? "", s)));
  if (resolvable) {
    console.error(
      `drop-component-dts-maps: ${f} names ${JSON.stringify(map.sources)}, which resolve. ` +
        "svelte-package appears to write usable component maps now — delete this script and its build step.",
    );
    process.exit(1);
  }
  fs.rmSync(mapPath);
  const dts = path.join(DIST, f.replace(/\.map$/, ""));
  if (fs.existsSync(dts)) {
    const text = fs.readFileSync(dts, "utf8");
    fs.writeFileSync(dts, text.replace(/\n?\/\/# sourceMappingURL=\S+\s*$/, "\n"));
  }
  dropped++;
}

console.log(`drop-component-dts-maps: removed ${dropped} component declaration map(s) that named no real file`);
