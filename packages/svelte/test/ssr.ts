//! Test helper: compiles `.svelte` sources to server-side JS so they can be
//! imported and rendered with `svelte/server` under plain Node — no bundler and
//! no jsdom. Not a test file itself (`ssr.ts` doesn't match `*.test.ts`).
//!
//! Output goes to a gitignored `.ssr/` directory at the package root, never into
//! `src/` — anything left in `src/` would be copied into `dist/` by
//! `svelte-package` and shipped. Because the output is flattened into one
//! directory, imports are rewritten as they're emitted:
//!   * `…/Foo.svelte`   → `./Foo.svelte.ssr.mjs` (compiled sibling)
//!   * any other relative import (`./context.js`, `../../src/store.js`)
//!                      → `../src/<basename>` (the real module, run by tsx)

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { compile } from "svelte/compiler";

const SUFFIX = ".svelte.ssr.mjs";
const OUT_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", ".ssr");

function rewriteImports(code: string): string {
  return code.replace(/(['"])(\.[^'"]+)\1/g, (_match, quote: string, spec: string) => {
    const base = path.basename(spec);
    if (spec.endsWith(".svelte")) {
      return `${quote}./${path.basename(spec, ".svelte")}${SUFFIX}${quote}`;
    }
    return `${quote}../src/${base}${quote}`;
  });
}

/** Compiles one component into `.ssr/` and returns the emitted path. */
function compileOne(sveltePath: string): string {
  const name = path.basename(sveltePath, ".svelte");
  const { js } = compile(fs.readFileSync(sveltePath, "utf8"), {
    generate: "server",
    name,
    filename: sveltePath,
  });
  fs.mkdirSync(OUT_DIR, { recursive: true });
  const outPath = path.join(OUT_DIR, `${name}${SUFFIX}`);
  fs.writeFileSync(outPath, rewriteImports(js.code));
  return outPath;
}

/**
 * Compiles every given `.svelte` file, then dynamically imports `entry` and
 * returns its default export (the component).
 */
export async function compileAndImport(entry: string, alsoCompile: string[] = []): Promise<unknown> {
  let entryOut = "";
  for (const file of [...alsoCompile, entry]) {
    const emitted = compileOne(file);
    if (file === entry) entryOut = emitted;
  }
  const mod = (await import(entryOut)) as { default: unknown };
  return mod.default;
}

/** Strips Svelte's SSR hydration comments so assertions read cleanly. */
export function clean(html: string): string {
  return html.replace(/<!--.*?-->/g, "").replace(/\s+/g, " ").trim();
}
