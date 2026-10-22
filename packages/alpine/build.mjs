// Two outputs, because Alpine has two very different audiences:
//
//   dist/*.js + .d.ts       ESM + types, via tsc — for bundler users.
//   dist/proteles-alpine.js a standalone IIFE, via esbuild — for the no-build
//                           majority who load Alpine from a CDN `<script src>`.
//                           It must be self-contained (no bare imports) and
//                           assign `window.protelesAuth`.

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import * as esbuild from "esbuild";

const root = path.dirname(fileURLToPath(import.meta.url));
const dist = path.join(root, "dist");

fs.rmSync(dist, { recursive: true, force: true });

// 1. ESM + types.
execFileSync(
  process.execPath,
  [path.join(root, "..", "..", "node_modules", "typescript", "bin", "tsc"), "-p", "tsconfig.json"],
  { cwd: root, stdio: "inherit" },
);

// 2. The standalone browser bundle.
await esbuild.build({
  entryPoints: [path.join(root, "src", "browser.ts")],
  outfile: path.join(dist, "proteles-alpine.js"),
  bundle: true,
  format: "iife",
  globalName: "protelesAuthBundle",
  platform: "browser",
  target: "es2019",
  minify: true,
  sourcemap: true,
  legalComments: "none",
});

const bundle = fs.readFileSync(path.join(dist, "proteles-alpine.js"), "utf8");
if (/(^|\n)\s*(import|export)\s/.test(bundle)) {
  throw new Error("browser bundle is not self-contained (found an import/export statement)");
}
console.log(`@proteles/alpine: built ESM + types, and a ${(bundle.length / 1024).toFixed(1)}kb standalone bundle`);
