// Build for a Solid library. Unlike the other packages, `tsc` alone isn't
// enough: Solid's JSX is compiled by its own Babel preset, and it compiles
// *differently* for the browser (fine-grained DOM updates) than for SSR (string
// concatenation). So we emit three things, matching the conventional Solid
// package layout and the `exports` map in package.json:
//
//   dist/source/  untranspiled JSX — used via the "solid" export condition, so a
//                 consumer's own build (vite-plugin-solid) compiles it for
//                 whichever target they're building. This is the preferred path.
//   dist/dom/     precompiled with generate:"dom", for bundlers that ignore the
//                 "solid" condition.
//   dist/ssr/     precompiled with generate:"ssr", for Node/SSR resolution.
//   dist/api/     the ./server entry (plain TS, no JSX).
//   dist/*.d.ts   types, from tsc, mirroring `src` (so `src/server/index.ts`
//                 types land at `dist/server/index.d.ts`). The compiled output
//                 deliberately uses different directory names than tsc's layout
//                 so the two can never collide.
//
// Types come from `tsc --emitDeclarationOnly`; everything else from Babel.

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { transformAsync } from "@babel/core";

const root = path.dirname(fileURLToPath(import.meta.url));
const srcDir = path.join(root, "src");
const distDir = path.join(root, "dist");

/** Every file under `src`, relative to it. */
function walk(dir, base = "") {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const rel = path.join(base, entry.name);
    if (entry.isDirectory()) out.push(...walk(path.join(dir, entry.name), rel));
    else out.push(rel);
  }
  return out;
}

/** `./x.jsx` and `./x.js` specifiers both resolve to emitted `.js` files. */
function rewriteSpecifiers(code) {
  return code.replace(/(from\s+['"])(\.[^'"]+)\.jsx(['"])/g, "$1$2.js$3");
}

async function compile(files, generate, outBase) {
  for (const rel of files) {
    const source = fs.readFileSync(path.join(srcDir, rel), "utf8");
    const { code } = await transformAsync(source, {
      filename: path.join(srcDir, rel),
      babelrc: false,
      configFile: false,
      presets: [
        ["babel-preset-solid", { generate, hydratable: generate === "ssr" ? false : true }],
        ["@babel/preset-typescript", { isTSX: rel.endsWith(".tsx"), allExtensions: true }],
      ],
    });
    const outPath = path.join(outBase, rel.replace(/\.tsx?$/, ".js"));
    fs.mkdirSync(path.dirname(outPath), { recursive: true });
    fs.writeFileSync(outPath, rewriteSpecifiers(code));
  }
}

fs.rmSync(distDir, { recursive: true, force: true });

const all = walk(srcDir).filter((f) => /\.tsx?$/.test(f));
// The ./server entry is plain TS with no JSX and no Solid runtime — it must not
// be duplicated into the client/server JSX bundles.
const serverEntry = all.filter((f) => f.startsWith(`server${path.sep}`));
const appFiles = all.filter((f) => !serverEntry.includes(f));

// 1. Untranspiled JSX source for the "solid" condition (types stripped, JSX kept).
for (const rel of appFiles) {
  const source = fs.readFileSync(path.join(srcDir, rel), "utf8");
  const { code } = await transformAsync(source, {
    filename: path.join(srcDir, rel),
    babelrc: false,
    configFile: false,
    presets: [["@babel/preset-typescript", { isTSX: rel.endsWith(".tsx"), allExtensions: true }]],
  });
  const outPath = path.join(distDir, "source", rel.replace(/\.tsx$/, ".jsx").replace(/\.ts$/, ".js"));
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  // Inside dist/source, JSX files keep the .jsx extension so a consumer's Solid
  // plugin picks them up.
  fs.writeFileSync(outPath, code.replace(/(from\s+['"])(\.[^'"]+)\.jsx(['"])/g, "$1$2.jsx$3"));
}

// 2/3. Precompiled client and server bundles.
await compile(appFiles, "dom", path.join(distDir, "dom"));
await compile(appFiles, "ssr", path.join(distDir, "ssr"));

// 4. The ./server entry (no JSX). Flattened: src/server/index.ts -> dist/api/index.js
for (const rel of serverEntry) {
  const source = fs.readFileSync(path.join(srcDir, rel), "utf8");
  const { code } = await transformAsync(source, {
    filename: path.join(srcDir, rel),
    babelrc: false,
    configFile: false,
    presets: [["@babel/preset-typescript", { allExtensions: true }]],
  });
  const outPath = path.join(distDir, "api", path.basename(rel).replace(/\.ts$/, ".js"));
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, rewriteSpecifiers(code));
}

// 5. Types.
execFileSync(
  process.execPath,
  [path.join(root, "..", "..", "node_modules", "typescript", "bin", "tsc"), "-p", "tsconfig.json", "--emitDeclarationOnly", "--declaration", "--outDir", "dist"],
  { cwd: root, stdio: "inherit" },
);

console.log("@proteles/solid: built dist/{source,dom,ssr,api} + types");
