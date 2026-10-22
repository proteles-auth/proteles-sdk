// Everything that has to be true before `npm publish` produces something a
// stranger can actually install.
//
// The failure this exists for is specific and one-way: npm refuses to republish
// a version, ever. A package that ships with a broken `repository`, a README
// full of links that 404, a dependency on a version nobody published, or — the
// sharpest one — no `publishConfig.access`, so a *scoped* package goes out
// restricted and the README's own install line cannot resolve it, is not a bug
// you fix by pushing a commit. You fix it by burning a version number in
// public. So the checks run before the publish, not after it.
//
// Each rule below is one that was actually broken here before this file
// existed. None of them are hypothetical.
//
// What this does NOT do is prove the code works — that is `npm test`'s 300-odd
// tests and the live runs in scripts/. This is strictly about the
// packaging: the metadata, the tarball's contents, and the claims the README
// makes to someone who has never seen the repository.
//
//   node tools/npm-publish-readiness.mjs        # this repository
//   node tools/npm-publish-readiness-test.mjs   # each rule, seen to fail

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

// `ROOT_OVERRIDE` exists for this check's own test, which drives it against
// fixture trees where each rule is broken one at a time. A check of this shape
// — eight loops that all pass over an empty or well-formed list — is exactly
// the kind that can be green because it is broken, so it is not enough for it
// to pass here; it has to have been *seen* to fail.
const ROOT = process.env.ROOT_OVERRIDE
  ? path.resolve(process.env.ROOT_OVERRIDE)
  : path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const PKGDIR = path.join(ROOT, "packages");
// The repository every package names. `npm publish --provenance` compares it
// with the repository the publishing workflow ran in and refuses a mismatch,
// and npm's "Repository" link is all a reader has to find the source.
const REPOSITORY_URL = "git+https://github.com/proteles-auth/proteles-sdk.git";
// The floor below is the real workspace's size; a fixture tree declares its own.
const MIN_PACKAGES = Number(process.env.MIN_PACKAGES ?? 10);

let pass = 0;
let fail = 0;
const ok = (m) => { console.log(`  ✓ ${m}`); pass++; };
const no = (m, detail) => {
  console.log(`  ✗ ${m}`);
  for (const d of [].concat(detail ?? [])) console.log(`      ${d}`);
  fail++;
};

// ---------------------------------------------------------------------------
// Load every publishable package.
// ---------------------------------------------------------------------------

const packages = fs.readdirSync(PKGDIR)
  .map((name) => ({ name, dir: path.join(PKGDIR, name) }))
  .filter((p) => fs.existsSync(path.join(p.dir, "package.json")))
  .map((p) => ({ ...p, json: JSON.parse(fs.readFileSync(path.join(p.dir, "package.json"), "utf8")) }))
  .filter((p) => p.json.private !== true);

// A guard, not a formality: every rule below is a loop, and a loop over an
// empty list passes. A glob that stopped matching would turn this whole file
// green while checking nothing — which is the exact failure mode it exists to
// prevent elsewhere.
if (packages.length < MIN_PACKAGES) {
  console.log(`FATAL: found only ${packages.length} publishable packages under packages/ — the discovery is wrong`);
  process.exit(1);
}
const byName = new Map(packages.map((p) => [p.json.name, p]));

// ---------------------------------------------------------------------------
// 1. The licence is a file, not just a claim in a field.
// ---------------------------------------------------------------------------
// Every package declared `"license": "MIT"` with no MIT text anywhere in the
// repository. npm always includes a LICENSE in the tarball regardless of
// `files`, so the fix is a real file per package — a declaration with no text
// gives a consumer's licence scanner nothing to find.

const rootLicense = fs.readFileSync(path.join(ROOT, "LICENSE"), "utf8");
{
  const bad = [];
  for (const p of packages) {
    const f = path.join(p.dir, "LICENSE");
    if (!fs.existsSync(f)) bad.push(`${p.json.name}: no LICENSE file`);
    else if (fs.readFileSync(f, "utf8") !== rootLicense) bad.push(`${p.json.name}: LICENSE differs from the root one`);
    else if (p.json.license !== "MIT") bad.push(`${p.json.name}: ships the MIT text but declares "${p.json.license}"`);
  }
  bad.length ? no("every package ships the licence it declares", bad) : ok(`every package ships the licence it declares (${packages.length} × MIT)`);
}

// ---------------------------------------------------------------------------
// 2. Scoped packages publish public.
// ---------------------------------------------------------------------------
// The default for a scoped name is `restricted`. On a free account the publish
// fails; on a paid one it silently succeeds *privately*, and the package page
// tells anonymous readers the package does not exist.

{
  const bad = packages
    .filter((p) => p.json.name.startsWith("@") && p.json.publishConfig?.access !== "public")
    .map((p) => `${p.json.name}: publishConfig.access is ${JSON.stringify(p.json.publishConfig?.access)}, not "public"`);
  bad.length ? no("every scoped package is marked for public access", bad) : ok("every scoped package is marked for public access");
}

// ---------------------------------------------------------------------------
// 3. `repository` points at this repository, and at the package that declares it.
// ---------------------------------------------------------------------------
// Wrong here and npm's "Repository" link lands on another package's source —
// or on the private repository these packages moved out of — and
// `--provenance` refuses the publish, or attests to the wrong subtree.

{
  const bad = [];
  for (const p of packages) {
    const r = p.json.repository;
    if (!r?.url) { bad.push(`${p.json.name}: no repository.url`); continue; }
    if (r.url !== REPOSITORY_URL) bad.push(`${p.json.name}: repository.url is "${r.url}", should be "${REPOSITORY_URL}"`);
    const expected = path.relative(ROOT, p.dir).split(path.sep).join("/");
    if (r.directory !== expected) bad.push(`${p.json.name}: repository.directory is "${r.directory}", should be "${expected}"`);
  }
  bad.length ? no("every repository names this repository and its own package", bad) : ok("every repository names this repository and its own package");
}

// ---------------------------------------------------------------------------
// 4. Cross-package ranges are satisfiable by what this workspace would publish.
// ---------------------------------------------------------------------------
// These are real semver ranges, not `workspace:*`, so npm resolves them from
// the registry at install time. A package published while depending on
// `^0.2.0` of a sibling still sitting at `0.1.0` is broken for every consumer
// and unfixable at that version number.
//
// Deliberately narrow: this understands the `^x.y.z` these all use and says so
// rather than guessing at anything more exotic.

{
  const bad = [];
  for (const p of packages) {
    for (const field of ["dependencies", "peerDependencies"]) {
      for (const [dep, range] of Object.entries(p.json[field] ?? {})) {
        if (!dep.startsWith("@proteles/")) continue;
        const target = byName.get(dep);
        if (!target) { bad.push(`${p.json.name} depends on ${dep}, which this workspace does not build`); continue; }
        const m = /^\^(\d+)\.(\d+)\.(\d+)$/.exec(range);
        if (!m) { bad.push(`${p.json.name} -> ${dep}: range "${range}" is not the ^x.y.z this check understands`); continue; }
        const [, ma, mi, pa] = m.map(Number);
        const v = /^(\d+)\.(\d+)\.(\d+)$/.exec(target.json.version);
        if (!v) { bad.push(`${dep} has a version this check cannot read: "${target.json.version}"`); continue; }
        const [, va, vi, vp] = v.map(Number);
        const satisfied = va === ma && (vi > mi || (vi === mi && vp >= pa));
        if (!satisfied) bad.push(`${p.json.name} wants ${dep}@${range}, but ${dep} is at ${target.json.version}`);
      }
    }
  }
  bad.length ? no("every @proteles/* range is satisfied by the version beside it", bad) : ok("every @proteles/* range is satisfied by the version beside it");
}

// ---------------------------------------------------------------------------
// 5. No relative links in a README.
// ---------------------------------------------------------------------------
// npmjs.com renders the README on the package page with no repository around
// it, so `[@proteles/bff](../bff)` is a 404 for every reader who arrives from
// the registry — which, once published, is most of them.

{
  const bad = [];
  for (const p of packages) {
    const readme = path.join(p.dir, "README.md");
    if (!fs.existsSync(readme)) { bad.push(`${p.json.name}: no README.md`); continue; }
    const text = fs.readFileSync(readme, "utf8");
    for (const m of text.matchAll(/\]\((\.\.?\/[^)\s]+)\)/g)) {
      bad.push(`${p.json.name}: relative link "${m[1]}" — 404 on npmjs.com`);
    }
  }
  bad.length ? no("no README links relatively out of its own package", bad) : ok("no README links relatively out of its own package");
}

// ---------------------------------------------------------------------------
// 6. Every `npm install @proteles/…` a README prints is a package we publish.
// ---------------------------------------------------------------------------
// The install line is the first thing a reader runs. One naming a package that
// was renamed, or never existed, fails at the very first step.

{
  const bad = [];
  let lines = 0;
  for (const p of packages) {
    const readme = path.join(p.dir, "README.md");
    if (!fs.existsSync(readme)) continue;
    for (const m of fs.readFileSync(readme, "utf8").matchAll(/npm (?:i|install|add) ([^\n`]+)/g)) {
      for (const tok of m[1].trim().split(/\s+/)) {
        if (!tok.startsWith("@proteles/")) continue;   // third-party peers are not ours to vouch for
        lines++;
        if (!byName.has(tok)) bad.push(`${p.json.name}: README says "npm install ${tok}", which this workspace does not publish`);
      }
    }
  }
  bad.length ? no("every @proteles package a README tells you to install exists", bad)
             : ok(`every @proteles package a README tells you to install exists (${lines} references)`);
}

// ---------------------------------------------------------------------------
// 7. The tarball would contain the entry points.
// ---------------------------------------------------------------------------
// `files` is an allow-list. An entry point outside it publishes a package that
// installs cleanly and then fails at `import` — the worst kind, because the
// publish looks like it worked.

{
  const bad = [];
  for (const p of packages) {
    const allow = p.json.files ?? [];
    const entries = [p.json.main, p.json.types, p.json.module].filter(Boolean);
    for (const e of Object.values(p.json.exports ?? {})) {
      if (typeof e === "string") entries.push(e);
      else for (const v of Object.values(e ?? {})) if (typeof v === "string") entries.push(v);
    }
    for (const entry of [...new Set(entries)]) {
      const rel = entry.replace(/^\.\//, "");
      const top = rel.split("/")[0];
      if (!allow.includes(top) && !allow.includes(rel)) {
        bad.push(`${p.json.name}: "${entry}" is outside files ${JSON.stringify(allow)} — it would not be in the tarball`);
      }
    }
  }
  bad.length ? no("every entry point is inside the published files list", bad) : ok("every entry point is inside the published files list");
}

// ---------------------------------------------------------------------------
// 8. One version across the workspace.
// ---------------------------------------------------------------------------
// These ten ship as a set and their inter-dependencies are pinned to a single
// minor. A drifted version is how you get `@proteles/next@0.2.0` depending on a
// `@proteles/bff@^0.1.0` that nobody is maintaining any more.

{
  const versions = [...new Set(packages.map((p) => p.json.version))];
  versions.length === 1
    ? ok(`all ${packages.length} packages are at one version (${versions[0]})`)
    : no("all packages are at one version", packages.map((p) => `${p.json.name}: ${p.json.version}`));
}

// ---------------------------------------------------------------------------
// 9. Every package this workspace builds is in the release script's list.
// ---------------------------------------------------------------------------
// `@proteles/alpine-ajax` sat in the workspace for a full release cycle, built,
// tested, documented and exercised against a live server — and never published, because
// the publish loop is a hand-written list of names and nobody added it to the
// list. Every rule above passed on it the whole time: they check that a package
// is *ready* to publish, and readiness is not shipping.
//
// The list is written out in the release workflow
// (.github/workflows/release-npm.yml) and in the runbook's hand-publish
// fallback (RELEASING.md), so this compares every one against the packages on
// disk, in both directions. A list spelled with a variable (`for p in $PKGS`)
// does not match the pattern, so a runbook step that names only new packages
// is not read as a publish list. A name in a list with no package behind it is
// the same defect seen from the other side: the hand-publish fallback would
// exit on it at the one moment CI is already down.
{
  const LISTS = [".github/workflows/release-npm.yml", "RELEASING.md"];
  const found = [];
  for (const rel of LISTS) {
    const f = path.join(ROOT, rel);
    if (!fs.existsSync(f)) continue;
    const text = fs.readFileSync(f, "utf8");
    // Hyphenated names included, deliberately: the regex that could not match
    // `alpine-ajax` is how the release-job check counted ten and stayed green.
    for (const m of text.matchAll(/for p in ([a-z0-9 -]+); do/g)) {
      found.push({ rel, names: m[1].trim().split(/\s+/) });
    }
  }
  // A loop over no lists passes, which is the failure this whole file exists to
  // refuse elsewhere.
  if (found.length === 0) {
    console.log("FATAL: found no publish list in " + LISTS.join(" or ") + " — the scan is wrong");
    process.exit(1);
  }
  const have = new Set(packages.map((p) => p.name));
  const bad = [];
  for (const { rel, names } of found) {
    const listed = new Set(names);
    for (const n of have) if (!listed.has(n)) bad.push(`${rel}: @proteles/${n} is built here but never published`);
    for (const n of listed) if (!have.has(n)) bad.push(`${rel}: publishes "${n}", which this workspace does not build`);
  }
  bad.length
    ? no("every package the workspace builds is in every publish list", bad)
    : ok(`every package the workspace builds is in every publish list (${found.length} list(s) × ${have.size})`);
}

// ---------------------------------------------------------------------------
// 10. A script tag a README hands integrators is pinned and hashed.
// ---------------------------------------------------------------------------
// `@proteles/alpine`'s README told integrators to load
// `https://cdn.jsdelivr.net/npm/@proteles/alpine` — no version, no
// `integrity` — so every site that followed it ran whatever was published
// last, the moment it was published. One
// compromised publish would have been script in every integrator's sign-in UI.
// Each `<script src="https://…">` in a README names an exact version and
// carries `integrity=`; a pinned `@proteles` version is this workspace's, so a
// release that bumps the version fails here until the README follows.
{
  const bad = [];
  let seen = 0;
  for (const p of packages) {
    const f = path.join(p.dir, "README.md");
    if (!fs.existsSync(f)) continue;
    for (const m of fs.readFileSync(f, "utf8").matchAll(/<script\b[^>]*>/g)) {
      const tag = m[0];
      const src = tag.match(/\bsrc="(https:\/\/[^"]+)"/)?.[1];
      if (!src) continue;
      seen++;
      const pinned = src.match(/\/npm\/((?:@[a-z0-9-]+\/)?[a-z0-9.-]+)@(\d+\.\d+\.\d+)\//);
      if (!pinned) bad.push(`${p.json.name}: ${src} names no exact version`);
      else if (byName.has(pinned[1]) && byName.get(pinned[1]).json.version !== pinned[2]) {
        bad.push(`${p.json.name}: ${src} pins ${pinned[2]}, but ${pinned[1]} is at ${byName.get(pinned[1]).json.version}`);
      }
      if (!/\bintegrity="sha(256|384|512)-/.test(tag)) bad.push(`${p.json.name}: ${src} carries no integrity hash`);
    }
  }
  bad.length
    ? no("every CDN script a README hands out is pinned and hashed", bad)
    : ok(`every CDN script a README hands out is pinned and hashed (${seen})`);
}

// ---------------------------------------------------------------------------
// 11. Every package says, before its install line, that it needs a Proteles account.
// ---------------------------------------------------------------------------
// These packages are clients of a hosted service, and do nothing without an
// account on it. Nothing on their npm pages said so, and people installed them
// expecting them to work on their own. So each README
// links the sign-up page before it tells anyone to `npm install`, and each
// description, which is what npm's search results show, says so too.
{
  const SIGNUP = "https://proteles.com/signup";
  const bad = [];
  for (const p of packages) {
    const f = path.join(p.dir, "README.md");
    if (fs.existsSync(f)) {
      const text = fs.readFileSync(f, "utf8");
      const notice = text.indexOf(SIGNUP);
      const install = text.search(/npm install /);
      if (notice < 0) bad.push(`${p.json.name}: README never links ${SIGNUP}`);
      else if (install >= 0 && notice > install) bad.push(`${p.json.name}: README links ${SIGNUP} only after its install line`);
    }
    if (!/Proteles account/.test(p.json.description ?? "")) {
      bad.push(`${p.json.name}: its description does not say it needs a Proteles account`);
    }
  }
  bad.length
    ? no("every package says up front that it needs a Proteles account", bad)
    : ok("every package says up front that it needs a Proteles account");
}

console.log();
if (fail) {
  console.log(`${fail} of ${pass + fail} checks FAILED`);
  process.exit(1);
}
console.log(`all ${pass} checks passed — ${packages.length} packages ready to publish`);
