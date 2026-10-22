// The publish-readiness check, driven against trees where each rule is broken.
//
// The check is eleven loops over a list of packages. Every one of them passes
// trivially on a well-formed tree, and eight of the nine would also pass on a
// tree they had stopped reading correctly. Green on the real repository is
// therefore not evidence that any of them work — the only evidence is watching
// each one fail on a tree that violates exactly its own rule, and stay green on
// the others.
//
// So: one fixture per rule, minimal, built from a known-good baseline and then
// broken in a single specific way. If a mutation stops producing a failure, the
// rule it belongs to has silently stopped being enforced, and this test says
// which one.

import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");
const CHECK = path.join(HERE, "npm-publish-readiness.mjs");

let pass = 0;
let fail = 0;
const ok = (m) => { console.log(`  ✓ ${m}`); pass++; };
const no = (m, detail) => { console.log(`  ✗ ${m}`); if (detail) console.log(`      ${detail}`); fail++; };

const WORK = fs.mkdtempSync(path.join(os.tmpdir(), "publish-readiness-"));
process.on("exit", () => fs.rmSync(WORK, { recursive: true, force: true }));

const LICENSE = fs.readFileSync(path.join(ROOT, "LICENSE"), "utf8");
const REPOSITORY_URL = "git+https://github.com/proteles-auth/proteles-sdk.git";

/** A two-package tree that satisfies every rule. `mutate` then breaks one. */
function makeTree(name, mutate) {
  const dir = path.join(WORK, name);
  const base = {
    core: {
      name: "@proteles/core", version: "0.1.0", license: "MIT",
      description: "Core. Needs a Proteles account.",
      main: "./dist/index.js", types: "./dist/index.d.ts",
      files: ["dist", "README.md"],
      publishConfig: { access: "public" },
      repository: { type: "git", url: REPOSITORY_URL, directory: "packages/core" },
    },
    wrap: {
      name: "@proteles/wrap", version: "0.1.0", license: "MIT",
      description: "Wrap. Needs a Proteles account.",
      main: "./dist/index.js", types: "./dist/index.d.ts",
      files: ["dist", "README.md"],
      dependencies: { "@proteles/core": "^0.1.0" },
      publishConfig: { access: "public" },
      repository: { type: "git", url: REPOSITORY_URL, directory: "packages/wrap" },
    },
  };
  const readmes = {
    core: "# @proteles/core\n\n> You need a Proteles account: [sign up for free](https://proteles.com/signup).\n\n```bash\nnpm install @proteles/core\n```\n",
    wrap: "# @proteles/wrap\n\n> You need a Proteles account: [sign up for free](https://proteles.com/signup).\n\n```bash\nnpm install @proteles/wrap\n```\n\nSee [core](https://www.npmjs.com/package/@proteles/core).\n",
  };

  // Rule 9 reads the publish lists in the release workflow and in the
  // runbook, so the fixture writes both. A bare `for p in ...; do` line is all
  // the rule matches on, and writing the whole workflow here would couple this
  // test to a file it is not testing.
  const ci = { line: "          for p in core wrap; do", runbook: "for p in core wrap; do npm publish -w \"@proteles/$p\"; done" };

  // Kept out of the package.json so a fixture's request for a broken licence
  // cannot itself leak into the data under test.
  const licenses = { core: LICENSE, wrap: LICENSE };

  mutate({ base, readmes, licenses, ci });

  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "LICENSE"), LICENSE);
  fs.mkdirSync(path.join(dir, ".github/workflows"), { recursive: true });
  if (ci.line !== null) fs.writeFileSync(path.join(dir, ".github/workflows/release-npm.yml"), `${ci.line}\n`);
  if (ci.runbook !== null) fs.writeFileSync(path.join(dir, "RELEASING.md"), "```sh\n" + `${ci.runbook}\n` + "```\n");
  for (const [short, json] of Object.entries(base)) {
    const pdir = path.join(dir, "packages", short);
    fs.mkdirSync(pdir, { recursive: true });
    fs.writeFileSync(path.join(pdir, "package.json"), JSON.stringify(json, null, 2) + "\n");
    if (readmes[short] !== null) fs.writeFileSync(path.join(pdir, "README.md"), readmes[short]);
    if (licenses[short] !== null) fs.writeFileSync(path.join(pdir, "LICENSE"), licenses[short]);
  }
  return dir;
}

function run(dir) {
  try {
    const out = execFileSync("node", [CHECK], {
      env: { ...process.env, ROOT_OVERRIDE: dir, MIN_PACKAGES: "2" },
      encoding: "utf8",
    });
    return { code: 0, out };
  } catch (e) {
    return { code: e.status ?? 1, out: (e.stdout ?? "") + (e.stderr ?? "") };
  }
}

/** The mutation must fail, and the message must name the rule. */
function expectFail(label, mutate, needle) {
  const r = run(makeTree(label, mutate));
  if (r.code !== 0 && r.out.includes(needle)) ok(label);
  else no(label, r.code === 0 ? "the check PASSED on a broken tree" : `failed, but never said "${needle}"`);
}

// ------------------------------------------------------------- the baseline ---
{
  const r = run(makeTree("baseline", () => {}));
  if (r.code === 0 && r.out.includes("all 11 checks passed")) ok("a well-formed tree passes all 11 rules");
  else no("a well-formed tree passes all 11 rules", r.out.trim().split("\n").slice(-4).join(" / "));
}

// ---------------------------------------------------------------- each rule ---
expectFail("1. a package declaring MIT with no LICENSE file fails",
  ({ licenses }) => { licenses.core = null; }, "no LICENSE file");

expectFail("1b. a LICENSE that differs from the root one fails",
  ({ licenses }) => { licenses.core = "All rights reserved.\n"; }, "differs from the root one");

expectFail("1c. shipping the MIT text while declaring another licence fails",
  ({ base }) => { base.core.license = "Apache-2.0"; }, 'declares "Apache-2.0"');

expectFail("2. a scoped package without publishConfig.access fails",
  ({ base }) => { delete base.wrap.publishConfig; }, "not \"public\"");

expectFail("2b. publishConfig.access=restricted fails",
  ({ base }) => { base.wrap.publishConfig = { access: "restricted" }; }, "not \"public\"");

expectFail("3. a repository.directory naming another package fails",
  ({ base }) => { base.wrap.repository.directory = "packages/core"; }, "should be \"packages/wrap\"");

expectFail("3b. a repository.directory with the monorepo's old sdk/ prefix fails",
  ({ base }) => { base.wrap.repository.directory = "sdk/packages/wrap"; }, "should be \"packages/wrap\"");

expectFail("3c. a repository.url naming another repository fails",
  ({ base }) => { base.core.repository.url = "git+https://example.invalid/r.git"; }, `should be "${REPOSITORY_URL}"`);

expectFail("4. a dependency range no sibling version satisfies fails",
  ({ base }) => { base.wrap.dependencies["@proteles/core"] = "^0.2.0"; }, "but @proteles/core is at 0.1.0");

expectFail("4b. a dependency on a package this workspace does not build fails",
  ({ base }) => { base.wrap.dependencies["@proteles/ghost"] = "^0.1.0"; }, "does not build");

expectFail("5. a relative README link fails",
  ({ readmes }) => { readmes.wrap += "\nSee [core](../core).\n"; }, "404 on npmjs.com");

expectFail("6. a README install line naming a package we do not publish fails",
  ({ readmes }) => { readmes.core += "\n```bash\nnpm install @proteles/nope\n```\n"; }, "does not publish");

expectFail("7. an entry point outside `files` fails",
  ({ base }) => { base.core.main = "./build/index.js"; }, "would not be in the tarball");

expectFail("7b. an exports subpath outside `files` fails",
  ({ base }) => { base.core.exports = { ".": { import: "./lib/index.js" } }; }, "would not be in the tarball");

expectFail("8. a version drifted from the rest fails",
  ({ base }) => { base.wrap.version = "0.2.0"; base.wrap.dependencies["@proteles/core"] = "^0.1.0"; },
  "all packages are at one version");

// The rule that would have caught @proteles/alpine-ajax: built, tested, and for
// a whole release cycle never published, because it was missing from a
// hand-written list and every other rule here passed on it happily.
expectFail("9. a package the workspace builds but never publishes fails",
  ({ ci }) => { ci.line = "      for p in core; do"; }, "built here but never published");

expectFail("9b. a publish list naming a package that does not exist fails",
  ({ ci }) => { ci.line = "      for p in core wrap ghost; do"; }, "does not build");

// Both lists are read, not just the first one found: the runbook's fallback is
// the one used when the workflow cannot run, so a stale copy there is the one
// that bites.
expectFail("9d. a runbook list missing a package fails, even with the workflow's list right",
  ({ ci }) => { ci.runbook = "for p in core; do npm publish -w \"@proteles/$p\"; done"; }, "RELEASING.md: @proteles/wrap is built here but never published");

expectFail("9e. a workflow list missing a package fails, even with the runbook's list right",
  ({ ci }) => { ci.line = "          for p in wrap; do"; }, ".github/workflows/release-npm.yml: @proteles/core is built here but never published");

// A runbook step that names packages through a variable is not a publish list.
{
  const r = run(makeTree("9f", ({ ci }) => { ci.runbook = 'for p in $PKGS; do npm publish -w "@proteles/$p"; done'; }));
  if (r.code === 0 && r.out.includes("(1 list(s) × 2)")) ok("9f. a `for p in $PKGS` loop is not read as a list, and the workflow's still is");
  else no("9f. a `for p in $PKGS` loop is not read as a list, and the workflow's still is", r.out.trim().split("\n").slice(-4).join(" / "));
}

{
  const r = run(makeTree("9g", ({ ci }) => { ci.line = null; ci.runbook = null; }));
  if (r.code !== 0 && r.out.includes("found no publish list")) ok("9g. a tree with neither the workflow nor the runbook refuses rather than passing");
  else no("9g. a tree with neither the workflow nor the runbook refuses rather than passing", r.code === 0 ? "it PASSED with no publish list" : r.out.trim());
}

// A hyphen is not decoration here. The release-job check counted ten packages
// and stayed green while ignoring an eleventh, because its regex was `[a-z]+`
// and could not match `alpine-ajax`. A rule that silently skips the only name
// shaped like the one that broke is worse than no rule.
expectFail("9c. \u2026and it sees hyphenated names, which is how this was missed before",
  ({ base, readmes, licenses, ci }) => {
    base["odd-one"] = { ...base.core, name: "@proteles/odd-one",
      repository: { ...base.core.repository, directory: "packages/odd-one" } };
    readmes["odd-one"] = "# @proteles/odd-one\n\n```bash\nnpm install @proteles/odd-one\n```\n";
    licenses["odd-one"] = licenses.core;
    ci.line = "      for p in core wrap; do";
    ci.runbook = "for p in core wrap odd-one; do npm publish; done";
  }, "@proteles/odd-one is built here but never published");

// An unpinned README script tag runs whatever was published last.
const script = (src, extra = "") => `\n<script src="${src}"${extra}></script>\n`;
const HASH = ' integrity="sha384-abc" crossorigin="anonymous"';
expectFail("10. a README script tag with no version fails",
  ({ readmes }) => { readmes.core += script("https://cdn.jsdelivr.net/npm/@proteles/core", HASH); }, "names no exact version");

expectFail("10b. a pinned script tag with no integrity hash fails",
  ({ readmes }) => { readmes.core += script("https://cdn.jsdelivr.net/npm/@proteles/core@0.1.0/dist/x.js"); }, "carries no integrity hash");

expectFail("10c. a script tag pinning another version of our own package fails",
  ({ readmes }) => { readmes.core += script("https://cdn.jsdelivr.net/npm/@proteles/core@0.0.9/dist/x.js", HASH); },
  "but @proteles/core is at 0.1.0");

{
  const r = run(makeTree("10d", ({ readmes }) => {
    readmes.core += script("https://cdn.jsdelivr.net/npm/@proteles/core@0.1.0/dist/x.js", HASH);
    readmes.core += script("https://cdn.jsdelivr.net/npm/alpinejs@3.15.12/dist/cdn.min.js", HASH);
  }));
  if (r.code === 0 && r.out.includes("pinned and hashed (2)")) ok("10d. pinned, hashed script tags pass, and are counted");
  else no("10d. pinned, hashed script tags pass, and are counted", r.out.trim().split("\n").slice(-4).join(" / "));
}

// Rule 11: the npm page says the package needs a Proteles account, early.
expectFail("11. a README that never links sign-up fails",
  ({ readmes }) => { readmes.core = readmes.core.replace("https://proteles.com/signup", "https://proteles.com/"); },
  "README never links https://proteles.com/signup");
expectFail("11b. a README that links sign-up only after its install line fails",
  ({ readmes }) => {
    const notice = readmes.wrap.match(/> You need[^\n]*\n\n/)[0];
    readmes.wrap = readmes.wrap.replace(notice, "") + "\n" + notice;
  },
  "only after its install line");
expectFail("11c. a description that doesn't mention the account fails",
  ({ base }) => { base.core.description = "Core."; },
  "its description does not say it needs a Proteles account");

// ------------------------------------------- the guard against reading nothing ---
// The floor exists because every rule above is a loop, and a loop over nothing
// passes. Point the check at an empty tree and it must refuse rather than
// congratulate itself.
{
  const empty = path.join(WORK, "empty/packages");
  fs.mkdirSync(empty, { recursive: true });
  fs.writeFileSync(path.join(WORK, "empty/LICENSE"), LICENSE);
  const r = run(path.join(WORK, "empty"));
  if (r.code !== 0 && r.out.includes("the discovery is wrong")) ok("a tree with no packages refuses rather than passing");
  else no("a tree with no packages refuses rather than passing", r.code === 0 ? "it PASSED on an empty tree" : r.out.trim());
}

console.log();
if (fail) {
  console.log(`${fail} of ${pass + fail} cases FAILED`);
  process.exit(1);
}
console.log(`all ${pass} cases passed`);
