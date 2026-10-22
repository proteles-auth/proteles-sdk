#!/usr/bin/env node
// The native-SDK release script, run where it can do no harm: against a stub
// Central Portal on loopback and a fixture tree — never a registry, never a
// credential.
//
// The release runs once per version, and what it does cannot be taken back.
// Its first execution should not be the one that matters, and two of its
// promises are only worth anything if they have been seen to hold:
//
//   * it refuses before building anything — a wrong tag, a missing variable, a
//     placeholder POM, a repository whose tag would release nothing for iOS —
//     and says what to do about it;
//   * it is idempotent — a version already on Central is skipped, so a retry
//     after a partial failure finishes the release instead of failing on it.
//
// What happens after preflight — Central's answers (VALIDATED under the default
// USER_MANAGED, PUBLISHED, FAILED) — is driven on every run with the toolchain
// staged: a fixture tree whose gradlew and publish-readiness.mjs are stand-ins
// that take a second. The real toolchain (a Gradle publish and an upload) needs
// the Android SDK and several minutes, so it runs only with `--full`: on a copy
// of mobile/ with the POM filled in, signed with a throwaway key made in a
// temporary GNUPGHOME (a test value, deleted after), uploading AUTOMATIC to the
// stub — and then again, to watch the second run skip.
//
// There is no iOS half to drive: the iOS release is the tag itself, because
// Package.swift is at the repository root (release.sh's header says why).
//
//   node mobile/scripts/release-check.mjs           # every case, toolchain staged
//   node mobile/scripts/release-check.mjs --full    # and the real Gradle publish

import { spawn, spawnSync, execFileSync } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "../..");
const RELEASE = path.join(HERE, "release.sh");

const work = fs.mkdtempSync(path.join(os.tmpdir(), "mobile-release-check-"));
process.on("exit", () => fs.rmSync(work, { recursive: true, force: true }));

const real = fs.readFileSync(path.join(ROOT, "mobile/android/gradle.properties"), "utf8");
const VERSION = /^VERSION_NAME=(.+)$/m.exec(real)?.[1];
if (!VERSION) { console.log("FATAL: no VERSION_NAME in mobile/android/gradle.properties"); process.exit(1); }

// gradle.properties with every POM_ value filled in, whether or not a
// maintainer has filled the committed one yet; and the same with two placeholders put
// back, written here rather than inherited, so the refusal is still tested
// once the committed file has none.
const filledProps = real.replace(/^(POM_[A-Z_]+=).*\.invalid.*$/gm, (_, k) => `${k}${k === "POM_DEVELOPER_EMAIL=" ? "release@example.com" : "https://example.com/proteles-android"}`);
const placeholderProps = filledProps.replace(/^(?:POM_URL|POM_DEVELOPER_EMAIL)=.*\n?/gm, "").replace(/\n*$/, "\n") +
  "POM_URL=https://PROJECT-URL-NOT-SET.invalid/proteles-android\nPOM_DEVELOPER_EMAIL=DEVELOPER-EMAIL-NOT-SET@proteles.invalid\n";

// A repository root holding only what release.sh reads before it would build:
// gradle.properties, with the placeholders either left in or filled, and the
// root Package.swift that makes the tag an iOS release.
function fixtureRoot(name, { placeholders, packageSwift = true }) {
  const root = path.join(work, name);
  const android = path.join(root, "mobile/android");
  fs.mkdirSync(android, { recursive: true });
  fs.writeFileSync(path.join(android, "gradle.properties"), placeholders ? placeholderProps : filledProps);
  if (packageSwift) fs.writeFileSync(path.join(root, "Package.swift"), "// swift-tools-version: 6.0\n");
  return root;
}

// A filled-in root with the toolchain staged, so release.sh runs past
// preflight in a second: a gradlew that publishes one file per artifact into
// build/repo, and a publish-readiness.mjs that passes. Each says what it is
// doing, so the order can be read from the output.
function stagedRoot(name) {
  const root = fixtureRoot(name, { placeholders: false });
  const android = path.join(root, "mobile/android");
  const exe = (file, text) => { fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file, text, { mode: 0o755 }); };
  exe(path.join(android, "gradlew"), `#!/usr/bin/env bash
set -e
here="$(cd "$(dirname "$0")" && pwd)"
v="$(sed -n 's/^VERSION_NAME=//p' "$here/gradle.properties")"
# The signing build gets a Gradle home of its own, never ~/.gradle,
# where another build on this machine could have left an init script.
[ -n "\${GRADLE_USER_HOME:-}" ] || { echo "stub gradle: no GRADLE_USER_HOME, so ~/.gradle and its init scripts" >&2; exit 1; }
echo "stub gradle: home \$GRADLE_USER_HOME" >&2
echo "stub gradle: publishing $v" >&2
for id in proteles-auth-core proteles-auth-android; do
  mkdir -p "$here/build/repo/com/proteles/$id/$v"
  echo stub > "$here/build/repo/com/proteles/$id/$v/$id-$v.pom"
done
`);
  exe(path.join(android, "scripts/publish-readiness.mjs"), `console.error("stub readiness: " + process.argv.slice(2).join(" "));\n`);
  return root;
}

const key = path.join(work, "key.asc");
// The armour lines are built from parts so that secret scanners, which match
// them literally, do not take this stand-in for a key.
const armour = (edge) => `-----${edge} PGP PRIVATE ${"KEY"} BLOCK-----`;
fs.writeFileSync(key, `${armour("BEGIN")}\n(a stand-in: nothing here signs)\n${armour("END")}\n`);
const notAKey = path.join(work, "not-a-key.txt");
fs.writeFileSync(notAKey, "hunter2\n");

// The Central Portal's `published` endpoint, answering from `central.published`.
// With `central.accept` set, also an upload that is kept, and a status that
// answers `central.state`: PUBLISHED (after which both artifacts read as
// published), VALIDATED (they do not, as under USER_MANAGED until someone
// presses Publish), or FAILED with Central's reasons. A request without the
// user token as its bearer is refused 401, as the Portal refuses it. Every
// request is recorded; anything else answers 500.
const BEARER = `Bearer ${Buffer.from("stub-user:stub-password").toString("base64")}`;
const central = { published: {}, requests: [], accept: false, uploads: [], state: "PUBLISHED" };
const server = http.createServer((req, res) => {
  const url = new URL(req.url, "http://stub");
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", () => {
    central.requests.push({ method: req.method, path: url.pathname, query: url.search, auth: req.headers.authorization });
    if (req.headers.authorization !== BEARER) {
      res.statusCode = 401;
      res.end("the stub refuses this token");
      return;
    }
    if (req.method === "GET" && url.pathname === "/api/v1/publisher/published") {
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ published: central.published[url.searchParams.get("name")] === true }));
      return;
    }
    if (central.accept && req.method === "POST" && url.pathname === "/api/v1/publisher/upload") {
      central.uploads.push({ query: url.search, type: req.headers["content-type"] ?? "", body: Buffer.concat(chunks) });
      res.end(`deployment-${central.uploads.length}`);
      return;
    }
    if (central.accept && req.method === "POST" && url.pathname === "/api/v1/publisher/status") {
      if (central.state === "PUBLISHED") central.published = { "proteles-auth-core": true, "proteles-auth-android": true };
      const errors = central.state === "FAILED" ? { "pkg:maven/com.proteles/proteles-auth-core": ["the stub's reason: invalid signature"] } : {};
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ deploymentId: url.searchParams.get("id"), deploymentState: central.state, errors }));
      return;
    }
    res.statusCode = 500;
    res.end("the stub was not expecting this");
  });
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const CENTRAL = `http://127.0.0.1:${server.address().port}`;

const credentials = {
  MOBILE_SIGNING_KEY: key,
  MOBILE_SIGNING_KEY_PASSWORD: "stub-passphrase",
  CENTRAL_PORTAL_TOKEN_USERNAME: "stub-user",
  CENTRAL_PORTAL_TOKEN_PASSWORD: "stub-password",
};

function run(env) {
  // Only PATH, HOME and TMPDIR from this environment: a real credential in the
  // caller's shell — or a GITHUB_REF_NAME from the workflow running this check
  // — must not reach the script under test.
  const base = { PATH: process.env.PATH, HOME: process.env.HOME, TMPDIR: process.env.TMPDIR ?? os.tmpdir() };
  return new Promise((resolve) => {
    const child = spawn("bash", [RELEASE], { env: { ...base, CENTRAL_PORTAL_URL: CENTRAL, ...env } });
    let out = "";
    child.stdout.on("data", (d) => (out += d));
    child.stderr.on("data", (d) => (out += d));
    child.on("close", (code) => resolve({ code, out }));
  });
}

let failures = 0;
function check(label, good, detail) {
  console.log(`  ${good ? "✓" : "✗"} ${label}`);
  if (!good) { if (detail) console.log(`      ${detail}`); failures++; }
}
async function expect(label, env, { code, says = [], never = [] }) {
  central.requests = [];
  const r = await run(env);
  const problems = [];
  if ((code === 0) !== (r.code === 0)) problems.push(`exited ${r.code}, wanted ${code === 0 ? "success" : "a refusal"}`);
  for (const s of says) if (!r.out.includes(s)) problems.push(`did not say: ${s}`);
  for (const s of never) if (r.out.includes(s)) problems.push(`said: ${s}`);
  console.log(`  ${problems.length ? "✗" : "✓"} ${label}`);
  if (problems.length) {
    for (const p of problems) console.log(`      ${p}`);
    console.log(r.out.replace(/^/gm, "      | "));
    failures++;
  }
  return r;
}

const filled = fixtureRoot("filled", { placeholders: false });
const withPlaceholders = fixtureRoot("placeholders", { placeholders: true });
const noManifest = fixtureRoot("no-manifest", { placeholders: false, packageSwift: false });
const tag = VERSION;
const building = "publishing signed artifacts"; // the first thing past preflight that builds
const notATag = "is not a mobile release tag";

console.log(`release.sh, preflight (VERSION_NAME ${VERSION}):`);
await expect("no tag is refused", { MOBILE_RELEASE_ROOT: filled, ...credentials }, { code: 1, says: [notATag], never: [building] });
await expect("npm's tag pattern (npm-vX.Y.Z) is refused", { MOBILE_RELEASE_ROOT: filled, GITHUB_REF_NAME: `npm-v${VERSION}`, ...credentials }, { code: 1, says: [notATag], never: [building] });
await expect("a v-prefixed tag is refused: the mobile tags are plain X.Y.Z", { MOBILE_RELEASE_ROOT: filled, GITHUB_REF_NAME: `v${VERSION}`, ...credentials }, { code: 1, says: [notATag], never: [building] });
await expect("the monorepo's old mobile-vX.Y.Z pattern is refused", { MOBILE_RELEASE_ROOT: filled, GITHUB_REF_NAME: `mobile-v${VERSION}`, ...credentials }, { code: 1, says: [notATag], never: [building] });
await expect("a branch name is refused", { MOBILE_RELEASE_ROOT: filled, GITHUB_REF_NAME: "main", ...credentials }, { code: 1, says: [notATag], never: [building] });
await expect("a tag that is not VERSION_NAME is refused, and says both", { MOBILE_RELEASE_ROOT: filled, GITHUB_REF_NAME: "99.0.0", ...credentials }, { code: 1, says: ["wants 99.0.0", `VERSION_NAME in mobile/android/gradle.properties is ${VERSION}`], never: [building] });
await expect("a root with no Package.swift is refused: the tag would release nothing for iOS", { MOBILE_RELEASE_ROOT: noManifest, GITHUB_REF_NAME: tag, ...credentials }, { code: 1, says: ["no Package.swift at the repository root"], never: [building] });
await expect("missing variables are refused, every one named at once", { MOBILE_RELEASE_ROOT: filled, GITHUB_REF_NAME: tag }, {
  code: 1,
  says: ["MOBILE_SIGNING_KEY MOBILE_SIGNING_KEY_PASSWORD CENTRAL_PORTAL_TOKEN_USERNAME CENTRAL_PORTAL_TOKEN_PASSWORD", "RELEASING.md"],
  never: [building],
});
await expect("a signing key that is not an armoured secret key is refused", { MOBILE_RELEASE_ROOT: filled, GITHUB_REF_NAME: tag, ...credentials, MOBILE_SIGNING_KEY: notAKey }, { code: 1, says: ["ASCII-armoured secret key"], never: [building] });
await expect("a publishing type Central does not know is refused", { MOBILE_RELEASE_ROOT: filled, GITHUB_REF_NAME: tag, ...credentials, CENTRAL_PUBLISHING_TYPE: "SOMETIMES" }, { code: 1, says: ["must be USER_MANAGED or AUTOMATIC"], never: [building] });
await expect("the POM placeholders are refused, each one listed", { MOBILE_RELEASE_ROOT: withPlaceholders, GITHUB_REF_NAME: tag, ...credentials }, { code: 1, says: ["still has placeholders", "POM_URL=", "POM_DEVELOPER_EMAIL="], never: [building] });
// Not a fixture: the committed gradle.properties, which is what a release made
// today would read. While it has placeholders it must refuse on them. Once a
// maintainer has filled them in there is nothing to show, and a run past preflight
// would start building, so it is not made. Run against a Central that already
// has the version, so that even a preflight that stopped refusing would skip
// the upload rather than build.
if (/\.invalid/.test(real.split("\n").filter((l) => !l.startsWith("#")).join("\n"))) {
  central.published = { "proteles-auth-core": true, "proteles-auth-android": true };
  await expect("the repository as committed refuses: its POM placeholders are still in", {
    GITHUB_REF_NAME: tag, ...credentials,
  }, { code: 1, says: ["still has placeholders"], never: [building] });
} else {
  console.log("  · the repository as committed has no placeholders left; nothing to refuse");
}

console.log("\nrelease.sh, idempotence:");
central.published = { "proteles-auth-core": true, "proteles-auth-android": true };
const done = await expect("a version already on Central is skipped, and the run succeeds", {
  MOBILE_RELEASE_ROOT: filled, GITHUB_REF_NAME: tag, GITHUB_SHA: "0".repeat(40), ...credentials,
}, { code: 0, says: ["already on Maven Central; skipping", `the tag ${tag} is the release`, `(${"0".repeat(40)})`, `released ${tag}`], never: [building] });
{
  const asked = central.requests.filter((r) => r.path === "/api/v1/publisher/published");
  const good = done.code === 0 && asked.length === 2 && asked.every((r) => r.auth === BEARER) && central.requests.length === 2;
  console.log(`  ${good ? "✓" : "✗"} …having asked Central about both artifacts, with the user token as a bearer, and nothing else`);
  if (!good) { console.log(`      requests: ${JSON.stringify(central.requests)}`); failures++; }
}
central.published = { "proteles-auth-core": true, "proteles-auth-android": false };
await expect("half a version on Central is refused rather than re-uploaded", {
  MOBILE_RELEASE_ROOT: filled, GITHUB_REF_NAME: tag, ...credentials,
}, { code: 1, says: ["only 1 of 2 artifacts are published"], never: [building] });
central.published = {};
await expect("a Central that refuses the token stops the release, and says what it answered", {
  MOBILE_RELEASE_ROOT: filled, GITHUB_REF_NAME: tag, ...credentials, CENTRAL_PORTAL_TOKEN_PASSWORD: "not-the-password",
}, { code: 1, says: ["could not ask Central", "the stub refuses this token"], never: [building] });

console.log("\nrelease.sh, past preflight (toolchain staged):");
central.accept = true;
{
  // The default publishing type: Central stops at VALIDATED, and the run says
  // someone must press Publish.
  central.published = {}; central.uploads = []; central.state = "VALIDATED";
  const r = await expect("USER_MANAGED: the upload stops at VALIDATED, and the run says to press Publish", {
    MOBILE_RELEASE_ROOT: stagedRoot("validated"), GITHUB_REF_NAME: tag, ...credentials,
  }, { code: 0, says: ["stub readiness: --repo", "--signed --release", "is VALIDATED", "presses Publish", `released ${tag}`] });
  const q = central.uploads[0]?.query ?? "";
  check("…one upload, USER_MANAGED, named for the version", central.uploads.length === 1 && q.includes("publishingType=USER_MANAGED") && q.includes(`name=proteles-android-${VERSION}`), JSON.stringify(central.uploads.map((u) => u.query)));
  // Gradle ran in a home of the release's own, which is gone now.
  const home = /stub gradle: home (\S+)/.exec(r.out)?.[1] ?? "";
  check("…Gradle ran in a fresh home inside the release's own work directory, not ~/.gradle",
    home.includes("/mobile-release.") && home.endsWith("/gradle-home") && !home.startsWith(path.join(os.homedir(), ".gradle")), `home: ${home || "(none reported)"}`);
  check("…and that home is gone once the release ends", home !== "" && !fs.existsSync(home), home);
}
{
  // AUTOMATIC: Central publishes the deployment itself, and the run waits for
  // PUBLISHED rather than stopping at VALIDATED. Then the same tag again finds
  // it out and uploads nothing.
  central.published = {}; central.uploads = []; central.state = "PUBLISHED";
  const root = stagedRoot("automatic");
  await expect("AUTOMATIC: the upload goes on to PUBLISHED", {
    MOBILE_RELEASE_ROOT: root, GITHUB_REF_NAME: tag, ...credentials, CENTRAL_PUBLISHING_TYPE: "AUTOMATIC",
  }, { code: 0, says: ["is PUBLISHED", `released ${tag}`], never: ["presses Publish"] });
  check("…one upload, AUTOMATIC", central.uploads.length === 1 && (central.uploads[0]?.query ?? "").includes("publishingType=AUTOMATIC"), JSON.stringify(central.uploads.map((u) => u.query)));
  await expect("the same tag again: already on Central, so nothing is built or uploaded", {
    MOBILE_RELEASE_ROOT: root, GITHUB_REF_NAME: tag, ...credentials, CENTRAL_PUBLISHING_TYPE: "AUTOMATIC",
  }, { code: 0, says: ["already on Maven Central; skipping", `released ${tag}`], never: [building, "Android: uploading"] });
  check("…still one upload", central.uploads.length === 1);
}
{
  central.published = {}; central.uploads = []; central.state = "FAILED";
  await expect("a deployment Central refuses stops the release with Central's reasons", {
    MOBILE_RELEASE_ROOT: stagedRoot("failed"), GITHUB_REF_NAME: tag, ...credentials,
  }, { code: 1, says: ["Central refused deployment", "the stub's reason: invalid signature"], never: [`released ${tag}`] });
}
central.accept = false;
central.state = "PUBLISHED";

if (process.argv.includes("--full")) await full();

server.close();
console.log();
if (failures) { console.log(`${failures} case(s) failed`); process.exit(1); }
console.log(process.argv.includes("--full")
  ? "release.sh refuses before it builds, releases Android, and skips what is already released"
  : "release.sh refuses before it builds, stops on Central's refusal, and skips what is already released");

async function full() {
  console.log("\nrelease.sh, end to end (--full):");
  // A copy of mobile/ and the root manifest as git sees them (new files
  // included, build output not), with the POM filled in, so preflight passes
  // and nothing here is touched.
  const root = path.join(work, "full");
  const files = execFileSync("git", ["-C", ROOT, "ls-files", "--cached", "--others", "--exclude-standard", "-z", "mobile", "Package.swift"], { encoding: "utf8" })
    .split("\0").filter(Boolean);
  for (const f of files) {
    if (!fs.existsSync(path.join(ROOT, f))) continue; // deleted in the worktree, still in the index
    fs.mkdirSync(path.dirname(path.join(root, f)), { recursive: true });
    fs.copyFileSync(path.join(ROOT, f), path.join(root, f));
    fs.chmodSync(path.join(root, f), fs.statSync(path.join(ROOT, f)).mode);
  }
  fs.copyFileSync(path.join(filled, "mobile/android/gradle.properties"), path.join(root, "mobile/android/gradle.properties"));

  const home = fs.mkdtempSync(path.join(os.tmpdir(), "rc-gpg-"));
  fs.chmodSync(home, 0o700);
  try {
    const passphrase = "throwaway-release-check";
    const gpg = (...a) => execFileSync("gpg", ["--batch", "--homedir", home, "--pinentry-mode", "loopback", "--passphrase", passphrase, ...a], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    gpg("--quick-gen-key", "Proteles release check (throwaway) <throwaway@release-check.invalid>", "rsa3072", "sign", "1d");
    const keyFile = path.join(home, "secret.asc");
    fs.writeFileSync(keyFile, gpg("--armor", "--export-secret-keys"));

    const env = {
      MOBILE_RELEASE_ROOT: root, GITHUB_REF_NAME: tag, GITHUB_SHA: "0".repeat(40),
      ...credentials, MOBILE_SIGNING_KEY: keyFile, MOBILE_SIGNING_KEY_PASSWORD: passphrase,
      CENTRAL_PUBLISHING_TYPE: "AUTOMATIC",
      ANDROID_HOME: process.env.ANDROID_HOME ?? path.join(os.homedir(), "Library/Android/sdk"),
    };
    central.published = {};
    central.accept = true;
    central.uploads = [];
    const first = await run(env);
    check("the first run releases Android", first.code === 0 && first.out.includes("is PUBLISHED") && first.out.includes(`released ${tag}`),
      `exit ${first.code}\n${first.out.split("\n").slice(-40).join("\n")}`);

    // What reached Central: one multipart upload, named and typed as asked,
    // whose zip holds every file of both components and nothing of the
    // repository's own metadata.
    check("one upload, AUTOMATIC, named for the version", central.uploads.length === 1 && central.uploads[0].query.includes("publishingType=AUTOMATIC") && central.uploads[0].query.includes(`name=proteles-android-${VERSION}`) && central.uploads[0].type.startsWith("multipart/form-data"),
      JSON.stringify(central.uploads.map((u) => ({ query: u.query, type: u.type }))));
    if (central.uploads.length) {
      // The one part of the multipart body: from the zip's first header to the
      // closing boundary.
      const { body, type } = central.uploads[0];
      const boundary = /boundary=(.+)$/.exec(type)?.[1] ?? "";
      const start = body.indexOf(Buffer.from("PK\x03\x04", "latin1"));
      const end = body.lastIndexOf(Buffer.from(`\r\n--${boundary}--`, "latin1"));
      const zip = path.join(work, "bundle.zip");
      fs.writeFileSync(zip, body.subarray(start, end > start ? end : body.length));
      const listing = spawnSyncText("unzip", ["-Z1", zip]);
      const entries = new Set(listing.split("\n").filter(Boolean));
      const want = [];
      for (const [id, main] of [["proteles-auth-core", "jar"], ["proteles-auth-android", "aar"]]) {
        const stem = `com/proteles/${id}/${VERSION}/${id}-${VERSION}`;
        for (const f of [`${stem}.${main}`, `${stem}-sources.jar`, `${stem}-javadoc.jar`, `${stem}.pom`, `${stem}.module`]) {
          want.push(f, `${f}.asc`, `${f}.md5`, `${f}.sha1`);
        }
      }
      const missing = want.filter((f) => !entries.has(f));
      const metadata = [...entries].filter((e) => e.includes("maven-metadata"));
      check(`the bundle holds all ${want.length} component files and no maven-metadata`, missing.length === 0 && metadata.length === 0,
        `missing: ${missing.join(", ") || "none"}; metadata: ${metadata.join(", ") || "none"}`);
    }

    // And again: everything is out, so nothing is built or uploaded.
    central.requests = [];
    const second = await run(env);
    check("a second run skips Android", second.code === 0 && second.out.includes("already on Maven Central; skipping") && !second.out.includes(building),
      `exit ${second.code}\n${second.out.split("\n").slice(-20).join("\n")}`);
    check("…and uploads nothing", central.uploads.length === 1 && !central.requests.some((r) => r.path.endsWith("/upload")));
  } finally {
    spawnSyncText("gpgconf", ["--homedir", home, "--kill", "all"]);
    fs.rmSync(home, { recursive: true, force: true });
    central.accept = false;
  }
}

function spawnSyncText(cmd, args) {
  const r = spawnSync(cmd, args, { encoding: "utf8" });
  return r.stdout ?? "";
}
