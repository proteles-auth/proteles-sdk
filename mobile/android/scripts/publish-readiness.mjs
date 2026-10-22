#!/usr/bin/env node
// Everything that has to be true of the Android SDK's Maven publication before
// Maven Central is asked to take it — `tools/npm-publish-readiness.mjs`,
// for the other registry.
//
// The failure is the same one-way kind. Central never deletes or replaces a
// released version: an upload missing its sources or javadoc jar, a signature or
// a checksum is refused at validation, and one that passes with a wrong POM — a
// placeholder URL, a dependency on a core of another version — is public for
// good, fixed only by burning a version number. So the publication is built and
// read here, file by file, before anyone has a key to upload it with.
//
// With no arguments it publishes twice into build/repo: once with no signing key,
// which must produce no signature at all (the signing plugin is applied only
// when a key is supplied), then signed with a throwaway key made for this run in
// a temporary GNUPGHOME — a test value, not a credential, deleted on exit. Every
// signature is verified against that key; then one signature is swapped for
// another file's, and the signature rule must refuse it, so the verification is
// seen to run and to refuse something.
//
//   node mobile/android/scripts/publish-readiness.mjs              build twice and check both
//   node … --repo DIR [--signed] [--gnupg-home DIR] [--release]        check a repository already published; build nothing
//   node … --release                                                   also refuse the POM placeholders (gradle.properties)
//   node … --self-test                                                 each rule against a fixture that breaks it
//
// What it does not do is prove the code works: that is `:core:test` and
// `:android:testDebugUnitTest`. This is the packaging only.

import { execFileSync, spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const ANDROID = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const MOBILE = path.dirname(ANDROID);

const GROUP = "com.proteles";
/** Every artifact the build publishes, and nothing else. */
export const ARTIFACTS = [
  { artifactId: "proteles-auth-core", packaging: "jar" },
  { artifactId: "proteles-auth-android", packaging: "aar" },
];

/** `KEY=value` from a .properties file; comments and blank lines skipped. */
export function readProperties(file) {
  const out = {};
  for (const line of fs.readFileSync(file, "utf8").split("\n")) {
    const m = /^\s*([A-Za-z0-9_.-]+)\s*=\s*(.*?)\s*$/.exec(line);
    if (m && !line.trimStart().startsWith("#")) out[m[1]] = m[2];
  }
  return out;
}

/** The inner text of the first `<name>…</name>`, or null. */
function tag(xml, name) {
  const m = new RegExp(`<${name}>([\\s\\S]*?)</${name}>`).exec(xml);
  return m ? m[1].trim() : null;
}

/** The project-level part of a POM: the nested blocks that also hold `<url>` or `<name>` removed. */
function projectLevel(pom) {
  return pom.replace(/<(licenses|developers|scm|dependencies|dependencyManagement|organization)>[\s\S]*?<\/\1>/g, "");
}

function digest(file, algorithm) {
  return crypto.createHash(algorithm).update(fs.readFileSync(file)).digest("hex");
}

/** The names in a zip; empty for an empty zip (which `unzip` calls an error), null for one it cannot read. */
function zipEntries(file) {
  const r = spawnSync("unzip", ["-Z1", file], { encoding: "utf8" });
  if (r.status === 0) return r.stdout.split("\n").filter(Boolean);
  return /Empty zipfile/.test(r.stdout + r.stderr) ? [] : null;
}

/** One entry of a zip as text. */
function zipText(file, entry) {
  return spawnSync("unzip", ["-p", file, entry], { encoding: "utf8" }).stdout ?? "";
}

/**
 * What the README in a javadoc jar must not say. Central keeps the jar as long
 * as the version exists, and the build (the root build.gradle.kts,
 * `publishedReadme`) cuts the README for it; this is that cut, read back from
 * the jar, so a README edited around the cut is caught before a release.
 */
export const UNPUBLISHABLE = [
  [/^## For contributors/m, "the contributors' part, which points into this repository"],
  [/\bM7\b/, "an open question (M7) that the owner rules on"],
  [/not (?:on Maven Central |published there )?yet/i, "\"not yet\" on Central, which is false once it is there"],
  [/<!-- \/?unpublished/, "an unpublished-block marker, so the cut did not run"],
  [/\]\(\.\.\//, "a link out of the SDK's directory, dead inside a jar"],
  [/\.invalid\b/, "a placeholder on .invalid"],
  [/<project-id>/, "the <project-id> placeholder"],
];

/**
 * Checks one repository. Returns `[rule, problems[]]` pairs, one per rule, so
 * the caller (and the self-test) can see which rule failed.
 *
 * `signed` says whether every file must carry a `.asc` or none may; with
 * `gnupgHome`, each signature is also verified against that keyring.
 * `readmes` are the files whose install lines must name `version`.
 */
export function checkRepository({ repo, version, signed, gnupgHome = null, release = false, readmes = [] }) {
  const results = [];
  const rule = (name, problems) => results.push([name, problems]);
  const base = path.join(repo, ...GROUP.split("."));

  // 1. Exactly the artifacts expected. Every rule after this is a loop over
  // what is found, and a loop over nothing passes.
  {
    const found = fs.existsSync(base) ? fs.readdirSync(base).filter((d) => fs.statSync(path.join(base, d)).isDirectory()).sort() : [];
    const want = ARTIFACTS.map((a) => a.artifactId).sort();
    const problems = [];
    for (const a of want) if (!found.includes(a)) problems.push(`${a} was not published`);
    for (const a of found) if (!want.includes(a)) problems.push(`${a} was published, and nothing here expects it`);
    for (const a of want) {
      const versions = found.includes(a) ? fs.readdirSync(path.join(base, a)).filter((d) => fs.statSync(path.join(base, a, d)).isDirectory()) : [];
      if (found.includes(a) && JSON.stringify(versions) !== JSON.stringify([version])) {
        problems.push(`${a} has versions [${versions.join(", ")}]; the repository should hold ${version} alone`);
      }
    }
    rule(`exactly ${want.join(" and ")} at ${version} are published`, problems);
  }

  const present = ARTIFACTS.filter((a) => fs.existsSync(path.join(base, a.artifactId, version)));
  const filesOf = (a) => {
    const stem = `${a.artifactId}-${version}`;
    return [`${stem}.${a.packaging}`, `${stem}-sources.jar`, `${stem}-javadoc.jar`, `${stem}.pom`, `${stem}.module`];
  };
  const dirOf = (a) => path.join(base, a.artifactId, version);

  // 2. Every file Central requires of a component.
  {
    const problems = [];
    for (const a of present) for (const f of filesOf(a)) if (!fs.existsSync(path.join(dirOf(a), f))) problems.push(`${a.artifactId}: no ${f}`);
    rule("each has its main file (.jar/.aar), -sources.jar, -javadoc.jar, .pom and .module", problems);
  }

  // 3. Checksums, and that they are the checksums of these bytes.
  {
    const problems = [];
    for (const a of present) {
      for (const f of filesOf(a)) {
        const file = path.join(dirOf(a), f);
        if (!fs.existsSync(file)) continue;
        for (const alg of ["md5", "sha1"]) {
          const sum = `${file}.${alg}`;
          if (!fs.existsSync(sum)) problems.push(`${a.artifactId}: no ${f}.${alg}`);
          else if (fs.readFileSync(sum, "utf8").trim().split(/\s+/)[0] !== digest(file, alg)) problems.push(`${a.artifactId}: ${f}.${alg} does not match ${f}`);
        }
      }
    }
    rule("each file has an .md5 and a .sha1 that match it", problems);
  }

  // 4. Signatures: all or none, and when a keyring is given, valid.
  {
    const problems = [];
    for (const a of present) {
      for (const f of filesOf(a)) {
        const file = path.join(dirOf(a), f);
        if (!fs.existsSync(file)) continue;
        const asc = `${file}.asc`;
        if (!signed) {
          if (fs.existsSync(asc)) problems.push(`${a.artifactId}: ${f}.asc exists, but no key was supplied`);
          continue;
        }
        if (!fs.existsSync(asc)) { problems.push(`${a.artifactId}: no ${f}.asc`); continue; }
        if (gnupgHome && !gpgVerifies(gnupgHome, asc, file)) problems.push(`${a.artifactId}: ${f}.asc does not verify`);
      }
    }
    rule(signed
      ? `each file has a .asc${gnupgHome ? " that verifies against the signing key" : ""}`
      : "no file is signed when no key is supplied", problems);
  }

  // 5. The POM Central requires, and that it describes this artifact.
  const poms = new Map();
  {
    const problems = [];
    for (const a of present) {
      const f = path.join(dirOf(a), `${a.artifactId}-${version}.pom`);
      if (!fs.existsSync(f)) continue;
      const pom = fs.readFileSync(f, "utf8");
      poms.set(a.artifactId, pom);
      const top = projectLevel(pom);
      const need = (what, value) => { if (!value) problems.push(`${a.artifactId}: the POM has no ${what}`); };
      if (tag(top, "groupId") !== GROUP) problems.push(`${a.artifactId}: groupId is ${tag(top, "groupId")}, not ${GROUP}`);
      if (tag(top, "artifactId") !== a.artifactId) problems.push(`${a.artifactId}: the POM's artifactId is ${tag(top, "artifactId")}`);
      if (tag(top, "version") !== version) problems.push(`${a.artifactId}: the POM's version is ${tag(top, "version")}, not ${version}`);
      // `jar` is Maven's default and may be left out; anything else must be said.
      if ((tag(top, "packaging") ?? "jar") !== a.packaging) problems.push(`${a.artifactId}: packaging is ${tag(top, "packaging") ?? "jar (by default)"}, not ${a.packaging}`);
      need("name", tag(top, "name"));
      need("description", tag(top, "description"));
      need("url", tag(top, "url"));
      const license = tag(pom, "licenses");
      if (!license || !/<name>MIT License<\/name>/.test(license) || !tag(license, "url")) problems.push(`${a.artifactId}: the POM does not name the MIT licence with its URL`);
      const developer = tag(pom, "developers");
      for (const f of ["id", "name", "email"]) need(`developer ${f}`, developer && tag(developer, f));
      const scm = tag(pom, "scm");
      for (const f of ["url", "connection", "developerConnection"]) need(`scm ${f}`, scm && tag(scm, f));
    }
    rule("each POM carries the name, description, url, licence, developers and scm Central requires", problems);
  }

  // 6. What an app actually resolves: the Android library's core is this one.
  {
    const problems = [];
    const pom = poms.get("proteles-auth-android");
    if (pom) {
      const deps = [...pom.matchAll(/<dependency>([\s\S]*?)<\/dependency>/g)].map((m) => m[1]);
      const core = deps.find((d) => tag(d, "groupId") === GROUP && tag(d, "artifactId") === "proteles-auth-core");
      if (!core) problems.push("proteles-auth-android's POM does not depend on proteles-auth-core");
      else if (tag(core, "version") !== version) problems.push(`proteles-auth-android depends on proteles-auth-core ${tag(core, "version")}, not ${version}`);
    }
    rule("proteles-auth-android depends on the proteles-auth-core published beside it", problems);
  }

  // 7. The jars hold what their names say.
  {
    const problems = [];
    for (const a of present) {
      const javadoc = path.join(dirOf(a), `${a.artifactId}-${version}-javadoc.jar`);
      if (fs.existsSync(javadoc) && !(zipEntries(javadoc) ?? []).includes("README.md")) problems.push(`${a.artifactId}: the javadoc jar has no README.md`);
      const sources = path.join(dirOf(a), `${a.artifactId}-${version}-sources.jar`);
      if (fs.existsSync(sources) && !(zipEntries(sources) ?? []).some((e) => e.endsWith(".kt"))) problems.push(`${a.artifactId}: the sources jar holds no Kotlin source`);
    }
    rule("each javadoc jar holds the README, and each sources jar holds source", problems);
  }

  // 7a. The README in the javadoc jar is the published one. Not only with
  // --release: the build makes the cut every time, so a README it misses is
  // wrong on the change that broke it, not on release day.
  {
    const problems = [];
    for (const a of present) {
      const javadoc = path.join(dirOf(a), `${a.artifactId}-${version}-javadoc.jar`);
      if (!fs.existsSync(javadoc) || !(zipEntries(javadoc) ?? []).includes("README.md")) continue;
      const text = zipText(javadoc, "README.md");
      for (const [pattern, what] of UNPUBLISHABLE) {
        const m = pattern.exec(text);
        if (m) problems.push(`${a.artifactId}: the javadoc jar's README has ${what}: ${JSON.stringify(m[0])}`);
      }
    }
    rule("each javadoc jar's README is the published cut: no contributors' part, open question, \"not yet\", placeholder or link out", problems);
  }

  // 8. Placeholders. Expected until a maintainer fills them in, and fatal for a
  // release: `.invalid` never resolves, and a POM is public for good.
  {
    const problems = [];
    for (const [id, pom] of poms) {
      for (const m of pom.matchAll(/[^\s<>]*\.invalid[^\s<>]*/g)) problems.push(`${id}: ${m[0]}`);
    }
    if (release) rule("no POM carries a placeholder (gradle.properties: POM_*)", problems);
    else if (problems.length) console.log(`  · placeholders the owner fills in before a release (--release refuses them):\n${[...new Set(problems.map((p) => p.replace(/^[^:]+: /, "")))].map((p) => `      ${p}`).join("\n")}`);
  }

  // 9. The install lines the READMEs show name this version.
  {
    const problems = [];
    let seen = 0;
    for (const f of readmes) {
      const text = fs.readFileSync(f, "utf8");
      const rel = path.relative(MOBILE, f);
      for (const m of text.matchAll(/com\.proteles:proteles-auth-(?:core|android):([^"'\s)]+)/g)) {
        seen++;
        if (m[1] !== version) problems.push(`${rel}: ${m[0]}, not ${version}`);
      }
      for (const m of text.matchAll(/\.package\(url:\s*"[^"]*",\s*from:\s*"([^"]+)"\)/g)) {
        seen++;
        if (m[1] !== version) problems.push(`${rel}: from: "${m[1]}", not ${version}`);
      }
    }
    if (readmes.length && seen === 0) problems.push("no install line with a version was found in any README — the scan is wrong");
    rule(`every README install line names VERSION_NAME (${version})`, problems);
  }

  return results;
}

function gpgVerifies(gnupgHome, asc, file) {
  const r = spawnSync("gpg", ["--batch", "--homedir", gnupgHome, "--verify", asc, file], { encoding: "utf8" });
  return r.status === 0;
}

function report(results) {
  let failed = 0;
  for (const [name, problems] of results) {
    if (problems.length === 0) { console.log(`  ✓ ${name}`); continue; }
    failed++;
    console.log(`  ✗ ${name}`);
    for (const p of problems) console.log(`      ${p}`);
  }
  return failed;
}

// ---------------------------------------------------------------------------
// The real run.
// ---------------------------------------------------------------------------

/** A failure that ends the run, thrown so that `finally` blocks still run. */
class Fatal extends Error {}

function gradlePublish(env) {
  const repo = path.join(ANDROID, "build/repo");
  // Whatever an earlier publish left — another version, a signed run — would
  // be read as this run's output.
  fs.rmSync(repo, { recursive: true, force: true });
  const r = spawnSync("./gradlew", ["--no-daemon", "--console=plain", "publishAllPublicationsToBuildRepository"], {
    cwd: ANDROID, stdio: "inherit", env,
  });
  // Thrown, not process.exit: the signed publish runs inside the `finally` that
  // deletes the throwaway key and stops its gpg-agent, and process.exit would
  // skip it.
  if (r.status !== 0) throw new Fatal(`gradle exited ${r.status ?? r.signal}`);
  return repo;
}

/**
 * The environment without the ORG_GRADLE_PROJECT_signing* variables. A key set
 * elsewhere — `signingInMemoryKey` in ~/.gradle/gradle.properties, or a
 * `-Dorg.gradle.project.` one in GRADLE_OPTS — still reaches the build and
 * signs; the unsigned run's "no file is signed" rule then fails and says so.
 */
function unsignedEnv() {
  const env = { ...process.env };
  for (const k of Object.keys(env)) if (/^ORG_GRADLE_PROJECT_signing/.test(k)) delete env[k];
  env.ANDROID_HOME ??= path.join(os.homedir(), "Library/Android/sdk");
  return env;
}

function throwawayKey() {
  // Short, because gpg-agent's socket lives in it and a Unix socket path is
  // limited to about a hundred bytes.
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "pr-gpg-"));
  fs.chmodSync(home, 0o700);
  const passphrase = crypto.randomBytes(12).toString("hex");
  const gpg = (...args) => execFileSync("gpg", ["--batch", "--homedir", home, "--pinentry-mode", "loopback", "--passphrase", passphrase, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  gpg("--quick-gen-key", "Proteles publish-readiness check (throwaway) <throwaway@publish-readiness.invalid>", "rsa3072", "sign", "1d");
  const key = gpg("--armor", "--export-secret-keys");
  const cleanup = () => {
    spawnSync("gpgconf", ["--homedir", home, "--kill", "all"]);
    fs.rmSync(home, { recursive: true, force: true });
  };
  return { home, key, passphrase, cleanup };
}

/**
 * The negative control for the check just made, with its own arguments. A
 * verification that accepted everything — or that never ran, because the
 * keyring did not reach the rule — would pass every file, so here the POM's
 * signature is replaced by the jar's: a valid signature, by the right key, of
 * other bytes. The signature rule must now refuse exactly that file. The
 * repository is put back afterwards.
 */
function signatureControl(check) {
  const dir = path.join(check.repo, "com/proteles/proteles-auth-core", check.version);
  const pomAsc = path.join(dir, `proteles-auth-core-${check.version}.pom.asc`);
  const jarAsc = path.join(dir, `proteles-auth-core-${check.version}.jar.asc`);
  const label = "a signature swapped for another file's is refused by the signature rule";
  if (!fs.existsSync(pomAsc) || !fs.existsSync(jarAsc)) { console.log(`  ✗ ${label}\n      there is no .asc to swap`); return 1; }
  const original = fs.readFileSync(pomAsc);
  fs.copyFileSync(jarAsc, pomAsc);
  let problems;
  try {
    // Placeholders and README versions are not what this is about.
    const results = quiet(() => checkRepository({ ...check, release: false, readmes: [] }));
    problems = results.find(([name]) => name.startsWith("each file has a .asc"))?.[1] ?? ["the signature rule did not run"];
  } finally {
    fs.writeFileSync(pomAsc, original);
  }
  const good = problems.length === 1 && problems[0] === `proteles-auth-core: proteles-auth-core-${check.version}.pom.asc does not verify`;
  console.log(`  ${good ? "✓" : "✗"} ${label}`);
  if (!good) console.log(`      the rule said: ${problems.length ? problems.join("; ") : "nothing — the signatures are not being verified"}`);
  return good ? 0 : 1;
}

/** Runs `f` with console.log silenced: the check's own notes are for a real run. */
function quiet(f) {
  const log = console.log;
  console.log = () => {};
  try { return f(); } finally { console.log = log; }
}

function readmesToCheck() {
  return [path.join(ANDROID, "README.md"), path.join(MOBILE, "ios/README.md"), path.join(MOBILE, "README.md")].filter((f) => fs.existsSync(f));
}

function main(args) {
  const release = args.includes("--release");
  const version = readProperties(path.join(ANDROID, "gradle.properties")).VERSION_NAME;
  if (!/^\d+\.\d+\.\d+$/.test(version ?? "")) { console.log(`FATAL: VERSION_NAME in gradle.properties is ${JSON.stringify(version)}, not MAJOR.MINOR.PATCH`); process.exit(1); }
  const readmes = readmesToCheck();
  let failed = 0;

  const at = args.indexOf("--repo");
  if (at >= 0) {
    const repo = path.resolve(args[at + 1] ?? "");
    const home = args.includes("--gnupg-home") ? path.resolve(args[args.indexOf("--gnupg-home") + 1]) : null;
    console.log(`${repo} (VERSION_NAME ${version}):`);
    failed += report(checkRepository({ repo, version, signed: args.includes("--signed"), gnupgHome: home, release, readmes }));
  } else {
    console.log("== unsigned: no key supplied ==");
    failed += report(checkRepository({ repo: gradlePublish(unsignedEnv()), version, signed: false, release, readmes }));

    console.log("\n== signed with a throwaway key ==");
    const key = throwawayKey();
    try {
      const env = { ...unsignedEnv(), ORG_GRADLE_PROJECT_signingInMemoryKey: key.key, ORG_GRADLE_PROJECT_signingInMemoryKeyPassword: key.passphrase };
      const repo = gradlePublish(env);
      const signedCheck = { repo, version, signed: true, gnupgHome: key.home, release, readmes };
      failed += report(checkRepository(signedCheck));
      failed += signatureControl(signedCheck);
    } finally {
      key.cleanup();
    }
  }

  console.log();
  if (failed) { console.log(`${failed} rule(s) FAILED`); process.exit(1); }
  console.log(`the Maven publication is ready: ${ARTIFACTS.map((a) => a.artifactId).join(", ")} ${version}`);
}

// ---------------------------------------------------------------------------
// The self-test: each rule against a repository that breaks it, and nothing else.
// ---------------------------------------------------------------------------

function selfTest() {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), "maven-readiness-"));
  process.on("exit", () => fs.rmSync(work, { recursive: true, force: true }));
  const V = "1.2.3";
  let failures = 0;

  const pom = (id, { packaging = null, deps = "", drop = [], extra = "" } = {}) => {
    const blocks = {
      name: `<name>${id}</name>`,
      description: "<description>d</description>",
      url: "<url>https://example.com/p</url>",
      licenses: "<licenses><license><name>MIT License</name><url>https://opensource.org/license/mit</url></license></licenses>",
      developers: "<developers><developer><id>p</id><name>P</name><email>p@example.com</email></developer></developers>",
      scm: "<scm><connection>scm:git:https://example.com/p.git</connection><developerConnection>scm:git:ssh://example.com/p.git</developerConnection><url>https://example.com/p</url></scm>",
    };
    for (const d of drop) delete blocks[d];
    return `<project><modelVersion>4.0.0</modelVersion><groupId>${GROUP}</groupId><artifactId>${id}</artifactId><version>${V}</version>${packaging ? `<packaging>${packaging}</packaging>` : ""}${Object.values(blocks).join("")}${extra}${deps}</project>\n`;
  };
  const coreDep = (v) => `<dependencies><dependency><groupId>${GROUP}</groupId><artifactId>proteles-auth-core</artifactId><version>${v}</version><scope>compile</scope></dependency></dependencies>`;

  /**
   * A repository that passes every rule; `mutate(repo, dirOf)` then breaks one.
   * `javadocReadme` is the README core's javadoc jar holds.
   */
  function build(name, { signed = false, poms = {}, javadocReadme = null, mutate = () => {} } = {}) {
    const repo = path.join(work, name, "repo");
    const src = path.join(work, name, "src");
    fs.mkdirSync(path.join(src, "core"), { recursive: true });
    fs.writeFileSync(path.join(src, "README.md"), "# readme\n\n## Install\n\nFrom Maven Central.\n");
    fs.writeFileSync(path.join(src, "core/README.md"), javadocReadme ?? "# readme\n");
    fs.writeFileSync(path.join(src, "A.kt"), "class A\n");
    const dirOf = (id) => path.join(repo, "com/proteles", id, V);
    for (const a of ARTIFACTS) {
      const dir = dirOf(a.artifactId);
      fs.mkdirSync(dir, { recursive: true });
      const stem = path.join(dir, `${a.artifactId}-${V}`);
      const readmeFile = a.artifactId === "proteles-auth-core" ? path.join(src, "core/README.md") : path.join(src, "README.md");
      execFileSync("zip", ["-qj", `${stem}.${a.packaging}`, path.join(src, "A.kt")]);
      execFileSync("zip", ["-qj", `${stem}-sources.jar`, path.join(src, "A.kt")]);
      execFileSync("zip", ["-qj", `${stem}-javadoc.jar`, readmeFile]);
      const isAndroid = a.artifactId === "proteles-auth-android";
      fs.writeFileSync(`${stem}.pom`, poms[a.artifactId] ?? pom(a.artifactId, isAndroid ? { packaging: "aar", deps: coreDep(V) } : {}));
      fs.writeFileSync(`${stem}.module`, "{}\n");
    }
    mutate(repo, dirOf);
    // Checksums and signatures last, so a mutation above is summed like the
    // real build would sum it; a mutation of the sums themselves goes in `after`.
    for (const a of ARTIFACTS) {
      if (!fs.existsSync(dirOf(a.artifactId))) continue;
      for (const f of fs.readdirSync(dirOf(a.artifactId))) {
        const file = path.join(dirOf(a.artifactId), f);
        if (/\.(md5|sha1|asc)$/.test(f)) continue;
        fs.writeFileSync(`${file}.md5`, digest(file, "md5"));
        fs.writeFileSync(`${file}.sha1`, digest(file, "sha1"));
        if (signed) fs.writeFileSync(`${file}.asc`, "-----BEGIN PGP SIGNATURE-----\n");
      }
    }
    return { repo, dirOf };
  }

  const readme = (name, text) => {
    const f = path.join(work, `${name}.md`);
    fs.writeFileSync(f, text);
    return f;
  };
  const goodReadme = readme("good", `implementation("com.proteles:proteles-auth-android:${V}")\n.package(url: "https://x.invalid/P.git", from: "${V}")\n`);

  /** Runs the check; `expect` is the one rule that must fail, or null for none. */
  const run = (label, { repo, signed = false, release = false, readmes = [goodReadme] }, expect) => {
    const results = quiet(() => checkRepository({ repo, version: V, signed, release, readmes }));
    const failedRules = results.filter(([, p]) => p.length).map(([n]) => n);
    const good = expect === null ? failedRules.length === 0 : failedRules.length === 1 && failedRules[0].includes(expect);
    console.log(`  ${good ? "✓" : "✗"} ${label}`);
    if (!good) {
      console.log(`      wanted ${expect === null ? "no failure" : `only "${expect}" to fail`}; failed: ${failedRules.length ? failedRules.join(" | ") : "nothing"}`);
      failures++;
    }
  };

  run("a well-formed unsigned repository passes", build("good"), null);
  run("a well-formed signed repository passes", { ...build("good-signed", { signed: true }), signed: true }, null);
  run("a missing artifact is caught", build("no-core", { mutate: (repo) => fs.rmSync(path.join(repo, "com/proteles/proteles-auth-core"), { recursive: true }) }), "exactly");
  run("a stray artifact is caught", build("stray", { mutate: (repo) => fs.mkdirSync(path.join(repo, `com/proteles/proteles-example/${V}`), { recursive: true }) }), "exactly");
  run("a second version left in the repository is caught", build("two-versions", { mutate: (repo) => fs.mkdirSync(path.join(repo, "com/proteles/proteles-auth-core/0.0.1")) }), "exactly");
  run("a missing javadoc jar is caught", build("no-javadoc", { mutate: (_, dirOf) => fs.rmSync(path.join(dirOf("proteles-auth-android"), `proteles-auth-android-${V}-javadoc.jar`)) }), "-javadoc.jar");
  run("a missing .module is caught", build("no-module", { mutate: (_, dirOf) => fs.rmSync(path.join(dirOf("proteles-auth-core"), `proteles-auth-core-${V}.module`)) }), ".module");
  {
    const b = build("no-sha1");
    fs.rmSync(path.join(b.dirOf("proteles-auth-core"), `proteles-auth-core-${V}.jar.sha1`));
    run("a missing .sha1 is caught", b, ".md5 and a .sha1");
    const c = build("bad-md5");
    fs.writeFileSync(path.join(c.dirOf("proteles-auth-core"), `proteles-auth-core-${V}.pom.md5`), "0".repeat(32));
    run("an .md5 that is not the file's is caught", c, ".md5 and a .sha1");
  }
  {
    const b = build("no-asc", { signed: true });
    fs.rmSync(path.join(b.dirOf("proteles-auth-android"), `proteles-auth-android-${V}.aar.asc`));
    run("a signed repository missing one .asc is caught", { ...b, signed: true }, ".asc");
    run("a signature in an unsigned build is caught", { ...build("stray-asc", { signed: true }), signed: false }, "no file is signed");
  }
  run("a POM without scm is caught", build("no-scm", { poms: { "proteles-auth-core": pom("proteles-auth-core", { drop: ["scm"] }) } }), "each POM");
  run("a POM without a developer is caught", build("no-dev", { poms: { "proteles-auth-core": pom("proteles-auth-core", { drop: ["developers"] }) } }), "each POM");
  run("a POM without a project url is caught (the scm url does not count)", build("no-url", { poms: { "proteles-auth-core": pom("proteles-auth-core", { drop: ["url"] }) } }), "each POM");
  run("an .aar whose POM says jar is caught", build("jar-aar", { poms: { "proteles-auth-android": pom("proteles-auth-android", { deps: coreDep(V) }) } }), "each POM");
  run("the Android library depending on another core is caught", build("core-skew", { poms: { "proteles-auth-android": pom("proteles-auth-android", { packaging: "aar", deps: coreDep("0.0.9") }) } }), "depends on");
  run("the Android library not depending on core is caught", build("no-core-dep", { poms: { "proteles-auth-android": pom("proteles-auth-android", { packaging: "aar" }) } }), "depends on");
  run("a javadoc jar without the README is caught", build("empty-javadoc", {
    mutate: (_, dirOf) => execFileSync("zip", ["-qd", path.join(dirOf("proteles-auth-core"), `proteles-auth-core-${V}-javadoc.jar`), "README.md"]),
  }), "javadoc jar holds the README");
  run("a sources jar without source is caught", build("empty-sources", {
    mutate: (_, dirOf) => {
      const jar = path.join(dirOf("proteles-auth-android"), `proteles-auth-android-${V}-sources.jar`);
      fs.rmSync(jar);
      execFileSync("zip", ["-qj", jar, path.join(work, "empty-sources", "src", "README.md")]);
    },
  }), "sources jar holds source");
  // What the build's cut removes, each left in once. The text around it is
  // what the real README's customer part looks like, so only the line named
  // can be what fails.
  for (const [label, line] of [
    ["the contributors' part", "## For contributors\n\nSee docs/mobile-SDKs.md."],
    ["the M7 note", "App identity: M7 in §1, the owner's to rule on."],
    ["\"not yet\" on Central", "It is not on Maven Central yet: the first release is still to be made."],
    ["the older \"not yet\" wording", "**From Maven Central**, once it is published there. It is not yet:"],
    ["an unpublished-block marker", "<!-- unpublished -->"],
    ["a link out of the directory", "[`mobile/README.md`](../README.md) covers both."],
    ["an .invalid placeholder", "maven { url = uri(\"https://PROJECT-URL-NOT-SET.invalid/x\") }"],
    ["the <project-id> placeholder", "maven { url = uri(\"https://gitlab.com/api/v4/projects/<project-id>/packages/maven\") }"],
  ]) {
    const text = `# Proteles for Android\n\n## Install\n\n${line}\n\n## Usage\n\nCall \`signIn\`.\n`;
    run(`a javadoc README carrying ${label} is caught`, build(`javadoc-${label.replace(/\W+/g, "-")}`, { javadocReadme: text }), "published cut");
  }
  {
    const placeholder = pom("proteles-auth-core", { drop: ["url"], extra: "<url>https://PROJECT-URL-NOT-SET.invalid/p</url>" });
    run("a placeholder passes an ordinary run", build("placeholder", { poms: { "proteles-auth-core": placeholder } }), null);
    run("a placeholder is refused with --release", { ...build("placeholder-release", { poms: { "proteles-auth-core": placeholder } }), release: true }, "placeholder");
  }
  run("a README naming another version is caught", { ...build("readme-skew"), readmes: [readme("skew", 'implementation("com.proteles:proteles-auth-core:0.0.1")\n')] }, "README");
  run("an iOS install line naming another version is caught", { ...build("readme-ios"), readmes: [readme("ios", '.package(url: "https://x.invalid/P.git", from: "0.0.1")\n')] }, "README");
  run("README files with no install line at all are caught", { ...build("readme-none"), readmes: [readme("none", "# nothing to install\n")] }, "README");

  // The real run, with a Gradle that publishes nothing unsigned and fails
  // signed: the throwaway key's directory (secret key and all) and its
  // gpg-agent must be gone afterwards, on the shared machine CI runs this on.
  {
    const label = "a failed signed publish still deletes the throwaway key and stops its agent";
    const fake = path.join(work, "gradle-fails", "android");
    // Its own TMPDIR, as short as the real one: gpg-agent's socket lives in
    // the key's directory, and a Unix socket path is limited to about a
    // hundred bytes.
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "prt-"));
    process.on("exit", () => fs.rmSync(tmp, { recursive: true, force: true }));
    fs.mkdirSync(path.join(fake, "scripts"), { recursive: true });
    fs.copyFileSync(fileURLToPath(import.meta.url), path.join(fake, "scripts/publish-readiness.mjs"));
    fs.writeFileSync(path.join(fake, "gradle.properties"), `VERSION_NAME=${V}\n`);
    fs.writeFileSync(path.join(fake, "gradlew"), '#!/bin/sh\n[ -z "$ORG_GRADLE_PROJECT_signingInMemoryKey" ]\n', { mode: 0o755 });
    const r = spawnSync("node", [path.join(fake, "scripts/publish-readiness.mjs")], { encoding: "utf8", env: { ...process.env, TMPDIR: tmp } });
    const left = fs.readdirSync(tmp).filter((d) => d.startsWith("pr-gpg-"));
    const good = r.status === 1 && /FATAL: gradle exited 1/.test(r.stdout) && left.length === 0;
    console.log(`  ${good ? "✓" : "✗"} ${label}`);
    if (!good) {
      console.log(`      exit ${r.status}; left behind: ${left.join(", ") || "nothing"}\n${(r.stdout + r.stderr).split("\n").slice(-8).map((l) => `      | ${l}`).join("\n")}`);
      failures++;
    }
    for (const d of left) spawnSync("gpgconf", ["--homedir", path.join(tmp, d), "--kill", "all"]);
  }

  console.log();
  if (failures) { console.log(`${failures} case(s) failed`); process.exit(1); }
  console.log("each rule fails on the repository that breaks it, and on no other");
}

if (process.argv.includes("--self-test")) selfTest();
else {
  try {
    main(process.argv.slice(2));
  } catch (e) {
    if (!(e instanceof Fatal)) throw e;
    console.log(`FATAL: ${e.message}`);
    process.exit(1);
  }
}
