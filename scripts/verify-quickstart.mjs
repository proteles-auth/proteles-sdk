// Runs a quickstart inside its own framework and walks it like a browser.
//
// The other verify-*.mjs scripts call the SDK's bindings directly, outside any
// framework. That is why none of them saw the Next.js quickstart fail three
// ways on 2026-09-29: the middleware did not compile for the Edge runtime, the
// App Router refused a module that called `createContext` without "use client",
// and Next's middleware adapter threw on a relative `Location`. Each of those
// lives in the framework's bundler or runtime, so the only check that sees them
// is one that installs the example, builds it with its own toolchain, serves it
// with its own server, and speaks HTTP to it.
//
// Proteles' integration tests run it for the Next.js quickstart. The table
// below covers all seven, for running by hand against a live server.
//
// Usage:
//   node scripts/verify-quickstart.mjs nextjs-quickstart          # install, build, start, walk, stop
//   node scripts/verify-quickstart.mjs nextjs-quickstart --dev    # the dev server instead of a build
//   node scripts/verify-quickstart.mjs nextjs-quickstart --attach # walk an app already on QS_PORT
//   node scripts/verify-quickstart.mjs --self-test                # this script's own guards, no server
//
// Env:
//   SDK_ISSUER, SDK_CLIENT_ID, SDK_CLIENT_SECRET   the client registered for
//     http://localhost:$QS_PORT/api/auth/callback. Handed to the app as
//     PROTELES_* environment variables. Every PROTELES_* variable the SDK reads
//     is set, the unused ones to "" (which the SDK reads as unset), and every
//     framework here lets a set variable win over its `.env` file — so a
//     developer's `.env` or `.env.local` cannot change the configuration under
//     test. The frameworks still read the rest of that file.
//   SDK_USERNAME, SDK_PASSWORD                      a password-only user.
//   QS_PORT                                         default: the example's own.
//     Must be free: the run refuses to start where something already answers,
//     since Next, Nuxt and SolidStart all default to 3000 and it would walk
//     whatever is there.
//   QS_SESSION_SECRET                               default: random. With
//     --attach it must be the app's own, for the stale-session checks.
//   QS_SKIP_INSTALL=1                               reuse node_modules as is.
//
// The app and its install and build see only the variables in `appEnv` —
// never this process's environment, which in CI holds the job's tokens. The
// install runs no lifecycle scripts, and an example with a tracked lockfile
// (`lockfile: true` below; the one the integration tests run) installs with `npm ci`, so a
// registry release cannot change what is tested. After changing that example's
// package.json, refresh its lockfile with
// `npm install --package-lock-only --ignore-scripts` in the example directory.
//
// Exit code: 0 all checks passed, 1 a check failed, 2 usage, 3 the install
// failed (no registry, or a lockfile this npm cannot use), which the integration
// tests count as a skip, the same way it treats the workspace install.

import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import http from "node:http";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";

// The cookie names come from the package that sets them, never retyped.
import { SessionCrypto, cookieNames } from "../packages/bff/dist/index.js";
import { leavingPageTarget } from "./leaving-page.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));

// The examples run over plain HTTP with PROTELES_COOKIE_SECURE=false (see
// appEnv), so their cookies carry the plain names, not the `__Host-` ones.
const { session: SESSION_COOKIE, flow: FLOW_COOKIE } = cookieNames(false);

/**
 * What differs between the examples. `start` serves the production build; the
 * ones whose `npm start` adds `--env-file=.env` are started without it here,
 * because this passes real environment variables and there may be no `.env`.
 * `logout` is the request the example's own sign-out control makes (`htmx` adds
 * the header an `hx-post` carries). Every one is a POST: `signOut()`
 * submits a form, and a GET only asks for confirmation; `protectedPath` is null where the example
 * has no guarded page; `signedInProbe` is a page whose server-rendered HTML
 * names the signed-in user, or null where only the browser renders the user;
 * `fragmentGuard` is a guarded fragment and the hypermedia library asking for it.
 * `lockfile` marks the example whose package-lock.json is tracked (see
 * .gitignore), which installs with `npm ci`.
 *
 * @type {Record<string, {
 *   port: number,
 *   lockfile?: boolean,
 *   dev: string[], build: string[] | null, start: string[],
 *   logout: { method: "GET" | "POST", htmx?: boolean },
 *   protectedPath: string | null,
 *   signedInProbe: string | null,
 *   fragmentGuard?: { path: string, library: "htmx" | "alpine-ajax" },
 * }>}
 */
const EXAMPLES = {
  "nextjs-quickstart": {
    port: 3000,
    lockfile: true,
    dev: ["npm", "run", "dev", "--", "--port", "$PORT"],
    build: ["npm", "run", "build"],
    start: ["npm", "start", "--", "--port", "$PORT"],
    logout: { method: "POST" },
    protectedPath: "/dashboard",
    signedInProbe: "/dashboard",
  },
  "sveltekit-quickstart": {
    port: 5173,
    dev: ["npm", "run", "dev", "--", "--port", "$PORT", "--strictPort"],
    build: ["npm", "run", "build"],
    start: ["npm", "run", "preview", "--", "--port", "$PORT", "--strictPort"],
    logout: { method: "POST" },
    protectedPath: "/dashboard",
    signedInProbe: "/dashboard",
  },
  "nuxt-quickstart": {
    port: 3000,
    dev: ["npm", "run", "dev", "--", "--port", "$PORT"],
    build: ["npm", "run", "build"],
    start: ["node", ".output/server/index.mjs"],
    logout: { method: "POST" },
    protectedPath: "/dashboard",
    signedInProbe: "/dashboard",
  },
  "solidstart-quickstart": {
    port: 3000,
    dev: ["npm", "run", "dev", "--", "--port", "$PORT"],
    build: ["npm", "run", "build"],
    start: ["node", ".output/server/index.mjs"],
    logout: { method: "POST" },
    protectedPath: "/dashboard",
    // Its AuthProvider takes no server-side user; the name arrives from /me.
    signedInProbe: null,
  },
  "htmx-quickstart": {
    port: 3600,
    dev: ["node", "server.mjs"],
    build: null,
    start: ["node", "server.mjs"],
    logout: { method: "POST", htmx: true },
    protectedPath: "/dashboard",
    signedInProbe: "/dashboard",
    fragmentGuard: { path: "/fragments/secret", library: "htmx" },
  },
  "alpine-quickstart": {
    port: 3500,
    dev: ["node", "server.mjs"],
    build: null,
    start: ["node", "server.mjs"],
    logout: { method: "POST" },
    protectedPath: null,
    signedInProbe: null,
  },
  "alpine-ajax-quickstart": {
    port: 3700,
    dev: ["node", "server.mjs"],
    build: null,
    start: ["node", "server.mjs"],
    logout: { method: "POST" },
    protectedPath: "/dashboard",
    signedInProbe: "/dashboard",
    fragmentGuard: { path: "/fragments/secret", library: "alpine-ajax" },
  },
};

// --- What the example is run with --------------------------------------------

/**
 * The only variables taken from this process's environment into the app's, its
 * install and its build: what npm and Node need to find themselves, their cache
 * and the registry. Not `...process.env`: in CI that holds the job's tokens
 * (CI_JOB_TOKEN, CI_REGISTRY_PASSWORD and the rest of the job's variables) and
 * this script's own SDK_CLIENT_SECRET and SDK_PASSWORD, and the install and
 * build run code from a few hundred registry packages.
 */
const PASS_THROUGH = new Set([
  "PATH", "HOME", "USER", "LOGNAME", "SHELL", "TMPDIR", "TMP", "TEMP", "LANG", "LC_ALL", "LC_CTYPE", "TERM", "TZ", "CI",
  "XDG_CACHE_HOME", "XDG_CONFIG_HOME", "NODE_OPTIONS", "NODE_NO_WARNINGS", "NODE_EXTRA_CA_CERTS",
  "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy",
  "SystemRoot", "ComSpec", "PATHEXT", "APPDATA", "LOCALAPPDATA", "USERPROFILE",
]);

/**
 * The app's environment. Every variable the SDK reads is set, to "" where the
 * SDK's default is wanted — `@proteles/bff` and the base-path helpers read ""
 * as unset — because each framework here loads the example's `.env` (or
 * `.env.local`) only into variables that are not set at all. So a developer's
 * PROTELES_REDIRECT_URI, say, cannot move the callback away from the client
 * this run was given. `--self-test` holds this list to the SDK's source.
 *
 * @param {NodeJS.ProcessEnv} from
 * @param {{ port: number, issuer: string, clientId: string, clientSecret: string, appUrl: string, sessionSecret: string }} app
 * @returns {Record<string, string>}
 */
function appEnv(from, app) {
  /** @type {Record<string, string>} */
  const env = {};
  for (const [k, v] of Object.entries(from)) {
    if (v !== undefined && (PASS_THROUGH.has(k) || /^npm_config_/i.test(k))) env[k] = v;
  }
  return {
    ...env,
    PORT: String(app.port),
    PROTELES_ISSUER: app.issuer,
    PROTELES_CLIENT_ID: app.clientId,
    PROTELES_CLIENT_SECRET: app.clientSecret,
    PROTELES_APP_URL: app.appUrl,
    PROTELES_SESSION_SECRET: app.sessionSecret,
    PROTELES_COOKIE_SECURE: "false",
    PROTELES_REDIRECT_URI: "",
    PROTELES_BASE_PATH: "",
    PROTELES_SCOPES: "",
    PROTELES_POST_LOGIN_REDIRECT: "",
    PROTELES_TIMEOUT_MS: "",
    PROTELES_END_SESSION: "",
    NEXT_PUBLIC_PROTELES_BASE_PATH: "",
    VITE_PROTELES_BASE_PATH: "",
    PUBLIC_PROTELES_BASE_PATH: "",
    NEXT_TELEMETRY_DISABLED: "1",
    NUXT_TELEMETRY_DISABLED: "1",
  };
}

/**
 * How an example is installed. No lifecycle scripts: none of the Next.js
 * example's dependencies needs one, and each is code from the registry run with
 * this machine's privileges. `npm ci` from the tracked lockfile where there is
 * one, so what is tested is what the lockfile says, not what the registry
 * published since. @param {{ lockfile?: boolean }} ex
 */
function installCommand(ex) {
  return ex.lockfile
    ? ["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"]
    : ["npm", "install", "--ignore-scripts", "--no-audit", "--no-fund", "--no-package-lock"];
}

/** Whether anything accepts a TCP connection on `port` at either loopback
 *  address. @param {number} port @returns {Promise<boolean>} */
function portInUse(port) {
  /** @param {string} host @returns {Promise<boolean>} */
  const attempt = (host) =>
    new Promise((resolve) => {
      const s = net.connect({ host, port });
      s.setTimeout(2000, () => (s.destroy(), resolve(false)));
      s.once("connect", () => (s.destroy(), resolve(true)));
      s.once("error", () => resolve(false));
    });
  return Promise.all([attempt("127.0.0.1"), attempt("::1")]).then(([v4, v6]) => v4 || v6);
}

/** Whether a child process is still running. @param {import("node:child_process").ChildProcess} child */
function running(child) {
  return child.exitCode === null && child.signalCode === null;
}

/** The environment variables the SDK's packages read, found in their source:
 *  `env("…")` in `@proteles/bff` and `process.env[…]` elsewhere. */
function sdkEnvReads() {
  /** @type {Set<string>} */
  const names = new Set();
  /** @param {string} dir */
  const scan = (dir) => {
    for (const entry of readdirSync(dir)) {
      const p = path.join(dir, entry);
      if (statSync(p).isDirectory()) scan(p);
      else if (/\.(ts|tsx|svelte|vue)$/.test(entry)) {
        const src = readFileSync(p, "utf8");
        for (const m of src.matchAll(/\benv\(\s*"([A-Z0-9_]+)"\s*\)|process\.env\??\.?\[\s*"([A-Z0-9_]+)"\s*\]|process\.env\.([A-Z0-9_]+)/g)) {
          const n = m[1] ?? m[2] ?? m[3];
          if (n && n.includes("PROTELES_")) names.add(n);
        }
      }
    }
  };
  const packages = path.join(here, "..", "packages");
  for (const pkg of readdirSync(packages)) {
    const src = path.join(packages, pkg, "src");
    if (existsSync(src)) scan(src);
  }
  return names;
}

/** JSON with its object keys sorted, so two spellings of one value compare equal.
 *  @param {unknown} v @returns {string} */
function canonical(v) {
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  if (v && typeof v === "object") {
    return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonical(/** @type {any} */ (v)[k])}`).join(",")}}`;
  }
  return JSON.stringify(v ?? null);
}

/**
 * Where an example's lockfile disagrees with its package.json, or with the
 * packages its `file:` dependencies link. `npm ci` refuses either, and the
 * linked packages' own package.json files are part of what it checks: when
 * 0.2.0 bumped them, the Next.js lockfile still recorded 0.1.1 and no
 * `@proteles/bff`, and the integration tests could not install it at all.
 * This reads files only, so the sdk job catches that before a live run does.
 * @param {any} pkg @param {any} lock @param {(rel: string) => any} readLinked
 * @returns {string[]}
 */
function lockDrift(pkg, lock, readLinked) {
  const drift = [];
  const root = lock?.packages?.[""] ?? {};
  for (const field of ["dependencies", "devDependencies"]) {
    if (canonical(pkg[field] ?? {}) !== canonical(root[field] ?? {})) {
      drift.push(`${field}: package.json ${canonical(pkg[field] ?? {})}, lockfile ${canonical(root[field] ?? {})}`);
    }
  }
  for (const spec of Object.values({ ...pkg.dependencies, ...pkg.devDependencies })) {
    if (typeof spec !== "string" || !spec.startsWith("file:")) continue;
    const rel = spec.slice("file:".length);
    const entry = lock?.packages?.[rel];
    if (!entry) {
      drift.push(`${rel} is linked and absent from the lockfile`);
      continue;
    }
    const linked = readLinked(rel);
    for (const f of ["version", "dependencies", "peerDependencies"]) {
      if (canonical(linked[f]) !== canonical(entry[f])) {
        drift.push(`${rel} ${f}: the package says ${canonical(linked[f])}, the lockfile ${canonical(entry[f])}`);
      }
    }
  }
  return drift;
}

/** Drives this script's guards against the inputs they exist for. Needs no
 *  server; the sdk job runs it after the build. @returns {Promise<number>} */
async function selfTest() {
  console.log("== verify-quickstart: self-test ==");
  let bad = 0;
  /** @param {boolean} ok @param {string} msg */
  const expect = (ok, msg) => {
    console.log(`  ${ok ? "✓" : "✗"} ${msg}`);
    if (!ok) bad++;
  };
  const app = { port: 3999, issuer: "http://issuer.test", clientId: "c", clientSecret: "s", appUrl: "http://localhost:3999", sessionSecret: "k" };

  // (1) The job's secrets stay out. Read back from a real child, as the app
  //     would see them, with the harness's own environment as the control.
  const planted = { ...process.env, CI_JOB_TOKEN: "planted-job-token", SDK_PASSWORD: "planted-password", npm_config_cache: "/planted/cache" };
  /** @param {Record<string, string | undefined>} env @returns {Promise<Record<string, string>>} */
  const seenBy = (env) =>
    new Promise((resolve, reject) => {
      const child = spawn(process.execPath, ["-e", "process.stdout.write(JSON.stringify(process.env))"], { env, stdio: ["ignore", "pipe", "inherit"] });
      let out = "";
      child.stdout.on("data", (c) => (out += c));
      child.on("error", reject);
      child.on("exit", () => resolve(JSON.parse(out)));
    });
  const control = await seenBy(planted);
  expect(control.CI_JOB_TOKEN === "planted-job-token", "control: a child started with the whole environment sees the planted job token");
  const seen = await seenBy(appEnv(planted, app));
  expect(!("CI_JOB_TOKEN" in seen) && !("SDK_PASSWORD" in seen), "the app's environment carries neither the job token nor SDK_PASSWORD");
  expect(seen.PATH === process.env.PATH && seen.npm_config_cache === "/planted/cache", "…but keeps PATH and npm's own settings");

  // (2) Every variable the SDK reads is pinned, so no `.env` can supply it.
  const reads = sdkEnvReads();
  expect(reads.has("PROTELES_ISSUER") && reads.has("NEXT_PUBLIC_PROTELES_BASE_PATH"), `control: the source scan finds the SDK's reads (${reads.size})`);
  const env = appEnv({}, app);
  const unpinned = [...reads].filter((n) => !(n in env));
  expect(unpinned.length === 0, `every PROTELES_* variable the SDK reads is set for the app${unpinned.length ? ` — not: ${unpinned.join(", ")}` : ""}`);

  // (3) No install runs lifecycle scripts; a locked example installs from its
  //     lockfile, which must be there (a fresh CI checkout has only what git tracks).
  expect(Object.values(EXAMPLES).every((ex) => installCommand(ex).includes("--ignore-scripts")), "no example's install runs lifecycle scripts");
  const locked = Object.entries(EXAMPLES).filter(([, ex]) => ex.lockfile);
  expect(locked.length > 0 && locked.every(([, ex]) => installCommand(ex)[1] === "ci"), `the locked examples install with npm ci (${locked.map(([n]) => n).join(", ")})`);
  for (const [n] of locked) {
    const dir = path.join(here, "..", "examples", n);
    expect(existsSync(path.join(dir, "package-lock.json")), `${n} has its package-lock.json`);
    const read = (/** @type {string} */ f) => JSON.parse(readFileSync(f, "utf8"));
    const pkg = read(path.join(dir, "package.json"));
    const lock = read(path.join(dir, "package-lock.json"));
    const readLinked = (/** @type {string} */ rel) => read(path.join(dir, rel, "package.json"));
    const drift = lockDrift(pkg, lock, readLinked);
    expect(drift.length === 0, `${n}'s lockfile agrees with its package.json and the packages it links${drift.length ? ` — ${drift.join("; ")}` : ""}`);
    // The control: the same lockfile with one linked version moved.
    const link = Object.keys(lock.packages ?? {}).find((k) => k.startsWith("../"));
    const doctored = structuredClone(lock);
    if (link) doctored.packages[link].version = "0.0.0-drifted";
    expect(link !== undefined && lockDrift(pkg, doctored, readLinked).some((d) => d.includes("0.0.0-drifted")), `control: a linked version the lockfile has wrong is caught (${n})`);
  }

  // (4) A port something already answers on is seen as taken.
  const listener = net.createServer().listen(0, "127.0.0.1");
  await new Promise((r) => listener.once("listening", r));
  const port = /** @type {import("node:net").AddressInfo} */ (listener.address()).port;
  expect(await portInUse(port), "a port with a listener on 127.0.0.1 is in use");
  await new Promise((r) => listener.close(r));
  expect(!(await portInUse(port)), "…and free once it has closed");

  // (5) A server that has exited is not taken for the one that answered.
  const quick = spawn(process.execPath, ["-e", ""], { stdio: "ignore" });
  await new Promise((r) => quick.once("exit", r));
  const slow = spawn(process.execPath, ["-e", "setTimeout(() => {}, 10000)"], { stdio: "ignore" });
  expect(!running(quick) && running(slow), "an exited child reads as gone, a live one as running");
  slow.kill();

  // (6) The guards above are called where they matter. A helper that passes
  //     its own test proves nothing once its call is gone, so the part of this
  //     file that runs the example is read back, and the scan is shown to see.
  const self = readFileSync(fileURLToPath(import.meta.url), "utf8");
  const runner = self.slice(self.indexOf("\n// --- Running the example"));
  expect(runner.length > 1 && runner.includes("async function main()"), "control: the scan finds the code that runs the example");
  const spawns = [...runner.matchAll(/\bspawn\(([^;]*?)\);/gs)].map((m) => m[1] ?? "");
  expect(spawns.length >= 2 && spawns.every((s) => s.includes("env: childEnv")), `every child the runner spawns gets childEnv (${spawns.length} spawns)`);
  expect(/const childEnv = appEnv\(process\.env,/.test(runner) && !/\.\.\.process\.env/.test(runner), "childEnv is built by appEnv, and nothing spreads process.env");
  expect(/await portInUse\(PORT\)/.test(runner) && /run\(installCommand\(example\)\)/.test(runner) && /!running\(server\)/.test(runner), "main checks the port, installs with installCommand and checks its server is still running");

  console.log(bad === 0 ? "\nthe guards hold" : `\n${bad} self-test case(s) wrong`);
  return bad === 0 ? 0 : 1;
}

const argv = process.argv.slice(2);
if (argv.includes("--self-test")) process.exit(await selfTest());
const name = argv.find((a) => !a.startsWith("--"));
const mode = argv.includes("--attach") ? "attach" : argv.includes("--dev") ? "dev" : "prod";
const example = name ? EXAMPLES[name] : undefined;
if (!name || !example) {
  console.error(`usage: verify-quickstart.mjs <${Object.keys(EXAMPLES).join("|")}> [--dev|--attach]`);
  process.exit(2);
}

const ISSUER = (process.env.SDK_ISSUER || "").replace(/\/+$/, "");
const CLIENT_ID = process.env.SDK_CLIENT_ID;
const CLIENT_SECRET = process.env.SDK_CLIENT_SECRET;
const USERNAME = process.env.SDK_USERNAME;
const PASSWORD = process.env.SDK_PASSWORD;
const PORT = Number(process.env.QS_PORT || example.port);
const SESSION_SECRET = process.env.QS_SESSION_SECRET || randomBytes(32).toString("base64");
const APP = `http://localhost:${PORT}`;
const dir = path.join(here, "..", "examples", name);

for (const [k, v] of Object.entries({ SDK_ISSUER: ISSUER, SDK_CLIENT_ID: CLIENT_ID, SDK_CLIENT_SECRET: CLIENT_SECRET, SDK_USERNAME: USERNAME, SDK_PASSWORD: PASSWORD })) {
  if (!v) {
    console.error(`missing required env ${k}`);
    process.exit(2);
  }
}

let passed = 0;
/** @param {unknown} cond @param {string} msg @param {string} [detail] */
function check(cond, msg, detail) {
  if (!cond) throw new Error(detail ? `${msg} — ${detail}` : msg);
  passed++;
  console.log(`  ✓ ${msg}`);
}

// --- The "browser": a cookie jar per host, and raw HTTP ----------------------
// node:http rather than fetch: undici's `redirect: "manual"` hides the status
// and Location of a redirect, which are exactly what is being checked.

/** @type {Map<string, Map<string, string>>} */
const jars = new Map();
/** @param {string} host */
function jarFor(host) {
  let jar = jars.get(host);
  if (!jar) jars.set(host, (jar = new Map()));
  return jar;
}
/** @param {string} host @param {string[]} setCookies */
function store(host, setCookies) {
  const jar = jarFor(host);
  for (const sc of setCookies) {
    const pair = sc.split(";")[0] ?? "";
    const eq = pair.indexOf("=");
    if (eq === -1) continue;
    const k = pair.slice(0, eq).trim();
    if (/max-age=0|expires=thu, 01 jan 1970/i.test(sc)) jar.delete(k);
    else jar.set(k, pair.slice(eq + 1).trim());
  }
}

/**
 * @typedef {{ status: number, location: string | undefined, leavingPage: boolean, setCookies: string[], headers: import("node:http").IncomingHttpHeaders, body: string }} Reply
 * @param {string} urlStr
 * @param {{ method?: string, body?: string, headers?: Record<string, string>, cookies?: boolean }} [opts]
 * @returns {Promise<Reply>}
 */
function request(urlStr, { method = "GET", body, headers = {}, cookies = true } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(urlStr);
    /** @type {Record<string, string | number>} */
    const h = { ...headers };
    const jar = jarFor(u.hostname);
    if (cookies && jar.size > 0) h.cookie = [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
    if (body !== undefined) {
      h["content-type"] ??= "application/x-www-form-urlencoded";
      h["content-length"] = Buffer.byteLength(body);
    }
    const req = http.request(
      { hostname: u.hostname, port: u.port || 80, path: u.pathname + u.search, method, headers: h },
      (res) => {
        let data = "";
        res.setEncoding("utf8");
        res.on("data", (c) => (data += c));
        res.on("end", () => {
          const setCookies = res.headers["set-cookie"] ?? [];
          if (cookies) store(u.hostname, setCookies);
          resolve({ status: res.statusCode ?? 0, location: res.headers.location ?? leavingPageTarget(res.statusCode, data), leavingPage: leavingPageTarget(res.statusCode, data) !== undefined, setCookies, headers: res.headers, body: data });
        });
      },
    );
    req.setTimeout(120_000, () => req.destroy(new Error(`timed out: ${method} ${urlStr}`)));
    req.on("error", reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

/** Resolves a Location the way a browser does: against the URL it answered. */
function follow(/** @type {string} */ from, /** @type {string | undefined} */ location) {
  if (!location) throw new Error(`no Location on the redirect from ${from}`);
  return new URL(location, from).href;
}

/** The session cookie a response set, if any. */
function sessionFrom(/** @type {Reply} */ res) {
  const sc = res.setCookies.find((c) => c.startsWith(`${SESSION_COOKIE}=`));
  return sc ? decodeURIComponent((sc.split(";")[0] ?? "").slice(SESSION_COOKIE.length + 1)) : undefined;
}

// --- The authorization server's side -----------------------------------------

/** Signs in at the AS the way a browser would, from an authorize URL to the
 *  redirect back at the app. Reads the form's own fields rather than assuming
 *  them. @param {string} authorizeUrl */
async function signInAtServer(authorizeUrl) {
  let res = await request(authorizeUrl);
  check(res.status === 303, "the authorization server sends a signed-out browser to its login page", `got ${res.status}`);
  const loginPage = follow(authorizeUrl, res.location);
  res = await request(loginPage);
  check(res.status === 200, "the login page renders", `got ${res.status}`);
  const form = res.body.match(/<form[^>]*method="post"[^>]*action="([^"]*)"[^>]*>([\s\S]*?)<\/form>/i);
  if (!form) throw new Error("no login form on the login page");
  const fields = new URLSearchParams();
  for (const input of (form[2] ?? "").matchAll(/<input[^>]*>/gi)) {
    const n = input[0].match(/name="([^"]*)"/)?.[1];
    const v = input[0].match(/value="([^"]*)"/)?.[1] ?? "";
    if (n) fields.set(n, v.replace(/&amp;/g, "&").replace(/&#x2F;|&#47;/g, "/"));
  }
  fields.set("username", /** @type {string} */ (USERNAME));
  fields.set("password", /** @type {string} */ (PASSWORD));
  const action = new URL(form[1] || "/login", loginPage).href;
  res = await request(action, { method: "POST", body: fields.toString() });
  // A completed sign-in leaves through the server's page, not a 303.
  check(res.leavingPage, `${USERNAME} signs in at the login form`, `got ${res.status}`);
  let next = follow(action, res.location);
  // Back through authorize, now signed in, until the AS lets go of the browser.
  for (let hops = 0; new URL(next).origin === new URL(ISSUER).origin && hops < 5; hops++) {
    res = await request(next);
    if (res.status < 300 || res.status >= 400) throw new Error(`the authorization server answered ${res.status} at ${next} (a consent page? the client should be first-party)`);
    next = follow(next, res.location);
  }
  return next;
}

/** Whether the AS still honours a refresh token: a direct refresh grant, which
 *  a spent or revoked one fails with `invalid_grant`. Any other answer (a busy
 *  server, say) proves neither, and throws. @param {string} refreshToken */
async function refreshTokenIsLive(refreshToken) {
  const res = await fetch(`${ISSUER}/oauth/token`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      authorization: `Basic ${Buffer.from(`${encodeURIComponent(/** @type {string} */ (CLIENT_ID))}:${encodeURIComponent(/** @type {string} */ (CLIENT_SECRET))}`).toString("base64")}`,
    },
    body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: refreshToken }).toString(),
  });
  if (res.ok) return true;
  const body = await res.text();
  if (res.status === 400 && /"invalid_grant"/.test(body)) return false;
  throw new Error(`the refresh-token probe got ${res.status}: ${body.slice(0, 200)}`);
}

// --- The walk ----------------------------------------------------------------

async function walk() {
  const appHost = new URL(APP).hostname;
  const crypto = new SessionCrypto(SESSION_SECRET);

  let res = await request(`${APP}/`);
  check(res.status === 200, "the home page renders signed out", `got ${res.status}${res.status >= 500 ? `: ${res.body.slice(0, 300)}` : ""}`);

  res = await request(`${APP}/api/auth/me`);
  check(res.status === 200 && JSON.parse(res.body).authenticated === false, "/api/auth/me says signed out", `got ${res.status} ${res.body.slice(0, 200)}`);

  let loginStart = `${APP}/api/auth/login?returnTo=%2F`;
  let landing = `${APP}/`;
  if (example.protectedPath) {
    const target = `${APP}${example.protectedPath}`;
    res = await request(target);
    const want = `${APP}/api/auth/login?returnTo=${encodeURIComponent(example.protectedPath)}`;
    check(res.status === 307 && follow(target, res.location) === want, `${example.protectedPath} signed out redirects to sign-in`, `got ${res.status} → ${res.location}`);
    // Whatever the Location's form, it must not be steered by a request header.
    res = await request(target, { headers: { "x-forwarded-host": "attacker.example", "x-forwarded-proto": "https" } });
    check(res.status === 307 && new URL(follow(target, res.location)).origin === APP, "a forged X-Forwarded-Host does not move the sign-in redirect", `got ${res.status} → ${res.location}`);
    loginStart = want;
    landing = target;
  }

  if (example.fragmentGuard) {
    // A guarded fragment asked for from the home page must send the user back
    // to the home page after sign-in, not to the fragment, which as a page is
    // a bare scrap of HTML.
    const { path: fragment, library } = example.fragmentGuard;
    const home = `${APP}/`;
    const want = "/api/auth/login?returnTo=%2F";
    if (library === "htmx") {
      res = await request(`${APP}${fragment}`, { headers: { "hx-request": "true", "hx-current-url": home } });
      check(res.status === 200 && res.headers["hx-redirect"] === want, `a signed-out htmx request for ${fragment} is sent to sign in, and back to the page`, `got ${res.status} → ${res.headers["hx-redirect"]}`);
    } else {
      res = await request(`${APP}${fragment}`, { headers: { "x-alpine-request": "true", "x-alpine-target": "secret", referer: home } });
      check(res.status === 401 && res.body.includes('id="secret"') && res.body.includes(`href="${want}"`), `a signed-out Alpine AJAX request for ${fragment} gets a sign-in link back to the page`, `got ${res.status}: ${res.body.slice(0, 200)}`);
    }
  }

  res = await request(loginStart);
  check(res.status === 302 && (res.location ?? "").startsWith(`${ISSUER}/oauth/authorize?`), "/api/auth/login redirects to the authorization server", `got ${res.status} → ${res.location}`);
  const authorize = new URL(/** @type {string} */ (res.location));
  check(authorize.searchParams.get("code_challenge_method") === "S256" && authorize.searchParams.get("nonce"), "the authorize request carries PKCE and a nonce");
  check(jarFor(appHost).has(FLOW_COOKIE), "the flow cookie is set");

  const callback = await signInAtServer(authorize.href);
  check(callback.startsWith(`${APP}/api/auth/callback?`), "the authorization server returns a code to the app's callback", callback);
  check(new URL(callback).searchParams.get("state") === authorize.searchParams.get("state"), "state round-trips unchanged");
  res = await request(callback);
  check(res.status === 303 && follow(callback, res.location) === landing, "the callback signs in and returns to where the user started", `got ${res.status} → ${res.location}`);
  const session = sessionFrom(res);
  check(session, "the session cookie is set");

  res = await request(`${APP}/api/auth/me`);
  const me = JSON.parse(res.body);
  const identity = me.user?.email ?? me.user?.preferredUsername ?? me.user?.sub;
  check(me.authenticated === true && identity, `/api/auth/me names the user (${identity})`);
  check(!/eyJ/.test(res.body) && !res.body.includes(/** @type {string} */ (session)), "/api/auth/me carries no token");

  if (example.signedInProbe) {
    res = await request(`${APP}${example.signedInProbe}`);
    check(res.status === 200 && res.body.includes(identity), `${example.signedInProbe} renders the signed-in user`, `got ${res.status}${res.status >= 500 ? `: ${res.body.slice(0, 300)}` : ""}`);
  }

  // An expired access token. Re-sealed with the app's own key, so this needs
  // the session secret the app was started with.
  const data = await crypto.decrypt(/** @type {string} */ (session));
  check(typeof data.refreshToken === "string", "the session holds a refresh token (offline_access)");
  /** @param {object} d */
  const stale = async (d) => crypto.encrypt({ ...d, accessExpiresAt: Date.now() - 1000 });

  // A public page must not spend the refresh token unless the rotated cookie
  // comes back with it: a spent token in the browser's cookie signs the user
  // out on the next request that refreshes.
  jarFor(appHost).set(SESSION_COOKIE, encodeURIComponent(await stale(data)));
  res = await request(`${APP}/`);
  check(res.status === 200, "the home page renders with an expired access token", `got ${res.status}`);
  const rotatedByHome = sessionFrom(res);
  if (!rotatedByHome) {
    check(await refreshTokenIsLive(/** @type {string} */ (data.refreshToken)), "rendering it spent no refresh token without handing back the rotated cookie");
  } else {
    check(true, "rendering it refreshed the session and handed back the rotated cookie");
  }

  // Sign in afresh: the probe above spent that refresh token, and the checks
  // below need one that only the app has used.
  jars.delete(appHost);
  res = await request(loginStart);
  const again = follow(loginStart, res.location);
  res = await request(again); // authorize: the AS still knows the browser
  const cb = follow(again, res.location);
  check(cb.startsWith(`${APP}/api/auth/callback?`), "signing in again goes straight back to the app", cb);
  res = await request(cb);
  const freshCookie = sessionFrom(res);
  check(freshCookie, "and sets a new session cookie");

  if (example.protectedPath) {
    const target = `${APP}${example.protectedPath}`;
    const fresh = await crypto.decrypt(/** @type {string} */ (freshCookie));
    jarFor(appHost).set(SESSION_COOKIE, encodeURIComponent(await stale(fresh)));
    res = await request(target);
    const want = `${APP}/api/auth/revalidate?returnTo=${encodeURIComponent(example.protectedPath)}`;
    check(res.status === 303 && follow(target, res.location) === want, `${example.protectedPath} with an expired access token goes through /revalidate`, `got ${res.status} → ${res.location}`);
    const reval = follow(target, res.location);
    res = await request(reval);
    check(res.status === 303 && follow(reval, res.location) === target && sessionFrom(res), "/revalidate refreshes, rotates the cookie and returns", `got ${res.status} → ${res.location}`);
    res = await request(target);
    check(res.status === 200 && (!example.signedInProbe || res.body.includes(identity)), `${example.protectedPath} renders after the refresh`, `got ${res.status}`);
  }

  const before = jarFor(appHost).get(SESSION_COOKIE);
  const logout = `${APP}/api/auth/logout`;
  // A GET — a link, an image, another site's redirect — only asks. The
  // refresh-token probe would spend the token, so the session is read at /me.
  res = await request(logout);
  check(
    res.status === 200 && /<form method="post"/.test(res.body) && !res.setCookies.some((c) => c.startsWith(`${SESSION_COOKIE}=`)),
    "a GET to sign-out shows a confirmation and clears nothing",
    `got ${res.status}`,
  );
  res = await request(`${APP}/api/auth/me`);
  check(JSON.parse(res.body).authenticated === true, "…and the user is still signed in");
  const { method, htmx } = example.logout;
  // What a browser sends with a form post or an hx-post from the app's own page.
  const fromThisPage = { origin: APP, "sec-fetch-site": "same-origin" };
  res = await request(logout, {
    method,
    ...(method === "POST" ? { body: "" } : {}),
    headers: { ...fromThisPage, ...(htmx ? { "hx-request": "true" } : {}) },
  });
  // Sign-out ends the session at the server too (the default since
  // 2026-10-09): the browser goes on to the end-session endpoint, hinted by the
  // ID token, which is asked to bring it home afterwards.
  /** @param {string | undefined} to */
  const endsTheSessionAndComesHome = (to) => {
    if (typeof to !== "string") return false;
    const u = new URL(to, logout);
    return (
      u.origin + u.pathname === `${ISSUER}/oauth/logout` &&
      u.searchParams.get("post_logout_redirect_uri") === `${APP}/` &&
      Boolean(u.searchParams.get("id_token_hint"))
    );
  };
  /** @type {string | undefined} */
  let endSession;
  if (htmx) {
    const hx = res.headers["hx-redirect"];
    endSession = Array.isArray(hx) ? hx[0] : hx;
    check(res.status === 200 && endsTheSessionAndComesHome(endSession), "sign-out (hx-post) sends htmx on to end the session at the server, then home", `got ${res.status} → ${endSession}`);
  } else {
    endSession = res.location;
    check(res.status === 303 && endsTheSessionAndComesHome(endSession), `sign-out (${method}) goes on to end the session at the server, then home`, `got ${res.status} → ${endSession}`);
  }
  check(res.setCookies.some((c) => c.startsWith(`${SESSION_COOKIE}=;`) && /Max-Age=0/i.test(c)), "sign-out clears the session cookie");
  const revoked = await crypto.decrypt(decodeURIComponent(/** @type {string} */ (before)));
  check(!(await refreshTokenIsLive(/** @type {string} */ (revoked.refreshToken))), "sign-out revoked the refresh token at the authorization server");
  res = await request(`${APP}/api/auth/me`);
  check(JSON.parse(res.body).authenticated === false, "/api/auth/me says signed out again");
  if (typeof endSession === "string") {
    // The live server takes what the BFF sent: its end-session endpoint answers
    // with the confirmation that ends the session there (RP-Initiated Logout).
    res = await request(new URL(endSession, logout).href);
    check(res.status === 200 && /<form method="post"/.test(res.body), "the server's end-session endpoint asks to confirm the sign-out", `got ${res.status}`);
  }
  if (example.protectedPath) {
    res = await request(`${APP}${example.protectedPath}`);
    check(res.status === 307, `${example.protectedPath} redirects to sign-in again`, `got ${res.status}`);
  }
}

// --- Running the example -----------------------------------------------------

/** @type {import("node:child_process").ChildProcess | undefined} */
let server;
let serverLog = "";

const childEnv = appEnv(process.env, {
  port: PORT,
  issuer: ISSUER,
  clientId: /** @type {string} */ (CLIENT_ID),
  clientSecret: /** @type {string} */ (CLIENT_SECRET),
  appUrl: APP,
  sessionSecret: SESSION_SECRET,
});

/** A failure that is about this machine, not the example: the integration tests skip on it. */
class InstallFailed extends Error {}

/** @param {string[]} cmd */
function run(cmd) {
  const [bin, ...args] = cmd.map((a) => a.replace("$PORT", String(PORT)));
  console.log(`  $ ${[bin, ...args].join(" ")}`);
  return new Promise((resolve, reject) => {
    const child = spawn(/** @type {string} */ (bin), args, { cwd: dir, env: childEnv, stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    child.stdout?.on("data", (c) => (out += c));
    child.stderr?.on("data", (c) => (out += c));
    child.on("error", reject);
    child.on("exit", (code) => {
      if (code === 0) resolve(undefined);
      else reject(new Error(`${[bin, ...args].join(" ")} exited ${code}\n${out.slice(-4000)}`));
    });
  });
}

/** @param {string[]} cmd */
async function startServer(cmd) {
  const [bin, ...args] = cmd.map((a) => a.replace("$PORT", String(PORT)));
  console.log(`  $ ${[bin, ...args].join(" ")} &`);
  // Its own process group, so stopping it stops what npm started under it.
  server = spawn(/** @type {string} */ (bin), args, { cwd: dir, env: childEnv, stdio: ["ignore", "pipe", "pipe"], detached: true });
  server.stdout?.on("data", (c) => (serverLog += c));
  server.stderr?.on("data", (c) => (serverLog += c));
  const deadline = Date.now() + 180_000;
  while (Date.now() < deadline) {
    if (server.exitCode !== null) throw new Error(`the server exited ${server.exitCode}\n${serverLog.slice(-4000)}`);
    try {
      await request(`${APP}/api/auth/me`, { cookies: false });
      return;
    } catch {
      await new Promise((r) => setTimeout(r, 500));
    }
  }
  throw new Error(`the server did not answer on ${APP} within 180 s\n${serverLog.slice(-4000)}`);
}

function stopServer() {
  if (!server?.pid || server.exitCode !== null) return;
  try {
    process.kill(-server.pid, "SIGTERM");
  } catch {
    // Already gone.
  }
}
process.on("exit", stopServer);
for (const sig of /** @type {const} */ (["SIGINT", "SIGTERM"])) process.on(sig, () => process.exit(130));

async function main() {
  console.log(`${name} (${mode}) on ${APP}`);
  if (mode !== "attach") {
    // Before the install, so a busy port costs nothing — and it must be free:
    // the readiness probe below takes any answer on it for this run's server.
    if (await portInUse(PORT)) {
      throw new Error(`something already listens on port ${PORT}; stop it or set QS_PORT (and register that port's callback on the client)`);
    }
    if (process.env.QS_SKIP_INSTALL !== "1") {
      await run(installCommand(example)).catch((e) => {
        throw new InstallFailed(e.message);
      });
    }
    if (mode === "prod" && example.build) await run(example.build);
    await startServer(mode === "dev" ? example.dev : example.start);
  }
  await walk();
  if (server && !running(server)) {
    throw new Error(`the server this run started exited during the walk (${server.exitCode ?? server.signalCode}), so what answered on ${APP} was not it`);
  }
}

main()
  .then(() => {
    stopServer();
    console.log(`${name} (${mode}): all ${passed} checks passed`);
  })
  .catch((e) => {
    stopServer();
    const install = e instanceof InstallFailed;
    console.error(`${name} (${mode}) ${install ? "could not be installed" : `FAILED after ${passed} checks`}: ${e.message}`);
    if (serverLog) console.error(`--- server output (last 3000 chars) ---\n${serverLog.slice(-3000)}`);
    process.exit(install ? 3 : 1);
  });
