//! SSR render tests for the real components. Solid's JSX needs its own Babel
//! transform, so these compile `src/components.tsx` with `babel-preset-solid`
//! (`generate: "ssr"`) and render with `renderToString` from `solid-js/web` —
//! which Node resolves to Solid's server build. No bundler, no jsdom.

import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { transformAsync } from "@babel/core";
import { renderToString } from "solid-js/web";

import { createAuth } from "../src/auth.ts";
import type { Auth, AuthUser } from "../src/types.ts";

const here = path.dirname(fileURLToPath(import.meta.url));
const srcDir = path.join(here, "..", "src");
const outDir = path.join(here, "..", ".ssr");

/**
 * Compiles a component module to Solid's SSR output and imports it. Output goes
 * to a gitignored `.ssr/` directory — never into `src/`, which the build copies
 * into `dist/`. Relative imports are rewritten to point back at the real
 * modules, which tsx runs directly.
 */
async function compileAndImport(relative: string): Promise<Record<string, unknown>> {
  const source = fs.readFileSync(path.join(srcDir, relative), "utf8");
  const { code } = await transformAsync(source, {
    filename: path.join(srcDir, relative),
    babelrc: false,
    configFile: false,
    presets: [
      ["babel-preset-solid", { generate: "ssr", hydratable: false }],
      ["@babel/preset-typescript", { isTSX: true, allExtensions: true }],
    ],
  });
  fs.mkdirSync(outDir, { recursive: true });
  const outPath = path.join(outDir, `${path.basename(relative, path.extname(relative))}.ssr.mjs`);
  // `./auth.js` / `./context.js` -> the real sources, one directory up.
  fs.writeFileSync(outPath, code!.replace(/(from\s+['"])\.\/([^'"]+)['"]/g, (_m, p1, f) => `${p1}../src/${f}"`));
  return (await import(outPath)) as Record<string, unknown>;
}

const components = (await compileAndImport("components.tsx")) as {
  AuthProvider: (props: Record<string, unknown>) => unknown;
  SignedIn: (props: Record<string, unknown>) => unknown;
  SignedOut: (props: Record<string, unknown>) => unknown;
  Protect: (props: Record<string, unknown>) => unknown;
  SignInButton: (props: Record<string, unknown>) => unknown;
  SignOutButton: (props: Record<string, unknown>) => unknown;
  SignUpButton: (props: Record<string, unknown>) => unknown;
  UserButton: (props: Record<string, unknown>) => unknown;
};

const noFetch = (async () => new Response("{}", { headers: { "content-type": "application/json" } })) as typeof fetch;

function authFor(state: "signedIn" | "signedOut" | "loading", user?: AuthUser): Auth {
  if (state === "loading") return createAuth({ fetch: noFetch }); // initialUser undefined => isLoading
  if (state === "signedIn") return createAuth({ initialUser: user ?? { sub: "u1" }, fetch: noFetch });
  return createAuth({ initialUser: null, fetch: noFetch });
}

/** Renders every component at once under one auth state, inside AuthProvider so
 *  context is wired exactly as in a real app. */
function renderAll(state: "signedIn" | "signedOut" | "loading", user?: AuthUser): string {
  const auth = authFor(state, user);
  const { AuthProvider, SignedIn, SignedOut, Protect, SignInButton, SignOutButton, SignUpButton, UserButton } = components;
  return renderToString(() =>
    AuthProvider({
      // The provider builds its own auth from these props, matching real usage.
      initialUser: state === "loading" ? undefined : (auth.user() as AuthUser | null),
      get children() {
        return [
          SignedIn({ get children() { return "IN"; } }),
          SignedOut({ get children() { return "OUT"; } }),
          Protect({
            get children() { return "ALLOW"; },
            get fallback() { return "DENY"; },
          }),
          SignInButton({ class: "cta", get children() { return "Continue"; } }),
          SignUpButton({ class: "join" }),
          SignOutButton({}),
          UserButton({ class: "chip" }),
        ];
      },
    }),
  ).replace(/<!--.*?-->/g, "");
}

test("signed in: SignedIn and Protect show content, SignedOut hides", () => {
  const html = renderAll("signedIn", { sub: "u1", email: "a@b.com", preferredUsername: "alice" });
  assert.match(html, /IN/, "SignedIn renders its children");
  assert.doesNotMatch(html, /OUT/, "SignedOut renders nothing");
  assert.match(html, /ALLOW/, "Protect renders its children");
  assert.doesNotMatch(html, /DENY/, "Protect does not render the fallback");
});

test("signed out: SignedOut shows, SignedIn hides, Protect shows the fallback", () => {
  const html = renderAll("signedOut");
  assert.doesNotMatch(html, /IN/);
  assert.match(html, /OUT/);
  assert.doesNotMatch(html, /ALLOW/);
  assert.match(html, /DENY/, "Protect falls back when signed out");
});

test("loading: neither SignedIn nor SignedOut renders, and Protect stays empty", () => {
  const html = renderAll("loading");
  assert.doesNotMatch(html, /IN/, "no signed-in flash before /me resolves");
  assert.doesNotMatch(html, /OUT/, "no signed-out flash before /me resolves");
  assert.doesNotMatch(html, /ALLOW/);
  assert.doesNotMatch(html, /DENY/, "Protect renders nothing at all while loading");
});

test("SignInButton renders a button with custom children and its class", () => {
  const html = renderAll("signedOut");
  assert.match(html, /<button[^>]*class="cta"[^>]*>Continue<\/button>/);
});

test("SignUpButton renders its default label and its class", () => {
  assert.match(renderAll("signedOut"), /<button[^>]*class="join"[^>]*>Sign up<\/button>/);
});

test("SignOutButton renders its default label", () => {
  assert.match(renderAll("signedOut"), /Sign out/);
});

test("UserButton shows the user's label, forwards class, and hides when signed out", () => {
  const signedIn = renderAll("signedIn", { sub: "u1", email: "a@b.com", preferredUsername: "alice" });
  assert.match(signedIn, /data-proteles="user-button"/);
  assert.match(signedIn, /data-proteles="user-label">alice</, "prefers preferredUsername");
  assert.match(signedIn, /alice<\/span> <button/, "the name does not run into the button");
  assert.match(signedIn, /data-proteles="user-signout"/);
  assert.match(signedIn, /class="chip"/, "class is forwarded");

  assert.doesNotMatch(renderAll("signedOut"), /data-proteles="user-button"/, "nothing without a user");
});

test("UserButton falls back to email, then sub", () => {
  assert.match(renderAll("signedIn", { sub: "u1", email: "a@b.com" }), /user-label">a@b\.com</);
  assert.match(renderAll("signedIn", { sub: "just-sub" }), /user-label">just-sub</);
});

test("AuthProvider renders during SSR without touching the network", () => {
  // The provider builds its own auth internally, so stub the *global* fetch to
  // prove nothing is requested while server-rendering (onMount never runs).
  const realFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = (async () => {
    calls++;
    return new Response("{}", { headers: { "content-type": "application/json" } });
  }) as typeof fetch;
  try {
    const html = renderAll("signedIn", { sub: "u1", preferredUsername: "alice" });
    assert.match(html, /alice/, "provider rendered its subtree");
    assert.equal(calls, 0, "no network during server rendering");
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("a component used outside <AuthProvider> throws an actionable error", () => {
  const { SignedIn } = components;
  assert.throws(
    () => renderToString(() => SignedIn({ get children() { return "IN"; } })),
    /useAuth\(\) must be called inside an <AuthProvider>/,
    "missing provider must fail loudly, not render silently",
  );
});
