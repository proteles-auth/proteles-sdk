//! SSR render tests for the real components, via `@vue/server-renderer` — no
//! jsdom and no bundler.

import { test } from "node:test";
import assert from "node:assert/strict";
import { createSSRApp, defineComponent, h } from "vue";
import { renderToString } from "@vue/server-renderer";

import { createAuth } from "../src/auth.ts";
import {
  AuthProvider,
  Protect,
  SignedIn,
  SignedOut,
  SignInButton,
  SignOutButton,
  SignUpButton,
  UserButton,
} from "../src/components.ts";
import { PROTELES_AUTH, protelesAuth, useAuth } from "../src/context.ts";
import type { Auth, AuthUser } from "../src/types.ts";

const noFetch = (async () => new Response("{}", { headers: { "content-type": "application/json" } })) as typeof fetch;

function authFor(state: "signedIn" | "signedOut" | "loading", user?: AuthUser): Auth {
  if (state === "loading") return createAuth({ fetch: noFetch }); // initialUser undefined => isLoading
  if (state === "signedIn") return createAuth({ initialUser: user ?? { sub: "u1" }, fetch: noFetch });
  return createAuth({ initialUser: null, fetch: noFetch });
}

/** Renders every component at once under a supplied auth object. */
function harness(auth: Auth) {
  return defineComponent({
    setup() {
      return () =>
        h("div", null, [
          h(SignedIn, null, { default: () => h("span", { "data-t": "in" }, "IN") }),
          h(SignedOut, null, { default: () => h("span", { "data-t": "out" }, "OUT") }),
          h(Protect, null, {
            default: () => h("span", { "data-t": "allow" }, "ALLOW"),
            fallback: () => h("span", { "data-t": "deny" }, "DENY"),
          }),
          h(SignInButton, { class: "cta" }, { default: () => "Continue" }),
          h(SignUpButton, { class: "join" }),
          h(SignOutButton),
          h(UserButton, { class: "chip" }),
        ]);
    },
  });
}

async function renderWith(state: "signedIn" | "signedOut" | "loading", user?: AuthUser): Promise<string> {
  const auth = authFor(state, user);
  const app = createSSRApp(harness(auth));
  app.provide(PROTELES_AUTH, auth);
  return (await renderToString(app)).replace(/<!--.*?-->/g, "");
}

test("signed in: SignedIn and Protect show content, SignedOut hides", async () => {
  const html = await renderWith("signedIn", { sub: "u1", email: "a@b.com", preferredUsername: "alice" });
  assert.match(html, /data-t="in"/, "SignedIn renders its children");
  assert.doesNotMatch(html, /data-t="out"/, "SignedOut renders nothing");
  assert.match(html, /data-t="allow"/, "Protect renders its children");
  assert.doesNotMatch(html, /data-t="deny"/, "Protect does not render the fallback");
});

test("signed out: SignedOut shows, SignedIn hides, Protect shows the fallback", async () => {
  const html = await renderWith("signedOut");
  assert.doesNotMatch(html, /data-t="in"/);
  assert.match(html, /data-t="out"/);
  assert.doesNotMatch(html, /data-t="allow"/);
  assert.match(html, /data-t="deny"/, "Protect falls back when signed out");
});

test("loading: neither SignedIn nor SignedOut renders, and Protect stays empty", async () => {
  const html = await renderWith("loading");
  assert.doesNotMatch(html, /data-t="in"/, "no signed-in flash before /me resolves");
  assert.doesNotMatch(html, /data-t="out"/, "no signed-out flash before /me resolves");
  assert.doesNotMatch(html, /data-t="allow"/);
  assert.doesNotMatch(html, /data-t="deny"/, "Protect renders nothing at all while loading");
});

test("SignInButton renders a button with custom children and a forwarded class", async () => {
  const html = await renderWith("signedOut");
  assert.match(html, /<button[^>]*class="cta"[^>]*>Continue<\/button>/);
});

test("SignUpButton renders its default label and a forwarded class", async () => {
  assert.match(await renderWith("signedOut"), /<button[^>]*class="join"[^>]*>Sign up<\/button>/);
});

test("SignUpButton's click calls signUp with its returnTo, and not signIn", () => {
  const calls: unknown[] = [];
  const auth: Auth = {
    ...createAuth({ initialUser: null, fetch: noFetch }),
    signIn: (o) => void calls.push(["signIn", o]),
    signUp: (o) => void calls.push(["signUp", o]),
  };
  const app = createSSRApp(defineComponent({ render: () => null }));
  app.provide(PROTELES_AUTH, auth);
  // `setup` run in the app's injection context, which is all `useAuth` needs.
  // The render function it returns builds the button, click handler and all.
  type Setup = (props: { returnTo?: string }, ctx: { slots: object }) => () => { props: { onClick: () => void } };
  const render = app.runWithContext(() => (SignUpButton.setup as unknown as Setup)({ returnTo: "/welcome" }, { slots: {} }));
  render().props.onClick();
  assert.deepEqual(calls, [["signUp", { returnTo: "/welcome" }]]);
});

test("SignOutButton renders its default label", async () => {
  assert.match(await renderWith("signedOut"), /Sign out/);
});

test("UserButton shows the user's label, forwards class, and hides when signed out", async () => {
  const signedIn = await renderWith("signedIn", { sub: "u1", email: "a@b.com", preferredUsername: "alice" });
  assert.match(signedIn, /data-proteles="user-button"/);
  assert.match(signedIn, /data-proteles="user-label">alice</, "prefers preferredUsername");
  assert.match(signedIn, /alice<\/span> <button/, "the name does not run into the button");
  assert.match(signedIn, /data-proteles="user-signout"/);
  assert.match(signedIn, /class="chip"/, "class is forwarded to the root element");

  const signedOut = await renderWith("signedOut");
  assert.doesNotMatch(signedOut, /data-proteles="user-button"/, "renders nothing without a user");
});

test("UserButton falls back to email, then sub", async () => {
  assert.match(await renderWith("signedIn", { sub: "u1", email: "a@b.com" }), /user-label">a@b\.com</);
  assert.match(await renderWith("signedIn", { sub: "just-sub" }), /user-label">just-sub</);
});

test("AuthProvider provides auth to its subtree without the plugin", async () => {
  const Child = defineComponent({
    setup() {
      const { user } = useAuth();
      return () => h("span", { "data-t": "child" }, user.value?.sub ?? "none");
    },
  });
  const app = createSSRApp(
    defineComponent({
      setup() {
        return () =>
          h(AuthProvider, { initialUser: { sub: "provided-user" } }, { default: () => h(Child) });
      },
    }),
  );
  const html = (await renderToString(app)).replace(/<!--.*?-->/g, "");
  assert.match(html, /data-t="child">provided-user</, "the subtree sees the provided user");
});

test("the protelesAuth plugin provides auth app-wide and does not fetch during SSR", async () => {
  const realFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = (async () => {
    calls++;
    return new Response("{}", { headers: { "content-type": "application/json" } });
  }) as typeof fetch;
  try {
    const Child = defineComponent({
      setup() {
        const { user } = useAuth();
        return () => h("span", { "data-t": "plug" }, user.value?.sub ?? "none");
      },
    });
    const app = createSSRApp(Child);
    app.use(protelesAuth({ initialUser: { sub: "plugin-user" } }));
    const html = (await renderToString(app)).replace(/<!--.*?-->/g, "");
    assert.match(html, /data-t="plug">plugin-user</, "the plugin provided auth");
    assert.equal(calls, 0, "no network during server rendering");
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("useAuth throws an actionable error with no provider or plugin", async () => {
  const Orphan = defineComponent({
    setup() {
      const { user } = useAuth();
      return () => h("span", null, user.value?.sub ?? "none");
    },
  });
  await assert.rejects(
    () => renderToString(createSSRApp(Orphan)),
    /requires the protelesAuth plugin \(app\.use\) or an <AuthProvider> ancestor/,
    "a missing provider must fail loudly, not render silently",
  );
});
