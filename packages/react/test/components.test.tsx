import { test } from "node:test";
import assert from "node:assert/strict";
// The test runner (tsx) transforms JSX with the classic runtime here, so React
// must be in scope. The library source imports React the same way; only the
// `tsc` build uses the modern automatic runtime (see tsconfig `jsx`).
import * as React from "react";
import type { ReactNode } from "react";
import { renderToStaticMarkup } from "react-dom/server";

void React;

import { AuthProvider } from "../src/AuthProvider.tsx";
import { AuthContext } from "../src/context.ts";
import { Protect, SignedIn, SignedOut, SignInButton, SignUpButton, UserButton } from "../src/components.tsx";
import { useAuth } from "../src/hooks.ts";
import type { AuthContextValue } from "../src/types.ts";

function mockAuth(overrides: Partial<AuthContextValue> = {}): AuthContextValue {
  return {
    user: null,
    isLoading: false,
    isAuthenticated: false,
    isUnavailable: false,
    signIn: () => undefined,
    signUp: () => undefined,
    signOut: () => undefined,
    reload: async () => undefined,
    basePath: "/api/auth",
    ...overrides,
  };
}

const render = (ui: ReactNode, value: AuthContextValue): string =>
  renderToStaticMarkup(<AuthContext.Provider value={value}>{ui}</AuthContext.Provider>);

test("SignedIn shows children only when authenticated and not loading", () => {
  const ui = (
    <SignedIn>
      <span>secret</span>
    </SignedIn>
  );
  assert.match(render(ui, mockAuth({ isAuthenticated: true, user: { sub: "u1" } })), /secret/);
  assert.doesNotMatch(render(ui, mockAuth({ isAuthenticated: false })), /secret/);
  // Hidden while the first /me is still loading, even if optimistic state is set.
  assert.doesNotMatch(render(ui, mockAuth({ isAuthenticated: true, isLoading: true })), /secret/);
});

test("SignedOut shows children only when signed out and not loading", () => {
  const ui = (
    <SignedOut>
      <span>please-sign-in</span>
    </SignedOut>
  );
  assert.match(render(ui, mockAuth({ isAuthenticated: false })), /please-sign-in/);
  assert.doesNotMatch(render(ui, mockAuth({ isAuthenticated: true, user: { sub: "u1" } })), /please-sign-in/);
  assert.doesNotMatch(render(ui, mockAuth({ isLoading: true })), /please-sign-in/);
});

test("Protect renders children when authenticated, fallback when not, nothing while loading", () => {
  const ui = (
    <Protect fallback={<span>denied</span>}>
      <span>granted</span>
    </Protect>
  );
  assert.match(render(ui, mockAuth({ isAuthenticated: true, user: { sub: "u1" } })), /granted/);
  assert.match(render(ui, mockAuth({ isAuthenticated: false })), /denied/);
  const loading = render(ui, mockAuth({ isLoading: true }));
  assert.doesNotMatch(loading, /granted/);
  assert.doesNotMatch(loading, /denied/);
});

test("SignInButton renders a button with a default label", () => {
  const html = render(<SignInButton />, mockAuth());
  assert.match(html, /<button[^>]*>Sign in<\/button>/);
});

test("SignInButton uses custom children as its label", () => {
  const html = render(<SignInButton>Continue</SignInButton>, mockAuth());
  assert.match(html, />Continue</);
});

test("SignUpButton renders a button with a default label, or its children", () => {
  assert.match(render(<SignUpButton />, mockAuth()), /<button[^>]*>Sign up<\/button>/);
  assert.match(render(<SignUpButton>Create an account</SignUpButton>, mockAuth()), />Create an account</);
});

test("SignUpButton's click calls signUp with its returnTo, and not signIn", () => {
  const calls: unknown[] = [];
  const seen: { button?: React.ReactElement<{ onClick: () => void }> } = {};
  // Called as a function inside a component, so its `useAuth` runs as part of
  // that component's render and the click handler can be reached directly.
  function Grab(): null {
    seen.button = SignUpButton({ returnTo: "/welcome" }) as React.ReactElement<{ onClick: () => void }>;
    return null;
  }
  render(
    <Grab />,
    mockAuth({ signIn: (o) => calls.push(["signIn", o]), signUp: (o) => calls.push(["signUp", o]) }),
  );
  seen.button!.props.onClick();
  assert.deepEqual(calls, [["signUp", { returnTo: "/welcome" }]]);
});

test("AuthProvider's signUp goes to the sign-up route, keeping returnTo as signIn does", () => {
  const seen: { auth?: AuthContextValue } = {};
  function Capture(): null {
    seen.auth = useAuth();
    return null;
  }
  renderToStaticMarkup(
    <AuthProvider basePath="/custom/auth">
      <Capture />
    </AuthProvider>,
  );

  // The provider navigates with `window.location`, which Node has no
  // stand-in for, so one is put in place for the calls alone.
  const assigned: string[] = [];
  const host = globalThis as { window?: unknown };
  host.window = { location: { pathname: "/pricing", search: "?plan=pro", assign: (url: string) => assigned.push(url) } };
  try {
    seen.auth!.signUp();
    seen.auth!.signUp({ returnTo: "/welcome" });
    seen.auth!.signIn({ returnTo: "/welcome" });
  } finally {
    delete host.window;
  }
  assert.deepEqual(assigned, [
    "/custom/auth/signup?returnTo=%2Fpricing%3Fplan%3Dpro",
    "/custom/auth/signup?returnTo=%2Fwelcome",
    "/custom/auth/login?returnTo=%2Fwelcome",
  ]);
});

test("UserButton shows the user's name and a sign-out control, and nothing when signed out", () => {
  const signedIn = render(
    <UserButton />,
    mockAuth({ isAuthenticated: true, user: { sub: "u1", email: "a@b.com", preferredUsername: "alice" } }),
  );
  assert.match(signedIn, /alice/); // preferredUsername preferred over email/sub
  assert.match(signedIn, /Sign out/);
  // Separated: unstyled, the name ran into the button ("aliceSign out").
  assert.match(signedIn, /alice<\/span> <button/);
  assert.doesNotMatch(signedIn, /a@b\.com/); // email not shown when a username exists

  // Falls back to email, then sub.
  assert.match(render(<UserButton />, mockAuth({ user: { sub: "u1", email: "a@b.com" } })), /a@b\.com/);
  assert.match(render(<UserButton />, mockAuth({ user: { sub: "just-sub" } })), /just-sub/);

  // Nothing when there is no user.
  assert.equal(render(<UserButton />, mockAuth({ user: null })), "");
});
