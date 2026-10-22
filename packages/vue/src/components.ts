//! The drop-in components. They read state from `useAuth()` and trigger the BFF
//! flows; they never talk to the authorization server directly, and the browser
//! never handles a token.
//!
//! Authored as `defineComponent` render functions rather than `.vue` SFCs: these
//! components are tiny and headless, so this keeps the package a plain
//! TypeScript build (no SFC compiler, no bundler) and directly unit-testable.
//! Consumers still use them as `<SignedIn>` in their own SFCs — the authoring
//! style here is invisible from the outside.

import { defineComponent, h, provide, type PropType, type VNode } from "vue";

import { createAuth } from "./auth.js";
import { PROTELES_AUTH, revalidateOnMount, useAuth } from "./context.js";
import type { AuthUser } from "./types.js";

/**
 * Provides auth to a subtree. Most apps install the `protelesAuth` plugin
 * instead; use this when you'd rather scope auth to part of the tree, or in a
 * framework that doesn't expose the app instance.
 */
export const AuthProvider = defineComponent({
  name: "ProtelesAuthProvider",
  props: {
    /** BFF mount path. Defaults to `VITE_PROTELES_BASE_PATH` or `/api/auth`. */
    basePath: { type: String, required: false },
    /** Server-known user: omit = fetch on mount, `null` = signed out. */
    initialUser: { type: Object as PropType<AuthUser | null>, default: undefined },
  },
  setup(props, { slots }) {
    const auth = createAuth({ basePath: props.basePath, initialUser: props.initialUser });
    provide(PROTELES_AUTH, auth);
    revalidateOnMount(auth);
    return () => slots.default?.();
  },
});

/** Renders its children only when a user is signed in (and loading is done). */
export const SignedIn = defineComponent({
  name: "ProtelesSignedIn",
  setup(_, { slots }) {
    const { isAuthenticated, isLoading } = useAuth();
    return () => (isAuthenticated.value && !isLoading.value ? slots.default?.() : null);
  },
});

/** Renders its children only when no user is signed in (and loading is done). */
export const SignedOut = defineComponent({
  name: "ProtelesSignedOut",
  setup(_, { slots }) {
    const { isAuthenticated, isLoading } = useAuth();
    return () => (!isAuthenticated.value && !isLoading.value ? slots.default?.() : null);
  },
});

/**
 * Gates content behind authentication, rendering the `fallback` slot when signed
 * out and nothing at all until who is signed in is known (see `isLoading`).
 */
export const Protect = defineComponent({
  name: "ProtelesProtect",
  setup(_, { slots }) {
    const { isAuthenticated, isLoading } = useAuth();
    return () => {
      if (isLoading.value) return null;
      return isAuthenticated.value ? slots.default?.() : (slots.fallback?.() ?? null);
    };
  },
});

/** A button that starts the login flow. */
export const SignInButton = defineComponent({
  name: "ProtelesSignInButton",
  props: {
    /** Path to return to after login. Defaults to the current path. */
    returnTo: { type: String, required: false },
    /** Force a social connection, e.g. `"google"`. */
    connection: { type: String, required: false },
  },
  setup(props, { slots }) {
    const { signIn } = useAuth();
    return (): VNode =>
      h(
        "button",
        {
          type: "button",
          onClick: () => signIn({ returnTo: props.returnTo, connection: props.connection }),
        },
        slots.default?.() ?? "Sign in",
      );
  },
});

/** A button that starts sign-up — or sign-in, where the workspace has not
 *  opened its sign-up page. */
export const SignUpButton = defineComponent({
  name: "ProtelesSignUpButton",
  props: {
    /** Path to return to after signing up. Defaults to the current path. */
    returnTo: { type: String, required: false },
  },
  setup(props, { slots }) {
    const { signUp } = useAuth();
    return (): VNode =>
      h(
        "button",
        { type: "button", onClick: () => signUp({ returnTo: props.returnTo }) },
        slots.default?.() ?? "Sign up",
      );
  },
});

/** A button that logs out. */
export const SignOutButton = defineComponent({
  name: "ProtelesSignOutButton",
  props: {
    /** Path to return to after logout. Defaults to `/`. */
    returnTo: { type: String, required: false },
  },
  setup(props, { slots }) {
    const { signOut } = useAuth();
    return (): VNode =>
      h(
        "button",
        { type: "button", onClick: () => signOut({ returnTo: props.returnTo }) },
        slots.default?.() ?? "Sign out",
      );
  },
});

/**
 * A compact identity chip: the user's name/email plus a sign-out control.
 * Renders nothing when signed out. Unstyled by design — pass `class`, which Vue
 * merges onto the root element automatically.
 */
export const UserButton = defineComponent({
  name: "ProtelesUserButton",
  setup() {
    const { user, signOut } = useAuth();
    return (): VNode | null => {
      const current = user.value;
      if (!current) return null;
      const label = current.preferredUsername || current.email || current.sub;
      return h("span", { "data-proteles": "user-button" }, [
        h("span", { "data-proteles": "user-label" }, label),
        // A space, as Svelte's template has: unstyled, the name otherwise
        // runs into the button ("aliceSign out").
        " ",
        h(
          "button",
          { type: "button", "data-proteles": "user-signout", onClick: () => signOut() },
          "Sign out",
        ),
      ]);
    };
  },
});
