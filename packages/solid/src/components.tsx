//! The drop-in components. They read state from `useAuth()` and trigger the BFF
//! flows; they never talk to the authorization server directly, and the browser
//! never handles a token.

import { onMount, Show, type JSX } from "solid-js";

import { createAuth } from "./auth.js";
import { AuthContext, useAuth } from "./context.js";
import type { AuthUser } from "./types.js";

export interface AuthProviderProps {
  children?: JSX.Element;
  /** BFF mount path. Defaults to `VITE_PROTELES_BASE_PATH` or `/api/auth`. */
  basePath?: string;
  /** Server-known user: omit = fetch on mount, `null` = known signed-out. */
  initialUser?: AuthUser | null;
}

/**
 * Wrap your app once (usually in the root layout). Creates the auth object,
 * provides it to every descendant, and revalidates against `/api/auth/me` on
 * mount — so a stale `initialUser` (e.g. after a logout in another tab)
 * self-corrects. `onMount` never runs during SSR, so rendering stays pure.
 */
export function AuthProvider(props: AuthProviderProps): JSX.Element {
  const auth = createAuth({ basePath: props.basePath, initialUser: props.initialUser });
  onMount(() => {
    void auth.reload();
  });
  return <AuthContext.Provider value={auth}>{props.children}</AuthContext.Provider>;
}

/** Renders its children only when a user is signed in (and loading is done). */
export function SignedIn(props: { children?: JSX.Element }): JSX.Element {
  const { isAuthenticated, isLoading } = useAuth();
  return <Show when={isAuthenticated() && !isLoading()}>{props.children}</Show>;
}

/** Renders its children only when no user is signed in (and loading is done). */
export function SignedOut(props: { children?: JSX.Element }): JSX.Element {
  const { isAuthenticated, isLoading } = useAuth();
  return <Show when={!isAuthenticated() && !isLoading()}>{props.children}</Show>;
}

/**
 * Gates content behind authentication, rendering `fallback` when signed out and
 * nothing at all until who is signed in is known (see `isLoading`).
 */
export function Protect(props: { children?: JSX.Element; fallback?: JSX.Element }): JSX.Element {
  const { isAuthenticated, isLoading } = useAuth();
  return (
    <Show when={!isLoading()}>
      <Show when={isAuthenticated()} fallback={props.fallback}>
        {props.children}
      </Show>
    </Show>
  );
}

export interface SignInButtonProps {
  children?: JSX.Element;
  class?: string;
  /** Path to return to after login. Defaults to the current path. */
  returnTo?: string;
  /** Force a social connection, e.g. `"google"`. */
  connection?: string;
}

/** A button that starts the login flow. */
export function SignInButton(props: SignInButtonProps): JSX.Element {
  const { signIn } = useAuth();
  return (
    <button
      type="button"
      class={props.class}
      onClick={() => signIn({ returnTo: props.returnTo, connection: props.connection })}
    >
      {props.children ?? "Sign in"}
    </button>
  );
}

export interface SignUpButtonProps {
  children?: JSX.Element;
  class?: string;
  /** Path to return to after signing up. Defaults to the current path. */
  returnTo?: string;
}

/** A button that starts sign-up — or sign-in, where the workspace has not
 *  opened its sign-up page. */
export function SignUpButton(props: SignUpButtonProps): JSX.Element {
  const { signUp } = useAuth();
  return (
    <button type="button" class={props.class} onClick={() => signUp({ returnTo: props.returnTo })}>
      {props.children ?? "Sign up"}
    </button>
  );
}

export interface SignOutButtonProps {
  children?: JSX.Element;
  class?: string;
  /** Path to return to after logout. Defaults to `/`. */
  returnTo?: string;
}

/** A button that logs out. */
export function SignOutButton(props: SignOutButtonProps): JSX.Element {
  const { signOut } = useAuth();
  return (
    <button type="button" class={props.class} onClick={() => signOut({ returnTo: props.returnTo })}>
      {props.children ?? "Sign out"}
    </button>
  );
}

/**
 * A compact identity chip: the user's name/email plus a sign-out control.
 * Renders nothing when signed out. Unstyled by design — pass `class`.
 */
export function UserButton(props: { class?: string }): JSX.Element {
  const { user, signOut } = useAuth();
  const label = (): string => {
    const current = user();
    if (!current) return "";
    return current.preferredUsername || current.email || current.sub;
  };
  return (
    <Show when={user()}>
      <span class={props.class} data-proteles="user-button">
        <span data-proteles="user-label">{label()}</span>{" "}
        <button type="button" data-proteles="user-signout" onClick={() => signOut()}>
          Sign out
        </button>
      </span>
    </Show>
  );
}
