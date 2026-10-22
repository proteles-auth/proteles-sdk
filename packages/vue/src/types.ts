//! Public types for the Vue SDK.

import type { ComputedRef, Ref } from "vue";

/** The current user, as exposed by the BFF's `/api/auth/me` — never a token. */
export interface AuthUser {
  sub: string;
  email?: string;
  preferredUsername?: string;
  [claim: string]: unknown;
}

export interface SignInOptions {
  /** Path to return to after login (defaults to the current path). */
  returnTo?: string;
  /** Force a specific social connection, e.g. `"google"`. */
  connection?: string;
}

/**
 * `signUp`'s options. No `connection`, unlike `signIn`'s: the server opens the
 * sign-up page before it reads one. A social sign-up is `signIn({ connection })`.
 */
export interface SignUpOptions {
  /** Path to return to after signing up (defaults to the current path). */
  returnTo?: string;
}

export interface SignOutOptions {
  /** Path to return to after logout (defaults to `/`). */
  returnTo?: string;
}

/**
 * The reactive auth API. `user` / `isLoading` / `isAuthenticated` /
 * `isUnavailable` are Vue refs, so they unwrap automatically in templates
 * (`{{ user?.email }}`) and stay reactive in `watch`/`computed`.
 */
export interface Auth {
  user: Ref<AuthUser | null>;
  /** True until who is signed in is known, from `initialUser` or from the first
   *  answer to `/api/auth/me`. A busy or unanswered `/me` is not an answer, and
   *  leaves it true (see `isUnavailable`). */
  isLoading: Ref<boolean>;
  isAuthenticated: ComputedRef<boolean>;
  /**
   * True while the last `/api/auth/me` could not say who is signed in — the
   * sign-in service was busy or out of reach — and another is scheduled. `user`
   * is then the last one known, and `isLoading` stays true if none is known yet,
   * so a busy spell does not look like a sign-out. False again once `/me`
   * answers.
   */
  isUnavailable: Ref<boolean>;
  signIn: (options?: SignInOptions) => void;
  /** `signIn`, opening on the workspace's sign-up page — or on its sign-in page
   *  where the workspace has not opened one. */
  signUp: (options?: SignUpOptions) => void;
  signOut: (options?: SignOutOptions) => void;
  /** Re-fetch `/api/auth/me` (e.g. after an action that changes the session). */
  reload: () => Promise<void>;
  basePath: string;
}

export interface CreateAuthOptions {
  /** BFF mount path. Defaults to `VITE_PROTELES_BASE_PATH` or `/api/auth`. */
  basePath?: string;
  /** Server-known user for SSR hydration. `undefined` = unknown (will fetch);
   *  `null` = known signed-out; an object = known signed-in. */
  initialUser?: AuthUser | null;
  /** Custom fetch (tests, tracing). Defaults to the global. */
  fetch?: typeof fetch;
  /** Navigation function; defaults to `window.location.assign`. Injectable so
   *  tests can assert where a sign-in would send the browser. */
  navigate?: (url: string) => void;
  /** Sign-out's form POST; defaults to submitting a hidden form. Injectable so
   *  tests can assert where a sign-out would post. */
  post?: (url: string) => void;
  /** Current path resolver, used as the default `returnTo`. */
  currentPath?: () => string | undefined;
}
