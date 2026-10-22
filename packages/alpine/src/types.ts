//! Public types for the Alpine SDK.

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
 * The auth store, reachable as `$store.proteles` or `$auth` in any Alpine
 * expression.
 *
 * Unlike the other framework SDKs this is a **plain object**, not a set of
 * signals or refs: `Alpine.store()` wraps whatever it's given in Alpine's own
 * reactivity, so the methods simply assign to `this` and the DOM follows.
 */
export interface AuthStore {
  user: AuthUser | null;
  /** True until who is signed in is known, from `initialUser` or from the first
   *  answer to `/api/auth/me`. A busy or unanswered `/me` is not an answer, and
   *  leaves it true (see `isUnavailable`). */
  isLoading: boolean;
  /** A getter, so it stays correct as `user` changes. */
  readonly isAuthenticated: boolean;
  /**
   * True while the last `/api/auth/me` could not say who is signed in — the
   * sign-in service was busy or out of reach — and another is scheduled. `user`
   * is then the last one known, and `isLoading` stays true if none is known yet,
   * so a busy spell does not look like a sign-out. False again once `/me`
   * answers.
   */
  isUnavailable: boolean;
  /** Called automatically by Alpine when the store is registered. */
  init: () => void;
  /** Re-fetch `/api/auth/me`. */
  reload: () => Promise<void>;
  signIn: (options?: SignInOptions) => void;
  /** `signIn`, opening on the workspace's sign-up page — or on its sign-in page
   *  where the workspace has not opened one. */
  signUp: (options?: SignUpOptions) => void;
  signOut: (options?: SignOutOptions) => void;
  basePath: string;
}

export interface CreateAuthStoreOptions {
  /** BFF mount path. Defaults to `/api/auth`. */
  basePath?: string;
  /** Server-known user, e.g. from a server-rendered `<script>` global.
   *  `undefined` = unknown (will fetch); `null` = known signed-out. */
  initialUser?: AuthUser | null;
  /** Custom fetch (tests, tracing). Defaults to the global. */
  fetch?: typeof fetch;
  /** Navigation function; defaults to `window.location.assign`. */
  navigate?: (url: string) => void;
  /** Sign-out's form POST; defaults to submitting a hidden form. Injectable so
   *  tests can assert where a sign-out would post. */
  post?: (url: string) => void;
  /** Current path resolver, used as the default `returnTo`. */
  currentPath?: () => string | undefined;
  /** Skip the automatic revalidation in `init()`. Useful when the page already
   *  seeded `initialUser` and you'd rather not spend a request. */
  revalidateOnInit?: boolean;
}

export interface ProtelesAuthOptions extends CreateAuthStoreOptions {
  /** Alpine store name. Defaults to `"proteles"` (`$store.proteles`). */
  storeName?: string;
  /** Magic-property name. Defaults to `"auth"` (`$auth`). */
  magicName?: string;
}

/** The subset of Alpine's plugin API this package uses. Declared structurally so
 *  the package builds and tests without Alpine installed — which matters,
 *  because Alpine cannot be imported in Node at all. */
export interface AlpineLike {
  store: (name: string, value?: unknown) => unknown;
  magic: (name: string, callback: (el: Element) => unknown) => void;
  directive: (name: string, callback: AlpineDirective) => void;
}

export type AlpineDirective = (
  el: HTMLElement,
  directive: { value?: string; modifiers?: string[]; expression?: string },
  utils: { effect: (fn: () => void) => void; cleanup?: (fn: () => void) => void },
) => void;
