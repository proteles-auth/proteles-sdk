//! The auth store: a Svelte readable of `AuthState` plus `signIn`/`signUp`/
//! `signOut`/`reload`. This is the idiomatic Svelte surface — components
//! auto-subscribe with `$auth`.
//!
//! It deliberately implements the store contract by hand rather than importing
//! `svelte/store`, for two reasons: the contract is tiny (a `subscribe` that
//! calls back immediately and returns an unsubscriber), and staying free of the
//! Svelte runtime keeps this module unit-testable in plain Node.

import { createRetry, fetchSession } from "./session.js";
import type { AuthState, AuthStore, CreateAuthOptions, SignInOptions, SignOutOptions, SignUpOptions } from "./types.js";
import { loginUrl, logoutUrl, resolveBasePath, signupUrl } from "./urls.js";

function defaultNavigate(url: string): void {
  if (typeof window !== "undefined") window.location.assign(url);
}

/**
 * Signs out by POST. The BFF answers a GET to its sign-out route with a
 * confirmation form rather than acting, so a link or an image on another site
 * cannot sign anybody out. A hidden form, submitted, is a top-level navigation
 * like the `window.location.assign` it replaces, and the browser sends this
 * page's `Origin` with it, which is what the BFF checks.
 */
function defaultPost(url: string): void {
  if (typeof document === "undefined") return;
  const form = document.createElement("form");
  form.method = "post";
  form.action = url;
  form.style.display = "none";
  document.body.appendChild(form);
  form.submit();
}

function defaultCurrentPath(): string | undefined {
  if (typeof window === "undefined") return undefined;
  return window.location.pathname + window.location.search;
}

/**
 * Creates the auth store. `<AuthProvider>` does this for you and puts it in
 * context; call it directly only if you want to own the instance (e.g. to share
 * one store outside the component tree).
 *
 * Note it does **not** fetch on creation — that would fire during SSR. The
 * provider calls `reload()` on mount; `initialUser` covers the first paint.
 */
export function createAuthStore(options: CreateAuthOptions = {}): AuthStore {
  return createStoppableAuthStore(options).store;
}

/**
 * `createAuthStore`, plus a `stop` for whoever owns the store to call when it
 * goes: it drops the pending `/me` retry, and a busy answer still in flight
 * then schedules none. `<AuthProvider>` calls it on destroy, so a provider that
 * has gone stops polling a busy server for nobody. Internal — `index.js` does
 * not export it — because this module stays free of the Svelte runtime and so
 * cannot hook `onDestroy` itself; a store made with `createAuthStore` keeps
 * asking until `/me` answers.
 */
export function createStoppableAuthStore(options: CreateAuthOptions = {}): { store: AuthStore; stop: () => void } {
  const basePath = resolveBasePath(options.basePath);
  const fetchImpl = options.fetch ?? ((...args: Parameters<typeof fetch>) => fetch(...args));
  const navigate = options.navigate ?? defaultNavigate;
  const post = options.post ?? defaultPost;
  const currentPath = options.currentPath ?? defaultCurrentPath;

  const subscribers = new Set<(value: AuthState) => void>();
  let state: AuthState = {
    user: options.initialUser ?? null,
    isLoading: options.initialUser === undefined,
    isAuthenticated: (options.initialUser ?? null) !== null,
    isUnavailable: false,
  };
  const retry = createRetry();
  let stopped = false;

  function set(next: Partial<AuthState>): void {
    const user = next.user !== undefined ? next.user : state.user;
    state = {
      user,
      isLoading: next.isLoading !== undefined ? next.isLoading : state.isLoading,
      isAuthenticated: user !== null,
      isUnavailable: next.isUnavailable !== undefined ? next.isUnavailable : state.isUnavailable,
    };
    for (const run of subscribers) run(state);
  }

  async function reload(): Promise<void> {
    const result = await fetchSession(basePath, fetchImpl);
    if (result.unavailable) {
      // Only say so: the user, and a first load's `isLoading`, stay as they
      // were, because a busy `/me` is not a sign-out.
      set({ isUnavailable: true });
      if (!stopped) retry.schedule(() => void reload(), result.retryAfter);
      return;
    }
    retry.cancel();
    set({ user: result.user, isLoading: false, isUnavailable: false });
  }

  const store: AuthStore = {
    // The Svelte store contract: call the subscriber immediately with the
    // current value, and return a function that removes it.
    subscribe(run: (value: AuthState) => void): () => void {
      subscribers.add(run);
      run(state);
      return () => subscribers.delete(run);
    },

    reload,

    signIn(opts?: SignInOptions): void {
      const returnTo = opts?.returnTo ?? currentPath();
      navigate(loginUrl(basePath, { ...opts, ...(returnTo ? { returnTo } : {}) }));
    },

    signUp(opts?: SignUpOptions): void {
      const returnTo = opts?.returnTo ?? currentPath();
      navigate(signupUrl(basePath, { ...opts, ...(returnTo ? { returnTo } : {}) }));
    },

    signOut(opts?: SignOutOptions): void {
      post(logoutUrl(basePath, opts));
    },

    basePath,
  };

  function stop(): void {
    stopped = true;
    retry.cancel();
  }
  return { store, stop };
}
