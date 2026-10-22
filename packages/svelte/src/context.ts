//! Context plumbing. `<AuthProvider>` sets the store; `getAuth()` reads it.

import { getContext, setContext } from "svelte";

import type { AuthStore } from "./types.js";

/** Context key. A symbol-like string keeps it collision-free without requiring
 *  consumers to import a symbol. */
export const AUTH_CONTEXT_KEY = "proteles-auth";

export function setAuthContext(store: AuthStore): AuthStore {
  setContext(AUTH_CONTEXT_KEY, store);
  return store;
}

/**
 * The auth store from context. Call during component initialization (the same
 * rule as any Svelte `getContext`), then use `$auth` in markup.
 *
 * Throws a clear error rather than returning undefined when the component isn't
 * inside an `<AuthProvider>`.
 */
export function getAuth(): AuthStore {
  const store = getContext<AuthStore | undefined>(AUTH_CONTEXT_KEY);
  if (!store) {
    throw new Error("@proteles/svelte: getAuth() must be called inside an <AuthProvider>");
  }
  return store;
}
