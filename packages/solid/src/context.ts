//! Context plumbing. `<AuthProvider>` sets the auth object; `useAuth()` reads it.

import { createContext, useContext } from "solid-js";

import type { Auth } from "./types.js";

/** The auth context. Exported so advanced callers can provide a custom instance
 *  (e.g. in tests or a micro-frontend host). */
export const AuthContext = createContext<Auth | undefined>(undefined);

/**
 * The auth object from the nearest `<AuthProvider>`. Call during component setup
 * (the same rule as any Solid `useContext`), then call the accessors in JSX:
 * `{user()?.email}`.
 *
 * Throws a clear error rather than returning undefined when there's no provider.
 */
export function useAuth(): Auth {
  const auth = useContext(AuthContext);
  if (!auth) {
    throw new Error("@proteles/solid: useAuth() must be called inside an <AuthProvider>");
  }
  return auth;
}

/** Just the user state — the common case. */
export function useUser(): Pick<Auth, "user" | "isLoading" | "isAuthenticated" | "isUnavailable"> {
  const { user, isLoading, isAuthenticated, isUnavailable } = useAuth();
  return { user, isLoading, isAuthenticated, isUnavailable };
}
