"use client";

//! The consumer-facing hooks.

import { useContext } from "react";

import { AuthContext } from "./context.js";
import type { AuthContextValue, AuthState } from "./types.js";

/** Full auth context (state + `signIn`/`signUp`/`signOut`/`reload`). Throws
 *  if used outside `<AuthProvider>`. */
export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error("@proteles/react: useAuth/useUser must be used within <AuthProvider>");
  }
  return ctx;
}

/** Just the user state — the common case. */
export function useUser(): AuthState {
  const { user, isLoading, isAuthenticated, isUnavailable } = useAuth();
  return { user, isLoading, isAuthenticated, isUnavailable };
}
