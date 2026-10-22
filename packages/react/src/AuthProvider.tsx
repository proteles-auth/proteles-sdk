"use client";

//! The provider that fetches `/api/auth/me`, holds the reactive auth state, and
//! exposes `signIn`/`signUp`/`signOut`/`reload`. Wrap your app once (e.g. in
//! `app/layout.tsx`). If you already know the user on the server, pass
//! `initialUser` (from `currentUser()` in `@proteles/next`) to avoid a
//! signed-out flash on first paint.

import * as React from "react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { AuthContext } from "./context.js";
import { createRetry, loadSession } from "./session.js";
import type { SessionState } from "./session.js";
import type { AuthContextValue, AuthUser, SignInOptions, SignOutOptions, SignUpOptions } from "./types.js";
import { loginUrl, logoutUrl, resolveBasePath, signupUrl } from "./urls.js";

export interface AuthProviderProps {
  children: React.ReactNode;
  /** BFF mount path. Defaults to `NEXT_PUBLIC_PROTELES_BASE_PATH` or `/api/auth`. */
  basePath?: string;
  /** Server-known user for SSR hydration. `undefined` = unknown (will fetch);
   *  `null` = known signed-out; an object = known signed-in. */
  initialUser?: AuthUser | null;
}

function currentPath(): string | undefined {
  if (typeof window === "undefined") return undefined;
  return window.location.pathname + window.location.search;
}

/**
 * Signs out by POST. The BFF answers a GET to its sign-out route with a
 * confirmation form rather than acting, so a link or an image on another site
 * cannot sign anybody out. A hidden form, submitted, is a top-level navigation
 * like the `window.location.assign` it replaces, and the browser sends this
 * page's `Origin` with it, which is what the BFF checks.
 */
function postTo(url: string): void {
  if (typeof document === "undefined") return;
  const form = document.createElement("form");
  form.method = "post";
  form.action = url;
  form.style.display = "none";
  document.body.appendChild(form);
  form.submit();
}

export function AuthProvider({ children, basePath: basePathProp, initialUser }: AuthProviderProps): React.ReactElement {
  const basePath = useMemo(() => resolveBasePath(basePathProp), [basePathProp]);
  const [session, setSession] = useState<SessionState>(() => ({
    user: initialUser ?? null,
    isLoading: initialUser === undefined,
    isUnavailable: false,
  }));
  // The one pending retry after a busy `/me`, for the provider's whole life.
  const [retry] = useState(createRetry);
  // Retries are scheduled only while mounted, so a chain in flight at unmount
  // stops at its next answer instead of polling a busy server for nobody.
  const mounted = useRef(false);

  const load = useCallback(
    (isCurrent: () => boolean): Promise<void> =>
      loadSession({ basePath, update: setSession, retry, isCurrent, keepTrying: () => mounted.current }),
    [basePath, retry],
  );

  const reload = useCallback((): Promise<void> => load(() => true), [load]);

  useEffect(() => {
    let active = true;
    mounted.current = true;
    // Always revalidate against the server on mount, even when seeded, so a
    // stale `initialUser` (e.g. after a logout in another tab) self-corrects.
    void load(() => active);
    return () => {
      active = false;
      mounted.current = false;
      retry.cancel();
    };
  }, [load, retry]);

  const signIn = useCallback(
    (options?: SignInOptions): void => {
      if (typeof window === "undefined") return;
      const returnTo = options?.returnTo ?? currentPath();
      window.location.assign(loginUrl(basePath, { ...options, returnTo }));
    },
    [basePath],
  );

  const signUp = useCallback(
    (options?: SignUpOptions): void => {
      if (typeof window === "undefined") return;
      const returnTo = options?.returnTo ?? currentPath();
      window.location.assign(signupUrl(basePath, { ...options, returnTo }));
    },
    [basePath],
  );

  const signOut = useCallback(
    (options?: SignOutOptions): void => {
      postTo(logoutUrl(basePath, options));
    },
    [basePath],
  );

  const { user, isLoading, isUnavailable } = session;
  const value = useMemo<AuthContextValue>(
    () => ({ user, isLoading, isAuthenticated: user !== null, isUnavailable, signIn, signUp, signOut, reload, basePath }),
    [user, isLoading, isUnavailable, signIn, signUp, signOut, reload, basePath],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
