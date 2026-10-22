//! The reactive auth object — Solid signals plus the `signIn`/`signUp`/
//! `signOut`/`reload` actions. Created once per app (by `<AuthProvider>`) and
//! shared via context.

import { createSignal, getOwner, onCleanup } from "solid-js";

import { createRetry, fetchSession } from "./session.js";
import type { Auth, AuthUser, CreateAuthOptions, SignInOptions, SignOutOptions, SignUpOptions } from "./types.js";
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
 * Creates the reactive auth object. Prefer `<AuthProvider>`; call this directly
 * only if you want to own the instance.
 *
 * It deliberately does **not** fetch on creation — that would fire during SSR.
 * The provider revalidates after mount; `initialUser` covers the first paint.
 *
 * Made under a reactive owner — a component, or `createRoot` — it asks `/me`
 * again after a busy answer only until that owner is disposed.
 */
export function createAuth(options: CreateAuthOptions = {}): Auth {
  const basePath = resolveBasePath(options.basePath);
  const fetchImpl = options.fetch ?? ((...args: Parameters<typeof fetch>) => fetch(...args));
  const navigate = options.navigate ?? defaultNavigate;
  const post = options.post ?? defaultPost;
  const currentPath = options.currentPath ?? defaultCurrentPath;

  const [user, setUser] = createSignal<AuthUser | null>(options.initialUser ?? null);
  const [isLoading, setIsLoading] = createSignal<boolean>(options.initialUser === undefined);
  // A plain derived accessor, deliberately not a `createMemo`: a memo needs a
  // reactive owner, so one created here would silently stop updating whenever
  // `createAuth` is called outside a component (which is a supported use). A
  // derived function tracks wherever it is *read*, and for a null check there is
  // nothing worth memoizing.
  const isAuthenticated = (): boolean => user() !== null;
  const [isUnavailable, setIsUnavailable] = createSignal<boolean>(false);
  const retry = createRetry();
  // Disposing the owner — `<AuthProvider>` unmounting — drops the pending
  // retry, and a busy answer still in flight then schedules none, so a provider
  // that has gone stops polling a busy server for nobody. Checked first because
  // `onCleanup` with no owner is never run, and says so in development; made
  // outside any owner, it keeps asking until `/me` answers.
  let stopped = false;
  if (getOwner()) {
    onCleanup(() => {
      stopped = true;
      retry.cancel();
    });
  }

  async function reload(): Promise<void> {
    const result = await fetchSession(basePath, fetchImpl);
    if (result.unavailable) {
      // Only say so: the user, and a first load's `isLoading`, stay as they
      // were, because a busy `/me` is not a sign-out.
      setIsUnavailable(true);
      if (!stopped) retry.schedule(() => void reload(), result.retryAfter);
      return;
    }
    retry.cancel();
    setUser(result.user);
    setIsLoading(false);
    setIsUnavailable(false);
  }

  function signIn(opts?: SignInOptions): void {
    const returnTo = opts?.returnTo ?? currentPath();
    navigate(loginUrl(basePath, { ...opts, ...(returnTo ? { returnTo } : {}) }));
  }

  function signUp(opts?: SignUpOptions): void {
    const returnTo = opts?.returnTo ?? currentPath();
    navigate(signupUrl(basePath, { ...opts, ...(returnTo ? { returnTo } : {}) }));
  }

  function signOut(opts?: SignOutOptions): void {
    post(logoutUrl(basePath, opts));
  }

  return { user, isLoading, isAuthenticated, isUnavailable, signIn, signUp, signOut, reload, basePath };
}
