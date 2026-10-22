//! The auth store. A plain object by design: `Alpine.store()` wraps it in
//! Alpine's reactivity, so mutating `this` is what drives the DOM.

import { createRetry, fetchSession } from "./session.js";
import type { AuthStore, AuthUser, CreateAuthStoreOptions, SignInOptions, SignOutOptions, SignUpOptions } from "./types.js";
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
 * Builds the store object. `protelesAuth()` registers this with Alpine for you;
 * call it directly only if you want to own the instance (e.g. to register it
 * under a different name yourself).
 *
 * Note `init()` is Alpine's own convention — it invokes it automatically when the
 * store is registered — so revalidation happens without the app wiring anything.
 */
export function createAuthStore(options: CreateAuthStoreOptions = {}): AuthStore {
  const basePath = resolveBasePath(options.basePath);
  const fetchImpl = options.fetch ?? ((...args: Parameters<typeof fetch>) => fetch(...args));
  const navigate = options.navigate ?? defaultNavigate;
  const post = options.post ?? defaultPost;
  const currentPath = options.currentPath ?? defaultCurrentPath;
  const revalidateOnInit = options.revalidateOnInit ?? true;
  const retry = createRetry();

  return {
    user: (options.initialUser ?? null) as AuthUser | null,
    isLoading: options.initialUser === undefined,
    isUnavailable: false,
    basePath,

    get isAuthenticated(): boolean {
      return this.user !== null;
    },

    init(): void {
      // Always revalidate against the server, even when seeded, so a stale
      // `initialUser` (e.g. after a logout in another tab) self-corrects.
      if (revalidateOnInit) void this.reload();
    },

    async reload(): Promise<void> {
      const result = await fetchSession(basePath, fetchImpl);
      if (result.unavailable) {
        // Only say so: the user, and a first load's `isLoading`, stay as they
        // were, because a busy `/me` is not a sign-out. The retry calls
        // `reload` on this same `this`, which is Alpine's reactive store when
        // Alpine made the call, so the retry's answer reaches the DOM too.
        this.isUnavailable = true;
        retry.schedule(() => void this.reload(), result.retryAfter);
        return;
      }
      retry.cancel();
      this.user = result.user;
      this.isLoading = false;
      this.isUnavailable = false;
    },

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
  };
}
