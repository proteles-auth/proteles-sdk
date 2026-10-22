//! The reactive auth object — Vue refs plus the `signIn`/`signUp`/`signOut`/
//! `reload` actions. Created once per app (by the plugin or `<AuthProvider>`)
//! and shared through provide/inject.

import { computed, getCurrentScope, onScopeDispose, ref } from "vue";

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
 * Creates the reactive auth object. Prefer the `protelesAuth` plugin or
 * `<AuthProvider>`; call this directly only if you want to own the instance.
 *
 * It deliberately does **not** fetch on creation — that would fire during SSR.
 * The plugin/provider calls `reload()` on mount; `initialUser` covers the first
 * paint.
 *
 * Made inside a component's `setup()`, or any effect scope, it asks `/me` again
 * after a busy answer only until that scope is disposed.
 */
export function createAuth(options: CreateAuthOptions = {}): Auth {
  const basePath = resolveBasePath(options.basePath);
  const fetchImpl = options.fetch ?? ((...args: Parameters<typeof fetch>) => fetch(...args));
  const navigate = options.navigate ?? defaultNavigate;
  const post = options.post ?? defaultPost;
  const currentPath = options.currentPath ?? defaultCurrentPath;

  const user = ref<AuthUser | null>(options.initialUser ?? null);
  const isLoading = ref<boolean>(options.initialUser === undefined);
  const isAuthenticated = computed(() => user.value !== null);
  const isUnavailable = ref<boolean>(false);
  const retry = createRetry();
  // Disposing the scope — `<AuthProvider>` unmounting, or the plugin's app —
  // drops the pending retry, and a busy answer still in flight then schedules
  // none, so a provider that has gone stops polling a busy server for nobody.
  // Made outside any scope, it keeps asking until `/me` answers.
  let stopped = false;
  if (getCurrentScope()) {
    onScopeDispose(() => {
      stopped = true;
      retry.cancel();
    });
  }

  async function reload(): Promise<void> {
    const result = await fetchSession(basePath, fetchImpl);
    if (result.unavailable) {
      // Only say so: the user, and a first load's `isLoading`, stay as they
      // were, because a busy `/me` is not a sign-out.
      isUnavailable.value = true;
      if (!stopped) retry.schedule(() => void reload(), result.retryAfter);
      return;
    }
    retry.cancel();
    user.value = result.user;
    isLoading.value = false;
    isUnavailable.value = false;
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
