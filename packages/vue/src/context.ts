//! provide/inject plumbing plus the Vue plugin.

import { effectScope, inject, onMounted, type App, type InjectionKey } from "vue";

import { createAuth } from "./auth.js";
import type { Auth, CreateAuthOptions } from "./types.js";

/** Injection key for the auth object. Exported so advanced callers can
 *  `provide()` a custom instance (e.g. in tests or a micro-frontend host). */
export const PROTELES_AUTH: InjectionKey<Auth> = Symbol("proteles-auth");

/**
 * The Vue plugin — the idiomatic way to install Proteles app-wide:
 *
 * ```ts
 * app.use(protelesAuth({ initialUser }));
 * ```
 *
 * It provides the auth object to every component and revalidates against
 * `/api/auth/me` once the app mounts (so a stale `initialUser` — e.g. after a
 * logout in another tab — self-corrects).
 */
export function protelesAuth(options: CreateAuthOptions = {}): {
  install: (app: App) => void;
  auth: Auth;
} {
  // A scope of the plugin's own, so the app's unmount can dispose of it, which
  // stops the `/me` retries after a busy answer (see `createAuth`).
  const scope = effectScope(true);
  const auth = scope.run(() => createAuth(options))!;
  return {
    auth,
    install(app: App) {
      app.provide(PROTELES_AUTH, auth);
      // `app.onUnmount` is Vue 3.5; earlier versions give a plugin no hook for
      // its app going, so there it keeps asking until `/me` answers.
      if (typeof app.onUnmount === "function") app.onUnmount(() => scope.stop());
      // Revalidate on the client only. `app.runWithContext` isn't needed here:
      // the fetch is plain and doesn't touch injection.
      if (typeof window !== "undefined") {
        void auth.reload();
      }
    },
  };
}

/**
 * The auth object from the nearest provider. Call during `setup()` (the same
 * rule as any Vue `inject`).
 *
 * Throws a clear error rather than returning undefined when neither the
 * `protelesAuth` plugin nor `<AuthProvider>` is installed.
 */
export function useAuth(): Auth {
  const auth = inject(PROTELES_AUTH, undefined);
  if (!auth) {
    throw new Error(
      "@proteles/vue: useAuth() requires the protelesAuth plugin (app.use) or an <AuthProvider> ancestor",
    );
  }
  return auth;
}

/** Just the user state — the common case. */
export function useUser(): Pick<Auth, "user" | "isLoading" | "isAuthenticated" | "isUnavailable"> {
  const { user, isLoading, isAuthenticated, isUnavailable } = useAuth();
  return { user, isLoading, isAuthenticated, isUnavailable };
}

/** Internal: used by `<AuthProvider>` to revalidate after mount. */
export function revalidateOnMount(auth: Auth): void {
  onMounted(() => {
    void auth.reload();
  });
}
