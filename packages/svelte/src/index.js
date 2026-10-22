/**
 * `@proteles/svelte` — Svelte components and stores for Proteles auth.
 *
 * They talk only to the BFF's `/api/auth/*` routes (see
 * `@proteles/svelte/server`), so no secrets or tokens ever reach the browser.
 *
 * ```svelte
 * <!-- +layout.svelte -->
 * <script>
 *   import { AuthProvider } from "@proteles/svelte";
 *   export let data;
 * </script>
 * <AuthProvider initialUser={data.user}><slot /></AuthProvider>
 * ```
 *
 * ```svelte
 * <!-- +page.svelte -->
 * <script>
 *   import { SignedIn, SignedOut, SignInButton, UserButton, getAuth } from "@proteles/svelte";
 *   const auth = getAuth();
 * </script>
 * <SignedOut><SignInButton /></SignedOut>
 * <SignedIn>Hi {$auth.user?.email} <UserButton /></SignedIn>
 * ```
 *
 * This entry point is plain JS (not TS) because it re-exports `.svelte`
 * components, which `tsc` cannot resolve; `svelte-package` generates the
 * matching `.d.ts` from the components themselves.
 */

export { default as AuthProvider } from "./AuthProvider.svelte";
export { default as SignedIn } from "./SignedIn.svelte";
export { default as SignedOut } from "./SignedOut.svelte";
export { default as Protect } from "./Protect.svelte";
export { default as SignInButton } from "./SignInButton.svelte";
export { default as SignOutButton } from "./SignOutButton.svelte";
export { default as SignUpButton } from "./SignUpButton.svelte";
export { default as UserButton } from "./UserButton.svelte";

export { createAuthStore } from "./store.js";
export { getAuth, setAuthContext, AUTH_CONTEXT_KEY } from "./context.js";
export { fetchSession } from "./session.js";
export { DEFAULT_BASE_PATH, loginUrl, logoutUrl, meUrl, resolveBasePath, signupUrl } from "./urls.js";
