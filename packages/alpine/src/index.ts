//! `@proteles/alpine` — Alpine.js plugin for Proteles authentication.
//!
//! Tokens live only in an encrypted, httpOnly cookie set by your own server; the
//! browser only ever sees the sanitized user from `/api/auth/me`.
//!
//! ```html
//! <script src="https://cdn.jsdelivr.net/npm/@proteles/alpine"></script>
//! <script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3/dist/cdn.min.js"></script>
//! <script>
//!   document.addEventListener("alpine:init", () => Alpine.plugin(protelesAuth()));
//! </script>
//!
//! <div x-signed-out><button @click="$auth.signIn()">Sign in</button></div>
//! <div x-signed-in>Hi <span x-text="$auth.user?.email"></span></div>
//! ```

export { protelesAuth } from "./plugin.js";
export { createAuthStore } from "./store.js";
export { fetchSession } from "./session.js";
export type { SessionResult } from "./session.js";
export { DEFAULT_BASE_PATH, loginUrl, logoutUrl, meUrl, resolveBasePath, signupUrl } from "./urls.js";
export type {
  AlpineDirective,
  AlpineLike,
  AuthStore,
  AuthUser,
  CreateAuthStoreOptions,
  ProtelesAuthOptions,
  SignInOptions,
  SignOutOptions,
  SignUpOptions,
} from "./types.js";
