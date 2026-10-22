//! `@proteles/vue` — Vue 3 composables and components for Proteles auth.
//!
//! They talk only to the BFF's `/api/auth/*` routes (see `@proteles/vue/server`
//! for the Nuxt/h3 side), so no secrets or tokens ever reach the browser.
//!
//! ```ts
//! // main.ts
//! import { protelesAuth } from "@proteles/vue";
//! app.use(protelesAuth());
//! ```
//!
//! ```vue
//! <script setup>
//! import { SignedIn, SignedOut, SignInButton, UserButton, useUser } from "@proteles/vue";
//! const { user } = useUser();
//! </script>
//!
//! <template>
//!   <SignedOut><SignInButton /></SignedOut>
//!   <SignedIn>Hi {{ user?.email }} <UserButton /></SignedIn>
//! </template>
//! ```

export { createAuth } from "./auth.js";
export { PROTELES_AUTH, protelesAuth, useAuth, useUser } from "./context.js";
export {
  AuthProvider,
  Protect,
  SignedIn,
  SignedOut,
  SignInButton,
  SignOutButton,
  SignUpButton,
  UserButton,
} from "./components.js";
export { fetchSession } from "./session.js";
export type { SessionResult } from "./session.js";
export { DEFAULT_BASE_PATH, loginUrl, logoutUrl, meUrl, resolveBasePath, signupUrl } from "./urls.js";
export type {
  Auth,
  AuthUser,
  CreateAuthOptions,
  SignInOptions,
  SignOutOptions,
  SignUpOptions,
} from "./types.js";
