//! `@proteles/solid` — Solid primitives and components for Proteles auth.
//!
//! They talk only to the BFF's `/api/auth/*` routes (see `@proteles/solid/server`
//! for the SolidStart side), so no secrets or tokens ever reach the browser.
//!
//! ```tsx
//! // src/app.tsx
//! import { AuthProvider } from "@proteles/solid";
//!
//! export default function App() {
//!   return <AuthProvider><Router>{/* … */}</Router></AuthProvider>;
//! }
//! ```
//!
//! ```tsx
//! import { SignedIn, SignedOut, SignInButton, UserButton, useUser } from "@proteles/solid";
//!
//! function Home() {
//!   const { user } = useUser();
//!   return (
//!     <>
//!       <SignedOut><SignInButton /></SignedOut>
//!       <SignedIn>Hi {user()?.email} <UserButton /></SignedIn>
//!     </>
//!   );
//! }
//! ```
//!
//! This entry point is `.tsx` because it re-exports JSX components; the build
//! ships both the untranspiled source (for the `solid` export condition) and
//! precompiled client/server bundles.

export { createAuth } from "./auth.js";
export { AuthContext, useAuth, useUser } from "./context.js";
export {
  AuthProvider,
  Protect,
  SignedIn,
  SignedOut,
  SignInButton,
  SignOutButton,
  SignUpButton,
  UserButton,
} from "./components.jsx";
export type {
  AuthProviderProps,
  SignInButtonProps,
  SignOutButtonProps,
  SignUpButtonProps,
} from "./components.jsx";
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
