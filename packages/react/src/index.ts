//! `@proteles/react` — drop-in components and hooks for the Proteles platform.
//!
//! They talk only to the `@proteles/next` BFF's `/api/auth/*` routes, so no
//! secrets or tokens ever reach the browser. The north-star:
//!
//! ```tsx
//! // app/layout.tsx
//! import { AuthProvider } from "@proteles/react";
//! export default function Root({ children }) {
//!   return <AuthProvider>{children}</AuthProvider>;
//! }
//!
//! // app/page.tsx
//! import { SignedIn, SignedOut, SignInButton, UserButton, useUser } from "@proteles/react";
//! export default function Home() {
//!   const { user } = useUser();
//!   return (
//!     <>
//!       <SignedOut><SignInButton /></SignedOut>
//!       <SignedIn>Hi {user?.email} <UserButton /></SignedIn>
//!     </>
//!   );
//! }
//! ```

export { AuthProvider } from "./AuthProvider.js";
export type { AuthProviderProps } from "./AuthProvider.js";
export { useAuth, useUser } from "./hooks.js";
export {
  Protect,
  SignedIn,
  SignedOut,
  SignInButton,
  SignOutButton,
  SignUpButton,
  UserButton,
} from "./components.js";
export type { SignInButtonProps, SignOutButtonProps, SignUpButtonProps } from "./components.js";
export { AuthContext } from "./context.js";
export { fetchSession } from "./session.js";
export type { SessionResult } from "./session.js";
export { DEFAULT_BASE_PATH, loginUrl, logoutUrl, meUrl, resolveBasePath, signupUrl } from "./urls.js";
export type {
  AuthContextValue,
  AuthState,
  AuthUser,
  SignInOptions,
  SignOutOptions,
  SignUpOptions,
} from "./types.js";
