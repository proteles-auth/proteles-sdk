"use client";

//! The drop-in UI components. They read state from `useAuth` and trigger the
//! BFF flows; they never talk to the authorization server directly, and the
//! browser never handles a token.

import * as React from "react";
import type { ReactNode } from "react";

import { useAuth } from "./hooks.js";
import type { SignInOptions, SignOutOptions, SignUpOptions } from "./types.js";

/** Renders its children only when a user is signed in (and loading is done). */
export function SignedIn({ children }: { children: ReactNode }): ReactNode {
  const { isAuthenticated, isLoading } = useAuth();
  return isAuthenticated && !isLoading ? children : null;
}

/** Renders its children only when no user is signed in (and loading is done). */
export function SignedOut({ children }: { children: ReactNode }): ReactNode {
  const { isAuthenticated, isLoading } = useAuth();
  return !isAuthenticated && !isLoading ? children : null;
}

/** Gates content behind authentication, showing `fallback` (default nothing)
 *  when signed out. Renders nothing while loading. */
export function Protect({ children, fallback = null }: { children: ReactNode; fallback?: ReactNode }): ReactNode {
  const { isAuthenticated, isLoading } = useAuth();
  if (isLoading) return null;
  return isAuthenticated ? children : fallback;
}

export interface SignInButtonProps extends SignInOptions {
  children?: ReactNode;
  className?: string;
}

/** A button that starts the login flow. */
export function SignInButton({ children, className, ...options }: SignInButtonProps): ReactNode {
  const { signIn } = useAuth();
  return (
    <button type="button" className={className} onClick={() => signIn(options)}>
      {children ?? "Sign in"}
    </button>
  );
}

export interface SignUpButtonProps extends SignUpOptions {
  children?: ReactNode;
  className?: string;
}

/** A button that starts sign-up — or sign-in, where the workspace has not
 *  opened its sign-up page. */
export function SignUpButton({ children, className, ...options }: SignUpButtonProps): ReactNode {
  const { signUp } = useAuth();
  return (
    <button type="button" className={className} onClick={() => signUp(options)}>
      {children ?? "Sign up"}
    </button>
  );
}

export interface SignOutButtonProps extends SignOutOptions {
  children?: ReactNode;
  className?: string;
}

/** A button that logs out. */
export function SignOutButton({ children, className, ...options }: SignOutButtonProps): ReactNode {
  const { signOut } = useAuth();
  return (
    <button type="button" className={className} onClick={() => signOut(options)}>
      {children ?? "Sign out"}
    </button>
  );
}

/** A compact identity chip: the user's name/email plus a sign-out control.
 *  Renders nothing when signed out. */
export function UserButton({ className }: { className?: string }): ReactNode {
  const { user, signOut } = useAuth();
  if (!user) return null;
  const label = user.preferredUsername || user.email || user.sub;
  return (
    <span className={className} data-proteles="user-button">
      <span data-proteles="user-label">{label}</span>{" "}
      <button type="button" data-proteles="user-signout" onClick={() => signOut()}>
        Sign out
      </button>
    </span>
  );
}
