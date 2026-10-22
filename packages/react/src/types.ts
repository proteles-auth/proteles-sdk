//! Public types for the React SDK.

/** The current user, as exposed by the BFF's `/api/auth/me` — never a token. */
export interface AuthUser {
  sub: string;
  email?: string;
  preferredUsername?: string;
  [claim: string]: unknown;
}

/** The reactive auth state every hook/component reads. */
export interface AuthState {
  user: AuthUser | null;
  /** True until who is signed in is known, from `initialUser` or from the first
   *  answer to `/api/auth/me`. A busy or unanswered `/me` is not an answer, and
   *  leaves it true (see `isUnavailable`). */
  isLoading: boolean;
  isAuthenticated: boolean;
  /**
   * True while the last `/api/auth/me` could not say who is signed in — the
   * sign-in service was busy or out of reach — and another is scheduled. `user`
   * is then the last one known, and `isLoading` stays true if none is known yet,
   * so a busy spell does not look like a sign-out. False again once `/me`
   * answers.
   */
  isUnavailable: boolean;
}

export interface SignInOptions {
  /** Path to return to after login (defaults to the current path). */
  returnTo?: string;
  /** Force a specific social connection, e.g. `"google"`. */
  connection?: string;
}

/**
 * `signUp`'s options. No `connection`, unlike `signIn`'s: the server opens the
 * sign-up page before it reads one. A social sign-up is `signIn({ connection })`.
 */
export interface SignUpOptions {
  /** Path to return to after signing up (defaults to the current path). */
  returnTo?: string;
}

export interface SignOutOptions {
  /** Path to return to after logout (defaults to `/`). */
  returnTo?: string;
}

/** The full context value (state + actions). */
export interface AuthContextValue extends AuthState {
  signIn: (options?: SignInOptions) => void;
  /** `signIn`, opening on the workspace's sign-up page — or on its sign-in page
   *  where the workspace has not opened one. */
  signUp: (options?: SignUpOptions) => void;
  signOut: (options?: SignOutOptions) => void;
  /** Re-fetch `/api/auth/me` (e.g. after an action that changes the session). */
  reload: () => Promise<void>;
  basePath: string;
}
