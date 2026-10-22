//! Public types for the core client.

import type { OAuthError } from "./errors.js";

/** A `fetch`-compatible function. Injectable so callers can supply a custom
 *  implementation (tests, tracing, a pooled agent); defaults to `globalThis.fetch`. */
export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

/** The OAuth/OIDC endpoints of an authorization server. */
export interface Endpoints {
  authorization: string;
  token: string;
  userinfo: string;
  revocation: string;
  jwks: string;
  /** OpenID Connect RP-Initiated Logout's `end_session_endpoint`: where a
   *  browser is sent to end the person's session at the authorization server,
   *  not only the app's. */
  endSession: string;
}

/** What `OAuthClient.endSessionUrl` puts on the end-session request. */
export interface EndSessionOptions {
  /** An ID token the server issued to this app for the session being ended.
   *  It identifies the app and the person; without one the request carries
   *  `client_id` instead, which identifies only the app. An expired one is
   *  fine: the server checks who issued it, not whether it is fresh. */
  idTokenHint?: string;
  /** Where the server sends the browser afterwards. It must be one of the
   *  app's registered `post_logout_redirect_uris`, exactly; the server drops
   *  any other, and the person stays on its signed-out page. */
  postLogoutRedirectUri?: string;
  /** Echoed back on the redirect to `postLogoutRedirectUri`. */
  state?: string;
}

export interface OAuthClientConfig {
  /** Authorization-server base URL, e.g. `https://auth.example.com`. For a
   *  multi-tenant deployment this is the tenant's issuer (its own host). */
  issuer: string;
  clientId: string;
  /** Present for confidential clients (the BFF); omit for public/PKCE-only
   *  clients. When set, the token endpoint is called with HTTP Basic auth. */
  clientSecret?: string;
  redirectUri: string;
  /** Space-delimited string or array. Defaults to `"openid profile email"`. */
  scopes?: string | string[];
  /** Override individual endpoints; anything omitted is derived from `issuer`
   *  by the server's conventional paths (`/oauth/authorize`, `/oauth/token`, …). */
  endpoints?: Partial<Endpoints>;
  /** Custom fetch; defaults to the global. */
  fetch?: FetchLike;
  /** Per-request timeout in milliseconds (default 10000). A slow or
   *  unresponsive AS must not hang the caller indefinitely. */
  timeoutMs?: number;
}

/** Extra parameters for an authorization request. */
export interface AuthorizationUrlOptions {
  /** Override the client's default scopes for this request. */
  scopes?: string | string[];
  /** OIDC `prompt` (e.g. `"login"`, `"consent"`, `"none"`). */
  prompt?: string;
  /**
   * OIDC `max_age`: seconds, and the oldest authentication you will accept.
   *
   * `prompt: "login"` re-authenticates unconditionally; this re-authenticates
   * only if the existing session is older than you allow, which is what a
   * step-up before a sensitive action actually wants — the user who signed in
   * ninety seconds ago should not be asked again.
   *
   * Check the result rather than assuming it. OIDC Core §3.1.2.1 requires the
   * server to return `auth_time` in the ID Token when this is sent, and the
   * honest reading of that is that the caller is expected to compare it:
   * `max_age` states a requirement, and `auth_time` is the answer. This server
   * enforces it, but an ID Token you did not check is a promise you took on
   * trust from a party you are in the middle of authenticating.
   *
   * `0` is meaningful and is not the same as omitting it — it demands a
   * reauthentication now.
   */
  maxAge?: number;
  /**
   * OIDC `login_hint`.
   *
   * **Sent, and not yet honoured.** The server's authorize endpoint does not
   * parse it and the login page does not read it, so the username field is not
   * pre-filled. It is left on the wire — it is a standard parameter and costs
   * nothing — but this comment used to say it pre-filled the field, which was
   * never true of this server.
   */
  loginHint?: string;
  /**
   * Force a specific tenant connection (e.g. `"google"`).
   *
   * The authorize endpoint sends an unauthenticated visitor straight to that
   * provider instead of the password form. A provider the tenant has not
   * configured is answered by the social route's own 404; a malformed value
   * falls back to the password form rather than being refused, because a bad
   * hint is the caller's mistake and not a reason to deny a sign-in.
   */
  connection?: string;
}

/** The one-time secrets an authorization request produces. `state`,
 *  `codeVerifier`, and `nonce` MUST be persisted (server-side, e.g. an
 *  encrypted cookie) until the callback and never exposed to the browser. */
export interface AuthorizationRequest {
  url: string;
  state: string;
  codeVerifier: string;
  nonce: string;
}

/** A normalized (camelCase) token response. */
export interface TokenResponse {
  accessToken: string;
  tokenType: string;
  expiresIn: number;
  refreshToken?: string;
  idToken?: string;
  scope?: string;
}

/** What `OAuthClient.revoke` learned. `ok` for any `2xx`; otherwise the error,
 *  whose `retryable` says whether trying again could change the answer. */
export type RevocationResult = { ok: true } | { ok: false; error: OAuthError };

/** The subset of userinfo claims we name explicitly; any additional claims the
 *  server returns are preserved on the same object. */
export interface UserInfo {
  sub: string;
  email?: string;
  preferredUsername?: string;
  [claim: string]: unknown;
}
