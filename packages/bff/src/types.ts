//! Public and internal types for the BFF.

import type { FetchLike } from "@proteles/js";

import type { CookieOptions } from "./cookies.js";

/** What we persist about a logged-in user, encrypted whole as the session
 *  cookie's value — there is no server-side session store, so the app scales
 *  horizontally with zero shared state. Because the cookie is httpOnly, the
 *  browser never sees these tokens; the React SDK only ever learns what
 *  `/api/auth/me` chooses to expose. A port of Go's `SessionData`. */
export interface SessionData {
  accessToken: string;
  refreshToken?: string;
  idToken?: string;
  /** Epoch milliseconds. */
  accessExpiresAt: number;
  sub: string;
  email?: string;
  preferredUsername?: string;
  /**
   * RFC 8176 authentication methods, from the ID Token's `amr`.
   *
   * What actually happened at sign-in — `["pwd"]`, `["pwd", "otp"]`, `["swk"]`
   * for a passkey. Absent when the token carried none, which the server
   * distinguishes from an empty list on purpose: `[]` asserts that no methods
   * were used, which is a different and false claim.
   *
   * Read it, do not compute from it. "Was this MFA?" is a policy question whose
   * answer differs per tenant, and a helper here would be this SDK deciding it.
   */
  amr?: string[];
  /**
   * OIDC `auth_time`: **seconds** since the epoch, when the user actually
   * authenticated — not when this session was created or last refreshed.
   *
   * Seconds, unlike every other timestamp on this interface, because that is
   * what the claim is and converting it here would leave the SDK's value and
   * the ID Token's disagreeing by a factor of a thousand for anyone who read
   * both.
   *
   * Survives refresh: the server re-mints the ID Token with the original
   * `auth_time` rather than restarting the clock, so this stays the answer to
   * "how long ago did a human prove who they were" across a month of rotations.
   * That is what makes it usable for a step-up decision.
   */
  authTime?: number;
  /**
   * Epoch milliseconds after which this session is finished regardless of how
   * many times it has been refreshed. Optional: cookies sealed before this
   * field existed decrypt fine and are governed by `accessExpiresAt` alone.
   *
   * The cookie's own `Max-Age` does not bound anything an attacker respects —
   * that is a request to a browser, and a replay with curl never sees it. The
   * IdP makes the same argument about its own session cookie. Without this, a stolen cookie could be
   * renewed indefinitely by looping the refresh path.
   */
  sessionExpiresAt?: number;
}

/**
 * A cookie plus its ready-made header line.
 *
 * Two shapes because runtimes disagree: some want a header appended to a
 * `Response`, others hand you a jar with `set(name, value, options)`. Carrying
 * both means nothing is lost in translation — an httpOnly/Secure/SameSite flag
 * dropped by a hand-rolled conversion is a silent downgrade.
 */
export interface SessionCookie {
  name: string;
  value: string;
  options: CookieOptions;
  header: string;
}

/** Where a rotated session cookie goes. Must reach the response being sent. */
export type CookieSink = (cookie: SessionCookie) => void;

/** What a presented session cookie actually is. */
export type SessionState =
  /** No cookie was presented. */
  | { kind: "none" }
  /** A live access token: usable as-is, no IdP round trip needed. */
  | { kind: "fresh"; data: SessionData }
  /** The access token is spent but a refresh token remains: provable, not proved. */
  | { kind: "stale"; data: SessionData }
  /** Undecryptable, past its absolute cap, or nothing left to refresh with. */
  | { kind: "dead" };

/** The short-lived record of an in-progress login, bridging the redirect to
 *  the authorization server and back. Stored in its own encrypted, 10-minute
 *  cookie so the callback works behind a load balancer with no sticky
 *  sessions. A port of Go's `oauthFlowState`, plus the post-login `returnTo`. */
export interface FlowState {
  state: string;
  codeVerifier: string;
  nonce: string;
  returnTo: string;
  /** Epoch milliseconds. */
  createdAt: number;
}

/** The user object exposed to the browser by `/api/auth/me` — never any token.
 *
 *  A `type` alias rather than an `interface`, and the difference is load-bearing
 *  rather than stylistic. TypeScript grants an *implicit index signature* to an
 *  object-literal type alias but never to an interface, on the reasoning that an
 *  interface can be reopened by declaration merging and so its full shape is not
 *  knowable at the point of use.
 *
 *  The consequence is that the hand-off both the `@proteles/react` and
 *  `@proteles/next` READMEs document —
 *
 *      const user = await currentUser();          // PublicUser | null
 *      <AuthProvider initialUser={user}>          // wants AuthUser | null
 *
 *  — did not compile. `AuthUser` carries `[claim: string]: unknown` so that a
 *  caller can read a custom claim, `PublicUser` structurally satisfies it, and
 *  as an interface it was still rejected:
 *
 *      TS2322: Index signature for type 'string' is missing in type 'PublicUser'.
 *
 *  Nothing extends or implements this, so the alias costs nothing. If that ever
 *  changes, the fix is to add the index signature here rather than to revert. */
export type PublicUser = {
  sub: string;
  email?: string;
  preferredUsername?: string;
  /** RFC 8176 methods used at sign-in, when the ID Token carried them. */
  amr?: string[];
  /** OIDC `auth_time`, in **seconds**: when the user authenticated. */
  authTime?: number;
};

/** Configuration a caller may pass explicitly; anything omitted is read from
 *  the environment (see `resolveConfig`). */
export interface ProtelesConfigInput {
  issuer?: string;
  clientId?: string;
  clientSecret?: string;
  redirectUri?: string;
  /** App origin, e.g. `https://app.example.com`. Used to derive `redirectUri`
   *  (`${appUrl}${basePath}/callback`) when `redirectUri` is not given. */
  appUrl?: string;
  scopes?: string | string[];
  /** Base64 of a 32-byte key used to encrypt the session/flow cookies. */
  sessionSecret?: string;
  /** Send cookies with `Secure`. Default true; set false only for plain-HTTP
   *  local development. */
  cookieSecure?: boolean;
  /** Where to send the browser after a successful login when no `returnTo`
   *  was supplied. Default `/`. */
  postLoginRedirect?: string;
  /** Where to send the browser after a failed login. Default = postLoginRedirect. */
  loginErrorRedirect?: string;
  /** Mount path of the auth route handlers. Default `/api/auth`. */
  basePath?: string;
  /**
   * Whether signing out also ends the person's session at Proteles. Default
   * `true`.
   *
   * Clearing only this app's cookie left the person signed in at Proteles, so
   * the next "Sign in" went straight through without a password: on a shared
   * computer, the previous person. So sign-out sends the browser on to the
   * server's end-session endpoint (OpenID Connect RP-Initiated Logout), which
   * asks the person to confirm, ends the session, tells the other apps that
   * registered for back-channel logout, and returns to `returnTo` on this app's
   * origin. **Register that URL as one of the app's
   * `post_logout_redirect_uris`** — `https://app.example.com/` for the default
   * `returnTo` of `/` — or the person stays on the server's signed-out page.
   *
   * `false` keeps sign-out to this app alone. Also settable with
   * `PROTELES_END_SESSION=false`.
   */
  endSession?: boolean;
  /** Custom fetch, forwarded to the core client (tests, tracing). */
  fetch?: FetchLike;
  /**
   * Per-request timeout, in milliseconds, for every call this makes to the
   * authorization server. Default 10000, from `@proteles/js`.
   *
   * Exposed because it was not, and the omission had teeth: `@proteles/js` has
   * always accepted `timeoutMs`, this package simply never passed it, so 10s
   * was unreachable for every consumer. A cold-starting authorization server,
   * a slow network, or a host busy generating a new tenant's signing keys all
   * push the token exchange past it. A user whose exchange times out is told
   * the sign-in service was busy and offered a fresh sign-in, and one whose
   * userinfo call times out gets the generic `?proteles_error=login_failed` a
   * wrong secret produces; neither says "timeout". Also settable with
   * `PROTELES_TIMEOUT_MS`.
   */
  timeoutMs?: number;
  /**
   * Called (server-side only) with a diagnostic reason when a login fails
   * (`context` is `"callback"`, which includes a code exchange the server was
   * too busy for or did not answer), when a refresh is put off because the
   * authorization server is busy, rate-limiting or unreachable and the session
   * is kept for the next request (`"refresh"` — once per request that finds
   * its session needing a refresh the server cannot give, so expect a burst of
   * them during a busy spell), when sign-out could not revoke the refresh
   * token (`"logout"`; a busy answer that came back quickly is retried once
   * before it is reported, a refusal or no answer is reported at once), when
   * a sign-out sent by another site is ignored (also `"logout"`), and when a
   * sign-in link names an `iss` other than `issuer` (`"login"`). That last is
   * not a failure: the sign-in goes ahead at `issuer`. It is told at most once
   * every ten minutes, and carries nothing of the `iss` itself, which anybody
   * can put in a link; leave it out of anything that alerts.
   *
   * Defaults to a `console.warn`. Auth failures are deliberately opaque to the
   * *browser* — the user only ever sees a generic error — but a server with no
   * signal at all makes misconfiguration (a wrong secret, an unreachable issuer)
   * genuinely hard to diagnose. Pass `false` to silence it, or your own logger.
   */
  onError?: ((reason: string, context: string) => void) | false;
}

/** Fully-resolved, validated configuration. */
export interface ProtelesConfig {
  issuer: string;
  clientId: string;
  clientSecret: string | undefined;
  redirectUri: string;
  scopes: string;
  sessionSecret: string;
  cookieSecure: boolean;
  postLoginRedirect: string;
  loginErrorRedirect: string;
  basePath: string;
  endSession: boolean;
  fetch: FetchLike | undefined;
  timeoutMs: number | undefined;
  onError: ((reason: string, context: string) => void) | false;
}
