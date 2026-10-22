//! The framework-agnostic Backend-for-Frontend. Operates on Web `Request`/
//! `Response`, so the very same object works as a Next App Router route handler
//! (`NextRequest extends Request`; a route may return a `Response`) and as Edge
//! middleware. It ports Proteles' reference Go web app — the redirect-based
//! OAuth flow with encrypted cookies and transparent refresh — over
//! `@proteles/js`.
//!
//! Security posture: access/refresh tokens live only inside the encrypted,
//! httpOnly session cookie. The browser never receives a token; it only ever
//! sees the sanitized user object from `/api/auth/me`.

import { JwksCache, OAuthClient, OAuthError, timingSafeEqual, verifyIdToken } from "@proteles/js";
import type { AuthorizationUrlOptions, IdTokenClaims, TokenResponse } from "@proteles/js";

import { cookieSecureFromEnv, resolveConfig } from "./config.js";
import { parseCookies, serializeCookie } from "./cookies.js";
import { SessionCrypto } from "./session.js";
import type {
  CookieSink,
  FlowState,
  ProtelesConfig,
  ProtelesConfigInput,
  PublicUser,
  SessionCookie,
  SessionData,
  SessionState,
} from "./types.js";

/** The names of the two cookies this package sets. */
export interface CookieNames {
  /** The sealed session: tokens and the user. */
  session: string;
  /** The sealed, single-use state of a sign-in in flight. */
  flow: string;
}

/**
 * The names the session and flow cookies go by: `__Host-proteles_session`
 * and `__Host-proteles_flow` whenever the cookies are `Secure`, and the plain
 * names when `cookieSecure` is off.
 *
 * The prefix is what stops a sibling host planting one. Without it, any host
 * under the app's registrable domain can set `proteles_session` for the whole
 * domain, and the browser sends it to the app as well. The values are sealed,
 * so nobody can forge one, but an honest value of the attacker's own — their
 * own session, or their own sign-in in flight — signs the victim into the app
 * as the attacker. It works against a signed-in victim too: equal-path cookies
 * arrive oldest first and `parseCookies` keeps the last. A browser refuses a
 * `__Host-` cookie from anywhere but the host itself, and without `Secure`,
 * `Path=/`, or with a `Domain`, which is why plain-HTTP development, where
 * `cookieSecure` is off, keeps the plain names.
 *
 * `secure` defaults to what the environment says (`PROTELES_COOKIE_SECURE`), as
 * `resolveConfig` reads it. Pass the value you configured when you set
 * `cookieSecure` in code, or read `AuthApp.cookieNames` from the app itself.
 * There is no constant: the name depends on configuration, and a constant that
 * kept its old name while its meaning changed would have every caller read the
 * wrong cookie in production, with no error.
 */
export function cookieNames(secure: boolean = cookieSecureFromEnv()): CookieNames {
  // Spelled out rather than built from a prefix, so each name is greppable and
  // a drift check can find the names the verify scripts read.
  return secure
    ? { session: "__Host-proteles_session", flow: "__Host-proteles_flow" }
    : { session: "proteles_session", flow: "proteles_flow" };
}

const FLOW_TTL_SECONDS = 600;
const SESSION_TTL_SECONDS = 30 * 24 * 60 * 60;
const REFRESH_SKEW_MS = 30_000;

/**
 * How long one refresh's answer is shared with every request still presenting
 * the refresh token it spent. The authorization server rotates on every
 * refresh and spends a token exactly once — the second of two requests racing
 * one token gets `invalid_grant` — and until the browser has stored the
 * rotated cookie, every request it sends still carries the old one. Sixty
 * seconds is the server's own window for treating a re-presented token as a
 * retry (`RETRY_WINDOW_SECONDS`).
 */
const REFRESH_SHARE_MS = 60_000;

/**
 * How long sign-out waits before its one retry of a revocation the server was
 * too busy to take. The server's password pool queues at most 32 hashes per
 * core (`QUEUE_PER_PERMIT`), on the order of a second of work, and the user is
 * waiting on this redirect.
 */
const REVOKE_RETRY_PAUSE_MS = 500;

/**
 * How soon a busy answer must have come back for sign-out to retry it. See
 * `revokeForSignOut` for why a slow answer, and no answer, are not retried.
 */
const REVOKE_RETRY_WINDOW_MS = 2_000;

/** Result of loading (and possibly refreshing) the session: the data, plus a
 *  `Set-Cookie` string when the cookie needs to be (re)written or cleared — or
 *  `busy` when it needed a refresh the authorization server could not give
 *  right now. A busy result leaves the cookie as it was, unless the exchange
 *  went through and only the new ID token could not be checked: then
 *  `setCookie` carries the rotated refresh token, still marked spent. */
interface LoadedSession {
  data: SessionData | null;
  setCookie?: string;
  busy?: { retryAfter: number | undefined };
}

/**
 * What one attempt to refresh a session came to. Three outcomes rather than
 * two, because "the grant is dead" and "come back shortly" call for opposite
 * things: the first ends the session, and the second must leave it — cookie,
 * refresh token and all — as it was, so that the next request can try again.
 */
type RefreshOutcome =
  | { kind: "refreshed"; data: SessionData }
  | { kind: "refused" }
  /** `successor`: the exchange rotated the refresh token, so the session to
   *  keep is not the one the cookie holds. See `refreshInto`. */
  | { kind: "busy"; retryAfter: number | undefined; successor?: SessionData };

/**
 * Thrown by `resolveSession` and `resolveUsableSession` when a spent session
 * needed a refresh and the authorization server could not give one right now.
 * It answered `503` — which is what a full password pool says, with
 * the client secret unchecked — or `429` from its rate limiter, another `5xx`
 * or a `408`, or it did not answer at all.
 *
 * Nothing was cleared, and the next request tries again. Answer with "try
 * again" — `503`, with `retryAfter` as `Retry-After` when it is set — and not
 * with a login redirect: the user is still signed in.
 *
 * Usually the sink was not called, because the cookie the browser holds is
 * still the session. The exception is an exchange that went through but whose
 * new ID token could not be checked, because the key set was out of reach:
 * the refresh token the cookie holds is spent by then, so the sink has already
 * been handed the session with its successor, and — as always — that cookie
 * must reach your response, the `503` included.
 *
 * These methods used to return `null` for any failed refresh, having cleared
 * the cookie, so a busy authorization server signed out everybody whose access
 * token happened to expire while it was busy.
 */
export class SessionUnavailableError extends Error {
  /** Seconds the authorization server asked for, when it said. */
  readonly retryAfter: number | undefined;

  constructor(retryAfter: number | undefined, options?: { cause?: unknown }) {
    super("the authorization server could not refresh the session right now; the session is intact", options);
    this.name = "SessionUnavailableError";
    this.retryAfter = retryAfter;
  }
}

/**
 * How often, at most, `AuthApp.login` tells `onError` that a sign-in link
 * named an `iss` other than the configured issuer: ten minutes, so an app
 * whose issuer is a custom domain hears of it while it matters and a stranger
 * looping `GET /login?iss=…` produces six reports an hour, not one a request.
 */
export const ISS_MISMATCH_REPORT_INTERVAL_MS = 10 * 60 * 1000;

export class AuthApp {
  readonly config: ProtelesConfig;
  /** The cookie names this app's configuration uses; see {@link cookieNames}. */
  readonly cookieNames: CookieNames;
  private readonly client: OAuthClient;
  private readonly crypto: SessionCrypto;
  /**
   * The issuer's published signing keys, held for the life of the app rather
   * than per request: an unknown `kid` refetches on its own, so the cache
   * survives a key rotation without being told about it, and a burst of logins
   * is one fetch rather than one each. Its fetch is bounded by `timeoutMs`,
   * like every other call to the authorization server.
   */
  private readonly jwks: JwksCache;
  /**
   * In-flight and just-finished refreshes, by the refresh token they spend.
   * A client must serialise refreshes across the whole app (rotation spends
   * each refresh token once; `docs/mobile-SDKs.md` §4); this is that, for
   * every request this process handles. Without
   * it, two requests arriving together with an expired access token each
   * presented the same refresh token, one lost, and the loser's response
   * cleared the session cookie — signing the user out because they opened two
   * tabs. (Across processes it cannot help: run one instance, or keep sessions
   * where one process owns each refresh.)
   */
  private readonly refreshes = new Map<string, { at: number; result: Promise<TokenResponse> }>();
  /** When `login` last told `onError` of an `iss` mismatch; see `login`. */
  private issMismatchReportedAt: number | undefined;

  constructor(input?: ProtelesConfigInput) {
    this.config = resolveConfig(input);
    this.cookieNames = cookieNames(this.config.cookieSecure);
    this.crypto = new SessionCrypto(this.config.sessionSecret);
    this.client = new OAuthClient({
      issuer: this.config.issuer,
      clientId: this.config.clientId,
      clientSecret: this.config.clientSecret,
      redirectUri: this.config.redirectUri,
      scopes: this.config.scopes,
      fetch: this.config.fetch,
      timeoutMs: this.config.timeoutMs,
    });
    this.jwks = new JwksCache(
      `${this.config.issuer.replace(/\/+$/, "")}/.well-known/jwks.json`,
      this.config.fetch,
      { timeoutMs: this.config.timeoutMs },
    );
  }

  /**
   * Verifies an `id_token`, if one came back.
   *
   * **The absence is the interesting case.** A response with no `id_token` is
   * legitimate when `openid` was not requested, and refusing it would break
   * every non-OIDC caller. But treating "no token" as "nothing to check" is how
   * a verification quietly stops happening — so when the scopes *do* ask for
   * `openid`, a missing `id_token` is a failure rather than a skip.
   *
   * `expectedNonce` is `string | null` with no default, so a caller has to say
   * which case it is. The callback passes the nonce it sealed; the refresh
   * paths pass `null`, because the refresh grant mints a token with no nonce.
   */
  /**
   * Verifies the ID Token and hands back its claims.
   *
   * Returned rather than discarded: this already parses and verifies the token,
   * and `amr`/`auth_time` live nowhere else. They are ID Token claims, not
   * userinfo claims, so the `fetchUserInfo` call that fills the rest of the
   * session cannot see them — which is why they were missing from it.
   */
  private async verifyIdTokenIfPresent(
    idToken: string | undefined,
    expectedNonce: string | null,
    // The access token from the same token response. Every ID token the server
    // mints carries its `at_hash`, on the refresh grant too, so both call sites
    // have one to bind.
    accessToken: string,
    required: boolean,
  ): Promise<IdTokenClaims | undefined> {
    const wantsOidc = this.config.scopes.includes("openid");
    if (!idToken) {
      if (required && wantsOidc) {
        throw new Error("the authorization server returned no id_token, but openid was requested");
      }
      return;
    }
    return await verifyIdToken(idToken, {
      issuer: this.config.issuer,
      audience: this.config.clientId,
      nonce: expectedNonce,
      accessToken,
      jwks: this.jwks,
    });
  }

  /** Routes a request to one of the `/api/auth/*` actions by its last path
   *  segment. Unknown actions 404. */
  async handle(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const action = url.pathname.split("/").filter(Boolean).pop() ?? "";
    switch (action) {
      case "login":
        return this.login(url);
      case "signup":
        return this.signup(url);
      case "callback":
        return this.callback(request, url);
      case "logout":
        return this.logout(request, url);
      case "me":
        return this.me(request);
      case "revalidate":
        return this.revalidate(request, url);
      default:
        return json({ error: "not_found" }, 404);
    }
  }

  // --- actions -----------------------------------------------------------

  /**
   * A sign-in, started by a link in the app — or by a third party, OpenID
   * Connect Core 1.0 §4's third-party-initiated login, which is why this is the
   * route to register as the app's `initiate_login_uri`. Proteles sends
   * somebody who has just accepted an invitation naming the app here as
   * `GET <basePath>/login?iss=<issuer>`. When accepting made their account,
   * they are already signed in at Proteles, and the ordinary sign-in this
   * starts is answered without another password; an account that existed
   * before signs in as usual.
   *
   * **`iss` is checked and never followed.** The sign-in always starts at the
   * configured issuer: a browser this app sends somewhere to sign in is sent
   * only to the issuer it trusts, whatever a link says. An `iss` that names a
   * different issuer, compared byte for byte as an ID token's is, does not stop
   * it — Proteles answers one workspace on several hosts (its own address, a
   * custom domain), each an issuer, and an invitation names the one it was
   * accepted on; refusing would strand the invitee on an error page, where
   * starting at the configured issuer only asks them to sign in.
   *
   * A mismatch is told to `onError` with the context `"login"` — not a
   * failure: the sign-in went ahead — so the reason invitees are asked for
   * their password again can be found. **Without the value, and at most once
   * every {@link ISS_MISMATCH_REPORT_INTERVAL_MS} for this `AuthApp`**: the
   * route is a public `GET`, so anybody can send it any `iss` as often as they
   * like, and a handler wired to an error tracker must not be flooded with
   * text a stranger chose. An app whose issuer is a custom domain sees it once
   * per interval, not once per invitee.
   */
  private async login(url: URL): Promise<Response> {
    const iss = url.searchParams.get("iss");
    if (iss !== null && iss !== this.config.issuer) {
      const now = Date.now();
      if (this.issMismatchReportedAt === undefined || now - this.issMismatchReportedAt >= ISS_MISMATCH_REPORT_INTERVAL_MS) {
        this.issMismatchReportedAt = now;
        this.reportError(
          `a sign-in link named an iss other than this app's issuer, ${this.config.issuer}; the sign-in was started ` +
            `there anyway (reported at most once every ${ISS_MISMATCH_REPORT_INTERVAL_MS / 60000} minutes)`,
          "login",
        );
      }
    }
    const connection = url.searchParams.get("connection") ?? undefined;
    return this.startAuthorization(url, connection ? { connection } : undefined);
  }

  /**
   * A sign-in that opens on the workspace's sign-up page (`prompt=create`,
   * OpenID Connect Prompt Create 1.0). Where the workspace has not opened that
   * page, the server ignores `create` and shows its sign-in page, so this is
   * then `login`. Either way the person comes back through `/callback`.
   *
   * No `connection`. The server acts on `create` before it reads one, so a
   * connection would only take effect where the sign-up page is closed, and
   * there it would turn a sign-up into a sign-in through that provider. A
   * social sign-up is `login` with a `connection`, where the workspace lets a
   * first social sign-in make an account.
   */
  private async signup(url: URL): Promise<Response> {
    return this.startAuthorization(url, { prompt: "create" });
  }

  /** What `login` and `signup` share: seal the flow into its cookie, and send
   *  the browser to the authorization server. */
  private async startAuthorization(url: URL, options: AuthorizationUrlOptions | undefined): Promise<Response> {
    const returnTo = safeReturnTo(url.searchParams.get("returnTo")) ?? this.config.postLoginRedirect;
    const authReq = await this.client.createAuthorizationUrl(options);
    const flow: FlowState = {
      state: authReq.state,
      codeVerifier: authReq.codeVerifier,
      nonce: authReq.nonce,
      returnTo,
      createdAt: Date.now(),
    };
    const flowCookie = serializeCookie(this.cookieNames.flow, await this.crypto.encrypt(flow), this.cookieOptions(FLOW_TTL_SECONDS));
    return redirect(authReq.url, 302, [flowCookie]);
  }

  private async callback(request: Request, url: URL): Promise<Response> {
    const clearFlow = serializeCookie(this.cookieNames.flow, "", this.cookieOptions(0));
    const fail = (reason: string) => {
      this.reportError(reason, "callback");
      return redirect(this.errorRedirect(), 303, [clearFlow]);
    };

    // Load + clear the single-use flow cookie regardless of outcome.
    const rawFlow = parseCookies(request.headers.get("cookie"))[this.cookieNames.flow];
    let flow: FlowState | null = null;
    if (rawFlow) {
      try {
        flow = await this.crypto.decrypt<FlowState>(rawFlow);
      } catch {
        flow = null;
      }
    }

    const asError = url.searchParams.get("error");
    // Quoted: the value is whoever sent the request's, and a raw newline in
    // it would forge lines in the app's log.
    if (asError) return fail(`authorization server returned error=${JSON.stringify(asError)}`);
    if (!flow) return fail(`no ${this.cookieNames.flow} cookie on the callback request (was login started on this origin?)`);
    if (Date.now() - flow.createdAt > FLOW_TTL_SECONDS * 1000) return fail("the login flow expired");
    if (!timingSafeEqual(flow.state, url.searchParams.get("state") ?? "")) return fail("state mismatch — possible CSRF, or a stale login tab");
    const code = url.searchParams.get("code");
    if (!code) return fail("no authorization code in the callback");

    let tokens: TokenResponse;
    try {
      tokens = await this.client.exchangeCode({ code, codeVerifier: flow.codeVerifier });
    } catch (e) {
      // "Not now" from the token endpoint is not a failed sign-in, and it used
      // to end in `login_failed` like one. The page it gets instead starts a
      // fresh flow; see `signInBusyPage` for why this code is not tried again.
      if (e instanceof OAuthError && e.retryable) {
        this.reportError(
          `the authorization server was busy or unreachable at the code exchange, so the user was offered a fresh sign-in: ${e.message}`,
          "callback",
        );
        const again = new URL(`${this.config.basePath}/login`, url.origin);
        again.searchParams.set("returnTo", safeReturnTo(flow.returnTo) ?? this.config.postLoginRedirect);
        return signInBusyPage(again.pathname + again.search, e.retryAfter, [clearFlow]);
      }
      // Otherwise almost always a server-to-server problem: a wrong client
      // secret, or a redirect_uri the client isn't registered for.
      return fail(`token exchange or userinfo failed: ${(e as Error).message}`);
    }

    let session: SessionData;
    try {
      // The nonce finally gets read. It has been minted, sent on the authorize
      // request, and sealed into this cookie since the BFF shipped, and nothing
      // ever compared it — so an `id_token` replayed from a different login of
      // the same user was indistinguishable from this one's.
      //
      // Hard-fails rather than warning, matching Proteles' reference Go web
      // app. A verification that can be skipped on failure is
      // one an attacker chooses to fail.
      const claims = await this.verifyIdTokenIfPresent(tokens.idToken, flow.nonce, tokens.accessToken, true);
      const info = await this.client.fetchUserInfo(tokens.accessToken);
      // The session's `sub` comes from userinfo, and only the ID token's is
      // signed. OIDC Core §5.3.2: the two MUST be the same, and a response
      // where they are not must not be used.
      if (claims && info.sub !== claims.sub) {
        throw new Error("the userinfo sub is not the ID token's sub");
      }
      session = {
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        idToken: tokens.idToken,
        accessExpiresAt: Date.now() + tokens.expiresIn * 1000,
        sub: info.sub,
        email: info.email,
        preferredUsername: info.preferredUsername,
        // From the verified token, never from an unverified read of it. Both
        // stay absent rather than defaulted when the token did not carry them:
        // an empty `amr` would assert that no methods were used, and a zero
        // `authTime` would claim the user authenticated in 1970.
        amr: claims?.amr,
        authTime: claims?.auth_time,
      };
    } catch (e) {
      // The ID token failed verification, or userinfo failed.
      return fail(`token exchange or userinfo failed: ${(e as Error).message}`);
    }

    const sessionCookie = await this.sessionCookie(session);
    return redirect(safeReturnTo(flow.returnTo) ?? this.config.postLoginRedirect, 303, [sessionCookie, clearFlow]);
  }

  /**
   * Signs the user out: revokes the refresh token and clears the session. Only
   * a POST from this app's own pages does that.
   *
   * This route used to act on any method, and a `SameSite=Lax` cookie still
   * goes with a top-level cross-site GET, so any page could sign a visitor out
   * — and revoke their refresh token upstream — with a link or an image. Fetch
   * Metadata alone closed most of that and left two gaps: a browser that sends
   * none, and a page on a sibling subdomain, which the browser marks
   * `same-site` and sends the cookie with. So a GET now renders a confirmation
   * form rather than acting, which keeps a bookmarked or linked sign-out URL
   * working, one click later; a POST is checked by {@link AuthApp.foreignPost};
   * and any other method is 405.
   *
   * A refused POST is answered 403 with nothing revoked and nothing cleared —
   * clearing the cookie would be the same forced sign-out, minus the revoke —
   * and reported through `onError` with the context `"logout"`.
   *
   * With `endSession` (the default), the browser then goes on to the server's
   * end-session endpoint rather than straight to `returnTo`, so the person is
   * signed out of Proteles too ({@link AuthApp.afterSignOut}).
   */
  private async logout(request: Request, url: URL): Promise<Response> {
    const returnTo = safeReturnTo(url.searchParams.get("returnTo")) ?? "/";
    const formAction = this.signOutFormAction();
    if (request.method === "GET" || request.method === "HEAD") {
      return signOutPage(`${this.config.basePath}/logout`, url.searchParams.has("returnTo") ? returnTo : undefined, formAction);
    }
    if (request.method !== "POST") {
      return new Response(null, { status: 405, headers: { allow: "GET, HEAD, POST" } });
    }
    const foreign = this.foreignPost(request);
    if (foreign) {
      this.reportError(`${foreign}, so the session was left alone`, "logout");
      return refusedSignOutPage(returnTo, formAction);
    }
    const raw = parseCookies(request.headers.get("cookie"))[this.cookieNames.session];
    let data: SessionData | undefined;
    if (raw) {
      try {
        data = await this.crypto.decrypt<SessionData>(raw);
      } catch {
        // An unreadable cookie names no token to revoke; it is cleared below.
      }
      if (data?.refreshToken) await this.revokeForSignOut(data.refreshToken);
    }
    return redirect(this.afterSignOut(returnTo, data?.idToken), 303, [this.clearSessionCookie()]);
  }

  /**
   * Where the browser goes once this app's session is gone: `returnTo` itself,
   * or — with `endSession`, the default — the server's end-session endpoint,
   * which ends the person's session at Proteles too and comes back to
   * `returnTo` as an absolute URL on this app's origin, when the app registered
   * it as a `post_logout_redirect_uri`.
   *
   * The ID token goes along as the hint whenever the session kept one: it names
   * both the app and the person, so the server can refuse a sign-out meant for
   * somebody else and name the app on its confirmation page. A session with
   * none (no `openid` scope, or an unreadable cookie) sends `client_id`, and
   * the person still reaches the server's own sign-out.
   *
   * A 303 rather than a page that moves on by itself: the htmx binding turns a
   * redirect into `HX-Redirect` for an `hx-post` sign-out, and a page would be
   * swapped into a fragment. The cost is `form-action`, which a browser
   * applies to the redirects after a form post — so this package's own
   * sign-out page allows the issuer's origin ({@link AuthApp.signOutFormAction}),
   * and an app whose own pages post the sign-out under a strict `form-action`
   * must list that origin too.
   */
  private afterSignOut(returnTo: string, idToken: string | undefined): string {
    if (!this.config.endSession) return returnTo;
    const ours = this.appOrigin();
    if (!ours) return returnTo;
    return this.client.endSessionUrl({
      idTokenHint: idToken,
      postLogoutRedirectUri: new URL(returnTo, ours).href,
    });
  }

  /** The `form-action` sources this package's sign-out pages send: the post
   *  goes to this origin, and with `endSession` its 303 to the issuer's. */
  private signOutFormAction(): string {
    if (!this.config.endSession) return "'self'";
    try {
      return `'self' ${new URL(this.client.getEndpoints().endSession).origin}`;
    } catch {
      return "'self'";
    }
  }

  /**
   * Why a POST did not come from this app's own pages, or `undefined` when
   * nothing says it did not. The same rule Proteles' reference web app
   * applies to every POST, with Fetch Metadata in front of it:
   *
   * - `Sec-Fetch-Site: cross-site` or `same-site`: another site, or a sibling
   *   subdomain, which `SameSite=Lax` does not keep out. A page cannot set it.
   * - An `Origin` that is not this app's, the origin of `redirectUri`. Every
   *   browser sends one on a cross-origin form POST.
   * - `Origin: null` without `Sec-Fetch-Site: same-origin`. A browser sends
   *   `null` for an opaque origin, such as a sandboxed frame, and also on the
   *   app's own form posts under `Referrer-Policy: no-referrer`, so the header
   *   that can tell the two apart decides.
   *
   * No `Origin` at all is allowed, as the reference app allows it. Every
   * browser sends one on a POST, so its absence is curl, a test, or a server
   * calling this one, not a browser being used against its owner.
   */
  private foreignPost(request: Request): string | undefined {
    const site = request.headers.get("sec-fetch-site");
    if (site === "cross-site" || site === "same-site") {
      return `the browser marked this sign-out Sec-Fetch-Site: ${site}`;
    }
    const origin = request.headers.get("origin");
    if (origin === null) return undefined;
    if (origin === "null") {
      return site === "same-origin" ? undefined : "this sign-out came from an opaque origin (Origin: null)";
    }
    const ours = this.appOrigin();
    if (ours === undefined) {
      return `redirectUri (${this.config.redirectUri}) is not an absolute URL, so this app's origin is unknown`;
    }
    return origin === ours ? undefined : `this sign-out came from ${origin}, and this app answers as ${ours}`;
  }

  /** This app's origin, as a browser writes it in `Origin`: `redirectUri`'s. */
  private appOrigin(): string | undefined {
    try {
      return new URL(this.config.redirectUri).origin;
    } catch {
      return undefined;
    }
  }

  /**
   * Revokes the refresh token being signed out — once more if the server
   * answered that it was only busy — and says so when it still did not happen.
   *
   * The session is cleared here whatever this finds: a user who asked to sign
   * out is signed out of this app. But a lost revocation leaves the refresh
   * family live at the authorization server until it expires, and it used to be
   * lost silently, because the core client drained any answer, `503` included.
   * A full password pool answers `503` at `/oauth/revoke` as it does
   * at the token endpoint, and that is a moment rather than a verdict, so one
   * retry after a short pause is worth the wait. A second failure is reported
   * through `onError`, not retried in a loop the user is waiting on.
   * `docs/mobile-SDKs.md` §10.4 holds the native SDKs to the same: clear
   * whether or not the revocation succeeded, and report the failure rather
   * than hide it.
   *
   * Only a busy *answer* that came back within {@link REVOKE_RETRY_WINDOW_MS}
   * is retried. The server's own `503` and `429` are immediate, and they are
   * what the retry is for. No answer is not retried — a refused connection
   * says nothing half a second will change, and a timeout has already spent
   * `timeoutMs` — and neither is a slow answer, such as a gateway's `504` after
   * its own upstream timeout. The redirect that clears the cookie is written
   * only when this returns: a retry after a timeout doubled sign-out to two
   * full `timeoutMs` and the pause, 20.5 s by default, past the request limit
   * of any host that sets one lower, and a response the host cuts off never
   * clears the cookie. With the window, the longest sign-out is the window,
   * the pause and one `timeoutMs`.
   */
  private async revokeForSignOut(refreshToken: string): Promise<void> {
    const started = Date.now();
    let result = await this.client.revoke(refreshToken);
    if (
      !result.ok &&
      result.error.retryable &&
      !result.error.unreachable &&
      Date.now() - started <= REVOKE_RETRY_WINDOW_MS
    ) {
      await new Promise((resolve) => setTimeout(resolve, REVOKE_RETRY_PAUSE_MS));
      result = await this.client.revoke(refreshToken);
    }
    if (!result.ok) {
      this.reportError(
        `the refresh token was not revoked at sign-out (${result.error.message}); the session cookie is cleared, ` +
          "but the refresh-token family stays live at the authorization server until it expires",
        "logout",
      );
    }
  }

  /**
   * Proves the session against the IdP and bounces back where the user was.
   *
   * This is how a context that cannot write cookies still gets a revalidated
   * session: middleware sends the request here, this route does the refresh and
   * attaches the rotated cookie, and the redirect returns the user to the page
   * they asked for. `isPublicPath` already exempts everything under `basePath`,
   * so it cannot loop through the guard that sent it.
   *
   * A refusal from the IdP falls through to the login redirect rather than an
   * error page: from the user's side a revoked session and an expired one are
   * the same event, and both are fixed by signing in.
   *
   * A busy IdP is neither, and gets a page that says try again, with the
   * cookie untouched. Not a redirect either way: back to `returnTo`, the
   * middleware would find the same spent session and bounce it straight here
   * again, and to the login it would read as a sign-out.
   */
  private async revalidate(request: Request, url: URL): Promise<Response> {
    const cookies: string[] = [];
    const returnTo = safeReturnTo(url.searchParams.get("returnTo")) ?? this.config.postLoginRedirect;
    let session: SessionData | null;
    try {
      session = await this.resolveSession(request, (c) => cookies.push(c.header));
    } catch (e) {
      if (e instanceof SessionUnavailableError) {
        return tryAgainPage(returnTo, `${this.config.basePath}/logout`, e.retryAfter, cookies);
      }
      throw e;
    }
    if (session) return redirect(returnTo, 303, cookies);

    const loginUrl = new URL(`${this.config.basePath}/login`, url.origin);
    loginUrl.searchParams.set("returnTo", returnTo);
    return redirect(loginUrl.pathname + loginUrl.search, 303, cookies);
  }

  private async me(request: Request): Promise<Response> {
    const loaded = await this.loadAndRefreshSession(request);
    const cookies = loaded.setCookie ? [loaded.setCookie] : [];
    if (loaded.busy) return busyJson(loaded.busy.retryAfter, cookies);
    if (!loaded.data) {
      return json({ authenticated: false }, 200, cookies);
    }
    return json({ authenticated: true, user: publicUser(loaded.data) }, 200, cookies);
  }

  // --- session helpers ---------------------------------------------------

  /**
   * Read-only session check for middleware / server components: returns the
   * session when the cookie decrypts and is still usable (access token valid,
   * or a refresh token is present so `/api/auth/me` can refresh it). Never
   * writes cookies. Ported from the "is there a session" half of Go's
   * `requireSession`.
   */
  async getSession(request: Request): Promise<SessionData | null> {
    const raw = parseCookies(request.headers.get("cookie"))[this.cookieNames.session];
    return raw ? this.decryptUsableSession(raw) : null;
  }

  /**
   * Decrypts a raw session token, returning it only if it is still usable.
   *
   * "Usable" means *there is a live access token*. It used to also accept the
   * mere presence of a refresh-token string, which is not evidence of anything:
   * the token was never presented to the IdP, so a sealed cookie kept naming its
   * user long after the account was revoked. Everything the IdP has since gained
   * — session revocation, factor resets — stopped at the relying party's door.
   *
   * The `REFRESH_SKEW_MS` boundary is the same one `loadAndRefreshSession` uses,
   * so a session cannot be "live" here and "needs refreshing" there.
   */
  async decryptUsableSession(raw: string): Promise<SessionData | null> {
    const state = await this.inspectRaw(raw);
    return state.kind === "fresh" ? state.data : null;
  }

  /**
   * What a presented cookie actually is. `getSession` collapses "no cookie" and
   * "cookie whose access token has expired" into the same `null`, and a guard
   * has to tell them apart: one means send the user to log in, the other means
   * revalidate — a round trip the user should never see.
   */
  async inspectSession(request: Request): Promise<SessionState> {
    const raw = parseCookies(request.headers.get("cookie"))[this.cookieNames.session];
    return raw ? this.inspectRaw(raw) : { kind: "none" };
  }

  private async inspectRaw(raw: string): Promise<SessionState> {
    let data: SessionData;
    try {
      data = await this.crypto.decrypt<SessionData>(raw);
    } catch {
      return { kind: "dead" };
    }
    // The absolute cap first: past it, nothing renews it.
    if (data.sessionExpiresAt !== undefined && Date.now() >= data.sessionExpiresAt) {
      return { kind: "dead" };
    }
    if (Date.now() + REFRESH_SKEW_MS < data.accessExpiresAt) return { kind: "fresh", data };
    return data.refreshToken ? { kind: "stale", data } : { kind: "dead" };
  }

  /**
   * Proves the session against the IdP when the access token is spent, and
   * clears it when the IdP refuses. The full port of Go's `requireSession`,
   * usable from anywhere that can attach a cookie to its response.
   *
   * `sink` is a required positional parameter and that is deliberate. The
   * alternative — returning `{ session, setCookie? }` — breaks callers in a way
   * whose obvious repair (`const { session } = await ...`) compiles and then
   * silently drops the rotated cookie. Refresh tokens here are single-use: the
   * presented one is revoked server-side on use, so losing the replacement does
   * not merely fail to help, it burns the family on next use and signs the user
   * out everywhere. A parameter cannot be forgotten, only deliberately ignored.
   *
   * If you have nowhere to put a cookie, do not call this — use `getSession`
   * and accept its access-token bound, or let `middleware()` bounce.
   *
   * Throws {@link SessionUnavailableError} when the refresh could not happen
   * *right now* — the authorization server was busy, rate-limiting, or out of
   * reach. The session is intact and the sink has not been called; answer with
   * "try again", not with a login redirect.
   */
  async resolveSession(request: Request, sink: CookieSink): Promise<SessionData | null> {
    const raw = parseCookies(request.headers.get("cookie"))[this.cookieNames.session];
    return this.resolveUsableSession(raw, sink);
  }

  /** `resolveSession` for runtimes that hand you a cookie jar, not a Request. */
  async resolveUsableSession(raw: string | undefined, sink: CookieSink): Promise<SessionData | null> {
    if (!raw) return null;
    const state = await this.inspectRaw(raw);
    if (state.kind === "fresh") return state.data;
    if (state.kind === "none") return null;
    if (state.kind === "dead") {
      sink(this.clearSessionCookieValue());
      return null;
    }

    const outcome = await this.refreshInto(state.data);
    if (outcome.kind === "busy") {
      if (outcome.successor) sink(await this.sessionCookieValue(outcome.successor));
      throw new SessionUnavailableError(outcome.retryAfter);
    }
    if (outcome.kind === "refused") {
      sink(this.clearSessionCookieValue());
      return null;
    }
    sink(await this.sessionCookieValue(outcome.data));
    return outcome.data;
  }

  /**
   * Exchanges the refresh token, and says which of three things happened.
   *
   * `refused` is what a revocation looks like from here: `invalid_grant`, or
   * any other answer that is a verdict on the request rather than on the
   * moment. It ends the session, as every failure used to.
   *
   * `busy` is the authorization server saying "not now": `503` (a full
   * password pool, whatever the body), `429`, another `5xx` or a
   * `408`, or no answer — `OAuthError.retryable`, which follows
   * `docs/mobile-SDKs.md` §10.9 item 4 in treating every `5xx` as temporary.
   * The session is kept and the next request retries. A `503` or `429` from
   * the server itself turned the request away before the grant was read, so
   * the refresh token is untouched. A lost answer, or a proxy's `5xx`, may have
   * come after the server rotated it. Keeping the session then defers the
   * sign-out to the next request, whose retry meets `invalid_grant`
   * (rotation spent it, and nothing can recover a spent token) — and a
   * retry more than 60 seconds after the rotation is what the server reads as
   * theft (`docs/mobile-SDKs.md` §2.3):
   * it burns the family and files a `refresh_token.reuse` warning in the
   * tenant's audit log, which clearing the session at once never did, because
   * it never presented the spent token again.
   *
   * Unlike §10.9 item 1, a still-live access token is not served in the
   * meantime: the refresh starts {@link REFRESH_SKEW_MS} before expiry, and
   * `/revalidate` handing back a session the middleware still reads as spent
   * would bounce the browser between the two.
   *
   * The refresh-minted ID token is classified the same way. One that fails
   * verification ends the session — a trust rule (signature, key, issuer,
   * audience), as §10.9 item 1 has it end a native one, and also, unlike item
   * 2, its `exp` or `iat`, or its absence when `openid` was asked for. One that
   * could not be checked, because the key set was out of reach (§10.9 item 4:
   * a key-set `5xx` is a network error), is busy — but the exchange went
   * through, so the refresh token the cookie holds is spent, and the session
   * to keep is `successor`: the old one with the rotated refresh token, its
   * access token still marked spent so that the next request refreshes again
   * and checks the ID token then. §10.9 item 5 keeps a native SDK's successor
   * for the same reason. Clearing the cookie here, as this did, dropped a live
   * successor and signed the user out over a cold key-set cache after a deploy
   * and one bad fetch.
   */
  private async refreshInto(data: SessionData): Promise<RefreshOutcome> {
    if (!data.refreshToken) return { kind: "refused" };
    let tok: TokenResponse;
    try {
      tok = await this.refreshOnce(data.refreshToken);
    } catch (e) {
      if (e instanceof OAuthError && e.retryable) {
        this.reportError(`refresh deferred, session kept for the next request to retry: ${e.message}`, "refresh");
        return { kind: "busy", retryAfter: e.retryAfter };
      }
      return { kind: "refused" };
    }
    const successor: SessionData = { ...data, refreshToken: tok.refreshToken ?? data.refreshToken };
    try {
      data.accessToken = tok.accessToken;
      if (tok.refreshToken) data.refreshToken = tok.refreshToken; // rotation: keep the newest
      // `null`, not the login's nonce: the refresh grant mints an `id_token`
      // with no nonce, because there is no authorize request to have carried
      // one. Passing the old nonce here would fail every refresh; omitting the
      // argument would let a *callback* skip the check by accident, which is
      // why `nonce` has no default.
      //
      // Called whether or not one came back. It used to be called only
      // inside `if (tok.idToken)`, where `required` never fired, and a refresh answer
      // with no ID token kept the session, installed the new tokens, and
      // compared no `sub` — the opposite of what the comment above says.
      const claims = await this.verifyIdTokenIfPresent(tok.idToken, null, tok.accessToken, true);
      // OIDC Core §12.2: a refreshed ID token names the same person as the
      // session's. One that names somebody else is not this session's, and
      // keeping it would hand the session to them.
      if (claims && claims.sub !== data.sub) {
        this.reportError("the ID token from a refresh names a different sub than the session; the session was ended", "refresh");
        return { kind: "refused" };
      }
      if (tok.idToken) {
        data.idToken = tok.idToken;
        // Re-read from the fresh token rather than left alone, so the session
        // cannot drift from the token it holds. The values do not move: the
        // server preserves both across a refresh rather than restarting the
        // clock, which is what makes `authTime` usable for a step-up decision
        // months into a session.
        data.amr = claims?.amr;
        data.authTime = claims?.auth_time;
      }
      data.accessExpiresAt = Date.now() + tok.expiresIn * 1000;
      return { kind: "refreshed", data };
    } catch (e) {
      if (e instanceof OAuthError && e.retryable) {
        this.reportError(
          `refresh deferred, the new ID token could not be checked (${e.message}); the rotated refresh token is kept`,
          "refresh",
        );
        return { kind: "busy", retryAfter: e.retryAfter, successor };
      }
      return { kind: "refused" };
    }
  }

  /**
   * One token exchange per refresh token, however many requests present it —
   * the ones that arrive while it is in flight wait for it, and the ones that
   * arrive within {@link REFRESH_SHARE_MS} after, still carrying the old
   * cookie, get the same answer. A failure is shared only with the requests
   * already waiting on it: the next one may be a retry that works.
   */
  private refreshOnce(refreshToken: string): Promise<TokenResponse> {
    const now = Date.now();
    for (const [token, entry] of this.refreshes) {
      if (now - entry.at > REFRESH_SHARE_MS) this.refreshes.delete(token);
    }
    const shared = this.refreshes.get(refreshToken);
    if (shared) return shared.result;
    const result = this.client.refresh(refreshToken);
    this.refreshes.set(refreshToken, { at: now, result });
    result.catch(() => this.refreshes.delete(refreshToken));
    return result;
  }

  /**
   * Loads the session and, if the access token is at/near expiry, transparently
   * refreshes it (rotation-aware), returning a `Set-Cookie` with the rotated
   * tokens. The full port of Go's `requireSession`.
   */
  private async loadAndRefreshSession(request: Request): Promise<LoadedSession> {
    const raw = parseCookies(request.headers.get("cookie"))[this.cookieNames.session];
    if (!raw) return { data: null };

    let data: SessionData;
    try {
      data = await this.crypto.decrypt<SessionData>(raw);
    } catch {
      return { data: null, setCookie: this.clearSessionCookie() };
    }
    // The absolute cap, as `inspectRaw` applies it. This was the one path
    // that skipped it: `/me` refreshed and resealed a cookie past its cap, so
    // a stolen one could be kept alive by calling it in a loop.
    if (data.sessionExpiresAt !== undefined && Date.now() >= data.sessionExpiresAt) {
      return { data: null, setCookie: this.clearSessionCookie() };
    }

    if (Date.now() + REFRESH_SKEW_MS < data.accessExpiresAt) {
      return { data };
    }
    if (!data.refreshToken) {
      return { data: null, setCookie: this.clearSessionCookie() };
    }

    // The same exchange `resolveUsableSession` makes. This was a second copy
    // of it, which is how a failure policy gets changed in one and not the
    // other.
    const outcome = await this.refreshInto(data);
    if (outcome.kind === "busy") {
      const setCookie = outcome.successor ? await this.sessionCookie(outcome.successor) : undefined;
      return { data: null, setCookie, busy: { retryAfter: outcome.retryAfter } };
    }
    if (outcome.kind === "refused") return { data: null, setCookie: this.clearSessionCookie() };
    return { data: outcome.data, setCookie: await this.sessionCookie(outcome.data) };
  }

  // --- middleware --------------------------------------------------------

  /**
   * Builds a route-protection middleware. Requests to the auth routes and
   * `publicPaths` pass through; anything else without a session is redirected
   * to `/api/auth/login?returnTo=…`. Returns `undefined` to let the request
   * continue (Next treats that as "proceed").
   */
  middleware(options?: {
    publicPaths?: (string | RegExp)[];
    /** Bounce a spent-but-refreshable session through `/revalidate`. Default true. */
    revalidate?: boolean;
  }): (request: Request) => Promise<Response | undefined> {
    const publicPaths = options?.publicPaths ?? [];
    const revalidate = options?.revalidate ?? true;
    return async (request: Request) => {
      const url = new URL(request.url);
      if (this.isPublicPath(url.pathname, publicPaths)) return undefined;
      const state = await this.inspectSession(request);
      if (state.kind === "fresh") return undefined;

      // Provable but unproven. Middleware cannot attach the rotated cookie —
      // a bare `Response` has no way to say "continue, with headers" — so send
      // the request somewhere that can, and come straight back. Without this the
      // user would be pushed to log in every time an access token expired, even
      // though the IdP would have renewed it silently.
      // Both of these send a **relative** `Location`, as `revalidate` above
      // already does — and that is a security property, not a style choice.
      //
      // `url.origin` is only as trustworthy as whatever produced the request
      // URL. On the Node path (`toWebRequest({ node: { req } })` — h3, Nuxt,
      // SolidStart, and any `node:http` server) it is built from
      // `X-Forwarded-Host`, which nothing here can verify. Putting that origin
      // into an absolute `Location` makes a request header decide where a
      // browser goes next: poison the header, and the app redirects to the
      // attacker's host. Behind a cache keyed on URL but not on that header, one
      // request poisons the redirect served to everyone else.
      //
      // A relative `Location` is resolved by the browser against the address it
      // actually reached, which is the origin we meant all along and the one
      // value in this exchange no header can move. RFC 9110 §10.2.2 has allowed
      // relative here since 7231 relaxed the old absolute-URI rule.
      if (state.kind === "stale" && revalidate) {
        const target = new URL(`${this.config.basePath}/revalidate`, url.origin);
        target.searchParams.set("returnTo", url.pathname + url.search);
        // Not `Response.redirect`, which requires an absolute URL and is the
        // reason this line carried one.
        return redirect(target.pathname + target.search, 303);
      }

      const loginUrl = new URL(`${this.config.basePath}/login`, url.origin);
      loginUrl.searchParams.set("returnTo", url.pathname + url.search);
      return redirect(loginUrl.pathname + loginUrl.search, 307);
    };
  }

  private isPublicPath(pathname: string, extra: (string | RegExp)[]): boolean {
    if (pathname.startsWith(`${this.config.basePath}/`)) return true;
    if (pathname === "/favicon.ico" || pathname.startsWith("/_next/")) return true;
    return extra.some((p) => matchesPath(pathname, p));
  }

  /** Reports a server-side failure reason through the configured hook. */
  private reportError(reason: string, context: string): void {
    if (this.config.onError === false) return;
    try {
      this.config.onError(reason, context);
    } catch {
      // A broken logger must never break the auth flow.
    }
  }

  // --- cookie plumbing ---------------------------------------------------

  private cookieOptions(maxAge: number) {
    return { maxAge, secure: this.config.cookieSecure, httpOnly: true, sameSite: "lax" as const, path: "/" };
  }

  private async sessionCookie(data: SessionData): Promise<string> {
    return (await this.sessionCookieValue(data)).header;
  }

  private clearSessionCookie(): string {
    return this.clearSessionCookieValue().header;
  }

  /**
   * The session cookie in both shapes at once, so a jar-based runtime does not
   * have to re-derive the flags by parsing the header back apart.
   *
   * Stamps `sessionExpiresAt` on first seal and preserves it thereafter: the
   * cap must survive every refresh, or renewing the session would push it out
   * forever and the bound would mean nothing.
   */
  private async sessionCookieValue(data: SessionData): Promise<SessionCookie> {
    data.sessionExpiresAt ??= Date.now() + SESSION_TTL_SECONDS * 1000;
    const value = await this.crypto.encrypt(data);
    const options = this.cookieOptions(SESSION_TTL_SECONDS);
    return { name: this.cookieNames.session, value, options, header: serializeCookie(this.cookieNames.session, value, options) };
  }

  private clearSessionCookieValue(): SessionCookie {
    const options = this.cookieOptions(0);
    return { name: this.cookieNames.session, value: "", options, header: serializeCookie(this.cookieNames.session, "", options) };
  }

  private errorRedirect(): string {
    const target = this.config.loginErrorRedirect;
    const sep = target.includes("?") ? "&" : "?";
    return `${target}${sep}proteles_error=login_failed`;
  }
}

// --- module-level helpers ------------------------------------------------

function publicUser(data: SessionData): PublicUser {
  return {
    sub: data.sub,
    email: data.email,
    preferredUsername: data.preferredUsername,
    amr: data.amr,
    authTime: data.authTime,
  };
}

/**
 * Whether `pathname` is covered by a `publicPaths` entry.
 *
 * A string entry matches exactly, or as a path-segment prefix — `"/blog"` covers
 * `/blog` and `/blog/post`, but NOT `/blogging`. `"/"` is exact-only: a naive
 * `startsWith` would make it match every route and silently leave the whole app
 * unprotected, which is the opposite of what listing one public page means.
 * A RegExp entry is tested as-is.
 */
export function matchesPath(pathname: string, pattern: string | RegExp): boolean {
  if (typeof pattern !== "string") return pattern.test(pathname);
  if (pathname === pattern) return true;
  if (pattern === "/") return false;
  const prefix = pattern.endsWith("/") ? pattern : `${pattern}/`;
  return pathname.startsWith(prefix);
}

/** Only same-origin, absolute-path returns are allowed — never a scheme, host,
 *  or protocol-relative `//evil.com`, which would be an open redirect.
 *
 *  Parsed, not prefix-matched. Browsers strip tab, CR and LF from a URL
 *  wherever they appear, so `/\t/evil.example` passed every prefix check here
 *  and arrived as `//evil.example`. A control character, DEL or a backslash is
 *  refused outright; what is left must resolve to the origin it started from,
 *  and is returned as the parser normalised it (a space becomes `%20`).
 *
 *  The normalised result is checked as well as the input, because it is the
 *  result that goes out. Dot-segment removal can leave a path that begins with
 *  two slashes — `/.//evil.example`, `/%2e//evil.example` and
 *  `/a/..//evil.example` all come out as `//evil.example` — which stayed on the
 *  origin while it was parsed against a base and is another host once a
 *  browser reads it as a `Location` or an `href`. */
export function safeReturnTo(path: string | null | undefined): string | null {
  if (!path) return null;
  if (!path.startsWith("/")) return null;
  if (/[\u0000-\u001f\u007f\\]/.test(path)) return null;
  const base = "http://return-to.invalid";
  let parsed: URL;
  try {
    parsed = new URL(path, base);
  } catch {
    return null;
  }
  if (parsed.origin !== base) return null;
  const normalised = parsed.pathname + parsed.search + parsed.hash;
  if (normalised.startsWith("//")) return null;
  return normalised;
}

function redirect(location: string, status: number, setCookies: string[] = []): Response {
  const headers = new Headers({ location });
  for (const c of setCookies) headers.append("set-cookie", c);
  return new Response(null, { status, headers });
}

/** Never stored: `/me` names the person the cookie belongs to, so a shared
 *  cache that kept an answer would hand it to the next visitor, and a browser
 *  that kept one would show the user as signed in after they signed out. */
function json(body: unknown, status = 200, setCookies: string[] = []): Response {
  const headers = new Headers({ "content-type": "application/json", "cache-control": "no-store" });
  for (const c of setCookies) headers.append("set-cookie", c);
  return new Response(JSON.stringify(body), { status, headers });
}

/**
 * `/me`'s answer when the session needs a refresh the authorization server
 * cannot give right now: `503`, and the server's `Retry-After` when it sent
 * one. Usually no `Set-Cookie`, because the cookie the browser holds is still
 * the session; `setCookies` is the rotated one when the exchange went through
 * and only the ID token could not be checked. Not `{ authenticated: false }`,
 * which says the user is signed out, and they are not.
 */
function busyJson(retryAfter: number | undefined, setCookies: string[] = []): Response {
  const headers = new Headers({ "content-type": "application/json", "cache-control": "no-store" });
  if (retryAfter !== undefined) headers.set("retry-after", String(retryAfter));
  for (const c of setCookies) headers.append("set-cookie", c);
  const body = { error: "temporarily_unavailable", message: "The sign-in service is busy. Try again shortly." };
  return new Response(JSON.stringify(body), { status: 503, headers });
}

/**
 * The page a browser gets from `/revalidate` when its session needs a refresh
 * the authorization server cannot give right now: `503`, `Retry-After` when the
 * server named a wait, and a link back to where the user was, which is the
 * retry. Not an automatic reload: every open tab polling a server that is
 * turning work away for being busy is the load it can least afford.
 *
 * And a way out. Every `5xx` counts as busy, so a refresh the server fails the
 * same way every time would otherwise leave the user on this page until the
 * session's absolute cap, with no control that ends it.
 */
function tryAgainPage(
  returnTo: string,
  logoutPath: string,
  retryAfter: number | undefined,
  setCookies: string[] = [],
): Response {
  const headers = new Headers({ "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
  if (retryAfter !== undefined) headers.set("retry-after", String(retryAfter));
  for (const c of setCookies) headers.append("set-cookie", c);
  const body = `<!doctype html>
<meta charset="utf-8">
<title>Try again in a moment</title>
<h1>Try again in a moment</h1>
<p>The sign-in service is busy. You are still signed in.</p>
<p><a href="${escapeHtml(returnTo)}">Try again</a></p>
<form method="post" action="${escapeHtml(logoutPath)}"><p>Or <button type="submit">sign out</button>.</p></form>
`;
  return new Response(body, { status: 503, headers });
}

/**
 * The page a browser gets from the callback when the code exchange met a busy
 * authorization server — a `503`, a `429`, another `5xx` or a `408`, or no
 * answer at all: `503`, `Retry-After` when the server named a wait, and a link
 * that starts sign-in again, back to where the user was going. It used to end
 * in `login_failed`, which reads as a wrong password or a broken app, when all
 * the user has to do is sign in again in a moment.
 *
 * A fresh flow, never this code again. This response clears the flow cookie,
 * as every callback does, and the code may already be spent: an answer that
 * was lost, or a proxy's `502`, can follow a redemption that went through, and
 * the server reads a code presented twice as a replay — it refuses it, audits
 * it, and revokes what the first presentation minted.
 */
function signInBusyPage(loginPath: string, retryAfter: number | undefined, setCookies: string[]): Response {
  const headers = new Headers({ "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
  if (retryAfter !== undefined) headers.set("retry-after", String(retryAfter));
  for (const c of setCookies) headers.append("set-cookie", c);
  const body = `<!doctype html>
<meta charset="utf-8">
<title>Sign in again in a moment</title>
<h1>Sign in again in a moment</h1>
<p>The sign-in service was busy, so you are not signed in yet.</p>
<p><a href="${escapeHtml(loginPath)}">Sign in again</a></p>
`;
  return new Response(body, { status: 503, headers });
}

/** `returnTo` has been through `safeReturnTo`, whose URL parser leaves `&`
 *  alone everywhere and `'` in the path and fragment; an attribute value
 *  needs both escaped. */
/**
 * Headers for the two sign-out pages. The confirmation is one button that
 * revokes the user's refresh tokens, so no other page may frame it and dress
 * the button up as something else: `frame-ancestors`, and `X-Frame-Options`
 * for browsers that predate it. `form-action 'self'` covers the post and the
 * `303` that follows it, since `returnTo` is always a path on this origin.
 */
function signOutPageHeaders(formAction: string): Headers {
  return new Headers({
    "content-type": "text/html; charset=utf-8",
    "cache-control": "no-store",
    "content-security-policy": `default-src 'none'; form-action ${formAction}; frame-ancestors 'none'; base-uri 'none'`,
    "x-frame-options": "DENY",
  });
}

/**
 * What a GET to the sign-out route gets: a form that signs out, posting back
 * to the same route with the same `returnTo`, and a way back.
 */
function signOutPage(logoutPath: string, returnTo: string | undefined, formAction: string): Response {
  const action = returnTo === undefined ? logoutPath : `${logoutPath}?returnTo=${encodeURIComponent(returnTo)}`;
  const body = `<!doctype html>
<meta charset="utf-8">
<title>Sign out</title>
<h1>Sign out?</h1>
<form method="post" action="${escapeHtml(action)}"><button type="submit">Sign out</button></form>
<p><a href="${escapeHtml(returnTo ?? "/")}">Cancel</a></p>
`;
  return new Response(body, { status: 200, headers: signOutPageHeaders(formAction) });
}

/**
 * What a sign-out POST from somewhere else gets. No form: if the cause is a
 * misconfigured `redirectUri` rather than another site, a form here would post
 * from the same origin and be refused again. The reason is in `onError`.
 */
function refusedSignOutPage(returnTo: string, formAction: string): Response {
  const body = `<!doctype html>
<meta charset="utf-8">
<title>Not signed out</title>
<h1>You are still signed in</h1>
<p>This sign-out request did not come from this app, so it was ignored. To sign out, use the app's own sign-out button.</p>
<p><a href="${escapeHtml(returnTo)}">Continue</a></p>
`;
  return new Response(body, { status: 403, headers: signOutPageHeaders(formAction) });
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}
