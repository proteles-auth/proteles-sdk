//! The framework-agnostic OAuth2/OIDC client — a TypeScript port of
//! Proteles' reference Go client, generalized for both confidential (BFF) and
//! public (PKCE-only) clients. It builds authorize URLs, exchanges codes,
//! refreshes with rotation, revokes, and reads userinfo. It holds no session
//! state: the caller persists `state`/`codeVerifier`/`nonce` between the
//! authorize step and the callback (that's what `@proteles/next` does with an
//! encrypted cookie).

import { base64 } from "./crypto.js";
import { OAuthError, parseRetryAfter } from "./errors.js";
import { codeChallengeS256, generateCodeVerifier, randomToken } from "./pkce.js";
import type {
  AuthorizationRequest,
  AuthorizationUrlOptions,
  EndSessionOptions,
  Endpoints,
  FetchLike,
  OAuthClientConfig,
  RevocationResult,
  TokenResponse,
  UserInfo,
} from "./types.js";

/** Also the key-set fetch's default, in `idtoken.ts`. */
export const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_SCOPES = "openid profile email";

/** Derives the server's conventional endpoints from an issuer, applying any
 *  explicit overrides. Exported so the BFF can reuse it. */
export function resolveEndpoints(issuer: string, override?: Partial<Endpoints>): Endpoints {
  const base = issuer.replace(/\/+$/, "");
  return {
    authorization: override?.authorization ?? `${base}/oauth/authorize`,
    token: override?.token ?? `${base}/oauth/token`,
    userinfo: override?.userinfo ?? `${base}/oauth/userinfo`,
    revocation: override?.revocation ?? `${base}/oauth/revoke`,
    jwks: override?.jwks ?? `${base}/.well-known/jwks.json`,
    endSession: override?.endSession ?? `${base}/oauth/logout`,
  };
}

export class OAuthClient {
  private readonly config: OAuthClientConfig;
  private readonly endpoints: Endpoints;
  private readonly fetchFn: FetchLike;
  private readonly scope: string;
  private readonly timeoutMs: number;

  constructor(config: OAuthClientConfig) {
    if (!config.issuer) throw new OAuthError("issuer is required");
    // Refused here, at start-up, rather than at the first sign-in. The server's
    // `iss` is always `scheme://host`, never with a trailing slash, and ID
    // tokens are compared to this value byte for byte (M2), so a configured
    // slash would fail every sign-in with an error that names the token.
    if (config.issuer.endsWith("/")) {
      throw new OAuthError(
        `issuer ${JSON.stringify(config.issuer)} ends with "/"; configure it exactly as the server's discovery document spells it, with no trailing slash`,
      );
    }
    if (!config.clientId) throw new OAuthError("clientId is required");
    if (!config.redirectUri) throw new OAuthError("redirectUri is required");

    const fetchFn = config.fetch ?? (globalThis.fetch as FetchLike | undefined);
    if (!fetchFn) {
      throw new OAuthError("no fetch implementation available; pass config.fetch");
    }

    this.config = config;
    this.fetchFn = fetchFn;
    this.scope = normalizeScopes(config.scopes) ?? DEFAULT_SCOPES;
    this.timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.endpoints = resolveEndpoints(config.issuer, config.endpoints);
  }

  /** The resolved endpoints (a copy). */
  getEndpoints(): Endpoints {
    return { ...this.endpoints };
  }

  /**
   * Generates a fresh `state`/`code_verifier`/`nonce` triple and returns the
   * URL to redirect the browser to plus the flow secrets to persist until the
   * callback. Mirrors `buildAuthorizationURL` in the Go reference.
   */
  async createAuthorizationUrl(options?: AuthorizationUrlOptions): Promise<AuthorizationRequest> {
    const state = await randomToken(32);
    const codeVerifier = await generateCodeVerifier(32);
    const nonce = await randomToken(16);
    const challenge = await codeChallengeS256(codeVerifier);
    const scope = normalizeScopes(options?.scopes) ?? this.scope;

    const url = new URL(this.endpoints.authorization);
    const p = url.searchParams;
    p.set("response_type", "code");
    p.set("client_id", this.config.clientId);
    p.set("redirect_uri", this.config.redirectUri);
    p.set("scope", scope);
    p.set("state", state);
    p.set("nonce", nonce);
    p.set("code_challenge", challenge);
    p.set("code_challenge_method", "S256");
    if (options?.prompt) p.set("prompt", options.prompt);
    // `!= null`, not truthiness: `max_age=0` is a legitimate request — "make
    // them authenticate now" — and a falsy check would silently drop exactly
    // the value a caller reaches for when they mean it most.
    if (options?.maxAge != null) p.set("max_age", String(Math.floor(options.maxAge)));
    if (options?.loginHint) p.set("login_hint", options.loginHint);
    if (options?.connection) p.set("connection", options.connection);

    return { url: url.toString(), state, codeVerifier, nonce };
  }

  /**
   * The URL that ends the person's session at the authorization server
   * (OpenID Connect RP-Initiated Logout 1.0), for a browser to be sent to. The
   * server asks the person to confirm, ends the session, tells the apps that
   * registered for back-channel logout, and returns the browser to
   * `postLogoutRedirectUri` when that is registered for this app.
   */
  endSessionUrl(options?: EndSessionOptions): string {
    const url = new URL(this.endpoints.endSession);
    const p = url.searchParams;
    // The hint names the app on its own (its `aud`); `client_id` beside it
    // must then agree with it, so it is sent only when there is no hint.
    if (options?.idTokenHint) p.set("id_token_hint", options.idTokenHint);
    else p.set("client_id", this.config.clientId);
    if (options?.postLogoutRedirectUri) p.set("post_logout_redirect_uri", options.postLogoutRedirectUri);
    if (options?.state) p.set("state", options.state);
    return url.toString();
  }

  /** Exchanges an authorization code (with its PKCE verifier) for tokens. */
  async exchangeCode(params: { code: string; codeVerifier: string; redirectUri?: string }): Promise<TokenResponse> {
    const form = new URLSearchParams();
    form.set("grant_type", "authorization_code");
    form.set("code", params.code);
    form.set("redirect_uri", params.redirectUri ?? this.config.redirectUri);
    form.set("code_verifier", params.codeVerifier);
    return this.tokenRequest(form);
  }

  /** Exchanges a refresh token for a fresh access token (and, with rotation
   *  enabled server-side, a new refresh token). */
  async refresh(refreshToken: string): Promise<TokenResponse> {
    const form = new URLSearchParams();
    form.set("grant_type", "refresh_token");
    form.set("refresh_token", refreshToken);
    return this.tokenRequest(form);
  }

  /**
   * Token revocation (RFC 7009). Never throws — a caller signing somebody out
   * clears its local session whatever happens here, and must be able to — but
   * says what happened rather than swallowing it.
   *
   * It used to resolve `void` whatever the answer, and "best effort" became
   * "silently skipped": a `503` from a busy server left a thirty-day refresh
   * family alive with nobody told. `ok` is true only for a `2xx`, which says
   * the server accepted the request — RFC 7009 §2.2 answers `200` for a token
   * it does not know, too, so not that something was found. Otherwise `error`
   * carries the status, the OAuth `error` code, and whether the same call is
   * worth making again (`error.retryable`).
   */
  async revoke(token: string): Promise<RevocationResult> {
    const form = new URLSearchParams();
    form.set("token", token);
    const headers = this.tokenEndpointHeaders(form);
    let res: Response;
    let text: string;
    try {
      ({ res, text } = await this.withTimeout((signal) =>
        this.fetchFn(this.endpoints.revocation, { method: "POST", headers, body: form.toString(), signal }),
      ));
    } catch (e) {
      return {
        ok: false,
        error: new OAuthError(`contacting authorization server failed: ${(e as Error).message}`, undefined, undefined, {
          unreachable: true,
        }),
      };
    }
    if (res.ok) return { ok: true };
    return { ok: false, error: errorFromResponse(res, text) };
  }

  /** Fetches the OIDC userinfo claims for an access token. */
  async fetchUserInfo(accessToken: string): Promise<UserInfo> {
    const { res, text } = await this.withTimeout((signal) =>
      this.fetchFn(this.endpoints.userinfo, {
        headers: { authorization: `Bearer ${accessToken}` },
        signal,
      }),
    );
    if (!res.ok) {
      throw new OAuthError(`userinfo request failed with HTTP ${res.status}`, undefined, res.status);
    }
    const data = JSON.parse(text) as Record<string, unknown>;
    const sub = typeof data["sub"] === "string" ? (data["sub"] as string) : "";
    return {
      ...data,
      sub,
      email: typeof data["email"] === "string" ? (data["email"] as string) : undefined,
      preferredUsername:
        typeof data["preferred_username"] === "string" ? (data["preferred_username"] as string) : undefined,
    };
  }

  // --- internals ---------------------------------------------------------

  private tokenEndpointHeaders(form: URLSearchParams): Record<string, string> {
    const headers: Record<string, string> = { "content-type": "application/x-www-form-urlencoded" };
    if (this.config.clientSecret) {
      // Confidential client: HTTP Basic (client_secret_basic).
      //
      // RFC 6749 §2.3.1 encodes each half with the
      // application/x-www-form-urlencoded algorithm before base64. For the
      // base64url ids and secrets this server issues that is the identity, but
      // a credential containing `+`, `%`, a space or `:` is only transmitted
      // correctly if it is encoded — and `:` in particular would otherwise be
      // read as the separator and split the credential in the wrong place.
      //
      // URLSearchParams applies exactly that algorithm; encodeURIComponent
      // only approximates it (it leaves `!*'()` alone and encodes a space as
      // %20 rather than +), so it is deliberately not used here.
      const enc = (v: string) => new URLSearchParams({ v }).toString().slice(2);
      headers.authorization = `Basic ${base64(`${enc(this.config.clientId)}:${enc(this.config.clientSecret)}`)}`;
    } else {
      // Public client: identify in the body (there is no secret to send).
      form.set("client_id", this.config.clientId);
    }
    return headers;
  }

  private async tokenRequest(form: URLSearchParams): Promise<TokenResponse> {
    const headers = this.tokenEndpointHeaders(form);
    let res: Response;
    let text: string;
    try {
      ({ res, text } = await this.withTimeout((signal) =>
        this.fetchFn(this.endpoints.token, { method: "POST", headers, body: form.toString(), signal }),
      ));
    } catch (e) {
      // No answer at all, which is not the same as a refusal: the caller may
      // be holding a perfectly good grant. `unreachable` is how it can tell.
      throw new OAuthError(`contacting authorization server failed: ${(e as Error).message}`, undefined, undefined, {
        unreachable: true,
      });
    }

    if (!res.ok) throw errorFromResponse(res, text);

    const body = JSON.parse(text) as Record<string, unknown>;
    return {
      accessToken: String(body["access_token"] ?? ""),
      tokenType: String(body["token_type"] ?? "Bearer"),
      expiresIn: Number(body["expires_in"] ?? 0),
      refreshToken: typeof body["refresh_token"] === "string" ? (body["refresh_token"] as string) : undefined,
      idToken: typeof body["id_token"] === "string" ? (body["id_token"] as string) : undefined,
      scope: typeof body["scope"] === "string" ? (body["scope"] as string) : undefined,
    };
  }

  /**
   * One request and its whole answer, under one deadline. The timer used to be cleared as soon as `fetch`
   * resolved, which is on the headers, and the body was read after with no
   * deadline: a server, or anything on the path to it, that sent headers and
   * then stalled the body held the caller for as long as it liked. The body is
   * read here, as text, with the timer still armed, so the abort ends a stalled
   * body as it ends a stalled connection — and the caller's "no answer" path
   * takes both. Parsing is left to the caller, so a malformed body is still a
   * parse error rather than "unreachable".
   */
  private async withTimeout(fn: (signal: AbortSignal) => Promise<Response>): Promise<{ res: Response; text: string }> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const res = await fn(controller.signal);
      return { res, text: await res.text() };
    } finally {
      clearTimeout(timer);
    }
  }
}

/**
 * The `OAuthError` for a non-`2xx` answer from the token or revocation
 * endpoint: its OAuth `error` code when the body is one, its status, and the
 * `Retry-After` it carried, if any.
 */
function errorFromResponse(res: Response, text: string): OAuthError {
  let code: string | undefined;
  try {
    const body = JSON.parse(text) as { error?: unknown };
    if (typeof body?.error === "string") code = body.error;
  } catch {
    // non-JSON error body — a proxy's HTML 503 is one
  }
  return new OAuthError(
    code ? `authorization server rejected the request: ${code}` : `authorization server returned HTTP ${res.status}`,
    code,
    res.status,
    { retryAfter: parseRetryAfter(res.headers.get("retry-after")) },
  );
}

function normalizeScopes(scopes: string | string[] | undefined): string | undefined {
  if (scopes === undefined) return undefined;
  return Array.isArray(scopes) ? scopes.join(" ") : scopes;
}
