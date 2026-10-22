//! `@proteles/js` — framework-agnostic OAuth2/OIDC client core.
//!
//! This is the substrate the framework SDKs build on: `@proteles/next` wraps it
//! in a Backend-for-Frontend (encrypted httpOnly cookies, route handlers), and
//! `@proteles/react` provides the drop-in components. Use this package directly
//! only when integrating a runtime we don't yet have a dedicated SDK for.

export { OAuthClient, resolveEndpoints } from "./client.js";
export { MAX_RETRY_AFTER_SECONDS, OAuthError, parseRetryAfter } from "./errors.js";
export { BACKCHANNEL_LOGOUT_EVENT, JwksCache, verifyIdToken, verifyLogoutToken } from "./idtoken.js";
export { codeChallengeS256, generateCodeVerifier, randomToken, timingSafeEqual } from "./pkce.js";
export type { IdTokenClaims, LogoutTokenClaims, VerifyIdTokenOptions, VerifyLogoutTokenOptions } from "./idtoken.js";
export type {
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
