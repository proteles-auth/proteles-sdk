//! `@proteles/bff` — the framework-agnostic Backend-for-Frontend core.
//!
//! Access and refresh tokens live only inside an AES-256-GCM encrypted,
//! httpOnly cookie set by the app's own server; the browser never receives a
//! token. Everything here operates on Web `Request`/`Response`, so the same
//! `AuthApp` works as a Next.js route handler, a SvelteKit endpoint, Edge
//! middleware, or a plain fetch handler.
//!
//! Most apps should use their framework's package instead — `@proteles/next`
//! or `@proteles/svelte` — which wrap this with framework-shaped helpers.

export { AuthApp, SessionUnavailableError, cookieNames, matchesPath, safeReturnTo } from "./handler.js";
export type { CookieNames } from "./handler.js";
export { SessionCrypto } from "./session.js";
export { cookieSecureFromEnv, resolveConfig } from "./config.js";
export { parseCookies, serializeCookie } from "./cookies.js";
export { contextOf, readSetCookies, sendNodeResponse, toWebRequest } from "./request.js";
export type { NodeRequestLike, NodeResponseLike, RequestSource } from "./request.js";
export type { CookieOptions } from "./cookies.js";
export type {
  FlowState,
  ProtelesConfig,
  ProtelesConfigInput,
  PublicUser,
  SessionData,
} from "./types.js";
