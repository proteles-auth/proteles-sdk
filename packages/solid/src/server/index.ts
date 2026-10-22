//! `@proteles/solid/server` — SolidStart bindings for the Proteles
//! Backend-for-Frontend.
//!
//! Access and refresh tokens live only in an encrypted, httpOnly cookie set by
//! your own server; the browser never receives a token. Wire it up with two
//! files:
//!
//! ```ts
//! // src/routes/api/auth/[...proteles].ts
//! import { protelesAuthHandler } from "@proteles/solid/server";
//! export const GET = protelesAuthHandler;
//! export const POST = protelesAuthHandler;
//! ```
//! ```ts
//! // src/middleware.ts  (registered via `middleware` in app.config.ts)
//! import { createMiddleware } from "@solidjs/start/middleware";
//! import { attachUser, guardRequest } from "@proteles/solid/server";
//!
//! export default createMiddleware({
//!   onRequest: [
//!     async (event) => {
//!       await attachUser(event);
//!       return guardRequest(event, { publicPaths: ["/"] });
//!     },
//!   ],
//! });
//! ```
//!
//! SolidStart runs on Nitro/h3, so handlers receive either a `FetchEvent`
//! (which carries a Web `Request`) or an h3 event. The shared adapter in
//! `@proteles/bff` normalizes both, and the SolidStart types are described
//! structurally so this package builds without `@solidjs/start` installed.

import { AuthApp, contextOf, toWebRequest } from "@proteles/bff";
import type { ProtelesConfigInput, PublicUser, RequestSource, SessionData } from "@proteles/bff";

export type { ProtelesConfigInput, PublicUser, RequestSource, SessionData } from "@proteles/bff";
// Re-exported so a SolidStart app needs only this package.
export { AuthApp, SessionUnavailableError, toWebRequest } from "@proteles/bff";

/** Key set on the event's `locals`/`context` bag by `attachUser`. */
export const CONTEXT_USER_KEY = "protelesUser";

let defaultAppInstance: AuthApp | undefined;

/**
 * One `AuthApp` per config object, kept for as long as the object is. An
 * `AuthApp` is what shares a refresh among the requests presenting one refresh
 * token, and what caches the issuer's keys, so building one per call gave each
 * request its own: two requests arriving with one expired access token each
 * spent the refresh token, and the one the server refused cleared the session
 * cookie. Pass the same object on every call — one built inside the handler is
 * a new object each time, and gets a new app each time.
 */
const appsByConfig = new WeakMap<ProtelesConfigInput, AuthApp>();

function appFor(input?: ProtelesConfigInput): AuthApp {
  if (input) {
    let app = appsByConfig.get(input);
    if (!app) {
      app = new AuthApp(input);
      appsByConfig.set(input, app);
    }
    return app;
  }
  if (!defaultAppInstance) defaultAppInstance = new AuthApp();
  return defaultAppInstance;
}

/** SolidStart's `FetchEvent` also exposes `locals`; treat it like `context`. */
function bagOf(source: RequestSource): Record<string, unknown> | undefined {
  const locals = (source as { locals?: Record<string, unknown> }).locals;
  return locals ?? contextOf(source);
}

/**
 * Handles the auth actions (`login`, `signup`, `callback`, `logout`, `me`,
 * `revalidate`), routing on the request's last path segment. Assign it directly
 * to `GET`/`POST` in an `api/auth/[...proteles].ts` route — SolidStart sends a
 * returned `Response` as-is.
 */
export async function protelesAuthHandler(
  source: RequestSource,
  input?: ProtelesConfigInput,
): Promise<Response> {
  return appFor(input).handle(toWebRequest(source));
}

/**
 * The sanitized current user (no tokens) — preferring a value `attachUser`
 * already put on the event, and otherwise decrypting the session cookie.
 */
export async function getUser(
  source: RequestSource,
  input?: ProtelesConfigInput,
): Promise<PublicUser | null> {
  const cached = bagOf(source)?.[CONTEXT_USER_KEY];
  if (cached !== undefined) return cached as PublicUser | null;

  const session = await appFor(input).getSession(toWebRequest(source));
  return session ? toPublicUser(session) : null;
}

/**
 * Resolves the current user and stores it on the event (`locals` when present,
 * else `context`) so later `getUser` calls and route code reuse it rather than
 * decrypting the cookie again.
 */
export async function attachUser(
  source: RequestSource,
  input?: ProtelesConfigInput,
): Promise<PublicUser | null> {
  const user = await getUser(source, input);
  const bag = bagOf(source);
  if (bag) bag[CONTEXT_USER_KEY] = user;
  return user;
}

/** The full session **including tokens** — server-side only. Use `getUser`
 *  unless you need the access token to call an API on the user's behalf. */
export async function getSession(
  source: RequestSource,
  input?: ProtelesConfigInput,
): Promise<SessionData | null> {
  return appFor(input).getSession(toWebRequest(source));
}

/**
 * Route protection for SolidStart middleware: returns a redirect `Response` when
 * the request should be bounced to login, or `undefined` to continue.
 */
export async function guardRequest(
  source: RequestSource,
  options?: { publicPaths?: (string | RegExp)[] },
  input?: ProtelesConfigInput,
): Promise<Response | undefined> {
  const guard = appFor(input).middleware({ publicPaths: options?.publicPaths ?? [] });
  return guard(toWebRequest(source));
}

function toPublicUser(session: SessionData): PublicUser {
  return {
    sub: session.sub,
    email: session.email,
    preferredUsername: session.preferredUsername,
  };
}
