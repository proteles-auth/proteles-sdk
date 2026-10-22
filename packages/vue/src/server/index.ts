//! `@proteles/vue/server` — Nuxt / h3 bindings for the Proteles
//! Backend-for-Frontend.
//!
//! Access and refresh tokens live only in an encrypted, httpOnly cookie set by
//! your own server; the browser never receives a token. Wire it up with two
//! files:
//!
//! ```ts
//! // server/routes/api/auth/[...proteles].ts
//! import { protelesAuthHandler } from "@proteles/vue/server";
//! export default defineEventHandler((event) => protelesAuthHandler(event));
//! ```
//! ```ts
//! // server/middleware/proteles.ts — puts the user on event.context
//! import { getUser } from "@proteles/vue/server";
//! export default defineEventHandler(async (event) => {
//!   event.context.protelesUser = await getUser(event);
//! });
//! ```
//!
//! The h3 types are described structurally rather than imported, so this package
//! builds and typechecks without `h3`/`nuxt` installed. The event-to-Request
//! adapter itself lives in `@proteles/bff` and is shared with `@proteles/solid`.

import { AuthApp, contextOf, toWebRequest } from "@proteles/bff";
import type { ProtelesConfigInput, PublicUser, RequestSource, SessionData } from "@proteles/bff";

export type { ProtelesConfigInput, PublicUser, RequestSource, SessionData } from "@proteles/bff";
// `toWebRequest` is shared with @proteles/solid (Nuxt and SolidStart both hand
// handlers h3 events); re-exported here so a Nuxt app needs only this package.
export { AuthApp, SessionUnavailableError, toWebRequest } from "@proteles/bff";

/** Key set on `event.context` by the middleware pattern above. */
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

/**
 * Handles the auth actions (`login`, `signup`, `callback`, `logout`, `me`,
 * `revalidate`), routing on the request's last path segment. Return its result
 * directly from a Nuxt/h3 event handler — Nitro sends a returned `Response`
 * as-is.
 */
export async function protelesAuthHandler(
  source: RequestSource,
  input?: ProtelesConfigInput,
): Promise<Response> {
  return appFor(input).handle(toWebRequest(source));
}

/**
 * The sanitized current user (no tokens) — preferring a value an earlier
 * middleware already put on `event.context`, and otherwise decrypting the
 * session cookie.
 */
export async function getUser(
  source: RequestSource,
  input?: ProtelesConfigInput,
): Promise<PublicUser | null> {
  const cached = contextOf(source)?.[CONTEXT_USER_KEY];
  if (cached !== undefined) return cached as PublicUser | null;

  const session = await appFor(input).getSession(toWebRequest(source));
  return session ? toPublicUser(session) : null;
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
 * Route protection for a Nuxt server middleware: returns a redirect `Response`
 * when the request should be bounced to login, or `undefined` to continue.
 *
 * ```ts
 * export default defineEventHandler(async (event) => {
 *   const redirect = await guardRequest(event, { publicPaths: ["/"] });
 *   if (redirect) return redirect;
 * });
 * ```
 */
export async function guardRequest(
  source: RequestSource,
  options?: { publicPaths?: (string | RegExp)[] },
  input?: ProtelesConfigInput,
): Promise<Response | undefined> {
  const app = appFor(input);
  const request = toWebRequest(source);
  const guard = app.middleware({ publicPaths: options?.publicPaths ?? [] });
  return guard(request);
}

function toPublicUser(session: SessionData): PublicUser {
  return {
    sub: session.sub,
    email: session.email,
    preferredUsername: session.preferredUsername,
  };
}
