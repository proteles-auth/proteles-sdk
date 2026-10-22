//! `@proteles/next` — Next.js bindings for the Proteles Backend-for-Frontend.
//!
//! The framework-agnostic core lives in `@proteles/bff`; this package adds the
//! Next-shaped helpers (catch-all route handlers, middleware, and the
//! `next/headers`-based server helpers) and re-exports the core so a Next app
//! only needs this one package.
//!
//! ```ts
//! // app/api/auth/[...proteles]/route.ts
//! import { createAuthHandlers } from "@proteles/next";
//! export const { GET, POST } = createAuthHandlers();
//! ```
//! ```ts
//! // middleware.ts
//! export { authMiddleware as middleware } from "@proteles/next";
//! ```
//! ```ts
//! // any Server Component
//! import { currentUser } from "@proteles/next";
//! const user = await currentUser();
//! ```

import { AuthApp } from "@proteles/bff";
import type { ProtelesConfigInput, PublicUser, SessionData } from "@proteles/bff";

// Re-export the core so `@proteles/next` remains a complete, single dependency.
export {
  AuthApp,
  cookieNames,
  SessionUnavailableError,
  matchesPath,
  safeReturnTo,
  SessionCrypto,
  resolveConfig,
  parseCookies,
  serializeCookie,
} from "@proteles/bff";
export type {
  CookieOptions,
  FlowState,
  ProtelesConfig,
  ProtelesConfigInput,
  PublicUser,
  SessionData,
} from "@proteles/bff";

/** Route-handler pair for a catch-all `/api/auth/[...proteles]/route.ts`. Both
 *  verbs delegate to the same router (login/logout are GET/POST-agnostic). */
export function createAuthHandlers(input?: ProtelesConfigInput): {
  GET: (request: Request) => Promise<Response>;
  POST: (request: Request) => Promise<Response>;
} {
  const app = new AuthApp(input);
  const handler = (request: Request): Promise<Response> => app.handle(request);
  return { GET: handler, POST: handler };
}

/** Explicitly-configured route protection, for `middleware.ts`. */
export function createAuthMiddleware(
  input?: ProtelesConfigInput,
  options?: { publicPaths?: (string | RegExp)[] },
): (request: Request) => Promise<Response | undefined> {
  const app = new AuthApp(input);
  return withAbsoluteRedirects(app, app.middleware(options));
}

/**
 * Makes the middleware's redirects absolute, which Next's middleware requires.
 *
 * `AuthApp.middleware` answers with a **relative** `Location` on purpose (its
 * comment explains why: the request's origin comes from headers nothing can
 * verify). Next's middleware adapter parses that header with no base, so every
 * signed-out or expired request to a protected route threw `TypeError: Invalid
 * URL` and became a 500 (found running the quickstart under Next 14.2,
 * 2026-09-29). Next alone needs this, so it happens here rather than in the
 * core, and every other binding keeps the relative form.
 *
 * The base is configuration, never the request: the origin of the configured
 * redirect URI. That is `PROTELES_APP_URL` (or `appUrl`) with the callback path
 * appended, unless `PROTELES_REDIRECT_URI` replaces it — and either way it is
 * the origin whose callback sets the session cookie, so it is the only origin
 * a sign-in started from can finish on. Resolving against it is what a browser
 * does with the relative form, with the configured origin in place of the one
 * the request claims.
 */
function withAbsoluteRedirects(
  app: AuthApp,
  guard: (request: Request) => Promise<Response | undefined>,
): (request: Request) => Promise<Response | undefined> {
  const base = new URL(app.config.redirectUri);
  return async (request: Request) => {
    const response = await guard(request);
    const location = response?.headers.get("location");
    if (response && location) response.headers.set("location", new URL(location, base).href);
    return response;
  };
}

// A lazily-built, env-configured app backing the zero-config exports below.
let defaultAppInstance: AuthApp | undefined;
let defaultMiddleware: ((request: Request) => Promise<Response | undefined>) | undefined;
function defaultApp(): AuthApp {
  if (!defaultAppInstance) defaultAppInstance = new AuthApp();
  return defaultAppInstance;
}

/** Zero-config middleware for `export { authMiddleware as middleware }`.
 *  Reads configuration from the environment on first use. */
export async function authMiddleware(request: Request): Promise<Response | undefined> {
  defaultMiddleware ??= withAbsoluteRedirects(defaultApp(), defaultApp().middleware());
  return defaultMiddleware(request);
}

/** Reads the current session inside a Server Component / route / action. */
export async function auth(): Promise<SessionData | null> {
  const { cookies } = await import("next/headers");
  const store = await cookies();
  const raw = store.get(defaultApp().cookieNames.session)?.value;
  if (!raw) return null;
  return defaultApp().decryptUsableSession(raw);
}

/** The sanitized current user (no tokens), or null. */
export async function currentUser(): Promise<PublicUser | null> {
  const session = await auth();
  if (!session) return null;
  return { sub: session.sub, email: session.email, preferredUsername: session.preferredUsername };
}
