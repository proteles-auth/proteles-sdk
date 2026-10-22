//! `@proteles/svelte/server` — SvelteKit bindings for the Proteles
//! Backend-for-Frontend.
//!
//! Access and refresh tokens live only in an encrypted, httpOnly cookie set by
//! your own server; the browser never receives a token. Wire it up with two
//! files:
//!
//! ```ts
//! // src/routes/api/auth/[...proteles]/+server.ts
//! import { createAuthHandlers } from "@proteles/svelte/server";
//! export const { GET, POST } = createAuthHandlers();
//! ```
//! ```ts
//! // src/hooks.server.ts
//! import { createAuthHandle } from "@proteles/svelte/server";
//! export const handle = createAuthHandle(undefined, { publicPaths: ["/"] });
//! ```
//!
//! The SvelteKit types are described structurally rather than imported, so this
//! package builds and typechecks without `@sveltejs/kit` installed.

import { AuthApp } from "@proteles/bff";
import type { ProtelesConfigInput, PublicUser, SessionData } from "@proteles/bff";

export type { ProtelesConfigInput, PublicUser, SessionData } from "@proteles/bff";
export { AuthApp, SessionUnavailableError } from "@proteles/bff";

/** The slice of SvelteKit's `RequestEvent` we use. */
export interface RequestEventLike {
  request: Request;
  locals?: Record<string, unknown>;
}

/** The slice of SvelteKit's `handle` hook signature we use. */
export interface HandleInput {
  event: RequestEventLike;
  resolve: (event: RequestEventLike) => Promise<Response> | Response;
}

/** Key set on `event.locals` by `createAuthHandle`. Declare it in your
 *  `src/app.d.ts` as `protelesUser: PublicUser | null` for typed access. */
export const LOCALS_USER_KEY = "protelesUser";

type RequestHandler = (event: RequestEventLike) => Promise<Response>;

/**
 * Request handlers for a catch-all `src/routes/api/auth/[...proteles]/+server.ts`.
 * Both verbs delegate to the same router — it dispatches on the last path
 * segment (`login`, `signup`, `callback`, `logout`, `me`, `revalidate`).
 */
export function createAuthHandlers(input?: ProtelesConfigInput): {
  GET: RequestHandler;
  POST: RequestHandler;
} {
  const app = onFirstUse(input);
  const handler: RequestHandler = async (event) => app().handle(event.request);
  return { GET: handler, POST: handler };
}

/**
 * The `AuthApp`, built on the first request rather than when the module loads.
 *
 * `vite build` imports every `+server.ts` to analyse it, so an app built at
 * import resolved its configuration during the build, and the build failed
 * unless the runtime secrets were in the build's environment (found running
 * the quickstart, 2026-09-29). A build machine should not need a session
 * secret. The cost is that a missing variable is reported by the first request
 * instead of at startup.
 */
function onFirstUse(input?: ProtelesConfigInput): () => AuthApp {
  let app: AuthApp | undefined;
  return () => (app ??= new AuthApp(input));
}

/**
 * A SvelteKit `handle` hook that (a) puts the current user on
 * `event.locals.protelesUser` for every request, and (b) optionally guards
 * routes, redirecting unauthenticated requests to `/api/auth/login?returnTo=…`.
 *
 * Pass `publicPaths` to allow-list unauthenticated routes. Omit `options`
 * entirely to only populate locals without guarding anything.
 */
export function createAuthHandle(
  input?: ProtelesConfigInput,
  options?: { publicPaths?: (string | RegExp)[]; protect?: boolean },
): (args: HandleInput) => Promise<Response> {
  const app = onFirstUse(input);
  const protect = options?.protect ?? options?.publicPaths !== undefined;
  let guard: ((request: Request) => Promise<Response | undefined>) | undefined;

  return async ({ event, resolve }) => {
    const session = await app().getSession(event.request);
    if (event.locals) {
      event.locals[LOCALS_USER_KEY] = session ? toPublicUser(session) : null;
    }
    if (protect) {
      guard ??= app().middleware({ publicPaths: options?.publicPaths ?? [] });
      const redirect = await guard(event.request);
      if (redirect) return redirect;
    }
    return resolve(event);
  };
}

/**
 * Reads the sanitized current user inside a `load` function or action —
 * preferring the value `createAuthHandle` already put on `locals`, and falling
 * back to decrypting the cookie when the hook isn't installed.
 */
export async function getUser(
  event: RequestEventLike,
  input?: ProtelesConfigInput,
): Promise<PublicUser | null> {
  const fromLocals = event.locals?.[LOCALS_USER_KEY];
  if (fromLocals !== undefined) return fromLocals as PublicUser | null;

  const session = await new AuthApp(input).getSession(event.request);
  return session ? toPublicUser(session) : null;
}

/** The full session (including tokens) — server-side only. Use `getUser` unless
 *  you genuinely need the access token to call an API on the user's behalf. */
export async function getSession(
  event: RequestEventLike,
  input?: ProtelesConfigInput,
): Promise<SessionData | null> {
  return new AuthApp(input).getSession(event.request);
}

function toPublicUser(session: SessionData): PublicUser {
  return {
    sub: session.sub,
    email: session.email,
    preferredUsername: session.preferredUsername,
  };
}
