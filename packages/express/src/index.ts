//! `@proteles/express` — Express bindings for the Proteles Backend-for-Frontend.
//!
//! The framework-agnostic core is `@proteles/bff`; this adds the Express-shaped
//! pieces and re-exports the core so an Express app needs one package.
//!
//! ```ts
//! import express from "express";
//! import { protelesAuth, requireAuth, userOf } from "@proteles/express";
//!
//! const app = express();
//! app.use(protelesAuth());                 // serves /api/auth/*
//! app.get("/dashboard", requireAuth(), (req, res) => {
//!   res.send(`hello ${userOf(req)?.preferredUsername}`);
//! });
//! ```
//!
//! Four decisions worth knowing.
//!
//! **`app.use(protelesAuth())` annotates; it does not guard.** It serves the
//! auth routes and attaches the session to everything else. A package where
//! `app.use` silently meant "this whole server now requires a login" would be a
//! surprising thing to add to an existing app. [`requireAuth`] is the opt-in.
//!
//! **The guard redirects browsers and answers XHR with 401.** A request asking
//! for JSON that is redirected to a login page receives an HTML document where
//! it expected data, and the caller reports "the API returned garbage" rather
//! than "I am signed out".
//!
//! **A session that only needs a refresh is refreshed, not sent to log in.** A
//! browser goes through `{basePath}/revalidate`, as `AuthApp.middleware` sends
//! it; a JSON caller is refreshed in place. Either way a busy authorization
//! server gets "try again" (`503`), not a sign-in: the guard used to read every
//! spent access token as signed out, so during a busy spell a user went to
//! `/login` and back, the code exchange met the same `503`, and the round trip
//! ended in `login_failed`.
//!
//! **The session is attached to the request rather than returned.** Express
//! middleware has no other way to hand a value to the next handler, and a second
//! decrypt per handler would be a second chance to disagree with the guard about
//! who is signed in.

import { AuthApp, SessionUnavailableError, sendNodeResponse, toWebRequest } from "@proteles/bff";
import type { ProtelesConfigInput, PublicUser, SessionData } from "@proteles/bff";

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

/** Where the resolved session is parked on the request. */
const SESSION_KEY = "protelesSession";

/** Where `protelesAuth` parks its `AuthApp`, so that `requireAuth` refreshes
 *  through the same one — see `requireAuth`. */
const APP_KEY = "protelesApp";

/** The Express pieces this package touches, structurally.
 *
 *  Typed here rather than by depending on `@types/express`: Express is an
 *  *optional* peer, and a hard type dependency would pull its types into a
 *  project that never installed it. */
export interface ExpressRequestLike {
  method?: string;
  url?: string;
  originalUrl?: string;
  headers: Record<string, string | string[] | undefined>;
  [key: string]: unknown;
}
export interface ExpressResponseLike {
  statusCode: number;
  setHeader: (name: string, value: string | string[]) => void;
  /** Read so that a rotated session cookie is added to, not written over,
   *  whatever `Set-Cookie` an earlier middleware already set. */
  getHeader?: (name: string) => number | string | string[] | undefined;
  end: (chunk?: string) => void;
}
export type NextFunction = (err?: unknown) => void;
export type Handler = (
  req: ExpressRequestLike,
  res: ExpressResponseLike,
  next: NextFunction,
) => void | Promise<void>;

/**
 * Hands every failure to Express instead of letting it leave the promise.
 *
 * Express 4 calls a middleware and drops what it returns, so a rejected
 * promise from an `async` one is unhandled — and Node's default since v15
 * turns that into a process exit. A refresh that fails at the IdP, or anything
 * else that throws, took the whole app down on one request. With `next(err)`
 * it reaches the app's error handler, as a synchronous throw would.
 */
function guarded(handler: Handler): Handler {
  return async (req, res, next) => {
    try {
      await handler(req, res, next);
    } catch (err) {
      next(err);
    }
  };
}

function nodeSource(req: ExpressRequestLike) {
  // `originalUrl`, not `url`. Express rewrites `url` to be relative to the
  // mount point, so a router mounted at `/api` would see `/auth/login` where the
  // basePath check expects `/api/auth/login` — the auth routes would fall
  // through to the app, and `returnTo` would be built from a path that does not
  // exist. `originalUrl` is the address the browser actually asked for.
  return { node: { req: { method: req.method, url: req.originalUrl ?? req.url, headers: req.headers } } };
}

/** The session this request resolved to, or `null`. Populated by
 *  [`protelesAuth`] and [`requireAuth`], which use the same key. */
export function sessionOf(req: ExpressRequestLike): SessionData | null {
  return (req[SESSION_KEY] as SessionData | undefined) ?? null;
}

/** The sanitized user (no tokens), or `null`. */
export function userOf(req: ExpressRequestLike): PublicUser | null {
  const session = sessionOf(req);
  if (!session) return null;
  return { sub: session.sub, email: session.email, preferredUsername: session.preferredUsername };
}

/** Serves the auth routes, and attaches the session to every other request. */
export function protelesAuth(input?: ProtelesConfigInput): Handler {
  const app = new AuthApp(input);
  return guarded(async (req, res, next) => {
    const request = toWebRequest(nodeSource(req));
    const url = new URL(request.url);
    if (url.pathname === app.config.basePath || url.pathname.startsWith(`${app.config.basePath}/`)) {
      await sendNodeResponse(res, await app.handle(request));
      return;
    }
    req[SESSION_KEY] = await app.getSession(request);
    req[APP_KEY] = app;
    next();
  });
}

export interface RequireAuthOptions {
  /** Where to send a browser with no session. Defaults to the login route. A
   *  browser whose session only needs a refresh goes through
   *  `{basePath}/revalidate` instead, which sends it to the login route if the
   *  authorization server refuses the refresh. */
  loginPath?: string;
}

/** Route protection.
 *
 *  A signed-out browser is redirected to the login route carrying `returnTo`; a
 *  signed-out XHR gets `401 {"error":"unauthenticated"}`.
 *
 *  A session whose access token is spent but whose refresh token may still be
 *  good is not signed out. A browser is sent through `{basePath}/revalidate`,
 *  which refreshes and comes straight back — or shows a `503` "try again" page
 *  while the authorization server is busy. A JSON caller cannot follow that
 *  usefully, so it is refreshed here: the rotated cookie is added to this
 *  response and the request continues; a refusal is the `401` above; and a
 *  busy authorization server is `503 {"error":"temporarily_unavailable"}`,
 *  with its `Retry-After`, the cookie untouched.
 *
 *  That refresh goes through the `AuthApp` `protelesAuth` created, when it ran
 *  on this request, not through this guard's own. An `AuthApp` shares one token
 *  exchange among the requests presenting the same refresh token, but only
 *  among its own, and every `requireAuth()` makes one. Two guarded requests —
 *  or one and `/me` — arriving together with an expired token would each spend
 *  the refresh token in a different app, one would meet `invalid_grant`, and
 *  its response would clear the cookie: signed out for opening two tabs.
 *
 *  The redirects are **relative**, so a forwarded host cannot choose where the
 *  browser lands. See the note in `AuthApp.middleware`: the request URL here is
 *  built from `X-Forwarded-Host`, which nothing in this package can verify. */
export function requireAuth(input?: ProtelesConfigInput, options?: RequireAuthOptions): Handler {
  const app = new AuthApp(input);
  return guarded(async (req, res, next) => {
    const request = toWebRequest(nodeSource(req));
    const url = new URL(request.url);
    let session = sessionOf(req);
    if (!session) {
      const state = await app.inspectSession(request);
      if (state.kind === "fresh") {
        session = state.data;
      } else if (state.kind === "stale" && !wantsJson(req)) {
        const target = new URL(`${app.config.basePath}/revalidate`, url.origin);
        target.searchParams.set("returnTo", url.pathname + url.search);
        res.statusCode = 303;
        res.setHeader("location", target.pathname + target.search);
        res.end();
        return;
      } else if (state.kind === "stale") {
        try {
          const refresher = (req[APP_KEY] as AuthApp | undefined) ?? app;
          session = await refresher.resolveSession(request, (c) => appendSetCookie(res, c.header));
        } catch (err) {
          if (!(err instanceof SessionUnavailableError)) throw err;
          res.statusCode = 503;
          res.setHeader("content-type", "application/json");
          res.setHeader("cache-control", "no-store");
          if (err.retryAfter !== undefined) res.setHeader("retry-after", String(err.retryAfter));
          res.end(JSON.stringify(TRY_AGAIN));
          return;
        }
      }
    }
    if (session) {
      req[SESSION_KEY] = session;
      next();
      return;
    }

    if (wantsJson(req)) {
      res.statusCode = 401;
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ error: "unauthenticated" }));
      return;
    }

    const login = new URL(options?.loginPath ?? `${app.config.basePath}/login`, url.origin);
    login.searchParams.set("returnTo", url.pathname + url.search);
    res.statusCode = 302;
    res.setHeader("location", login.pathname + login.search);
    res.end();
  });
}

/** The body a JSON caller gets while the authorization server is busy — the
 *  one `{basePath}/me` answers with. */
const TRY_AGAIN = { error: "temporarily_unavailable", message: "The sign-in service is busy. Try again shortly." };

/** Adds a cookie to the response. `setHeader` replaces, so whatever an earlier
 *  middleware set is read back first and kept. */
function appendSetCookie(res: ExpressResponseLike, cookie: string): void {
  const prior = res.getHeader?.("set-cookie");
  const kept = prior === undefined ? [] : Array.isArray(prior) ? prior : [String(prior)];
  res.setHeader("set-cookie", [...kept, cookie]);
}

/** Whether this caller wants data rather than a page. */
function wantsJson(req: ExpressRequestLike): boolean {
  const header = (name: string): string => {
    const v = req.headers[name];
    return (Array.isArray(v) ? v.join(",") : v) ?? "";
  };
  if (header("x-requested-with").toLowerCase() === "xmlhttprequest") return true;
  const accept = header("accept").toLowerCase();
  // Only when JSON is asked for *and* HTML is not. A browser navigation sends
  // `text/html,…,*/*` and must not match. `fetch` defaults to `*/*`, which is
  // ambiguous, and is treated as a navigation: a redirect is at least
  // followable, where a 401 to a real navigation is a dead end.
  if (!accept.includes("application/json")) return false;
  return !accept.includes("text/html");
}
