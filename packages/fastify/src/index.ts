//! `@proteles/fastify` — a Fastify plugin for the Proteles Backend-for-Frontend.
//!
//! ```ts
//! import Fastify from "fastify";
//! import { protelesPlugin, requireAuth, sessionOf } from "@proteles/fastify";
//!
//! const app = Fastify();
//! await app.register(protelesPlugin);        // serves /api/auth/*
//! app.get("/dashboard", { preHandler: requireAuth() }, async (req) =>
//!   `hello ${sessionOf(req)?.sub}`);
//! ```
//!
//! Fastify differs from Express in one way that matters here: it owns the
//! response object, and writing to `reply.raw` behind its back leaves the
//! framework believing the request is still open. So the auth routes are
//! registered as real routes and answered through `reply`, rather than
//! intercepted in a hook — which is also why this is a plugin rather than a
//! middleware.
//!
//! **`Set-Cookie` goes through `reply.header` once per cookie.** A `Response`
//! can carry several, and Fastify's `headers()` object cannot hold duplicates —
//! folding them into one comma-joined value produces a session cookie the
//! browser will not accept, and the flow completes with the user signed out and
//! nothing in any log saying why.
//!
//! The rest of the decisions are `@proteles/express`'s, for the same reasons:
//! registering the plugin does not guard the app, the guard answers XHR with a
//! 401 rather than a redirect, the redirect it does send is relative, and a
//! session that only needs a refresh is refreshed rather than sent to log in —
//! so a busy authorization server gets "try again", not a sign-in.

import { AuthApp, SessionUnavailableError, readSetCookies, toWebRequest } from "@proteles/bff";
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

const SESSION_KEY = "protelesSession";

/** Where the plugin parks its `AuthApp`, so that `requireAuth` refreshes
 *  through the same one — see `requireAuth`. */
const APP_KEY = "protelesApp";

/** The Fastify pieces this package touches, structurally — Fastify is an
 *  optional peer, so its types are not a dependency. */
export interface FastifyRequestLike {
  method?: string;
  url?: string;
  headers: Record<string, string | string[] | undefined>;
  raw?: { method?: string; url?: string; headers: Record<string, string | string[] | undefined> };
  [key: string]: unknown;
}
export interface FastifyReplyLike {
  code: (status: number) => FastifyReplyLike;
  header: (name: string, value: string) => FastifyReplyLike;
  send: (payload?: unknown) => unknown;
}
export interface FastifyInstanceLike {
  all: (path: string, handler: (req: FastifyRequestLike, reply: FastifyReplyLike) => unknown) => unknown;
  addHook: (
    name: "onRequest",
    hook: (req: FastifyRequestLike, reply: FastifyReplyLike) => Promise<void> | void,
  ) => unknown;
  /** For the scope the auth routes are registered in; see `protelesPlugin`. */
  register: (plugin: (instance: FastifyInstanceLike) => Promise<void>) => unknown;
  hasContentTypeParser: (contentType: string) => boolean;
  addContentTypeParser: (
    contentType: string,
    options: { parseAs: "string" },
    parser: (req: unknown, body: string) => Promise<unknown>,
  ) => unknown;
}

function nodeSource(req: FastifyRequestLike) {
  const raw = req.raw ?? req;
  return { node: { req: { method: raw.method, url: raw.url, headers: raw.headers } } };
}

/** The session this request resolved to, or `null`. */
export function sessionOf(req: FastifyRequestLike): SessionData | null {
  return (req[SESSION_KEY] as SessionData | undefined) ?? null;
}

/** The sanitized user (no tokens), or `null`. */
export function userOf(req: FastifyRequestLike): PublicUser | null {
  const session = sessionOf(req);
  if (!session) return null;
  return { sub: session.sub, email: session.email, preferredUsername: session.preferredUsername };
}

/** Writes a Web `Response` out through a Fastify reply.
 *
 *  Exported because it is the piece most likely to be needed by an app doing
 *  something custom, and the `Set-Cookie` rule in it is not one to reimplement. */
export async function sendReply(reply: FastifyReplyLike, response: Response): Promise<unknown> {
  // One `header()` call per cookie. `reply.headers({...})` takes an object,
  // which cannot hold two `set-cookie` keys — and a folded cookie header is one
  // the browser rejects, which reads as "the login did nothing".
  for (const cookie of readSetCookies(response.headers)) reply.header("set-cookie", cookie);
  response.headers.forEach((value, key) => {
    if (key.toLowerCase() === "set-cookie") return;
    reply.header(key, value);
  });
  const body = await response.text();
  return reply.code(response.status).send(body.length > 0 ? body : undefined);
}

export interface PluginOptions extends Record<string, unknown> {
  proteles?: ProtelesConfigInput;
}

/** The type of every SDK sign-out: an empty form post. */
const FORM = "application/x-www-form-urlencoded";

/** Registers the auth routes and attaches the session to every request.
 *
 *  Registering does **not** guard the app; see [`requireAuth`]. */
export async function protelesPlugin(
  fastify: FastifyInstanceLike,
  options?: PluginOptions,
): Promise<void> {
  const app = new AuthApp(options?.proteles);

  // A scope of their own for the auth routes, so that the form parser they need
  // covers them and nothing else. Stock Fastify parses JSON and plain text
  // only, and answered every sign-out `415`. Added in the app's own scope
  // instead, the parser would make an app that registers @fastify/formbody
  // after this plugin fail to start, on "already present"; an app that
  // registered one before keeps it here too, because a scope inherits its
  // parent's parsers.
  fastify.register(async (routes) => {
    if (!routes.hasContentTypeParser(FORM)) {
      routes.addContentTypeParser(FORM, { parseAs: "string" }, async (_req, body) => body);
    }
    // A wildcard under the base path, registered as real routes so Fastify
    // knows it answered them.
    routes.all(`${app.config.basePath}/*`, async (req, reply) =>
      sendReply(reply, await app.handle(toWebRequest(nodeSource(req)))),
    );
    routes.all(app.config.basePath, async (req, reply) =>
      sendReply(reply, await app.handle(toWebRequest(nodeSource(req)))),
    );
  });

  fastify.addHook("onRequest", async (req) => {
    const request = toWebRequest(nodeSource(req));
    const url = new URL(request.url);
    if (url.pathname === app.config.basePath || url.pathname.startsWith(`${app.config.basePath}/`)) {
      return;
    }
    (req as Record<string, unknown>)[SESSION_KEY] = await app.getSession(request);
    (req as Record<string, unknown>)[APP_KEY] = app;
  });
}
// Not encapsulated: what `fastify-plugin` marks, without the dependency. Fastify
// hands an ordinary plugin a child scope, and a hook added in one runs only for
// the routes added in it — so under `app.register` the session hook ran for the
// auth routes alone, which it skips. `sessionOf` and `userOf` were `null` on
// every app route, and `requireAuth` refreshed through its own `AuthApp` rather
// than this one, which is the double refresh it exists to prevent.
(protelesPlugin as unknown as Record<symbol, unknown>)[Symbol.for("skip-override")] = true;

export interface RequireAuthOptions {
  /** Where to send a browser with no session. Defaults to the login route. A
   *  browser whose session only needs a refresh goes through
   *  `{basePath}/revalidate` instead, which sends it to the login route if the
   *  authorization server refuses the refresh. */
  loginPath?: string;
}

/** A `preHandler` that refuses anonymous requests.
 *
 *  Browsers are redirected with `returnTo`; callers asking for JSON get
 *  `401 {"error":"unauthenticated"}`. The redirects are relative, so a
 *  forwarded host cannot choose where the browser lands.
 *
 *  A session whose access token is spent but whose refresh token may still be
 *  good is not refused. A browser is sent through `{basePath}/revalidate`,
 *  which refreshes and comes straight back — or shows a `503` "try again" page
 *  while the authorization server is busy. A JSON caller is refreshed here: the
 *  rotated cookie goes out with this reply and the request continues; a
 *  refusal is the `401`; and a busy authorization server is
 *  `503 {"error":"temporarily_unavailable"}`, with its `Retry-After`, the
 *  cookie untouched.
 *
 *  That refresh goes through the plugin's `AuthApp` when the plugin's hook ran
 *  on this request, not through this guard's own: an `AuthApp` shares one token
 *  exchange only among its own requests, and every `requireAuth()` makes one.
 *  Two guarded requests — or one and `/me` — arriving together with an expired
 *  token would each spend the refresh token in a different app, one would meet
 *  `invalid_grant`, and its reply would clear the cookie. */
export function requireAuth(
  input?: ProtelesConfigInput,
  options?: RequireAuthOptions,
): (req: FastifyRequestLike, reply: FastifyReplyLike) => Promise<unknown | undefined> {
  const app = new AuthApp(input);
  return async (req, reply) => {
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
        return reply.code(303).header("location", target.pathname + target.search).send();
      } else if (state.kind === "stale") {
        try {
          // `reply.header` adds each `set-cookie` rather than replacing it,
          // which is what `sendReply` relies on too.
          const refresher = ((req as Record<string, unknown>)[APP_KEY] as AuthApp | undefined) ?? app;
          session = await refresher.resolveSession(request, (c) => reply.header("set-cookie", c.header));
        } catch (err) {
          if (!(err instanceof SessionUnavailableError)) throw err;
          reply.code(503).header("content-type", "application/json").header("cache-control", "no-store");
          if (err.retryAfter !== undefined) reply.header("retry-after", String(err.retryAfter));
          return reply.send(JSON.stringify(TRY_AGAIN));
        }
      }
    }
    if (session) {
      (req as Record<string, unknown>)[SESSION_KEY] = session;
      return undefined;
    }

    if (wantsJson(req)) {
      return reply
        .code(401)
        .header("content-type", "application/json")
        .send(JSON.stringify({ error: "unauthenticated" }));
    }

    const login = new URL(options?.loginPath ?? `${app.config.basePath}/login`, url.origin);
    login.searchParams.set("returnTo", url.pathname + url.search);
    return reply.code(302).header("location", login.pathname + login.search).send();
  };
}

/** The body a JSON caller gets while the authorization server is busy — the
 *  one `{basePath}/me` answers with. */
const TRY_AGAIN = { error: "temporarily_unavailable", message: "The sign-in service is busy. Try again shortly." };

function wantsJson(req: FastifyRequestLike): boolean {
  const source = req.raw ?? req;
  const header = (name: string): string => {
    const v = source.headers[name];
    return (Array.isArray(v) ? v.join(",") : v) ?? "";
  };
  if (header("x-requested-with").toLowerCase() === "xmlhttprequest") return true;
  const accept = header("accept").toLowerCase();
  if (!accept.includes("application/json")) return false;
  return !accept.includes("text/html");
}
