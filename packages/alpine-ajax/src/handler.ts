//! The Alpine AJAX-aware auth surface. Thin wrappers over `@proteles/bff` that
//! add one thing: a request that came from Alpine AJAX is answered in a shape
//! Alpine can actually put somewhere.

import { AuthApp, contextOf, safeReturnTo, toWebRequest } from "@proteles/bff";
import type { ProtelesConfigInput, PublicUser, RequestSource, SessionData } from "@proteles/bff";

import { alpineTargets, isAlpineRequest, signInFragment } from "./alpine-ajax.js";
import type { HeaderSource } from "./alpine-ajax.js";

/** Key used when caching the user on an event's `context`/`locals` bag. */
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

function bagOf(source: RequestSource): Record<string, unknown> | undefined {
  const locals = (source as { locals?: Record<string, unknown> }).locals;
  return locals ?? contextOf(source);
}

/**
 * Handles `login`, `signup`, `callback`, `logout`, `me` and `revalidate`.
 *
 * Unlike the htmx package, this does **not** rewrite the redirects these routes
 * emit, because there is nothing to rewrite them to — Alpine AJAX reads no
 * response header that would make the browser navigate. The redirects stay
 * genuine redirects, which is correct for the routes that matter: `login`,
 * `signup` and `callback` are browser navigations to and from the
 * authorization server, and they must remain so.
 *
 * What that means for your markup is one line, and it is in the README because
 * getting it wrong is the whole failure mode this package is about: **the
 * sign-in, sign-up and sign-out controls carry no `x-target`.** A plain link,
 * or a form that posts normally.
 */
export async function protelesAuthHandler(
  source: RequestSource & HeaderSource,
  input?: ProtelesConfigInput,
): Promise<Response> {
  return appFor(input).handle(toWebRequest(source));
}

function loginUrlFor(app: AuthApp, request: Request, source: HeaderSource): string {
  const url = new URL(request.url);
  const loginUrl = new URL(`${app.config.basePath}/login`, url.origin);
  loginUrl.searchParams.set("returnTo", returnToFor(app, source, request));
  // Relative, deliberately. `url.origin` is only as trustworthy as whatever
  // built the request URL — on the Node path that is `X-Forwarded-Host`, which
  // nothing here can verify — so an absolute `Location` lets a request header
  // choose where the browser goes next. A relative one is resolved by the
  // browser against the address it actually reached, which is the origin we
  // meant and the one value in the exchange no header can move. Same fix as
  // `AuthApp.middleware`; see the comment there.
  return loginUrl.pathname + loginUrl.search;
}

/**
 * Where the browser should land after signing in from this request.
 *
 * Not a fragment's own URL. The sign-in link is a navigation, the round trip
 * ends in a navigation to `returnTo`, and a fragment rendered as a page is a
 * bare `<div>` with no layout and nothing to click (found running the
 * quickstart, 2026-09-29). Alpine AJAX sends no header naming the page, but
 * `fetch` sends the page as the `Referer` under the default referrer policy.
 * Only its path is used, and only when it is on this app's configured origin —
 * the redirect URI's — so the header cannot send the browser anywhere else;
 * failing that, `postLoginRedirect`. A plain navigation, and an Alpine request
 * that replaces the whole document (`_top`), is the page, and keeps its own URL.
 */
function returnToFor(app: AuthApp, source: HeaderSource, request: Request): string {
  const url = new URL(request.url);
  if (!isAlpineRequest(source) || alpineTargets(source).includes("_top")) return url.pathname + url.search;
  const page = request.headers.get("referer");
  if (page) {
    let parsed: URL | undefined;
    try {
      parsed = new URL(page);
    } catch {
      parsed = undefined;
    }
    if (parsed && parsed.origin === new URL(app.config.redirectUri).origin) {
      const path = safeReturnTo(parsed.pathname + parsed.search);
      if (path) return path;
    }
  }
  return app.config.postLoginRedirect;
}

export interface GuardOptions {
  publicPaths?: (string | RegExp)[];
  /** Overrides the copy in the fragment an Alpine caller receives. */
  message?: string;
  linkText?: string;
}

/**
 * Route protection. Returns a response to send, or `undefined` to continue.
 *
 * For a browser navigation this is the ordinary redirect `@proteles/bff` emits.
 * For an Alpine AJAX request it is a `401` carrying a fragment addressed to the
 * ids in `X-Alpine-Target` — because Alpine merges bodies on error statuses, so
 * that lands in place, whereas a redirect would be followed by `fetch` and the
 * login page merged into whatever the caller was rendering.
 */
export async function guardRequest(
  source: RequestSource & HeaderSource,
  options?: GuardOptions,
  input?: ProtelesConfigInput,
): Promise<Response | undefined> {
  const app = appFor(input);
  const request = toWebRequest(source);
  const redirect = await app.middleware({ publicPaths: options?.publicPaths ?? [] })(request);
  if (!redirect) return undefined;
  if (!isAlpineRequest(source)) return redirect;

  return signInResponse(source, loginUrlFor(app, request, source), options);
}

function signInResponse(
  source: HeaderSource,
  loginUrl: string,
  options?: { message?: string; linkText?: string },
): Response {
  const body = signInFragment(alpineTargets(source), {
    loginUrl,
    message: options?.message,
    linkText: options?.linkText,
  });
  return new Response(body, {
    // 401, not 200. Alpine merges the body either way, but the status is the
    // only thing a `x-target.4xx` rule, an `ajax:error` listener, or a log line
    // can key on — and answering "not signed in" with 200 makes the one
    // interesting event in the flow invisible to all three.
    status: 401,
    headers: {
      "content-type": "text/html; charset=utf-8",
      // A sign-in prompt is per-session by definition; a shared cache handing
      // it to the next visitor would be worse than useless.
      "cache-control": "no-store",
    },
  });
}

/** The sanitized current user (no tokens), reusing a cached value when present. */
export async function getUser(
  source: RequestSource,
  input?: ProtelesConfigInput,
): Promise<PublicUser | null> {
  const cached = bagOf(source)?.[CONTEXT_USER_KEY];
  if (cached !== undefined) return cached as PublicUser | null;

  const session = await appFor(input).getSession(toWebRequest(source));
  return session ? toPublicUser(session) : null;
}

/** Resolves the user and caches it on the event, for frameworks with a context bag. */
export async function attachUser(
  source: RequestSource,
  input?: ProtelesConfigInput,
): Promise<PublicUser | null> {
  const user = await getUser(source, input);
  const bag = bagOf(source);
  if (bag) bag[CONTEXT_USER_KEY] = user;
  return user;
}

/** The full session **including tokens** — server-side only. */
export async function getSession(
  source: RequestSource,
  input?: ProtelesConfigInput,
): Promise<SessionData | null> {
  return appFor(input).getSession(toWebRequest(source));
}

/**
 * The guard to reach for inside a route that renders a fragment.
 *
 * ```js
 * const auth = await requireUser({ node: { req } });
 * if (auth.response) return sendNodeResponse(res, auth.response);
 * html(res, `<div id="profile">Hello ${auth.user.email}</div>`);
 * ```
 *
 * The response is a target-addressed `401` fragment for Alpine callers and an
 * ordinary redirect otherwise, so the same handler serves a full page load and
 * a fragment request.
 */
export async function requireUser(
  source: RequestSource & HeaderSource,
  options?: { message?: string; linkText?: string },
  input?: ProtelesConfigInput,
): Promise<{ user: PublicUser; response?: undefined } | { user?: undefined; response: Response }> {
  const user = await getUser(source, input);
  if (user) return { user };

  const app = appFor(input);
  const request = toWebRequest(source);
  const loginUrl = loginUrlFor(app, request, source);
  if (isAlpineRequest(source)) return { response: signInResponse(source, loginUrl, options) };
  return { response: new Response(null, { status: 307, headers: { location: loginUrl } }) };
}

function toPublicUser(session: SessionData): PublicUser {
  return {
    sub: session.sub,
    email: session.email,
    preferredUsername: session.preferredUsername,
  };
}
