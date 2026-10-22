//! The htmx-aware auth surface. Thin wrappers over `@proteles/bff` that add one
//! thing: every redirect becomes an `HX-Redirect` when the caller was htmx.

import { AuthApp, contextOf, safeReturnTo, toWebRequest } from "@proteles/bff";
import type { ProtelesConfigInput, PublicUser, RequestSource, SessionData } from "@proteles/bff";

import { currentUrl, isBoosted, isHtmxRequest, toHtmxResponse } from "./htmx.js";
import type { HeaderSource } from "./htmx.js";

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
 * Handles `login`, `signup`, `callback`, `logout`, `me` and `revalidate`,
 * converting redirects to `HX-Redirect` for htmx callers.
 *
 * This matters most for **logout**, which is usually an `hx-post`: a plain 303
 * would have htmx swap the post-logout page into a fragment. It also covers a
 * `hx-get`/`hx-boost`ed sign-in or sign-up link. The `callback` route is exercised by a real
 * browser navigation from the authorization server, so it is normally not an htmx
 * request and keeps its ordinary redirect.
 */
export async function protelesAuthHandler(
  source: RequestSource & HeaderSource,
  input?: ProtelesConfigInput,
): Promise<Response> {
  const request = toWebRequest(source);
  const response = await appFor(input).handle(request);
  return toHtmxResponse(response, source);
}

/**
 * Route protection. Returns a response to send when the request should be
 * bounced to login, or `undefined` to continue.
 *
 * For an htmx request this is an `HX-Redirect`, so a protected fragment request
 * navigates the browser to login instead of injecting the login page into an
 * `hx-target`.
 */
export async function guardRequest(
  source: RequestSource & HeaderSource,
  options?: { publicPaths?: (string | RegExp)[] },
  input?: ProtelesConfigInput,
): Promise<Response | undefined> {
  const app = appFor(input);
  const request = toWebRequest(source);
  const redirect = await app.middleware({ publicPaths: options?.publicPaths ?? [] })(request);
  if (!redirect) return undefined;
  const location = redirect.headers.get("location");
  if (location && isFragmentRequest(source)) {
    // The core named this request's own URL; for a fragment, name the page.
    const target = new URL(location, "http://location.invalid");
    target.searchParams.set("returnTo", returnToFor(app, source, request));
    redirect.headers.set("location", target.pathname + target.search);
  }
  return toHtmxResponse(redirect, source);
}

/** An htmx request for part of a page, as opposed to a boosted navigation. */
function isFragmentRequest(source: HeaderSource): boolean {
  return isHtmxRequest(source) && !isBoosted(source);
}

/**
 * Where the browser should land after signing in from this request.
 *
 * Not a fragment's own URL. The sign-in round trip ends in a *navigation* to
 * `returnTo`, and a fragment rendered as a page is a bare `<p>` with no layout
 * and nothing to click (seen in the Alpine AJAX quickstart on 2026-09-29; this
 * package built `returnTo` the same way). The page is the URL htmx sends in
 * `HX-Current-URL`. Only its path is used, and only when
 * it is on this app's configured origin — the redirect URI's — so the header
 * cannot send the browser anywhere else; failing that, `postLoginRedirect`.
 * A plain navigation or a boosted one *is* the page, and keeps its own URL.
 */
function returnToFor(app: AuthApp, source: HeaderSource, request: Request): string {
  const url = new URL(request.url);
  if (!isFragmentRequest(source)) return url.pathname + url.search;
  const page = currentUrl(source);
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
 * Returns either the user or a ready-to-send `response`, so a handler reads:
 *
 * ```js
 * const auth = await requireUser(event);
 * if (auth.response) return auth.response;
 * return html(`<p>Hello ${auth.user.email}</p>`);
 * ```
 *
 * The response is an `HX-Redirect` for htmx callers and an ordinary redirect
 * otherwise, so the same handler works for a full page load and a fragment
 * request.
 */
export async function requireUser(
  source: RequestSource & HeaderSource,
  input?: ProtelesConfigInput,
): Promise<{ user: PublicUser; response?: undefined } | { user?: undefined; response: Response }> {
  const user = await getUser(source, input);
  if (user) return { user };

  const app = appFor(input);
  const request = toWebRequest(source);
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
  //
  // `hx-redirect` too: htmx assigns it to `window.location`, which resolves a
  // relative value the same way.
  const location = loginUrl.pathname + loginUrl.search;
  const response = isHtmxRequest(source)
    ? new Response(null, { status: 200, headers: { "hx-redirect": location } })
    : new Response(null, { status: 307, headers: { location } });
  return { response };
}

function toPublicUser(session: SessionData): PublicUser {
  return {
    sub: session.sub,
    email: session.email,
    preferredUsername: session.preferredUsername,
  };
}
