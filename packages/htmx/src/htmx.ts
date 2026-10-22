//! htmx's request/response header protocol, as it concerns authentication.
//!
//! The problem this file exists to solve: **htmx follows redirects with XHR.**
//! When an unauthenticated `hx-get` hits a protected route and the server answers
//! `302 → /api/auth/login`, the browser's XHR transparently follows it, htmx gets
//! the *login page's HTML* back, and swaps that into whatever `hx-target` said —
//! so the login form appears inside a table cell and the address bar never
//! changes. It's the single most common htmx auth bug.
//!
//! The fix is htmx's own escape hatch: answer `200` with an `HX-Redirect` header
//! and htmx performs a real browser navigation instead.

/** htmx sets this on every request it makes. */
export const HX_REQUEST_HEADER = "hx-request";
/** Tells htmx to do a full browser navigation. */
export const HX_REDIRECT_HEADER = "hx-redirect";
/** Tells htmx to do a client-side (history-preserving) navigation. */
export const HX_LOCATION_HEADER = "hx-location";
/** Fires client-side events after a swap. */
export const HX_TRIGGER_HEADER = "hx-trigger";
/** Set by htmx when the request is a history restore, which we treat as normal. */
export const HX_BOOSTED_HEADER = "hx-boosted";
/** The browser's current URL, which htmx sends with every request. */
export const HX_CURRENT_URL_HEADER = "hx-current-url";

/** Anything we can read request headers from. */
export type HeaderSource =
  | Request
  | Headers
  | { headers: Headers }
  | { headers: Record<string, string | string[] | undefined> }
  | { node: { req: { headers: Record<string, string | string[] | undefined> } } };

function readHeader(source: HeaderSource, name: string): string | undefined {
  const lower = name.toLowerCase();

  if (typeof Headers !== "undefined" && source instanceof Headers) {
    return source.get(lower) ?? undefined;
  }
  const candidate = source as {
    headers?: Headers | Record<string, string | string[] | undefined>;
    node?: { req: { headers: Record<string, string | string[] | undefined> } };
  };

  const raw = candidate.headers ?? candidate.node?.req.headers;
  if (!raw) return undefined;

  if (typeof Headers !== "undefined" && raw instanceof Headers) {
    return raw.get(lower) ?? undefined;
  }
  const value = (raw as Record<string, string | string[] | undefined>)[lower];
  if (value === undefined) return undefined;
  return Array.isArray(value) ? value[0] : value;
}

/**
 * Whether this request came from htmx.
 *
 * `hx-boost`ed navigations also carry `HX-Request`, and they want the same
 * treatment: a boosted link click is still an XHR that would otherwise swap a
 * login page into the body.
 */
export function isHtmxRequest(source: HeaderSource): boolean {
  return readHeader(source, HX_REQUEST_HEADER) === "true";
}

/** Whether this request is an `hx-boost`ed navigation. */
export function isBoosted(source: HeaderSource): boolean {
  return readHeader(source, HX_BOOSTED_HEADER) === "true";
}

/** The page the browser was on when htmx made this request, if it said. */
export function currentUrl(source: HeaderSource): string | undefined {
  return readHeader(source, HX_CURRENT_URL_HEADER);
}

/**
 * A response that makes htmx navigate the whole browser to `location`.
 *
 * Status 200 is deliberate: htmx only reads `HX-Redirect` on a successful
 * response, and a 3xx would be followed by XHR before htmx ever saw the header.
 */
export function htmxRedirect(location: string, init?: ResponseInit): Response {
  const headers = new Headers(init?.headers);
  headers.set(HX_REDIRECT_HEADER, location);
  return new Response(null, { ...init, status: init?.status ?? 200, headers });
}

/**
 * A response that makes htmx swap in a new location client-side, preserving
 * history — the SPA-ish counterpart to `htmxRedirect`. Use it for in-app moves;
 * prefer `htmxRedirect` when leaving for the authorization server, since that
 * needs a genuine navigation.
 */
export function htmxLocation(location: string, init?: ResponseInit): Response {
  const headers = new Headers(init?.headers);
  headers.set(HX_LOCATION_HEADER, location);
  return new Response(null, { ...init, status: init?.status ?? 200, headers });
}

/** Adds an `HX-Trigger` event to a response, e.g. to tell the page a sign-in
 *  happened so it can refresh a user menu. */
export function withHtmxTrigger(response: Response, event: string, detail?: unknown): Response {
  const headers = new Headers(response.headers);
  const value = detail === undefined ? event : JSON.stringify({ [event]: detail });
  headers.set(HX_TRIGGER_HEADER, value);
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

/**
 * Converts a redirect response into an htmx-friendly one, leaving anything else
 * untouched.
 *
 * This is what makes the shared BFF safe to reuse for htmx: the core emits
 * ordinary 302/303/307 redirects, and this rewrites them to `HX-Redirect` when —
 * and only when — the caller was htmx. Cookies set alongside the redirect
 * (session, flow) are preserved, which matters because the login and callback
 * responses carry both a redirect *and* a `Set-Cookie`.
 */
export function toHtmxResponse(response: Response, source: HeaderSource): Response {
  if (!isHtmxRequest(source)) return response;
  const location = response.headers.get("location");
  if (!location || response.status < 300 || response.status > 399) return response;

  const headers = new Headers(response.headers);
  headers.delete("location");
  headers.set(HX_REDIRECT_HEADER, location);
  return new Response(null, { status: 200, headers });
}
