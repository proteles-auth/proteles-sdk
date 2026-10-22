//! Alpine AJAX's request protocol, as it concerns authentication.
//!
//! **This is not the htmx package with the names changed, and the reason is a
//! protocol difference that decides the whole design.**
//!
//! htmx's auth problem is that XHR follows redirects, so an unauthenticated
//! `hx-get` answered with `302 → login` swaps the login page into an `hx-target`.
//! htmx supplies an escape hatch — `HX-Redirect` — and `@proteles/htmx` is
//! essentially that one rewrite.
//!
//! Alpine AJAX has the same problem and **no such escape hatch**. Its own
//! reference says it plainly: "The JavaScript Fetch API follows all redirects
//! transparently, so Alpine AJAX cannot distinguish between 300 class status
//! codes." There is no response header that makes it navigate. A server cannot
//! force a full page load, full stop.
//!
//! What Alpine AJAX *does* give us is better than a workaround, once you stop
//! looking for the htmx shape:
//!
//!   * every request carries `X-Alpine-Request: true` and `X-Alpine-Target`,
//!     the space-separated ids the response is expected to fill;
//!   * response bodies are merged **for every status, including 4xx**.
//!
//! So the answer to "this fragment needs a session" is not a redirect at all. It
//! is a `401` whose body is a fragment carrying *the id the caller asked for*,
//! containing a sign-in link. Alpine merges it exactly where the content would
//! have gone, the user sees "your session expired — sign in" in place, and the
//! address bar never fills with a login page injected into a table cell.
//!
//! The id matters. Alpine matches merged fragments by id, and a body whose ids
//! do not match fires `ajax:missing` and swaps nothing — which looks to the user
//! like the click did nothing at all. That is why `signInFragment` takes the
//! targets from the request rather than guessing.

/** Alpine AJAX sets this on every request it makes. */
export const ALPINE_REQUEST_HEADER = "x-alpine-request";
/** The space-separated element ids the response is expected to fill. */
export const ALPINE_TARGET_HEADER = "x-alpine-target";

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

/** Whether this request came from Alpine AJAX rather than a browser navigation. */
export function isAlpineRequest(source: HeaderSource): boolean {
  return readHeader(source, ALPINE_REQUEST_HEADER) === "true";
}

/**
 * The element ids this request expects the response to fill.
 *
 * Empty for a normal navigation. `_top` — Alpine's own name for "replace the
 * whole document" — is returned as given; a caller rendering into it is
 * rendering a page, not a fragment.
 */
export function alpineTargets(source: HeaderSource): string[] {
  const raw = readHeader(source, ALPINE_TARGET_HEADER);
  if (!raw) return [];
  return raw.split(/\s+/).filter(Boolean);
}

/**
 * Escapes text for interpolation into HTML.
 *
 * Small, and here rather than pulled in: the only untrusted values this package
 * interpolates are an element id taken from a request header and a URL it built
 * itself, and a dependency for five replacements would be a dependency in
 * everybody's lockfile.
 */
export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/**
 * An id that is safe to put in an HTML `id` attribute.
 *
 * `X-Alpine-Target` is attacker-controlled — it is a request header — and it is
 * interpolated into markup. Escaping alone would be enough for correctness, but
 * an id is a narrow thing and an allow-list is the honest bound: anything
 * outside it is not an id Alpine could have been targeting anyway, so refusing
 * it costs nothing and removes the question entirely.
 */
function isSafeId(id: string): boolean {
  return /^[A-Za-z][\w:.-]*$/.test(id) && id.length <= 128;
}

export interface SignInFragmentOptions {
  /** Where the sign-in link points. */
  loginUrl: string;
  /** Shown above the link. */
  message?: string;
  /** The link's text. */
  linkText?: string;
}

/**
 * The body of a "this needs a session" response, addressed to the ids the
 * caller asked for.
 *
 * Rendered once per target, because Alpine merges by id and a body missing the
 * requested id fires `ajax:missing` and swaps nothing — which is
 * indistinguishable, to the person clicking, from the click not working.
 *
 * The link is a plain `<a href>` with no `x-target`. That is deliberate:
 * leaving for the authorization server is a genuine navigation, and an
 * `x-target` on it would fetch the sign-in page and try to merge it into the
 * fragment — the exact bug this package exists to avoid, reintroduced by the
 * markup that was supposed to escape it.
 */
export function signInFragment(targets: string[], options: SignInFragmentOptions): string {
  // Not "your session has expired": most people who meet this never had one.
  const message = options.message ?? "Sign in to see this.";
  const linkText = options.linkText ?? "Sign in";
  const href = escapeHtml(options.loginUrl);
  const inner =
    `<p>${escapeHtml(message)}</p>` +
    `<p><a href="${href}" data-proteles-signin>${escapeHtml(linkText)}</a></p>`;

  const usable = targets.filter((t) => t !== "_top" && isSafeId(t));
  if (usable.length === 0) {
    // No addressable target: either a whole-document replacement or nothing we
    // are willing to echo. A bare fragment is still the right body — Alpine
    // replaces the document for `_top`, and a normal navigation renders it as a
    // page.
    return inner;
  }
  return usable.map((id) => `<div id="${escapeHtml(id)}">${inner}</div>`).join("");
}
