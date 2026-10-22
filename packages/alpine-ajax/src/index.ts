//! `@proteles/alpine-ajax` — Alpine AJAX server helpers for Proteles auth.
//!
//! Alpine AJAX keeps no client auth state: the server renders the HTML, so this
//! package is **server-only**. There is no browser bundle and no client-side
//! auth script to keep in sync — which is rather the point of choosing it.
//!
//! It is a sibling of `@proteles/htmx` and deliberately not a copy. htmx lets a
//! server force a navigation with `HX-Redirect`; Alpine AJAX does not, by its
//! own documentation — `fetch` follows every redirect transparently and no
//! response header changes that. So where the htmx package rewrites redirects,
//! this one answers an Alpine request with a `401` fragment addressed to the
//! ids in `X-Alpine-Target`, which Alpine merges in place because it merges
//! bodies on error statuses too.
//!
//! ```js
//! // the auth routes — plain redirects, because login, signup and callback
//! // are real browser navigations to and from the authorization server
//! if (url.pathname.startsWith("/api/auth/")) {
//!   return sendNodeResponse(res, await protelesAuthHandler({ node: { req } }));
//! }
//!
//! // a route that renders a fragment
//! const auth = await requireUser({ node: { req } });
//! if (auth.response) return sendNodeResponse(res, auth.response);
//! html(res, `<div id="profile">Hello ${auth.user.email}</div>`);
//! ```
//!
//! One markup rule, and it is the whole failure mode: **the sign-in, sign-up
//! and sign-out controls carry no `x-target`.** See the README.

export {
  attachUser,
  CONTEXT_USER_KEY,
  getSession,
  getUser,
  guardRequest,
  protelesAuthHandler,
  requireUser,
} from "./handler.js";
export type { GuardOptions } from "./handler.js";
export {
  ALPINE_REQUEST_HEADER,
  ALPINE_TARGET_HEADER,
  alpineTargets,
  escapeHtml,
  isAlpineRequest,
  signInFragment,
} from "./alpine-ajax.js";
export type { HeaderSource, SignInFragmentOptions } from "./alpine-ajax.js";
