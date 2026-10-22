//! `@proteles/htmx` — htmx server helpers for Proteles authentication.
//!
//! htmx keeps no client state: the server renders the HTML, so this package is
//! **server-only**. There is no browser bundle to load and no client-side auth
//! script to keep in sync — which is rather the point of choosing htmx.
//!
//! What it adds over `@proteles/bff` is htmx's redirect protocol. htmx follows
//! redirects with XHR, so an unauthenticated `hx-get` answered with `302 → login`
//! ends up swapping the login page into an `hx-target`. Every helper here answers
//! `HX-Redirect` instead when the caller was htmx, so the browser navigates
//! properly.
//!
//! ```js
//! // the auth routes
//! if (url.pathname.startsWith("/api/auth/")) {
//!   return sendNodeResponse(res, await protelesAuthHandler({ node: { req } }));
//! }
//!
//! // a route that renders a fragment
//! const auth = await requireUser({ node: { req } });
//! if (auth.response) return sendNodeResponse(res, auth.response);
//! html(res, `<p>Hello ${auth.user.email}</p>`);
//! ```

export {
  attachUser,
  CONTEXT_USER_KEY,
  getSession,
  getUser,
  guardRequest,
  protelesAuthHandler,
  requireUser,
} from "./handler.js";
export {
  currentUrl,
  HX_BOOSTED_HEADER,
  HX_CURRENT_URL_HEADER,
  HX_LOCATION_HEADER,
  HX_REDIRECT_HEADER,
  HX_REQUEST_HEADER,
  HX_TRIGGER_HEADER,
  htmxLocation,
  htmxRedirect,
  isBoosted,
  isHtmxRequest,
  toHtmxResponse,
  withHtmxTrigger,
} from "./htmx.js";
export type { HeaderSource } from "./htmx.js";

// The Node/Web plumbing an htmx backend needs, re-exported so this is the only
// Proteles package an htmx app installs.
export { AuthApp, SessionUnavailableError, sendNodeResponse, toWebRequest } from "@proteles/bff";
export type {
  NodeRequestLike,
  NodeResponseLike,
  ProtelesConfigInput,
  PublicUser,
  RequestSource,
  SessionData,
} from "@proteles/bff";
