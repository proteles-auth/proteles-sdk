# @proteles/htmx

> **You need a Proteles account.** Proteles is a hosted sign-in service, and this
> package is a client for it: without an account it does nothing.
> [Sign up for free on proteles.com](https://proteles.com/signup), then register your app to get its
> issuer, client ID and secret.

htmx server helpers for Proteles authentication.

**Server-only, on purpose.** htmx keeps no client state — the server renders the
HTML — so there is no browser bundle to load and no client-side auth script to
keep in sync. Tokens live in an encrypted, `httpOnly` cookie and never reach the
browser at all.

## The problem this solves

htmx follows redirects **with XHR**. So when an unauthenticated `hx-get` hits a
protected route and your server answers `302 → /api/auth/login`:

1. the browser's XHR quietly follows the redirect,
2. htmx receives the **login page's HTML**,
3. and swaps it into whatever `hx-target` said.

You get a login form nested inside a table cell, and the address bar never
changes. It's the most common htmx auth bug.

Every helper here answers with htmx's own escape hatch instead — `200` plus an
`HX-Redirect` header — but **only when the caller was htmx**. A normal page load
still gets a proper `3xx`, so the same route works both ways.

## Install

```bash
npm install @proteles/htmx
```

## Setup

```js
import http from "node:http";
import { getUser, guardRequest, protelesAuthHandler, requireUser, sendNodeResponse } from "@proteles/htmx";

// `node:http` drops the promise a request listener returns, and Node exits on
// an unhandled rejection — so catch it, or one request that throws stops the
// whole server.
http.createServer((req, res) => {
  route(req, res).catch((err) => {
    console.error(err);
    res.statusCode = 500;
    res.end();
  });
}).listen(3000);

async function route(req, res) {
  const event = { node: { req } };
  const url = new URL(req.url, "http://localhost:3000");

  // 1. The auth routes.
  if (url.pathname.startsWith("/api/auth/")) {
    return sendNodeResponse(res, await protelesAuthHandler(event));
  }

  // 2. A protected page.
  if (url.pathname === "/dashboard") {
    const redirect = await guardRequest(event, { publicPaths: ["/"] });
    if (redirect) return sendNodeResponse(res, redirect);
    const user = await getUser(event);
    return html(res, `<h1>Hi ${user.email}</h1>`);
  }

  // 3. A fragment that needs a user.
  if (url.pathname === "/fragments/secret") {
    const auth = await requireUser(event);
    if (auth.response) return sendNodeResponse(res, auth.response);
    return html(res, `<p>🔒 for ${auth.user.email}</p>`);
  }
}
```

Your HTML needs no auth-specific attributes:

```html
<button hx-get="/api/auth/login">Sign in</button>
<button hx-get="/api/auth/signup">Sign up</button>
<button hx-post="/api/auth/logout">Sign out</button>

<!-- an auth-aware fragment the server renders either way -->
<div hx-get="/fragments/user" hx-trigger="load" hx-swap="outerHTML"></div>
```

`hx-post="/api/auth/logout"` is the case people hit first: a plain `303` there
would have htmx swap the post-logout page into a fragment.

`/api/auth/signup` is `/login` opening on the workspace's hosted sign-up page,
which signs the new person in and brings them back to `returnTo`. Where the
workspace has not opened that page, the person sees the ordinary sign-in page.
See [`@proteles/bff`](https://www.npmjs.com/package/@proteles/bff#sign-up).

## API

| Export | Purpose |
| --- | --- |
| `protelesAuthHandler(event, config?)` | Handles `login`/`signup`/`callback`/`logout`/`me`/`revalidate`, htmx-aware |
| `guardRequest(event, { publicPaths }, config?)` | A response to send when the request should bounce to login, else `undefined` |
| `requireUser(event, config?)` | `{ user }` or `{ response }` — the per-route/fragment guard |
| `getUser(event, config?)` | The sanitized user (no tokens) |
| `attachUser(event, config?)` | Resolves and caches the user on the event's `context`/`locals` |
| `getSession(event, config?)` | The full session **including tokens** — server-side only |

### htmx protocol helpers

| Export | Purpose |
| --- | --- |
| `isHtmxRequest(source)` | Reads `HX-Request`; works with a `Request`, `Headers`, `{ headers }`, or an h3-style event |
| `isBoosted(source)` | Reads `HX-Boosted` |
| `htmxRedirect(url)` | `200` + `HX-Redirect` (a full browser navigation) |
| `htmxLocation(url)` | `200` + `HX-Location` (a client-side navigation) |
| `withHtmxTrigger(res, event, detail?)` | Adds `HX-Trigger`, e.g. to refresh a user menu after sign-in |
| `toHtmxResponse(res, source)` | Rewrites a `3xx` to `HX-Redirect` **only** for htmx callers, preserving `Set-Cookie` |

`toHtmxResponse` is what makes the shared BFF safe here, and preserving
`Set-Cookie` matters: the login response carries a redirect *and* the encrypted
flow cookie, and the callback carries the session cookie *and* a flow-clear.

`@proteles/bff`'s `AuthApp`, `toWebRequest`, and `sendNodeResponse` are
re-exported, so this is the only Proteles package an htmx app installs.

### Note on the callback

`/api/auth/callback` is reached by a real browser navigation from the
authorization server, so it is *not* an htmx request and correctly keeps its
ordinary redirect. That asymmetry is deliberate and covered by tests.

## Inviting people into your app

Register `<your app>/api/auth/login` as the app's sign-in start address (its
`initiate_login_uri`). An invitation sent through the Management API with the
app's `client_id` then sends the person who accepts it to that route with `iss`,
and the sign-in it starts finds the account they just made already signed in.
The route checks `iss` against `PROTELES_ISSUER` and always signs in at
`PROTELES_ISSUER`, whatever `iss` names.

## Configuration (environment)

Read by `@proteles/bff`: `PROTELES_ISSUER`, `PROTELES_CLIENT_ID`,
`PROTELES_CLIENT_SECRET`, `PROTELES_SESSION_SECRET` (base64 of 32 random bytes),
`PROTELES_APP_URL` or `PROTELES_REDIRECT_URI`, plus optional `PROTELES_SCOPES`,
`PROTELES_COOKIE_SECURE`, `PROTELES_BASE_PATH`.

### Local development on Node 18

Node 18's `fetch` tries `localhost` over IPv6 (`::1`) first and does not fall
back to IPv4, so against an authorization server listening only on IPv4 the
browser redirect works but the *server-side* token exchange gets no answer, and
the login ends on a page saying the sign-in service was busy. Use Node 20 or
later, whose `fetch` falls back. Do not point `PROTELES_ISSUER` at `127.0.0.1`
to get around it: the issuer must be exactly what the server's
`/.well-known/openid-configuration` reports (for a tenant, its own host, such as
`http://acme.localhost:8080`), and a server that routes tenants by host answers
a bare IP with 404 unless it was told to serve one there. Check the server log:
the BFF reports the reason there (never to the browser).

## Develop

```bash
npm install      # from the repository root
npm run build    # tsc -> dist
npm test         # tsx + node:test
```

26 unit tests, most asserting the htmx and browser paths side by side. Because
htmx auth is purely a matter of which headers come back, the behaviour is also
fully verified over **real HTTP** against a live authorization server in
Proteles' integration tests (see
[`verify-htmx.mjs`](https://github.com/proteles-auth/proteles-sdk/blob/main/scripts/verify-htmx.mjs)) — and end-to-end in a real
browser with real htmx, confirming that a protected fragment request navigates to
login instead of injecting the login form into the page.
