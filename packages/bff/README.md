# @proteles/bff

> **You need a Proteles account.** Proteles is a hosted sign-in service, and this
> package is a client for it: without an account it does nothing.
> [Sign up for free on proteles.com](https://proteles.com/signup), then register your app to get its
> issuer, client ID and secret.

The framework-agnostic Backend-for-Frontend core for Proteles.

**You probably want a framework package instead:**

- **[`@proteles/next`](https://www.npmjs.com/package/@proteles/next)** — Next.js: catch-all route handlers,
  `authMiddleware`, `currentUser()`.
- **[`@proteles/svelte`](https://www.npmjs.com/package/@proteles/svelte)** — SvelteKit: request handlers, a `handle`
  hook, and the UI components.

Both wrap this package, and both re-export what you need, so you don't install
this directly unless you're integrating a runtime neither covers.

## What it does

Access and refresh tokens live only inside an AES-256-GCM encrypted, `httpOnly`
cookie set by your own server — the browser never receives a token, only the
sanitized user from `/api/auth/me`. This sidesteps the "refresh token in
`localStorage`" footgun.

It ports the session and handlers of Proteles' reference Go web app (encrypted
session/flow cookies, PKCE redirect flow, transparent refresh-with-rotation,
revoke-on-logout) on top of [`@proteles/js`](https://www.npmjs.com/package/@proteles/js).

Everything operates on Web `Request`/`Response`, so one `AuthApp` works as a
Next.js route handler, a SvelteKit endpoint, Edge middleware, or a plain fetch
handler — and is fully unit-testable on plain Node.

## Install

```bash
npm install @proteles/bff
```

If you're on Next.js, SvelteKit, Nuxt, SolidStart, or htmx, install that
framework's package instead — each depends on this one and re-exports what you
need.

## Usage

```ts
import { AuthApp } from "@proteles/bff";

const app = new AuthApp(); // reads PROTELES_* from the environment

// Route the six actions by the request's last path segment:
//   /login  /signup  /callback  /logout  /me  /revalidate
// (`/revalidate` is the one `middleware()` bounces through — see below.)
const response = await app.handle(request);
```

Other entry points:

- `app.middleware({ publicPaths })` → a route guard returning a redirect (or
  `undefined` to continue).
- `app.getSession(request)` → the session, read-only, no cookie writes. Returns
  a session only while its **access token is live** — the presence of a refresh
  token is not evidence of anything until the token has actually been presented
  to the authorization server.
- `app.inspectSession(request)` → `none | fresh | stale | dead`. `getSession`
  collapses "no cookie" and "spent cookie" into the same `null`; a guard needs to
  tell them apart, because one means *log in* and the other means *revalidate*.
- `app.resolveSession(request, sink)` → proves a spent session against the
  authorization server and clears it when refused. The `sink` receives the
  rotated cookie and **must** reach the response you are about to send: refresh
  tokens are single-use, so dropping it signs the user out everywhere on the next
  request. It throws `SessionUnavailableError` when the server cannot refresh
  *right now* — see [When the authorization server is busy](#when-the-authorization-server-is-busy).
- `app.decryptUsableSession(rawCookieValue)` → for framework helpers that read
  the cookie themselves.
- `app.cookieNames` → `{ session, flow }`, the names this app's cookies go by:
  `__Host-proteles_session` and `__Host-proteles_flow` whenever `cookieSecure`
  is on, as it is by default, and `proteles_session` and `proteles_flow` when it
  is off. The prefix makes the browser refuse either cookie from any host but
  the app's own, so a sibling host cannot plant a session or a sign-in.
  `cookieNames(secure?)` gives the same pair without an app, reading
  `PROTELES_COOKIE_SECURE` when `secure` is omitted.

### Sign-up

`GET {basePath}/signup?returnTo=…` starts a sign-in exactly as `/login` does,
with `prompt=create` on the authorization request, so the person lands on the
workspace's hosted sign-up page. Once they have chosen a password they are
signed in and come back through `/callback`, as from any sign-in. Where the
workspace has not opened its sign-up page, the server ignores `create` and the
person sees the ordinary sign-in page.

It takes no `connection`: the server acts on `create` first, so a connection
would only steer the fallback to sign-in. For a sign-up through a social
provider, send the person to `/login?connection=…`; that makes an account where
the workspace lets a first social sign-in do so.

### Inviting people into your app

Register `<your app>/api/auth/login` as the app's sign-in start address (its
`initiate_login_uri`). An invitation sent through the Management API with the
app's `client_id` then sends the person who accepts it to that route with `iss`,
and the sign-in it starts finds the account they just made already signed in.
The route checks `iss` against `PROTELES_ISSUER` and always signs in at
`PROTELES_ISSUER`, whatever `iss` names.

### Revalidation

`middleware()` bounces a spent-but-refreshable session through
`GET {basePath}/revalidate`, which refreshes, sets the rotated cookie, and
redirects back. Middleware cannot attach a cookie itself — a bare `Response`
has no way to say "continue, with headers" — so without the bounce an expired
access token would send the user to log in every 15 minutes. Pass
`middleware({ revalidate: false })` to opt out.

### When the authorization server is busy

A refresh the authorization server turns away **for now** does not end the
session. That means a `503` (the token endpoint says `temporarily_unavailable`
when its password pool is full, so a confidential client's secret went
unchecked), a `429` from its rate limiter, any other `5xx` or a `408`, or no
answer at all. The cookie keeps the refresh token it had, nothing is written,
and the next request tries again. The one exception: when the exchange went
through and only the new ID token could not be checked, because the key set
could not be fetched, the refresh token the cookie holds is already spent, so
the cookie is rewritten with its successor (still marked as needing a refresh)
and the caller is told to try again all the same:

| Where | What the caller gets |
| --- | --- |
| `GET {basePath}/me` | `503 {"error":"temporarily_unavailable"}`, with the server's `Retry-After` when it sent one |
| `GET {basePath}/revalidate` | a `503` page with a *Try again* link back to `returnTo` — not a redirect, which the middleware would bounce straight back — and a *sign out* button, since a server that fails every refresh the same way would otherwise leave no way off it |
| `resolveSession` / `resolveUsableSession` | a thrown `SessionUnavailableError`, whose `retryAfter` is that header in seconds; the sink is not called, except with the successor in the case above — and that cookie must reach your `503` like any other |
| `requireAuth` in `@proteles/express` and `@proteles/fastify` | a browser is sent through `/revalidate`, as `middleware()` sends it; a JSON caller is refreshed in place, and gets `503 {"error":"temporarily_unavailable"}` with the `Retry-After` while the server is busy |

`invalid_grant`, and every other `4xx`, is a verdict on the grant and still ends
the session exactly as before. So does a refresh-minted ID token that fails
verification — but not one whose key set could not be fetched, which is the
exception above. Each deferral is reported through `onError` with the context
`"refresh"`: once per request that needed the refresh, so a busy minute can
produce a burst of them.

The browser packages (`@proteles/react`, `vue`, `svelte`, `solid`, `alpine`)
read `/me`'s `503` the same way: they keep the last known user, set
`isUnavailable`, and ask `/me` again after the `Retry-After` or a backoff, so the
UI does not flip to signed out while the server is busy.

Sign-in meets the same moments at its code exchange. A `503`, a `429`, another
`5xx` or a `408`, or no answer there, gets a `503` page — with the server's
`Retry-After` when it sent one — that says the sign-in service was busy and links
to `{basePath}/login` with the same `returnTo`: a fresh flow. The code is never
presented again. The flow cookie is spent, and the code may have been redeemed
by an exchange whose answer was lost, which a second presentation would turn
into a replay: refused, audited, and the tokens the first one minted revoked.
`invalid_grant` and every other `4xx` still end in `login_failed`.

One limit, stated so nobody has to find it. If the answer to a refresh was
*lost* rather than refused — a timeout or a proxy's `502` after the server had
already rotated the token — the retry meets `invalid_grant` and the session ends
then, one request later; and if that retry comes more than 60 seconds after the
rotation, the server reads it as a stolen token: it burns the token's family and
files a `refresh_token.reuse` warning in the tenant's audit log, which clearing
the session at once never caused.

What this shares with the native SDKs' rules in
[`docs/mobile-SDKs.md`](https://github.com/proteles-auth/proteles-sdk/blob/main/docs/mobile-SDKs.md) §10.9: item 4, that a
`5xx` from the token, revocation or key-set endpoint is a network error, not a
verdict; item 3's reading of `Retry-After` (seconds or an HTTP-date, capped at an
hour); and item 5, that a successor in hand is kept. Where it differs:

- **Any other `4xx` ends the session**, where item 1 ends a native one only on
  `invalid_grant`, a refresh-minted ID token that fails a trust rule, or a token
  already known dead: `invalid_client`, `invalid_request` and
  `unauthorized_client` end it here too.
- **A refresh-minted ID token is judged on its clock.** An `exp` or `iat` that
  fails the check ends the session; item 2 says a native SDK does not judge
  them.
- **A still-live access token is not served** while the refresh is put off
  (item 1 serves it): the refresh starts 30 seconds before expiry, and
  `/revalidate` returning a session the middleware still reads as spent would
  loop.
- **There is no backoff** (item 3): the next request that needs a refresh tries
  again at once. `Retry-After` is passed on to the caller, not enforced here.

### Signing out

A `POST` to `{basePath}/logout` from your app's own pages clears the session
cookie whatever happens upstream, and revokes the refresh token. A `GET` there
answers with a confirmation form instead of acting, and a `POST` from anywhere
else is refused with `403`: the browser marked it `Sec-Fetch-Site: cross-site`
or `same-site`, or its `Origin` is not the origin of `redirectUri` (an
`Origin: null` passes only when the browser also marks it `same-origin`). A
`POST` with no `Origin` is not a browser and is served. Nothing is revoked or
cleared on a refusal, and `onError` is told with the context `"logout"`. Every
browser package's `signOut()` submits the form `POST`; a control of your own
should be `<form method="post" action="/api/auth/logout">`, not a link.

Once it acts, it revokes the refresh token. A revocation the server answers as
busy — `503`, `429`, another `5xx` or `408` — within two seconds is tried once
more after half a second. No answer, and a slower busy answer, are not retried:
the redirect that clears the cookie waits on the revocation, and a second
attempt that could run a full `timeoutMs` again kept sign-out waiting past the
request limit of any host that sets one lower, which then never delivered the
cleared cookie. So sign-out waits at most one `timeoutMs` and 2.5 seconds. If
the revocation still did not happen, `onError` is told with the context
`"logout"`, because the refresh-token family then stays live at the
authorization server until it expires.

**Then it signs the person out of Proteles too.** The `303` goes on to the
server's end-session endpoint (OpenID Connect RP-Initiated Logout), carrying
the session's ID token as `id_token_hint` (or `client_id` when the session kept
none) and `returnTo` as an absolute URL on your app's origin. The server asks
the person to confirm, ends their session there, tells every other app that
registered a `backchannel_logout_uri`, and sends the browser back to that URL.
Before this, sign-out cleared only your app's cookie: the session at Proteles
stayed alive, and the next "Sign in" went straight through without a password —
on a shared computer, as the previous person.

- **Register where sign-out returns to**, as one of the app's
  `post_logout_redirect_uris`: `https://app.example.com/` for the default
  `returnTo` of `/`, and each other `returnTo` you use. The server follows only
  an exact match; anything else leaves the person on its signed-out page.
- **A strict `form-action` on your own pages must allow the issuer's origin**,
  because a browser applies it to the `303` that follows the sign-out post.
  This package's own sign-out confirmation already does.
- **`endSession: false`** (or `PROTELES_END_SESSION=false`) keeps sign-out to
  your app alone, as before.

**When the person signs out somewhere else** — at Proteles itself, through
another app, with "sign out everywhere", or by resetting their password — this
package is not told: it has no route for back-channel logout tokens, because
its sessions are encrypted cookies with nothing on the server to end. The
server does revoke the refresh token behind the session, so the app's session
lasts until its access token expires (15 minutes by default, the server's
`ACCESS_TOKEN_TTL_SECONDS`), fails to refresh, and ends then. An app that keeps
its own server-side sessions and needs them to end at once can register a
`backchannel_logout_uri` and verify the tokens with `@proteles/js`'s
`verifyLogoutToken` (its README, *Back-channel logout*).

A session also carries an absolute cap (`sessionExpiresAt`, 30 days) inside the
sealed payload. The cookie's `Max-Age` is a request to a browser; a replay with
`curl` never sees it, so without an embedded bound a stolen cookie could be
renewed indefinitely by looping the refresh path. The cap is stamped once and
survives every refresh.

## Configuration

Read from the environment (`PROTELES_ISSUER`, `PROTELES_CLIENT_ID`,
`PROTELES_CLIENT_SECRET`, `PROTELES_SESSION_SECRET`, `PROTELES_APP_URL` /
`PROTELES_REDIRECT_URI`, `PROTELES_SCOPES`, `PROTELES_COOKIE_SECURE`,
`PROTELES_POST_LOGIN_REDIRECT`, `PROTELES_BASE_PATH`, `PROTELES_TIMEOUT_MS`,
`PROTELES_END_SESSION`), or
passed explicitly to the constructor. See the framework packages' READMEs for
the full table.

`PROTELES_TIMEOUT_MS` (or `timeoutMs`) bounds every call this makes to the
authorization server; it defaults to 10 000. Raise it if your AS cold-starts, if
the network between you is slow, or if a request can land while the server is
busy with something expensive like minting a new tenant's signing keys. A
too-tight timeout is worth knowing about because of how it presents: a
timed-out code exchange shows the user the page that says the sign-in service
was busy, and a timed-out userinfo call the `?proteles_error=login_failed` that a
wrong client secret also produces. Neither says "timeout". Check the server-side
`onError` diagnostic — a timeout says `This operation was aborted`.

## Security notes

- The session cookie is AES-256-GCM encrypted via **Web Crypto**, so it also
  works on Edge runtimes; a tampered or wrong-key value is rejected and never
  trusted.
- `state` is validated with a constant-time comparison; a mismatch fails closed.
- `returnTo` is restricted to same-origin absolute paths — no open redirects.
- Failed logins redirect with a generic `?proteles_error=login_failed`; the raw
  authorization-server error is never surfaced to the browser.

## Develop

```bash
npm install      # from the repository root
npm run build    # tsc -> dist
npm test         # tsx + node:test — 17 tests, incl. a full
                 # login→callback→me→logout flow against a mocked AS
```
