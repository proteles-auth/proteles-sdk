# @proteles/next

> **You need a Proteles account.** Proteles is a hosted sign-in service, and this
> package is a client for it: without an account it does nothing.
> [Sign up for free on proteles.com](https://proteles.com/signup), then register your app to get its
> issuer, client ID and secret.

A Backend-for-Frontend (BFF) that adds Proteles authentication to a Next.js app.

**Why a BFF?** Access and refresh tokens live only inside an encrypted,
`httpOnly` cookie set by *your own* server. The browser never receives a token —
it only ever sees the sanitized user object from `/api/auth/me`. This sidesteps
the "refresh token in `localStorage`" footgun and is how modern Auth0/Clerk SDKs
work.

It ports the session and handlers of Proteles' reference Go web app (encrypted
session/flow cookies, PKCE redirect flow, transparent refresh-with-rotation,
revoke-on-logout) to Next.js, built on [`@proteles/js`](https://www.npmjs.com/package/@proteles/js).

## Install

```bash
npm install @proteles/next @proteles/js
```

## Setup (three files)

```ts
// app/api/auth/[...proteles]/route.ts
import { createAuthHandlers } from "@proteles/next";
export const { GET, POST } = createAuthHandlers();
```

```ts
// proxy.ts — protect everything except public routes. Next 16's name for
// middleware.ts; on Next 14 or 15 use that file and `as middleware`.
export { authMiddleware as proxy } from "@proteles/next";
export const config = { matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"] };
```

```ts
// any Server Component / route / action
import { currentUser } from "@proteles/next";
const user = await currentUser(); // { sub, email, preferredUsername } | null
```

**Call `currentUser()` in your protected routes too, not only in middleware.**
In every page, route handler and server action that needs a signed-in user,
check that it is not `null` and send the visitor to sign in when it is. Next.js
releases before 14.2.25 and 15.2.3 let one request header skip middleware
entirely (CVE-2025-29927). This package's peer range starts at the fixed
releases, but a check that lives only in middleware fails open whenever
middleware does not run.

The peer range excludes only the releases with CVE-2025-29927. It is not a list
of safe releases. Later advisories were fixed in patch releases that the range
still admits. For example, the React Server Components remote code execution
of December 2025 (CVE-2025-66478 in Next.js, CVE-2025-55182 in React) affects
App Router apps, and every app using this package is one, on each 15.x and 16.x
minor until that minor's fix (15.2.6, 15.5.7 and 16.0.7 among them). Run the
latest patch release of your Next.js line.

Prefer the [`@proteles/react`](https://www.npmjs.com/package/@proteles/react) components (`<SignInButton>`,
`<UserButton>`, `useUser()`) for the client UI — they talk to these route
handlers, never to the authorization server directly.

## Configuration (environment)

All read from the environment; nothing is required in code.

| Variable | Required | Default | Notes |
| --- | --- | --- | --- |
| `PROTELES_ISSUER` | ✅ | | Your tenant's issuer, e.g. `https://acme.auth.proteles.com` |
| `PROTELES_CLIENT_ID` | ✅ | | |
| `PROTELES_CLIENT_SECRET` | | | Set for a confidential client (recommended for a BFF) |
| `PROTELES_REDIRECT_URI` | ✅* | | `*` or derive from `PROTELES_APP_URL` + `/api/auth/callback` |
| `PROTELES_APP_URL` | | | App origin, used to derive the redirect URI. The middleware's redirects are made absolute against the redirect URI's origin (Next.js middleware refuses a relative `Location`), so this must be the origin people browse |
| `PROTELES_SESSION_SECRET` | ✅ | | **Base64 of 32 random bytes** — encrypts the cookies |
| `PROTELES_SCOPES` | | `openid profile email offline_access` | |
| `PROTELES_COOKIE_SECURE` | | `true` | Set `false` only for plain-HTTP local dev |
| `PROTELES_POST_LOGIN_REDIRECT` | | `/` | |
| `PROTELES_BASE_PATH` | | `/api/auth` | Where the route handlers are mounted |

Generate a session secret:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
```

You can also pass any of these to `createAuthHandlers({ ... })` /
`createAuthMiddleware({ ... })` explicitly instead of using env.

## Endpoints

The catch-all route handles, relative to `basePath` (`/api/auth`):

| Route | What it does |
| --- | --- |
| `GET /login?returnTo=…&connection=…` | Starts login: sets the flow cookie, redirects to the AS (PKCE + state + nonce). `connection` picks a social provider — the authorize endpoint sends an unauthenticated visitor straight to that provider instead of the password form. An unknown provider is answered by the social route's own 404; a malformed one falls back to the password form rather than being refused. |
| `GET /signup?returnTo=…` | Starts login as `/login` does, with `prompt=create`, so the person lands on the workspace's hosted sign-up page and, once they have chosen a password, comes back through `/callback` signed in. Where the workspace has not opened its sign-up page, they see the ordinary sign-in page. Takes no `connection`: for a sign-up through a social provider, use `/login?connection=…`. `signUp()` and `<SignUpButton>` in `@proteles/react` go here. |
| `GET /callback` | Verifies `state`, exchanges the code, fetches userinfo, sets the session cookie, redirects to `returnTo`. If the authorization server is busy at the code exchange (`503`, `429`, another `5xx`, `408`) or does not answer, serves a `503` page, with the server's `Retry-After` when it sent one, that links to a fresh `/login` with the same `returnTo`; the code is never presented again. See [`@proteles/bff`](https://www.npmjs.com/package/@proteles/bff#when-the-authorization-server-is-busy). |
| `POST /logout?returnTo=…` | Clears the session and revokes the refresh token — once more if the server answered within two seconds that it was busy, and reported through `onError` if it still did not happen. Only from your app's own pages: a `POST` whose `Origin` is another one, or that the browser marks `Sec-Fetch-Site: cross-site` or `same-site`, is refused with `403` and changes nothing. A `GET` answers with a confirmation form that posts here, so a link or an image elsewhere cannot sign your users out. `signOut()` and `<SignOutButton>` post. |
| `GET /me` | `{ authenticated, user? }` — transparently refreshes an expired access token first. If the authorization server is busy (`503`), rate-limiting (`429`) or unreachable, answers `503` with its `Retry-After` and keeps the session for the next request; see [`@proteles/bff`](https://www.npmjs.com/package/@proteles/bff#when-the-authorization-server-is-busy). |
| `GET /revalidate?returnTo=…` | Refreshes a spent-but-refreshable session, sets the rotated cookie, and redirects back to `returnTo` (or to the login flow if the session is gone; to a `503` *try again* page, cookie untouched, if the authorization server is busy). `authMiddleware` sends users here **by default**, because middleware cannot attach a cookie to a "continue" response — without the bounce an expired access token would send people to log in every 15 minutes. Opt out with `authMiddleware({ revalidate: false })`. |

## Inviting people into your app

Register `<your app>/api/auth/login` as the app's sign-in start address (its
`initiate_login_uri`). An invitation sent through the Management API with the
app's `client_id` then sends the person who accepts it to that route with `iss`,
and the sign-in it starts finds the account they just made already signed in.
The route checks `iss` against `PROTELES_ISSUER` and always signs in at
`PROTELES_ISSUER`, whatever `iss` names.

## Security notes

- The session cookie is AES-256-GCM encrypted (Web Crypto, so it also works on
  the Edge runtime, where Next 14 and 15 run middleware); a tampered or wrong-key value is
  rejected and never trusted.
- `state` is validated with a constant-time comparison; a mismatch fails closed.
- `returnTo` is restricted to same-origin absolute paths — no open redirects.
- Failed logins redirect to `…?proteles_error=login_failed` with a generic
  signal; the raw AS error is never surfaced to the browser.

## Develop

```bash
npm install      # from the repository root
npm run build    # tsc -> dist
npm test         # tsx + node:test (full login→callback→me→logout flow, mocked AS)
```
