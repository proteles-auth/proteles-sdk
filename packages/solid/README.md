# @proteles/solid

> **You need a Proteles account.** Proteles is a hosted sign-in service, and this
> package is a client for it: without an account it does nothing.
> [Sign up for free on proteles.com](https://proteles.com/signup), then register your app to get its
> issuer, client ID and secret.

Solid primitives and components for Proteles authentication, plus the SolidStart
server handlers.

Tokens live only in an encrypted, `httpOnly` cookie set by your own server — the
browser never receives one, only the sanitized user from `/api/auth/me`.

## Install

```bash
npm install @proteles/solid
```

## The five-minute setup (SolidStart)

**1. The auth routes** — the whole OAuth flow, in one file:

```ts
// src/routes/api/auth/[...proteles].ts
import { protelesAuthHandler } from "@proteles/solid/server";

export const GET = protelesAuthHandler;
export const POST = protelesAuthHandler;
```

**2. Middleware** — put the user on the event and guard routes:

```ts
// src/middleware.ts   (register it via `middleware` in app.config.ts)
import { createMiddleware } from "@solidjs/start/middleware";
import { attachUser, guardRequest } from "@proteles/solid/server";

export default createMiddleware({
  onRequest: [
    async (event) => {
      await attachUser(event);
      return guardRequest(event, { publicPaths: ["/"] });
    },
  ],
});
```

**3. Wrap the app** so the UI can read auth state:

```tsx
// src/app.tsx
import { AuthProvider } from "@proteles/solid";

export default function App() {
  return (
    <AuthProvider>
      <Router>{/* … */}</Router>
    </AuthProvider>
  );
}
```

Then use the components anywhere:

```tsx
import { SignedIn, SignedOut, SignInButton, UserButton, useUser } from "@proteles/solid";

export default function Home() {
  const { user } = useUser();
  return (
    <>
      <SignedOut>
        <SignInButton />
      </SignedOut>

      <SignedIn>
        Hi {user()?.email} <UserButton />
      </SignedIn>
    </>
  );
}
```

## Client API

### `<AuthProvider>`

Wrap your app once. Creates the auth object, provides it to every descendant, and
revalidates against `/api/auth/me` on mount (so a stale `initialUser` — e.g.
after a logout in another tab — self-corrects). `onMount` never runs during SSR,
so server rendering stays pure.

| Prop | Notes |
| --- | --- |
| `initialUser` | From the server. Omit = fetch on mount, `null` = known signed-out, an object = known signed-in. |
| `basePath` | BFF mount path. Defaults to `VITE_PROTELES_BASE_PATH` or `/api/auth`. |

### `useUser()` / `useAuth()`

State is exposed as Solid **accessors** — call them:

```tsx
const { user, isLoading, isAuthenticated, signIn, signUp, signOut, reload } = useAuth();

return (
  <Show when={!isLoading()} fallback={<p>Loading…</p>}>
    <Show when={isAuthenticated()}>{user()!.sub}</Show>
    <button onClick={() => signIn({ connection: "google" })}>Google</button>
  </Show>
);
```

They track inside JSX, `createMemo`, and `createEffect` like any signal.
`useUser()` returns just the four state accessors (`user`, `isLoading`,
`isAuthenticated`, `isUnavailable`). Both throw a clear error if
used outside an `<AuthProvider>`.

`isAuthenticated` is a plain derived accessor rather than a `createMemo`, so it
works even when `createAuth()` is called outside a component (a memo needs a
reactive owner and would silently stop updating there).

### Components

| Component | Renders |
| --- | --- |
| `<SignedIn>` | its children when a user is signed in |
| `<SignedOut>` | its children when no user is signed in |
| `<Protect fallback={…}>` | its children when signed in, else `fallback` (nothing while loading) |
| `<SignInButton returnTo? connection?>` | a button that starts login (`connection` picks a social provider) |
| `<SignUpButton returnTo?>` | a button that starts sign-up ([below](#sign-up)) |
| `<SignOutButton returnTo?>` | a button that logs out |
| `<UserButton>` | the user's name/email plus a sign-out control |

`<SignInButton>`/`<SignUpButton>`/`<SignOutButton>`/`<UserButton>` are unstyled
by design — pass `class`. The three wrappers (`<SignedIn>`, `<SignedOut>`,
`<Protect>`) render only their children and take no `class`; passing one is a
type error.

`<SignedIn>`/`<SignedOut>` render nothing until who is signed in is known — from
`initialUser`, or from the first answer to `/api/auth/me`, which a busy spell
(below) does not give — so there's no signed-in/out flash.

### Sign-up

`signUp({ returnTo })` and `<SignUpButton>` send the person through
`/api/auth/signup` to the workspace's hosted sign-up page. They give their email
address, follow the link they are mailed, choose a password, and come back to
`returnTo` (by default the page they were on) signed in, as after a sign-in.
Where the workspace has not opened its sign-up page, they see the ordinary
sign-in page instead.

It takes no `connection`. For a sign-up through a social provider, use
`signIn({ connection })`: a first sign-in through it makes an account where
the workspace allows that.

### When the sign-in service is busy

While the authorization server is too busy to refresh a session, the BFF's
`/api/auth/me` answers `503` and keeps the session cookie. That — or a `429`, a
`408`, any other `5xx`, or no answer at all — is read as "could not tell", not
as signed out: `user()` stays the last one known (`isLoading()` stays `true` if
no answer has come yet), `isUnavailable()` turns `true`, and `/me` is asked
again after the server's `Retry-After` (capped at an hour) or, when it named
none, after 2 s, 4 s, 8 s and so on up to 30 s. The next answer clears
`isUnavailable()`. A `401`, or `{ authenticated: false }`, still means signed
out, as before.

`<SignedIn>` keeps rendering for the known user meanwhile; read
`isUnavailable()` to tell them the service is busy. An `<AuthProvider>` that
unmounts stops asking.

## Server API (`@proteles/solid/server`)

| Export | Purpose |
| --- | --- |
| `protelesAuthHandler(event, config?)` | Handles `login`/`callback`/`logout`/`me`; assign straight to `GET`/`POST` |
| `attachUser(event, config?)` | Resolves the user and stores it on the event (`locals`, else `context`) |
| `getUser(event, config?)` | The sanitized user (no tokens) — reuses `attachUser`'s value when present |
| `getSession(event, config?)` | The full session **including tokens** — server-side only |
| `guardRequest(event, { publicPaths }, config?)` | A redirect `Response` when the request should bounce to login, else `undefined` |
| `toWebRequest(source)` | The adapter (shared with `@proteles/vue`): accepts a Web `Request`, a SolidStart `FetchEvent`, or an h3 event |

`publicPaths` entries match exactly or as a path-segment prefix: `"/blog"` covers
`/blog` and `/blog/post` but not `/blogging`. `"/"` is **exact-only**, so listing
the home page doesn't accidentally make the whole app public.

## Inviting people into your app

Register `<your app>/api/auth/login` as the app's sign-in start address (its
`initiate_login_uri`). An invitation sent through the Management API with the
app's `client_id` then sends the person who accepts it to that route with `iss`,
and the sign-in it starts finds the account they just made already signed in.
The route checks `iss` against `PROTELES_ISSUER` and always signs in at
`PROTELES_ISSUER`, whatever `iss` names.

## Configuration (environment)

Server-side, read by the handlers — same names as every Proteles BFF package:

| Variable | Required | Default |
| --- | --- | --- |
| `PROTELES_ISSUER` | ✅ | |
| `PROTELES_CLIENT_ID` | ✅ | |
| `PROTELES_CLIENT_SECRET` | | *(omit for a public PKCE client)* |
| `PROTELES_SESSION_SECRET` | ✅ | **base64 of 32 random bytes** |
| `PROTELES_REDIRECT_URI` | ✅* | `*` or derived from `PROTELES_APP_URL` |
| `PROTELES_APP_URL` | | |
| `PROTELES_SCOPES` | | `openid profile email offline_access` |
| `PROTELES_COOKIE_SECURE` | | `true` |
| `PROTELES_BASE_PATH` | | `/api/auth` |

Client-side, only `VITE_PROTELES_BASE_PATH` is read (and only if you moved the
routes). Generate a session secret:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
```

## Packaging note

Solid's JSX is compiled by its own Babel preset, and it compiles *differently*
for the browser (fine-grained DOM updates) than for SSR (string concatenation).
So this package ships the conventional Solid layout:

- `dist/source/` — untranspiled JSX, selected by the **`solid` export
  condition**. This is the preferred path: your build (`vite-plugin-solid`)
  compiles it for whichever target you're building.
- `dist/dom/` and `dist/ssr/` — precompiled fallbacks for tooling that ignores
  the `solid` condition.
- `dist/api/` — the `./server` entry (plain TS, no JSX).

## Develop

```bash
npm install      # from the repository root
npm run build    # babel (source/dom/ssr) + tsc types -> dist
npm test         # tsx + node:test
```

Tests cover the reactive auth object, the components (compiled with
`babel-preset-solid` and server-rendered via `solid-js/web` — no bundler, no
jsdom), and the SolidStart bindings for both event shapes. The full loop also
runs against a **live** server via
[`scripts/verify-solid.mjs`](https://github.com/proteles-auth/proteles-sdk/blob/main/scripts/verify-solid.mjs) (run by
Proteles' integration tests), which renders the **published** SSR bundle.
