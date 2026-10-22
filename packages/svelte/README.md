# @proteles/svelte

> **You need a Proteles account.** Proteles is a hosted sign-in service, and this
> package is a client for it: without an account it does nothing.
> [Sign up for free on proteles.com](https://proteles.com/signup), then register your app to get its
> issuer, client ID and secret.

Svelte components and stores for Proteles authentication, plus the SvelteKit
server handlers. Works with **Svelte 4 and 5**.

Tokens live only in an encrypted, `httpOnly` cookie set by your own server — the
browser never receives one, only the sanitized user from `/api/auth/me`.

## Install

```bash
npm install @proteles/svelte
```

## The five-minute setup (SvelteKit)

**1. The auth routes** — the whole OAuth flow, in one file:

```ts
// src/routes/api/auth/[...proteles]/+server.ts
import { createAuthHandlers } from "@proteles/svelte/server";
export const { GET, POST } = createAuthHandlers();
```

**2. The hook** — puts the user on `locals` and guards routes:

```ts
// src/hooks.server.ts
import { createAuthHandle } from "@proteles/svelte/server";
export const handle = createAuthHandle(undefined, { publicPaths: ["/"] });
```

**3. Hand the user to the client** so the first paint is correct:

```ts
// src/routes/+layout.server.ts
import { getUser } from "@proteles/svelte/server";
export const load = async (event) => ({ user: await getUser(event) });
```

```svelte
<!-- src/routes/+layout.svelte -->
<script>
  import { AuthProvider } from "@proteles/svelte";
  export let data;
</script>

<AuthProvider initialUser={data.user}><slot /></AuthProvider>
```

Then use the components anywhere:

```svelte
<!-- src/routes/+page.svelte -->
<script>
  import { SignedIn, SignedOut, SignInButton, UserButton, getAuth } from "@proteles/svelte";
  const auth = getAuth();
</script>

<SignedOut>
  <SignInButton />
</SignedOut>

<SignedIn>
  Hi {$auth.user?.email} <UserButton />
</SignedIn>
```

## Client API

### `<AuthProvider>`

Wrap your app once. Creates the auth store, puts it in context, and revalidates
against `/api/auth/me` on mount (so a stale `initialUser` — e.g. after a logout
in another tab — self-corrects).

| Prop | Notes |
| --- | --- |
| `initialUser` | From `getUser(event)` in a server `load`. `undefined` = fetch on mount, `null` = known signed-out, an object = known signed-in. |
| `basePath` | BFF mount path. Defaults to `PUBLIC_PROTELES_BASE_PATH` or `/api/auth`. |

### `getAuth()`

The auth store, from context. Call during component initialization, then use
`$auth` in markup:

```svelte
<script>
  import { getAuth } from "@proteles/svelte";
  const auth = getAuth();
</script>

{#if $auth.isLoading}Loading…{:else if $auth.isAuthenticated}{$auth.user.sub}{/if}
<button on:click={() => auth.signIn({ connection: "google" })}>Google</button>
```

The store value is `{ user, isLoading, isAuthenticated, isUnavailable }`; the
store object also carries `signIn(opts?)`, `signUp(opts?)`, `signOut(opts?)`,
`reload()`, and `basePath`. It throws a clear error if used outside an
`<AuthProvider>`.

### Components

| Component | Renders |
| --- | --- |
| `<SignedIn>` | its slot when a user is signed in |
| `<SignedOut>` | its slot when no user is signed in |
| `<Protect>` | its default slot when signed in, else the `fallback` slot (nothing while loading) |
| `<SignInButton returnTo? connection?>` | a button that starts login (`connection` picks a social provider, e.g. `"google"`) |
| `<SignUpButton returnTo?>` | a button that starts sign-up ([below](#sign-up)) |
| `<SignOutButton returnTo?>` | a button that logs out |
| `<UserButton>` | the user's name/email plus a sign-out control |

`<SignInButton>`/`<SignUpButton>`/`<SignOutButton>`/`<UserButton>` are unstyled
by design — pass `class`. The wrappers (`<AuthProvider>`, `<SignedIn>`,
`<SignedOut>`, `<Protect>`) render only their slot and declare no `class` prop;
passing one is accepted and silently dropped.

`<SignedIn>`/`<SignedOut>` render nothing until who is signed in is known — from
`initialUser`, or from the first answer to `/api/auth/me`, which a busy spell
(below) does not give — so there's no signed-in/out flash.

### Sign-up

`auth.signUp({ returnTo })` and `<SignUpButton>` send the person through
`/api/auth/signup` to the workspace's hosted sign-up page. They give their email
address, follow the link they are mailed, choose a password, and come back to
`returnTo` (by default the page they were on) signed in, as after a sign-in.
Where the workspace has not opened its sign-up page, they see the ordinary
sign-in page instead.

It takes no `connection`. For a sign-up through a social provider, use
`auth.signIn({ connection })`: a first sign-in through it makes an account where
the workspace allows that.

### When the sign-in service is busy

While the authorization server is too busy to refresh a session, the BFF's
`/api/auth/me` answers `503` and keeps the session cookie. That — or a `429`, a
`408`, any other `5xx`, or no answer at all — is read as "could not tell", not
as signed out: `$auth.user` stays the last one known (`$auth.isLoading` stays
`true` if no answer has come yet), `$auth.isUnavailable` turns `true`, and `/me`
is asked again after the server's `Retry-After` (capped at an hour) or, when it
named none, after 2 s, 4 s, 8 s and so on up to 30 s. The next answer clears
`$auth.isUnavailable`. A `401`, or `{ authenticated: false }`, still means
signed out, as before.

`<SignedIn>` keeps rendering for the known user meanwhile; read
`$auth.isUnavailable` to tell them the service is busy. An `<AuthProvider>`
that is destroyed stops asking.

## Server API (`@proteles/svelte/server`)

| Export | Purpose |
| --- | --- |
| `createAuthHandlers(config?)` | `{ GET, POST }` for `src/routes/api/auth/[...proteles]/+server.ts` |
| `createAuthHandle(config?, { publicPaths, protect })` | A SvelteKit `handle` hook: sets `locals.protelesUser`, and guards routes when `publicPaths` is given |
| `getUser(event, config?)` | The sanitized user (no tokens) — prefers `locals`, falls back to the cookie |
| `getSession(event, config?)` | The full session **including tokens** — server-side only, for calling APIs as the user |

`publicPaths` entries match exactly or as a path-segment prefix: `"/blog"` covers
`/blog` and `/blog/post` but not `/blogging`. `"/"` is **exact-only**, so listing
the home page doesn't accidentally make the whole app public.

For typed `locals`, add to `src/app.d.ts`:

```ts
import type { PublicUser } from "@proteles/svelte/server";

declare global {
  namespace App {
    interface Locals {
      protelesUser: PublicUser | null;
    }
  }
}
export {};
```

## Inviting people into your app

Register `<your app>/api/auth/login` as the app's sign-in start address (its
`initiate_login_uri`). An invitation sent through the Management API with the
app's `client_id` then sends the person who accepts it to that route with `iss`,
and the sign-in it starts finds the account they just made already signed in.
The route checks `iss` against `PROTELES_ISSUER` and always signs in at
`PROTELES_ISSUER`, whatever `iss` names.

## Configuration (environment)

Server-side, read by the handlers from `process.env` on the first request (so
`vite build` does not need them) — same names as the other Proteles BFF
packages. Vite and SvelteKit load a `.env` file into `import.meta.env` and
`$env/*` only, not into `process.env`; the
[quickstart's `vite.config.js`](https://github.com/proteles-auth/proteles-sdk/blob/main/examples/sveltekit-quickstart/vite.config.js)
copies the `PROTELES_` ones across for development, and in production they come
from the real environment. Or pass them explicitly as the first argument.

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

Client-side, only `PUBLIC_PROTELES_BASE_PATH` is read (and only if you moved the
routes). Generate a session secret:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
```

## Svelte 4 and 5

The components use `export let` props and slots, which both major versions
support, so one build works for either. The store implements the plain Svelte
store contract (`subscribe` returning an unsubscriber) — no runes required.

## Develop

```bash
npm install      # from the repository root
npm run build    # svelte-package -> dist
npm test         # tsx + node:test
```

Tests cover the store contract and the SvelteKit handlers, and render the real
`.svelte` components through the Svelte compiler + `svelte/server` — no bundler
and no jsdom. The full loop also runs against a **live** server via
[`scripts/verify-sveltekit.mjs`](https://github.com/proteles-auth/proteles-sdk/blob/main/scripts/verify-sveltekit.mjs) (run by
Proteles' integration tests).
