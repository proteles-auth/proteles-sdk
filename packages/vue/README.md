# @proteles/vue

> **You need a Proteles account.** Proteles is a hosted sign-in service, and this
> package is a client for it: without an account it does nothing.
> [Sign up for free on proteles.com](https://proteles.com/signup), then register your app to get its
> issuer, client ID and secret.

Vue 3 composables and components for Proteles authentication, plus the Nuxt/h3
server handlers.

Tokens live only in an encrypted, `httpOnly` cookie set by your own server — the
browser never receives one, only the sanitized user from `/api/auth/me`.

## Install

```bash
npm install @proteles/vue
```

## The five-minute setup (Nuxt)

**1. The auth routes** — the whole OAuth flow, in one file:

```ts
// server/routes/api/auth/[...proteles].ts
import { protelesAuthHandler } from "@proteles/vue/server";

export default defineEventHandler((event) => protelesAuthHandler(event));
```

**2. Server middleware** — put the user on the event and guard routes:

```ts
// server/middleware/proteles.ts
import { getUser, guardRequest, CONTEXT_USER_KEY } from "@proteles/vue/server";

export default defineEventHandler(async (event) => {
  event.context[CONTEXT_USER_KEY] = await getUser(event);
  const redirect = await guardRequest(event, { publicPaths: ["/"] });
  if (redirect) return redirect;
});
```

**3. Install the plugin** with the server-known user, so the first paint is right.
Take the user the middleware put on `event.context` — not `useFetch("/api/auth/me")`
during server rendering, which refreshes an expired access token and rotates
the refresh token without Nuxt passing the new cookie on to the browser, which
is then signed out on its next refresh:

```ts
// plugins/proteles.ts (as in the Nuxt quickstart)
import { protelesAuth } from "@proteles/vue";

type InitialUser = { user: Record<string, unknown> | null; known: boolean };

export default defineNuxtPlugin(async (nuxtApp) => {
  // Set on the server, carried to the browser in the payload.
  const initial = useState<InitialUser | null>("proteles-initial-user", () => null);
  if (import.meta.server) {
    const { CONTEXT_USER_KEY } = await import("@proteles/vue/server");
    const { cookieNames } = await import("@proteles/bff");
    const user = (useRequestEvent()?.context[CONTEXT_USER_KEY] as InitialUser["user"] | undefined) ?? null;
    // No user but a session cookie: an expired access token (or a dead
    // session) that only /api/auth/me can settle. Render "loading" rather than
    // "signed out" until it has. The name follows PROTELES_COOKIE_SECURE, as the
    // server middleware's own configuration does.
    initial.value = { user, known: user !== null || !useCookie(cookieNames().session).value };
  }
  nuxtApp.vueApp.use(protelesAuth({ initialUser: initial.value?.known ? (initial.value.user as never) : undefined }));
});
```

A session cookie the middleware could not read as live (an expired access
token) renders as "loading" until `/api/auth/me` has refreshed it, rather than
as "signed out". `cookieNames` comes from `@proteles/bff`, a dependency of
this package; list it in your own `package.json` to import it, as the
quickstart does. It gives `__Host-proteles_session` whenever cookies are
`Secure` and `proteles_session` when `PROTELES_COOKIE_SECURE=false`; if you set
`cookieSecure` in code rather than the environment, pass the same value.

Then use the components anywhere:

```vue
<script setup>
import { SignedIn, SignedOut, SignInButton, UserButton, useUser } from "@proteles/vue";

const { user } = useUser();
</script>

<template>
  <SignedOut>
    <SignInButton />
  </SignedOut>

  <SignedIn>
    Hi {{ user?.email }} <UserButton />
  </SignedIn>
</template>
```

### Plain Vue (no Nuxt)

```ts
// main.ts
import { createApp } from "vue";
import { protelesAuth } from "@proteles/vue";
import App from "./App.vue";

createApp(App).use(protelesAuth()).mount("#app");
```

You still need a server serving `/api/auth/*` — use
[`@proteles/bff`](https://www.npmjs.com/package/@proteles/bff) directly in whatever backend you have.

## Client API

### `protelesAuth(options?)` — the plugin

The idiomatic install. Provides auth to every component and revalidates against
`/api/auth/me` once mounted (so a stale `initialUser` — e.g. after a logout in
another tab — self-corrects).

| Option | Notes |
| --- | --- |
| `initialUser` | From the server. Omit = fetch on mount, `null` = known signed-out, an object = known signed-in. |
| `basePath` | BFF mount path. Defaults to `VITE_PROTELES_BASE_PATH` or `/api/auth`. |

`protelesAuth()` also returns its `auth` object, if you want a reference outside
components: `const { auth } = protelesAuth()`.

### `<AuthProvider>`

The component alternative to the plugin — use it to scope auth to a subtree, or
where you don't control the app instance. Takes the same props.

### `useUser()` / `useAuth()`

```vue
<script setup>
import { useAuth } from "@proteles/vue";

const { user, isLoading, isAuthenticated, signIn, signUp, signOut, reload } = useAuth();
</script>

<template>
  <p v-if="isLoading">Loading…</p>
  <p v-else-if="isAuthenticated">{{ user.sub }}</p>
  <button @click="signIn({ connection: 'google' })">Google</button>
</template>
```

`user`, `isLoading`, `isAuthenticated` and `isUnavailable` are refs, so they
unwrap in templates and stay reactive in `watch`/`computed`. `useUser()` returns
just those four.
Both throw a clear error if used without the plugin or an `<AuthProvider>`.

### Components

| Component | Renders |
| --- | --- |
| `<SignedIn>` | its slot when a user is signed in |
| `<SignedOut>` | its slot when no user is signed in |
| `<Protect>` | its default slot when signed in, else the `fallback` slot (nothing while loading) |
| `<SignInButton return-to? connection?>` | a button that starts login (`connection` picks a social provider) |
| `<SignUpButton return-to?>` | a button that starts sign-up ([below](#sign-up)) |
| `<SignOutButton return-to?>` | a button that logs out |
| `<UserButton>` | the user's name/email plus a sign-out control |

`<SignInButton>`/`<SignUpButton>`/`<SignOutButton>`/`<UserButton>` are unstyled
by design, and `class` reaches their root element through Vue's normal
attribute inheritance.

That does **not** apply to `<SignedIn>`, `<SignedOut>` and `<Protect>`: they
render their slot directly, so their root is a fragment, and Vue does not
inherit attributes onto a fragment root. A `class` there is dropped and Vue
warns about extraneous non-props attributes. Wrap them in an element you style
yourself.

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
as signed out: `user` stays the last one known (`isLoading` stays `true` if no
answer has come yet), `isUnavailable` turns `true`, and `/me` is asked again
after the server's `Retry-After` (capped at an hour) or, when it named none,
after 2 s, 4 s, 8 s and so on up to 30 s. The next answer clears
`isUnavailable`. A `401`, or `{ authenticated: false }`, still means signed out,
as before.

`<SignedIn>` keeps rendering for the known user meanwhile; read `isUnavailable`
to tell them the service is busy. An `<AuthProvider>` that unmounts stops
asking, and so does the plugin when its app unmounts (Vue 3.5 and later).

## Server API (`@proteles/vue/server`)

| Export | Purpose |
| --- | --- |
| `protelesAuthHandler(event, config?)` | Handles `login`/`callback`/`logout`/`me`; return it straight from an h3 handler |
| `getUser(event, config?)` | The sanitized user (no tokens) — prefers `event.context`, falls back to the cookie |
| `getSession(event, config?)` | The full session **including tokens** — server-side only |
| `guardRequest(event, { publicPaths }, config?)` | A redirect `Response` when the request should bounce to login, else `undefined` |
| `toWebRequest(source)` | The adapter: accepts a Web `Request`, `{ request }`, `{ web: { request } }`, or an h3 event's `node.req` |

`publicPaths` entries match exactly or as a path-segment prefix: `"/blog"` covers
`/blog` and `/blog/post` but not `/blogging`. `"/"` is **exact-only**, so listing
the home page doesn't accidentally make the whole app public.

The auth endpoints are driven entirely by the URL, method, and cookie header —
none reads a request body — so `toWebRequest` never consumes one, and a body your
framework needs downstream stays intact.

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

## Authoring note

The components are `defineComponent` render functions rather than `.vue` SFCs.
They're tiny and headless, so this keeps the package a plain TypeScript build —
no SFC compiler, no bundler — and directly unit-testable. From the outside
nothing changes: you use `<SignedIn>` in your own SFCs as normal.

## Develop

```bash
npm install      # from the repository root
npm run build    # tsc -> dist
npm test         # tsx + node:test
```

Tests cover the reactive auth object, the components (server-rendered via
`@vue/server-renderer` — no jsdom), and the Nuxt/h3 bindings including the
event-to-Request adapter. The full loop also runs against a **live** server via
[`scripts/verify-nuxt.mjs`](https://github.com/proteles-auth/proteles-sdk/blob/main/scripts/verify-nuxt.mjs) (run by
Proteles' integration tests).
