# @proteles/alpine

> **You need a Proteles account.** Proteles is a hosted sign-in service, and this
> package is a client for it: without an account it does nothing.
> [Sign up for free on proteles.com](https://proteles.com/signup), then register your app to get its
> issuer, client ID and secret.

Alpine.js plugin for Proteles authentication — **no build step required**.

Tokens live only in an encrypted, `httpOnly` cookie set by your own server. The
browser never receives one, only the sanitized user from `/api/auth/me`.

Alpine has no component model, so this package looks different from the other
framework SDKs: instead of `<SignedIn>` components you get a reactive store, a
`$auth` magic, and two directives you put on any element.

## The two-script setup

```html
<!-- 1. Proteles first, so it can hook alpine:init before Alpine starts -->
<script src="https://cdn.jsdelivr.net/npm/@proteles/alpine@0.3.0/dist/proteles-alpine.js"
        integrity="sha384-REPLACE-WITH-THE-HASH-BELOW" crossorigin="anonymous"></script>
<!-- 2. Alpine -->
<script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.15.12/dist/cdn.min.js"
        integrity="sha384-REPLACE-WITH-THE-HASH-BELOW" crossorigin="anonymous"></script>

<body x-data>
  <div x-signed-out>
    <button @click="$auth.signIn()">Sign in</button>
  </div>

  <div x-signed-in>
    Hi <span x-text="$auth.user?.email"></span>
    <button @click="$auth.signOut()">Sign out</button>
  </div>
</body>
```

That's it — the bundle registers itself on `alpine:init`.

### Pin the version, and the hash

A CDN URL without a version runs whatever was published last, from the moment
it is published, on your sign-in page. So name an exact version, and give the
browser the hash of the file you reviewed: with `integrity`, it refuses any
other bytes. Compute each hash once, for the exact URL you load:

```bash
curl -fsSL https://cdn.jsdelivr.net/npm/@proteles/alpine@0.3.0/dist/proteles-alpine.js | openssl dgst -sha384 -binary | openssl base64 -A
```

and write `integrity="sha384-<what that prints>"`. Until you do, the
placeholder above makes the browser refuse the script, which fails closed. To
avoid the CDN altogether, serve `node_modules/@proteles/alpine/dist/proteles-alpine.js`
from your own origin.

### ⚠️ You need `x-data` somewhere above your directives

Alpine only initializes directives **inside an `x-data` tree**. An element with
`x-signed-in` and no `x-data` ancestor is silently never processed, so it stays
visible — showing signed-in content to signed-out visitors. One empty `x-data`
on `<body>` (as above) covers the whole page and is the simplest fix.

### With a bundler instead

```bash
npm install @proteles/alpine alpinejs
```

```js
import Alpine from "alpinejs";
import { protelesAuth } from "@proteles/alpine";

Alpine.plugin(protelesAuth());
Alpine.start();
```

## What the plugin registers

| Thing | Use |
| --- | --- |
| `Alpine.store("proteles")` | `$store.proteles.user`, etc. |
| `$auth` magic | `$auth.user`, `$auth.isLoading`, `$auth.isAuthenticated`, `$auth.isUnavailable`, `$auth.signIn()`, `$auth.signUp()`, `$auth.signOut()`, `$auth.reload()` |
| `x-signed-in` | shows the element only when signed in |
| `x-signed-out` | shows the element only when signed out |

Both directives keep the element **hidden until who is signed in is known** —
from `initialUser`, or from the first answer to `/api/auth/me`, which a busy
spell (below) does not give — so neither branch flashes the wrong UI. They set
`display` the way `x-show` does, and restore the element's original value when
revealing it.
`$auth.isLoading` is there if you want an explicit placeholder.

`Alpine.store()` provides the reactivity: the store is a plain object, and
Alpine's `init()` convention triggers the first revalidation automatically.

## Sign-up

```html
<button @click="$auth.signUp()">Create an account</button>
```

`$auth.signUp({ returnTo })` sends the person through `/api/auth/signup` to the
workspace's hosted sign-up page. They give their email address, follow the link
they are mailed, choose a password, and come back to `returnTo` (by default the
page they were on) signed in, as after a sign-in. Where the workspace has not
opened its sign-up page, they see the ordinary sign-in page instead.

It takes no `connection`. For a sign-up through a social provider, use
`$auth.signIn({ connection })`: a first sign-in through it makes an account
where the workspace allows that.

## When the sign-in service is busy

While the authorization server is too busy to refresh a session, the BFF's
`/api/auth/me` answers `503` and keeps the session cookie. That — or a `429`, a
`408`, any other `5xx`, or no answer at all — is read as "could not tell", not
as signed out: `$auth.user` stays the last one known (`$auth.isLoading` stays
`true` if no answer has come yet), `$auth.isUnavailable` turns `true`, and `/me`
is asked again after the server's `Retry-After` (capped at an hour) or, when it
named none, after 2 s, 4 s, 8 s and so on up to 30 s. The next answer clears
`$auth.isUnavailable`. A `401`, or `{ authenticated: false }`, still means
signed out, as before.

`x-signed-in` keeps showing its element for the known user meanwhile; read
`$auth.isUnavailable` to tell them the service is busy.

## Options

```js
Alpine.plugin(protelesAuth({
  basePath: "/api/auth",     // BFF mount path (default; or VITE_PROTELES_BASE_PATH)
  initialUser: serverUser,   // skip the signed-out flash if the page knows the user
  revalidateOnInit: true,    // set false to trust initialUser and save a request
  storeName: "proteles",     // Alpine store name
  magicName: "auth",         // so `$auth`
}));
```

With the CDN build, set `window.protelesAuthOptions = {...}` **before** the
script tag, or `window.protelesAuthOptions = null` to opt out of
auto-registration and call `Alpine.plugin(protelesAuth({...}))` yourself.

## The server half

Alpine is client-only, so there's no meta-framework to plug into: you serve
`/api/auth/*` from whatever backend you have. With Node, that's about ten lines
using [`@proteles/bff`](https://www.npmjs.com/package/@proteles/bff):

```js
import http from "node:http";
import { AuthApp, sendNodeResponse, toWebRequest } from "@proteles/bff";

const auth = new AuthApp(); // reads PROTELES_* from the environment

http.createServer(async (req, res) => {
  if (req.url.startsWith("/api/auth/")) {
    await sendNodeResponse(res, await auth.handle(toWebRequest({ node: { req } })));
    return;
  }
  // …serve your pages
}).listen(3000);
```

See [`examples/alpine-quickstart`](https://github.com/proteles-auth/proteles-sdk/tree/main/examples/alpine-quickstart) for a
complete runnable version. In another language, implement the same four routes
— the example's ~40-line Node backend shows all of them. If you
call `$auth.signUp()`, add `/signup`: `/login`'s authorization request with
`prompt=create`.

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

## Configuration (environment)

Server-side, read by `@proteles/bff`: `PROTELES_ISSUER`, `PROTELES_CLIENT_ID`,
`PROTELES_CLIENT_SECRET`, `PROTELES_SESSION_SECRET` (base64 of 32 random bytes),
`PROTELES_APP_URL` or `PROTELES_REDIRECT_URI`, plus optional `PROTELES_SCOPES`,
`PROTELES_COOKIE_SECURE`, `PROTELES_BASE_PATH`.

Client-side, only `VITE_PROTELES_BASE_PATH` is read, and only under a bundler.

## Develop

```bash
npm install      # from the repository root
npm run build    # tsc (ESM + types) + esbuild (standalone browser bundle)
npm test         # tsx + node:test
```

**How this package is tested.** Alpine can't be imported in Node at all — it
touches `MutationObserver` at module scope — so the unit tests run against a
faithful stub of the three plugin APIs used (`store`, `magic`, `directive`),
including Alpine's reactivity and its `init()` call. Separate tests evaluate the
*built* browser bundle in a fake-window sandbox to prove it's self-contained and
self-registering.

Real-DOM behaviour is verified in an actual browser, and the server half runs
over real HTTP against a live authorization server in Proteles' integration
tests (see
[`verify-alpine.mjs`](https://github.com/proteles-auth/proteles-sdk/blob/main/scripts/verify-alpine.mjs)).
