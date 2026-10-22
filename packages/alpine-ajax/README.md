# @proteles/alpine-ajax

> **You need a Proteles account.** Proteles is a hosted sign-in service, and this
> package is a client for it: without an account it does nothing.
> [Sign up for free on proteles.com](https://proteles.com/signup), then register your app to get its
> issuer, client ID and secret.

Server helpers for [Alpine AJAX](https://alpine-ajax.js.org) apps authenticating
with [Proteles](https://proteles.com).

Alpine AJAX keeps no client auth state — the server renders the HTML — so this
package is **server-only**. There is no browser bundle and no client-side auth
script to keep in sync, which is rather the point of choosing it.

## Install

```bash
npm install @proteles/alpine-ajax
```

## The one rule

**Your sign-in, sign-up and sign-out controls carry no `x-target`.**

```html
<!-- right: a real navigation to the authorization server -->
<a href="/api/auth/login">Sign in</a>
<a href="/api/auth/signup">Sign up</a>
<form method="post" action="/api/auth/logout"><button>Sign out</button></form>

<!-- wrong: fetches the sign-in page and merges it into #app -->
<a href="/api/auth/login" x-target="app">Sign in</a>
```

That is not a style preference, and it is worth understanding why, because it is
the difference between this package and its htmx sibling.

htmx has the same underlying problem — XHR follows redirects, so an
unauthenticated fragment request ends up swapping a login page into a table cell
— and htmx supplies an escape hatch: answer `200` with `HX-Redirect` and the
browser navigates. `@proteles/htmx` is essentially that one rewrite.

Alpine AJAX has no such hatch. Its own reference is explicit: *"The JavaScript
Fetch API follows all redirects transparently, so Alpine AJAX cannot distinguish
between 300 class status codes."* No response header makes it navigate. A server
**cannot** force a full page load.

So this package does not try. Signing in is a navigation, so it stays one.

## What it does instead

Alpine AJAX merges response bodies for **every** status, including 4xx. So the
right answer to "this fragment needs a session" is not a redirect that `fetch`
will silently follow — it is a `401` whose body is addressed to the ids the
caller asked for in `X-Alpine-Target`.

The user sees *"Sign in to see this. — Sign in"* exactly where the content
would have gone, and the link brings them back to the page — read from the
request's `Referer`, path only, on the configured origin — rather than to the
fragment's own URL. No login page in a table cell, no address bar surprise, and the
status is a real one that `x-target.4xx`, an `ajax:error` listener and your logs
can all key on.

```js
import { protelesAuthHandler, requireUser } from "@proteles/alpine-ajax";
import { sendNodeResponse } from "@proteles/bff";

// the auth routes
if (url.pathname.startsWith("/api/auth/")) {
  return sendNodeResponse(res, await protelesAuthHandler({ node: { req } }));
}

// a route that renders a fragment
const auth = await requireUser({ node: { req } });
if (auth.response) return sendNodeResponse(res, auth.response);
html(res, `<div id="profile">Hello ${auth.user.email}</div>`);
```

The id in the body matters. Alpine merges by id, and a response that does not
contain the requested one fires `ajax:missing` and swaps nothing — which, to the
person clicking, is indistinguishable from the click not working. `requireUser`
takes the ids from the request rather than guessing.

## API

| Export | What it does |
| --- | --- |
| `protelesAuthHandler(source, config?)` | Handles `login`, `signup`, `callback`, `logout`, `me`, `revalidate`. Redirects stay redirects. |
| `guardRequest(source, options?, config?)` | Middleware guard. Returns a response to send, or `undefined` to continue. |
| `requireUser(source, options?, config?)` | In-route guard. Returns `{ user }` or `{ response }`. |
| `getUser(source, config?)` | The sanitized user (no tokens), or `null`. |
| `attachUser(source, config?)` | Same, cached on the framework's context bag. |
| `getSession(source, config?)` | The full session **including tokens** — server-side only. |
| `isAlpineRequest(source)` | Whether `X-Alpine-Request: true` is set. |
| `alpineTargets(source)` | The ids from `X-Alpine-Target`. |
| `signInFragment(targets, options)` | The body `requireUser` sends, if you want to build your own. |

`options` on the two guards takes `message` and `linkText` to change the copy,
and `guardRequest` also takes `publicPaths`.

`/api/auth/signup` is `/login` opening on the workspace's hosted sign-up page,
which signs the new person in and brings them back to `returnTo`. Where the
workspace has not opened that page, the person sees the ordinary sign-in page.
See [`@proteles/bff`](https://www.npmjs.com/package/@proteles/bff#sign-up).

### Reacting on the client

The `401` is a normal Alpine response, so the usual hooks work:

```html
<div id="profile" x-init x-target="profile"
     @ajax:error="if ($event.detail.status === 401) location.reload()">
</div>
```

Reloading is often the friendliest thing: the guarded page then does a real
navigation to sign-in, with `returnTo` already set.

## Inviting people into your app

Register `<your app>/api/auth/login` as the app's sign-in start address (its
`initiate_login_uri`). An invitation sent through the Management API with the
app's `client_id` then sends the person who accepts it to that route with `iss`,
and the sign-in it starts finds the account they just made already signed in.
The route checks `iss` against `PROTELES_ISSUER` and always signs in at
`PROTELES_ISSUER`, whatever `iss` names.

## Security notes

`X-Alpine-Target` is a request header, so it is attacker-controlled, and it is
interpolated into HTML. Ids that could not be Alpine targets anyway — anything
outside `[A-Za-z][\w:.-]*`, or longer than 128 characters — are dropped rather
than escaped, which removes the question instead of answering it. Everything
that is interpolated is escaped as well.

The sign-in response is `Cache-Control: no-store`. It is per-session by
definition, and a shared cache handing it to the next visitor would be worse
than useless.

## Develop

```bash
npm run build      # tsc
npm run typecheck
npm test
```

The live loop against a real authorization server is
[`scripts/verify-alpine-ajax.mjs`](https://github.com/proteles-auth/proteles-sdk/blob/main/scripts/verify-alpine-ajax.mjs),
which Proteles' integration tests run.
