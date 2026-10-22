# Proteles Alpine AJAX quickstart

A complete [Alpine AJAX](https://alpine-ajax.js.org) app with authentication, in
**one file** — and with **no client-side auth code at all**. The server renders
auth-aware fragments, which is the point of choosing a hypermedia library.

## What's here

[`server.mjs`](server.mjs) is the whole app. Four things to read:

| Route | What it shows |
| --- | --- |
| `/api/auth/*` | handed straight to `protelesAuthHandler` |
| `/fragments/user` | an auth-aware fragment — renders either branch, no guard needed |
| `/fragments/secret` | a fragment that *requires* a user, guarded by `requireUser` |
| `/dashboard` | a protected page, guarded by `guardRequest` |

## The one rule

**The sign-in and sign-out controls carry no `x-target`.**

```html
<a href="/api/auth/login">Sign in</a>
<form method="post" action="/api/auth/logout"><button>Sign out</button></form>
<div id="user" x-init="$ajax('/fragments/user')"></div>
```

Alpine AJAX cannot be told by the server to navigate. Its reference is explicit:
*"The JavaScript Fetch API follows all redirects transparently, so Alpine AJAX
cannot distinguish between 300 class status codes."* So an `x-target` on the
sign-in link would fetch the authorization server's sign-in page and merge it
into your layout — the classic hypermedia auth bug, and there is no response
header that fixes it.

Signing in is a navigation. Leave it one.

## What happens to a guarded fragment

Try `Load a protected fragment` while signed out. The request is answered with a
**401** whose body carries `id="secret"` — the id the click asked for — so Alpine
merges *"Sign in to see this. — Sign in"* exactly where the content would have
gone. That link returns you to the page after signing in, not to the fragment's
own URL (which as a page would be a bare `<div>`): the page is read from the
request's `Referer`, path only and only from this app's configured origin.

That is what `@proteles/alpine-ajax` adds over the raw BFF: Alpine merges
response bodies on error statuses too, so the right answer is a 401 addressed to
the caller's target rather than a redirect `fetch` would silently follow.

## Run it

Requires **Node 20.6+** (for `--env-file`) and a running Proteles server.

1. **Create an app (client)** whose redirect URI is
   `http://localhost:3700/api/auth/callback`:

   ```bash
   curl -sX POST http://localhost:8080/api/v1/apps \
     -H "Authorization: Bearer $MANAGEMENT_BOOTSTRAP_TOKEN" \
     -H 'content-type: application/json' \
     -d '{
       "tenant_id": "00000000-0000-0000-0000-000000000001",
       "client_name": "Alpine AJAX Quickstart",
       "token_endpoint_auth_method": "client_secret_basic",
       "grant_types": ["authorization_code", "refresh_token"],
       "redirect_uris": ["http://localhost:3700/api/auth/callback"],
       "post_logout_redirect_uris": ["http://localhost:3700/"],
       "scopes": ["openid", "profile", "email", "offline_access"],
       "first_party": true
     }'
   ```

   With a tenant's own management key instead of the bootstrap token, send the
   same request to the tenant's host (for example
   `http://acme.localhost:8080/api/v1/apps`) without `tenant_id`.

2. **Configure.** `cp .env.example .env` and fill it in. `npm start` reads it
   with Node's `--env-file`; variables already in the environment win, which is
   how a host would set them. Without a `.env`, run `node server.mjs` directly.

3. **Build the local SDK packages** (this example links them via `file:`, and
   their `dist/` is not committed), then install and run:

   ```bash
   ( cd ../.. && npm install && npm run build )   # build @proteles/js, /bff, /alpine-ajax
   npm install
   npm start
   ```

4. Open <http://localhost:3700>.

## Things worth noticing

* `document.cookie` is empty. The tokens live in an encrypted, httpOnly cookie
  the browser cannot read — that is the BFF pattern, and it is why this app has
  no client-side auth code to get wrong.
* The 401 is a real status, so `x-target.4xx`, an `ajax:error` listener and your
  access log can all see that a session expired. Answering with 200 would make
  the one interesting event in the flow invisible to every one of them.
* Nothing here is Alpine-AJAX-specific except the markup. The same server
  functions back the htmx, Svelte, Vue, Solid and Next examples.
