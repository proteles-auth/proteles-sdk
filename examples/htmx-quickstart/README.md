# Proteles htmx quickstart

A complete htmx app with authentication, in **one file** — and with **no
client-side auth code at all**. The server renders auth-aware fragments, which is
the htmx way.

## What's here

[`server.mjs`](server.mjs) is the whole app. Four things to read:

| Route | What it shows |
| --- | --- |
| `/api/auth/*` | handed straight to `protelesAuthHandler` |
| `/fragments/user` | an auth-aware fragment — renders either branch, no guard needed |
| `/fragments/secret` | a fragment that *requires* a user, guarded by `requireUser` |
| `/dashboard` | a protected page, guarded by `guardRequest` |

The HTML has no auth attributes beyond ordinary htmx:

```html
<button hx-get="/api/auth/login">Sign in</button>
<button hx-post="/api/auth/logout">Sign out</button>
<div hx-get="/fragments/user" hx-trigger="load" hx-swap="outerHTML"></div>
```

## Run it

Requires **Node 20.6+** (for `--env-file`) and a running Proteles server.

1. **Create an app (client)** whose redirect URI is
   `http://localhost:3600/api/auth/callback`:

   ```bash
   curl -sX POST http://localhost:8080/api/v1/apps \
     -H "Authorization: Bearer $MANAGEMENT_BOOTSTRAP_TOKEN" \
     -H 'content-type: application/json' \
     -d '{
       "tenant_id": "00000000-0000-0000-0000-000000000001",
       "client_name": "htmx Quickstart",
       "token_endpoint_auth_method": "client_secret_basic",
       "grant_types": ["authorization_code", "refresh_token"],
       "redirect_uris": ["http://localhost:3600/api/auth/callback"],
       "post_logout_redirect_uris": ["http://localhost:3600/"],
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

3. **Build the local SDK packages** (linked via `file:`), then install and run:

   ```bash
   ( cd ../.. && npm install && npm run build )   # build @proteles/js, /bff, /htmx
   npm install
   npm start
   ```

4. Open <http://localhost:3600>.

## The thing to actually try

While **signed out**, click **“Load a protected fragment.”**

The browser navigates to the login page — a real navigation, address bar and all.

That is the whole point of this package. Without the `HX-Redirect` conversion,
htmx would follow the `302` with XHR and swap the **login form into the little
`#secret` div**, leaving you on the same URL wondering what happened. Verified in
a real browser as part of this example's checks.

Sign in, and you are back on the page you clicked from — not on the fragment's
own URL, which as a page would be a bare `<p>`: `requireUser` names the page
htmx sends in `HX-Current-URL` (its path, on this app's configured origin). Click
it again: the fragment renders inline, as fragments should.

## How it's verified

htmx auth is entirely about which headers come back, so it's fully scriptable:
Proteles' integration tests — see
[`verify-htmx.mjs`](../../scripts/verify-htmx.mjs) — stand up this backend
and drives a real login against a live authorization server, asserting at each
step that an htmx caller gets `HX-Redirect` where a browser gets a `3xx`,
including the `hx-post` logout and the deliberate exception for the callback.
