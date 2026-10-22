# Proteles Alpine quickstart

A **no-build** page with authentication: two script tags and a couple of
directives, served by a ~40-line Node backend.

Tokens live only in an encrypted, `httpOnly` cookie on the server — open devtools
and `document.cookie` is empty.

## What's here

- [`public/index.html`](public/index.html) — the whole frontend. Two `<script>`
  tags, `x-data` on `<body>`, and `x-signed-in` / `x-signed-out` blocks using
  `$auth`.
- [`server.mjs`](server.mjs) — the whole backend. A plain `node:http` server that
  serves the page and hands `/api/auth/*` to `@proteles/bff` via its
  `toWebRequest` + `sendNodeResponse` helpers. Express/Fastify/Koa wire up the
  same way.

## Run it

Requires **Node 20.6+** (for `--env-file`) and a running Proteles server.

1. **Create an app (client)** whose redirect URI is
   `http://localhost:3500/api/auth/callback`:

   ```bash
   curl -sX POST http://localhost:8080/api/v1/apps \
     -H "Authorization: Bearer $MANAGEMENT_BOOTSTRAP_TOKEN" \
     -H 'content-type: application/json' \
     -d '{
       "tenant_id": "00000000-0000-0000-0000-000000000001",
       "client_name": "Alpine Quickstart",
       "token_endpoint_auth_method": "client_secret_basic",
       "grant_types": ["authorization_code", "refresh_token"],
       "redirect_uris": ["http://localhost:3500/api/auth/callback"],
       "post_logout_redirect_uris": ["http://localhost:3500/"],
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

3. **Build the local SDK packages** (this example links them via `file:`), then
   install and run:

   ```bash
   ( cd ../.. && npm install && npm run build )   # build @proteles/js, /bff, /alpine
   npm install
   npm start
   ```

4. Open <http://localhost:3500>, click **Sign in**, authenticate, and you're back
   — signed in, with the signed-out block hidden.

> The page loads the SDK bundle from `/proteles-alpine.js`, which the server maps
> to `node_modules`. In production, use the CDN URL shown in `index.html`.

## Two things worth copying

**`x-data` on `<body>`.** Alpine only initializes directives inside an `x-data`
tree. Without it, `x-signed-in` never runs and its content stays visible to
signed-out visitors. One empty `x-data` at the root covers the page.

**Diagnose failures from the server log.** Login failures are deliberately opaque
to the browser (`?proteles_error=login_failed`), but the BFF logs the actual
reason server-side, e.g.:

```
[proteles] callback failed: token exchange or userinfo failed: authorization server rejected the request: invalid_client
```

## How it's verified

The server half runs over real HTTP against a live authorization server in
Proteles' integration tests — see
[`verify-alpine.mjs`](../../scripts/verify-alpine.mjs). It stands up this
same backend, drives login → callback → `/me` → logout with cookies crossing the
wire, and checks that the callback emits its two `Set-Cookie` headers separately.
The published browser bundle is checked there too.

The Alpine layer itself (directives, store, `$auth`) is verified in a real
browser, since Alpine cannot run in Node.
