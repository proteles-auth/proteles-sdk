# Proteles SolidStart quickstart

Authentication in a SolidStart app with three files, using
[`@proteles/solid`](../../packages/solid). Tokens live only in an encrypted,
`httpOnly` cookie on the server — the browser never sees one.

## The three files

```ts
// src/routes/api/auth/[...proteles].ts — the whole OAuth flow
export const GET = protelesAuthHandler;
export const POST = protelesAuthHandler;
```

```ts
// src/middleware.ts — user on the event + route protection
export default createMiddleware({
  onRequest: [
    async (event) => {
      await attachUser(event);
      return guardRequest(event, { publicPaths: ["/"] });
    },
  ],
});
```

```tsx
// src/app.tsx — make auth state available to the UI
<AuthProvider><Router>{/* … */}</Router></AuthProvider>
```

Then use the components anywhere: `<SignedIn>`, `<SignedOut>`, `<SignInButton>`,
`<UserButton>`, `useUser()`. See [`src/routes/index.tsx`](src/routes/index.tsx)
and the protected [`src/routes/dashboard.tsx`](src/routes/dashboard.tsx).

Remember Solid state is **accessors** — call them: `user()?.email`.

## Run it

Requires **Node 20.19+ or 22.12+** (SolidStart 1.3 and its Vite).

1. **Create an app (client).** Against a running Proteles server, mint a client
   via the Management API (or the dashboard). It must be confidential, use the
   `authorization_code` + `refresh_token` grants, and register the redirect URI
   `http://localhost:3000/api/auth/callback`:

   ```bash
   curl -sX POST http://localhost:8080/api/v1/apps \
     -H "Authorization: Bearer $MANAGEMENT_BOOTSTRAP_TOKEN" \
     -H 'content-type: application/json' \
     -d '{
       "tenant_id": "00000000-0000-0000-0000-000000000001",
       "client_name": "SolidStart Quickstart",
       "token_endpoint_auth_method": "client_secret_basic",
       "grant_types": ["authorization_code", "refresh_token"],
       "redirect_uris": ["http://localhost:3000/api/auth/callback"],
       "post_logout_redirect_uris": ["http://localhost:3000/"],
       "scopes": ["openid", "profile", "email", "offline_access"],
       "first_party": true
     }'
   ```

   With a tenant's own management key instead of the bootstrap token, send the
   same request to the tenant's host (for example
   `http://acme.localhost:8080/api/v1/apps`) without `tenant_id`.

2. **Configure.** `cp .env.example .env` and fill in `PROTELES_ISSUER`,
   `PROTELES_CLIENT_ID`, `PROTELES_CLIENT_SECRET`, and a generated
   `PROTELES_SESSION_SECRET`.

3. **Build the local SDK packages** (this example links them via `file:`), then
   install and run:

   ```bash
   ( cd ../.. && npm install && npm run build )   # build @proteles/js, /bff, /solid
   npm install
   npm run dev
   ```

4. Open <http://localhost:3000>, click **Sign in**, authenticate, and you're
   back — signed in, with `/dashboard` now reachable.

> In a real project you'd depend on the published `@proteles/*` packages instead
> of the `file:` links used here.

## Production

```bash
npm run build
npm start        # node --env-file=.env .output/server/index.mjs
```

`vinxi start` does not read `.env`, so `npm start` runs the build with Node's
`--env-file`. `PORT` picks the port.

The `.env` made for local development is not a production one. Before
`npm start` serves real users from it, delete `PROTELES_COOKIE_SECURE=false`
(otherwise the session cookie goes out without `Secure`) and set
`PROTELES_APP_URL` to the https origin you serve. A variable set in the host's
environment wins over the file, but only that variable: a host that sets
everything except `PROTELES_COOKIE_SECURE` still gets the file's `false`. On a
host that sets them all, leave the file out and run `node .output/server/index.mjs`
directly — `--env-file` stops at startup when its file is missing.

[`app.config.ts`](app.config.ts) dedupes `solid-js`. This example links the SDK
with `file:`, so without it the production bundle carries a second copy of
Solid from the SDK workspace, and the page renders blank with
`useAuth() must be called inside an <AuthProvider>`.

## How it's verified

[`scripts/verify-quickstart.mjs solidstart-quickstart`](../../scripts/verify-quickstart.mjs)
runs this example under `vinxi dev` (`--dev`) or as the production build and
walks it like a browser against a live server. The server bindings are plain
functions over events and `Response`s, so the full loop is also exercised
without SolidStart, against the **live** authorization server, by
[`scripts/verify-solid.mjs`](../../scripts/verify-solid.mjs), which Proteles'
integration tests run. It drives the
route handler through login → AS login → callback → `/me` → `attachUser` →
`guardRequest` (allowed *and* blocked) → logout, and server-renders the
**published SSR bundle** against the resulting session.
