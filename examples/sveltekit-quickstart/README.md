# Proteles SvelteKit quickstart

Authentication in a SvelteKit app with three files, using
[`@proteles/svelte`](../../packages/svelte). Tokens live only in an encrypted,
`httpOnly` cookie on the server — the browser never sees one.

## The three files

```ts
// src/routes/api/auth/[...proteles]/+server.ts — the whole OAuth flow
export const { GET, POST } = createAuthHandlers();
```

```ts
// src/hooks.server.ts — user on locals + route protection
export const handle = createAuthHandle(undefined, { publicPaths: ["/"] });
```

```svelte
<!-- src/routes/+layout.svelte — make auth state available to the UI -->
<AuthProvider initialUser={data.user}><slot /></AuthProvider>
```

(with a one-line `+layout.server.ts` handing `getUser(event)` to that layout).

Then use the components anywhere: `<SignedIn>`, `<SignedOut>`, `<SignInButton>`,
`<UserButton>`, `getAuth()`. See [`src/routes/+page.svelte`](src/routes/+page.svelte)
and the protected [`src/routes/dashboard`](src/routes/dashboard).

## Run it

Requires **Node 20+**. SvelteKit 2 runs on 18.13, but Node 18's `fetch` tries
`localhost` over IPv6 first and does not fall back to IPv4, so the app's calls to
a local Proteles server listening on IPv4 are refused — and 18 is past its end
of life.

1. **Create an app (client).** Against a running Proteles server, mint a client
   via the Management API (or the dashboard). It must be confidential, use the
   `authorization_code` + `refresh_token` grants, and register the redirect URI
   `http://localhost:5173/api/auth/callback`:

   ```bash
   curl -sX POST http://localhost:8080/api/v1/apps \
     -H "Authorization: Bearer $MANAGEMENT_BOOTSTRAP_TOKEN" \
     -H 'content-type: application/json' \
     -d '{
       "tenant_id": "00000000-0000-0000-0000-000000000001",
       "client_name": "SvelteKit Quickstart",
       "token_endpoint_auth_method": "client_secret_basic",
       "grant_types": ["authorization_code", "refresh_token"],
       "redirect_uris": ["http://localhost:5173/api/auth/callback"],
       "post_logout_redirect_uris": ["http://localhost:5173/"],
       "scopes": ["openid", "profile", "email", "offline_access"],
       "first_party": true
     }'
   ```

   With a tenant's own management key instead of the bootstrap token, send the
   same request to the tenant's host (for example
   `http://acme.localhost:8080/api/v1/apps`) without `tenant_id`.

2. **Configure.** `cp .env.example .env` and fill in `PROTELES_ISSUER`,
   `PROTELES_CLIENT_ID`, `PROTELES_CLIENT_SECRET`, and a generated
   `PROTELES_SESSION_SECRET`. The SDK reads these from `process.env`, where Vite
   does not put a `.env` file's values, so [`vite.config.js`](vite.config.js)
   copies the `PROTELES_` ones across for `npm run dev`, `npm run build` and
   `npm run preview`. Copy those lines if you start from your own config.

3. **Build the local SDK packages** (this example links them via `file:`), then
   install and run:

   ```bash
   ( cd ../.. && npm install && npm run build )   # build @proteles/js, /bff, /svelte
   npm install
   npm run dev
   ```

4. Open <http://localhost:5173>, click **Sign in**, authenticate, and you're
   back — signed in, with `/dashboard` now reachable.

> In a real project you'd depend on the published `@proteles/*` packages instead
> of the `file:` links used here.

## Production

`npm run build` needs none of the variables: the SDK reads them on the first
request. `adapter-auto` picks an adapter for the platform it detects; on your
own server, use `@sveltejs/adapter-node` and start it with the variables in the
environment (`node --env-file=.env build`, Node 20.6+). If that is the `.env`
from local development, first delete its `PROTELES_COOKIE_SECURE=false`
(otherwise the session cookie goes out without `Secure`) and set
`PROTELES_APP_URL` to the https origin you serve: a variable set in the host's
environment overrides only itself. A platform with no
`process.env` needs the configuration passed explicitly, for example from
`$env/dynamic/private`, as the first argument to `createAuthHandlers` and
`createAuthHandle`.

## How it's verified

[`scripts/verify-quickstart.mjs sveltekit-quickstart`](../../scripts/verify-quickstart.mjs)
runs this example under `vite dev` (`--dev`) or `vite build` + `vite preview`
and walks it like a browser against a live server. The server bindings are also
plain functions over Web `Request`/`Response`, so the full loop is exercised
without SvelteKit, against the **live** authorization server, by
[`scripts/verify-sveltekit.mjs`](../../scripts/verify-sveltekit.mjs), which
Proteles' integration tests run. It
drives `+server.ts` login → AS login → callback → `/me` → the `handle` hook
(both allowed and guarded) → logout, and server-renders the **published**
components against the resulting session.
