# Proteles Nuxt quickstart

Authentication in a Nuxt app with three files, using
[`@proteles/vue`](../../packages/vue). Tokens live only in an encrypted,
`httpOnly` cookie on the server — the browser never sees one.

## The three files

```ts
// server/routes/api/auth/[...proteles].ts — the whole OAuth flow
export default defineEventHandler((event) => protelesAuthHandler(event));
```

```ts
// server/middleware/proteles.ts — user on context + route protection
event.context[CONTEXT_USER_KEY] = await getUser(event);
const redirect = await guardRequest(event, { publicPaths: ["/"] });
if (redirect) return redirect;
```

```ts
// plugins/proteles.ts — make auth state available to the UI, seeded with the
// user the middleware read on the server
nuxtApp.vueApp.use(protelesAuth({ initialUser }));
```

Seed the plugin from what the server middleware put on `event.context`, as
[`plugins/proteles.ts`](plugins/proteles.ts) does — not by fetching
`/api/auth/me` while rendering. That request refreshes an expired access token
and rotates the refresh token, and Nuxt does not pass its `Set-Cookie` on to the
page, so the browser would keep a spent token and be signed out on its next
refresh.

Then use the components anywhere: `<SignedIn>`, `<SignedOut>`, `<SignInButton>`,
`<UserButton>`, `useUser()`. See [`pages/index.vue`](pages/index.vue) and the
protected [`pages/dashboard.vue`](pages/dashboard.vue).

## Run it

Requires **Node 20.19+ or 22.12+** (Nuxt 3.21).

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
       "client_name": "Nuxt Quickstart",
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
   ( cd ../.. && npm install && npm run build )   # build @proteles/js, /bff, /vue
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

`nuxt build` suggests `node .output/server/index.mjs`, which does not read
`.env`: without the variables every route answers 500, the public home page
included, because the middleware reads the session on every request. `npm start`
loads `.env`, and `npm run preview` reads it too.

The `.env` made for local development is not a production one. Before
`npm start` serves real users from it, delete `PROTELES_COOKIE_SECURE=false`
(otherwise the session cookie goes out without `Secure`) and set
`PROTELES_APP_URL` to the https origin you serve. A variable set in the host's
environment wins over the file, but only that variable: a host that sets
everything except `PROTELES_COOKIE_SECURE` still gets the file's `false`. On a
host that sets them all, leave the file out and run `node .output/server/index.mjs`
directly — `--env-file` stops at startup when its file is missing.

## How it's verified

[`scripts/verify-quickstart.mjs nuxt-quickstart`](../../scripts/verify-quickstart.mjs)
runs this example under `nuxt dev` (`--dev`) or as the production build and
walks it like a browser against a live server, including a page rendered with
an expired access token, which must not spend the refresh token behind the
browser's back. The server bindings take h3-shaped events and return
`Response`s, so the full loop is also exercised without Nuxt, against the
**live** authorization server, by
[`scripts/verify-nuxt.mjs`](../../scripts/verify-nuxt.mjs), which Proteles'
integration tests run. It drives the
route handler through login → AS login → callback → `/me` → the middleware
pattern → `guardRequest` (allowed *and* blocked) → logout, and server-renders the
**published** components against the resulting session. That verifier drives real
h3-shaped events, so the event-to-Request adapter is covered too.
