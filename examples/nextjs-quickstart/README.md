# Proteles Next.js quickstart

Authentication in a Next.js App Router app with three files, using
[`@proteles/next`](../../packages/next) (the BFF) and
[`@proteles/react`](../../packages/react) (the components). Tokens live only in an
encrypted, httpOnly cookie on the server — the browser never sees one.

## The three files

```ts
// app/api/auth/[...proteles]/route.ts — the whole OAuth flow
export const { GET, POST } = createAuthHandlers();
```

```ts
// proxy.ts — route protection (Next 16's name for middleware.ts)
const proxy = createAuthMiddleware(undefined, { publicPaths: ["/"] });
export default proxy;
```

```tsx
// app/layout.tsx — make auth state available to the UI
<AuthProvider initialUser={await currentUser()}>{children}</AuthProvider>
```

Then use the components anywhere: `<SignedIn>`, `<SignedOut>`, `<SignInButton>`,
`<UserButton>`, `useUser()`. See [`app/page.tsx`](app/page.tsx) and the protected
[`app/dashboard/page.tsx`](app/dashboard/page.tsx).

Protected pages also call `currentUser()` themselves and redirect to sign-in when
it returns `null`, as `app/dashboard/page.tsx` does, rather than trusting that
the proxy ran. Next.js releases before 14.2.25 let one request header skip
middleware entirely (CVE-2025-29927); a guard that lives only there fails open
whenever it does not run.

This example runs **Next.js 16** with React 19. On Next 14 or 15, `@proteles/next`
works the same way; name the file `middleware.ts` (Next 16 calls it `proxy.ts`
and warns on the old name).

## Run it

Requires **Node 20.9+**, Next.js 16's own floor.

1. **Create a tenant + app.** Against a running Proteles server, mint a client via
   the Management API (or the dashboard). It must be confidential, use the
   `authorization_code` + `refresh_token` grants, and register the redirect URI
   `http://localhost:3000/api/auth/callback`:

   ```bash
   curl -sX POST http://localhost:8080/api/v1/apps \
     -H "Authorization: Bearer $MANAGEMENT_BOOTSTRAP_TOKEN" \
     -H 'content-type: application/json' \
     -d '{
       "tenant_id": "00000000-0000-0000-0000-000000000001",
       "client_name": "Quickstart",
       "token_endpoint_auth_method": "client_secret_basic",
       "grant_types": ["authorization_code", "refresh_token"],
       "redirect_uris": ["http://localhost:3000/api/auth/callback"],
       "post_logout_redirect_uris": ["http://localhost:3000/"],
       "scopes": ["openid", "profile", "email", "offline_access"],
       "first_party": true
     }'
   ```

   Note the returned `client_id` / `client_secret`.

   With a tenant's own management key instead of the bootstrap token, send the
   same request to the tenant's host (for example
   `http://acme.localhost:8080/api/v1/apps`) without `tenant_id`.

2. **Configure.** `cp .env.example .env.local` and fill in `PROTELES_ISSUER`,
   `PROTELES_CLIENT_ID`, `PROTELES_CLIENT_SECRET`, and a generated
   `PROTELES_SESSION_SECRET`. `PROTELES_APP_URL` must be the origin you open in
   the browser: the proxy's sign-in redirect is built from it (Next.js needs an
   absolute URL there, and the request's own `Host` is not trusted for one).

3. **Build the local SDK packages** (this example links them via `file:`), then
   install and run:

   ```bash
   ( cd ../.. && npm install && npm run build )   # build @proteles/js, /bff, /next, /react
   npm install
   npm run dev
   ```

4. Open <http://localhost:3000>, click **Sign in**, authenticate, and you're
   back — signed in, with `/dashboard` now reachable.

For production, `npm run build && npm start`. Next.js reads `.env.local` in both,
so a `.env.local` from local development that comes along is used in production:
first delete its `PROTELES_COOKIE_SECURE=false` (otherwise the session cookie
goes out without `Secure`) and set `PROTELES_APP_URL` to the https origin you
serve. A variable set in the host's environment wins over the file, but only
that variable, so leaving `PROTELES_COOKIE_SECURE` unset there does not undo the
file's `false`. `next start` needs no file when the host sets them all.

> In a real project you'd depend on the published `@proteles/*` packages instead
> of the `file:` links used here.
>
> The links point outside this directory. Turbopack, Next 16's default bundler,
> follows them. TypeScript needs one thing it would not with published
> packages: the linked `@proteles/react` resolves React's types from the SDK
> workspace, which tests against React 18, while this app uses React 19's. The
> `paths` in `tsconfig.json` point every `react` and `react-dom` type import at
> this app's own, so there is one set; drop them when you depend on the
> published packages.

## How it's verified

This example itself is installed, built with `next build`, served with
`next start` and walked like a browser — sign-in at the real login form,
`/dashboard`, an expired access token through `/revalidate`, sign-out — by
[`scripts/verify-quickstart.mjs`](../../scripts/verify-quickstart.mjs), which
Proteles' integration tests run against a live server. That is
the check that sees what only Next's bundler and runtime can: the proxy
bundle, the Server/Client Component boundary, and Next's rules for the proxy's
redirects. The BFF on its own, outside Next, is covered by
[`verify-live.mjs`](../../scripts/verify-live.mjs).

That check installs this directory's tracked `package-lock.json` with `npm ci`,
so the Next.js it tests changes only when the lockfile does. After editing
`package.json`, refresh it with `npm install --package-lock-only --ignore-scripts`.
