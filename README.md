# Proteles SDKs

> **Requires Proteles.** Proteles is a hosted sign-in service, and everything
> in this repository is a client for it: without an account these packages do
> nothing. **[Sign up for free on proteles.com](https://proteles.com/signup)**,
> then register your app to get its issuer, client ID and secret.

The SDKs for the Proteles identity platform: add sign-in to an app in five
minutes without reading an OAuth spec. Depth in seven front-end ecosystems —
**React / Next.js**, **Svelte / SvelteKit**, **Vue / Nuxt**,
**Solid / SolidStart**, **Alpine.js**, **Alpine AJAX** and **htmx**, from a
compiled SPA to server-rendered hypermedia with no client JS of our own — plus
bindings for the **Express** and **Fastify** servers, a typed client for the
Management API, and native SDKs for **iOS** and **Android**.

Each package's README, and its npm description, also says that it needs a
Proteles account before its install line
([`tools/npm-publish-readiness.mjs`](tools/npm-publish-readiness.mjs), rule 11).

## Packages

All thirteen are on npm at **0.3.0** and are released together, at one version
([`CHANGELOG.md`](CHANGELOG.md)).

| Package | What it is |
| --- | --- |
| [`@proteles/js`](packages/js/README.md) | Framework-agnostic OAuth core: PKCE, code exchange, refresh rotation, revoke, userinfo, ID-token and logout-token verification. |
| [`@proteles/bff`](packages/bff/README.md) | Framework-agnostic Backend-for-Frontend: encrypted httpOnly session + the login/callback/logout/me flow over Web `Request`/`Response`. Tokens never reach the browser. |
| [`@proteles/next`](packages/next/README.md) | **Next.js** bindings: catch-all `/api/auth/*` route handlers, `authMiddleware`, `currentUser()`. |
| [`@proteles/react`](packages/react/README.md) | **React** components: `<SignInButton>`, `<UserButton>`, `<SignedIn>/<SignedOut>`, `useUser()`, `<Protect>`. |
| [`@proteles/svelte`](packages/svelte/README.md) | **Svelte + SvelteKit**: the same components as stores/slots, plus SvelteKit request handlers and a `handle` hook. Svelte 4 and 5. |
| [`@proteles/vue`](packages/vue/README.md) | **Vue 3 + Nuxt**: a plugin + `useAuth`/`useUser` composables and the same components, plus Nuxt/h3 handlers. |
| [`@proteles/solid`](packages/solid/README.md) | **Solid + SolidStart**: signal-based `useAuth`/`useUser` and the same components, plus SolidStart handlers and middleware helpers. |
| [`@proteles/alpine`](packages/alpine/README.md) | **Alpine.js, no build step**: a `$auth` store plus `x-signed-in`/`x-signed-out` directives, shipped as a small self-contained CDN bundle. |
| [`@proteles/htmx`](packages/htmx/README.md) | **htmx, server-only**: HX-Redirect-aware login/logout, route and fragment guards. No client-side auth script at all. |
| [`@proteles/alpine-ajax`](packages/alpine-ajax/README.md) | **Alpine AJAX, server-only**: route and fragment guards that answer a target-addressed `401` — Alpine cannot be told to navigate, so a redirect is the wrong answer. |
| [`@proteles/express`](packages/express/README.md) | **Express**: one middleware that serves the auth routes and attaches the session, and an opt-in `requireAuth()` that redirects browsers and answers JSON callers with `401`. |
| [`@proteles/fastify`](packages/fastify/README.md) | **Fastify**: a plugin that registers the auth routes and attaches the session, and an opt-in `requireAuth()` pre-handler, which redirects browsers and answers JSON callers with `401`. |
| [`@proteles/management`](packages/management/README.md) | Typed client for the Management API — **every `/api/v1/*` operation**: tenants, apps, users, keys, connections, branding, webhooks, mail, SAML, resources and the audit trail, including the incident path (MFA reset, session revoke, suspend, secret rotation). Its wire types are generated from [`spec/openapi.json`](spec/openapi.json). |

### Choosing packages

| You're building | Install |
| --- | --- |
| Next.js app | `@proteles/next` + `@proteles/react` |
| SvelteKit app | `@proteles/svelte` |
| Nuxt / Vue app | `@proteles/vue` |
| SolidStart / Solid app | `@proteles/solid` |
| Alpine.js page (no build) | `@proteles/alpine` |
| htmx app (server-rendered) | `@proteles/htmx` |
| Alpine AJAX app (server-rendered) | `@proteles/alpine-ajax` |
| Express or Fastify server | `@proteles/express` or `@proteles/fastify` |
| Something else | `@proteles/bff` (server) and/or `@proteles/js` (core) |
| Control-plane tooling / CI | `@proteles/management` |
| iOS or Android app | the native SDKs, below |

## Mobile SDKs

Native sign-in through the system browser, with PKCE, a verified ID token,
refresh with rotation and a cross-process lock, and a sign-out that ends the
refresh family. Start with [`mobile/README.md`](mobile/README.md), which
covers both and walks through registering the app.

| Platform | Install | Details |
| --- | --- | --- |
| iOS 17.4+ (Swift 6) | Swift Package Manager: `https://github.com/proteles-auth/proteles-sdk`, product **`ProtelesAuth`** | [`mobile/ios/README.md`](mobile/ios/README.md) |
| Android (minSdk 26) | Maven Central: `com.proteles:proteles-auth-android` (it brings `com.proteles:proteles-auth-core`) | [`mobile/android/README.md`](mobile/android/README.md) |

The native SDKs have their own version, starting at 0.1.0, and their own
changelog, [`mobile/CHANGELOG.md`](mobile/CHANGELOG.md). Their design and the
contract both are built to are in [`docs/mobile-SDKs.md`](docs/mobile-SDKs.md).

## Examples

Seven runnable quickstarts, one per front-end ecosystem:

- [`examples/nextjs-quickstart`](examples/nextjs-quickstart) — Next.js App Router
  with `@proteles/next` + `@proteles/react`.
- [`examples/sveltekit-quickstart`](examples/sveltekit-quickstart) — SvelteKit
  with `@proteles/svelte`.
- [`examples/nuxt-quickstart`](examples/nuxt-quickstart) — Nuxt with
  `@proteles/vue`.
- [`examples/solidstart-quickstart`](examples/solidstart-quickstart) — SolidStart
  with `@proteles/solid`.
- [`examples/alpine-quickstart`](examples/alpine-quickstart) — a no-build HTML page
  with `@proteles/alpine`, served by a ~40-line Node backend.
- [`examples/htmx-quickstart`](examples/htmx-quickstart) — a one-file htmx app with
  `@proteles/htmx`, where the server renders auth-aware fragments.
- [`examples/alpine-ajax-quickstart`](examples/alpine-ajax-quickstart) — the same
  shape for Alpine AJAX, and the one place the two hypermedia packages visibly
  differ: signing in is a plain link, because Alpine cannot be told to navigate.

Each example's README says how to register its app and run it.

## Build and test

npm workspaces. Packages build with `tsc` — except `@proteles/svelte`
(`svelte-package`), `@proteles/solid` (Babel, emitting JSX source plus precompiled
dom/ssr bundles), and `@proteles/alpine` (tsc plus an esbuild browser bundle) —
and test with `tsx` and the Node built-in test runner (`node:test`). Components
are server-rendered in tests via each framework's own SSR renderer
(`react-dom/server`, `svelte/server`, `@vue/server-renderer`, `solid-js/web`), so
there's no jsdom either. The packages support Node **18.12+**.

```bash
npm install          # install all workspaces
npm run build        # build every package
npm test             # test every package, then the scripts', vectors' and tools' self-tests
npm run typecheck    # typecheck every package and the scripts
```

The native SDKs, from the repository root:

```bash
swift test                                    # iOS (Package.swift is at the root); see mobile/ios/README.md
(cd mobile/android && ./gradlew :core:test :android:testDebugUnitTest)   # Android
```

### Against a live server

The unit tests mock the authorization server. These run the SDKs against a
real one — a Proteles tenant of your own, or a local server — and are run by
Proteles' integration tests:

- [`scripts/verify-quickstart.mjs`](scripts/verify-quickstart.mjs) installs an
  example, builds and serves it with its own framework, and walks it like a
  browser: sign-in at the real login form, the protected page, an expired
  access token, sign-out and revocation.
- [`verify-live.mjs`](scripts/verify-live.mjs) drives the Next.js BFF,
  [`verify-sveltekit.mjs`](scripts/verify-sveltekit.mjs) the SvelteKit
  handlers, [`verify-nuxt.mjs`](scripts/verify-nuxt.mjs) the Nuxt/h3 handlers,
  [`verify-solid.mjs`](scripts/verify-solid.mjs) the SolidStart handlers,
  [`verify-alpine.mjs`](scripts/verify-alpine.mjs) a plain Node backend over
  real HTTP, [`verify-htmx.mjs`](scripts/verify-htmx.mjs) htmx's HX-Redirect
  protocol, [`verify-alpine-ajax.mjs`](scripts/verify-alpine-ajax.mjs) Alpine
  AJAX's target-addressed 401, and
  [`verify-management.mjs`](scripts/verify-management.mjs) the Management API
  client. The SSR-capable ones also server-render the *published* build against
  the resulting session.
- [`mobile/live`](mobile/live) gives the native SDKs' live suites a server.

Each script's header lists the environment it needs (`SDK_ISSUER`,
`SDK_CLIENT_ID` and so on). Express and Fastify have no quickstart and no live
check; their own tests drive them against a mocked authorization server and
real Express and Fastify. The Alpine layer's **browser** half is not checked by
any script here: Alpine needs a DOM, and none of these scripts starts a browser.

## Releases

npm releases are tagged `npm-vX.Y.Z`; the native SDKs are tagged with a plain
`X.Y.Z` (no `v`), because SwiftPM reads this repository's tags as versions of
the iOS package. Each has its own version numbers.
[`RELEASING.md`](RELEASING.md) is the runbook; npm packages are published with
[provenance](https://docs.npmjs.com/generating-provenance-statements).

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Security

Please report a vulnerability privately, not in an issue: see
[`SECURITY.md`](SECURITY.md).

## License

[MIT](LICENSE).
