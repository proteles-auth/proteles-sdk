# Changelog

All thirteen `@proteles/*` packages are versioned and released together, so this
is one file rather than thirteen. They share a version because their
inter-dependencies are pinned to a single minor (`@proteles/next` depends on
`@proteles/bff@^0.3.0` and so on). Letting them drift apart would mean
maintaining every combination.

The format is [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
versioning is [semver](https://semver.org/spec/v2.0.0.html). While the major is
`0`, a minor bump is where a breaking change goes.

Each release is tagged `npm-vX.Y.Z` in this repository
([`RELEASING.md`](RELEASING.md)). Versions up to 0.3.0 were released before the
packages moved here, so their tags are not in this repository; their links
below go to npm instead. The native SDKs have their own changelog,
[`mobile/CHANGELOG.md`](mobile/CHANGELOG.md).

## [Unreleased]

### Changed (every package)

- The source now lives in a public repository,
  <https://github.com/proteles-auth/proteles-sdk>. Each `package.json`'s
  `repository`, `homepage` and `bugs` point there.
- Each package ships source maps (`.js.map` and `.d.ts.map`) and the `src/`
  they point at, so a debugger steps through the TypeScript and "go to
  definition" lands in the source. `@proteles/solid` and `@proteles/svelte`
  ship `.d.ts.map` files only; `tsconfig.base.json` says why.
- Released from this repository's `npm-vX.Y.Z` tags with npm provenance: each
  version links to the commit and workflow run that built it.

### Added (`@proteles/management`)

- `inviteTenantOwner(tenantId, { email })`, for
  `POST /api/v1/tenants/{tenant_id}/owner-invitations` (platform token only):
  mails a tenant's owner an invitation, the way to give a tenant
  `createTenant` made an owner. It returns `OwnerInvitation` (`email`, `role`,
  `expiresAt`, `delivered`, and `replaced`: the platform's earlier invitations
  to other addresses that this one withdrew), never the link. The mail goes
  through the deployment's relay only; a deployment without one is refused
  with `mail_not_configured`, now in `ManagementErrorCode`.
  `withdrawTenantOwnerInvitation(tenantId, { email })`, for `DELETE` on the
  same path, takes one back. `Tenant` gains `ownerCount`, `null` when the
  server could not count and absent from a server that predates it.
- `CreateTenantInput.ownerEmail`'s description no longer suggests it gives the
  tenant an owner. It records a contact address and nothing else.
- `initiateLoginUri` on `createApp`, `updateApp` (`null` clears it) and
  `listApps`, and `clientId` on `inviteUser`: the app an accepted invitation
  sends its invitee to. A server
  that predates them refuses either field with a 400 (its bodies take no
  unknown field); omitted, nothing changes.

### Changed (`@proteles/bff`, and every package built on it)

- The login route works as an app's sign-in start address
  (`initiate_login_uri`), as it already did: Proteles sends somebody who
  accepts an invitation naming the app to `<basePath>/login?iss=…`, and the
  route starts an ordinary sign-in at the configured `issuer`, never at the
  one `iss` names. New: when `iss` names another issuer, `onError` is told,
  with the context `"login"`, at most once every ten minutes for each
  `AuthApp`. It is not a failure — the sign-in goes ahead — and the report
  carries nothing of the `iss` the link sent, which anybody can make up. A
  handler that alerts on `onError` should leave `"login"` out.

### Fixed (`@proteles/management`)

- The README's count of operations is the spec's again (102; it said
  eighty-nine since 0.2.0).

## [0.3.0] — 2026-10-18

### Changed (every package)

- Every README now says, before its install line, that the package needs a
  Proteles account, and links <https://proteles.com/signup>. Every
  `package.json` description says so too, since that's what npm's search
  results show. People were installing the packages expecting them to work
  without a backend. `tools/npm-publish-readiness.mjs` checks both
  (rule 11).
- Hostnames in the docs that don't exist are corrected:
  - `@proteles/management`'s base URL example is `https://auth.proteles.com`,
    not `https://api.proteles.com`;
  - `@proteles/next`'s issuer example is `https://acme.auth.proteles.com`,
    the form a tenant's address takes.

### Added (`@proteles/management`)

- `WebhookEventName` gains the account events: `user.created`,
  `user.deactivated`, `user.reactivated`, `account.deleted` and
  `email.changed`, so `createWebhook` and `replaceWebhook` can subscribe an
  endpoint to them. Each delivery's `data` carries `sub`, the account's id.
  A server that predates them
  refuses the names with a 400.
- `checkApp(clientId)`: "Test this app", for `GET /api/v1/apps/{client_id}/check`.
  It says what the app's registration will do before a real person finds out:
  whether it is on, whether a refresh token is issued, its redirect and
  post-logout addresses, `openid`, and its back-channel logout address, as
  findings at `ok`, `info`, `warning` or `problem`, with `ready` false on any
  problem. New types `AppCheck`, `AppCheckFinding` and `AppCheckLevel`. A
  server that predates it answers 404.

### Added (`@proteles/bff`)

- `GET {basePath}/signup`: a sign-in that opens on the workspace's hosted
  sign-up page, by adding `prompt=create` (OpenID Connect Prompt Create 1.0) to
  the authorization request `/login` would make. The person gives an email
  address, follows the link they are mailed, chooses a password, and comes
  back through `/callback` signed in, to `returnTo`. Where the workspace has not
  opened its sign-up page, the server ignores `create` and the person sees the
  ordinary sign-in page. It takes no `connection`: the server reads `create`
  first, so one would only steer the fallback. Every package built on
  `@proteles/bff` serves the route as it is: `@proteles/next`,
  `@proteles/express`, `@proteles/fastify`, `@proteles/htmx`,
  `@proteles/alpine-ajax`, and the server entries of `@proteles/vue`,
  `@proteles/svelte` and `@proteles/solid`.

### Added (`@proteles/react`, `@proteles/vue`, `@proteles/svelte`, `@proteles/solid`, `@proteles/alpine`)

- `signUp({ returnTo })` beside `signIn`, which goes to that route; `returnTo`
  defaults to the current page, as `signIn`'s does. With it come `signupUrl`
  beside `loginUrl`, the `SignUpOptions` type, and a `<SignUpButton returnTo?>`
  beside `<SignInButton>` in every package but `@proteles/alpine`, where it is
  `$auth.signUp()`.

### Changed — breaking (`@proteles/react`, `@proteles/vue`, `@proteles/svelte`, `@proteles/solid`, `@proteles/alpine`)

- **The auth state has a required `signUp`**: `AuthContextValue` in
  `@proteles/react`, `AuthStore` in `@proteles/svelte` and `@proteles/alpine`,
  and `Auth` in `@proteles/vue` and `@proteles/solid`. A value built by hand
  for `AuthContext.Provider`, `PROTELES_AUTH`, `AuthContext` or
  `setAuthContext` — usually a test double — must now set it.

## [0.2.0] — 2026-10-13

Everything since 0.1.1. The BFF now verifies the ID Token, another site can no
longer sign users out, a sibling host can no longer plant a session, a busy
authorization server no longer signs anyone out, `@proteles/express` and
`@proteles/fastify` are new, and `@proteles/management` reaches every operation
the Management API publishes.

It is a minor version because it breaks existing code. Each break is under a
"Changed — breaking" heading below, with its migration: `@proteles/next`'s peer
range, which now excludes the Next.js releases affected by CVE-2025-29927;
`resolveSession` and `revoke()` in `@proteles/js` and `@proteles/bff`, which now
report a busy authorization server instead of hiding it; sign-out, which is now
a `POST` from the app's own pages; the cookies' `__Host-` names, which sign
everybody in once more; a required `isUnavailable` on the browser packages'
auth state; and the `@proteles/management` type changes.

Anyone on 0.1.1 should upgrade. The authorization server now spends each
refresh token exactly once, but 0.1.1's BFF sends its own refresh for every
request that arrives with an expired access token. Suppose two such requests
arrive together, from two tabs or from a page and its fetch. With the current
server, one refresh succeeds, the other request's response clears the cookie,
and a 0.1.1 user is signed out. 0.2.0 shares one refresh between those
requests; see Fixed.

### Added (`@proteles/js`)

- `verifyLogoutToken(raw, { issuer, audience, jwks })`: verifies an OIDC
  Back-Channel Logout 1.0 logout token (§2.6) as a relying party's
  `backchannel_logout_uri` receives it in the `logout_token` form field, and
  returns its claims — `sid` names the session that ended, `sub` the person,
  `jti` the token (a retry repeats it). The signature is checked by the code
  that checks ID tokens, and the issuer and audience as an ID token's are; then
  `typ` `logout+jwt`, `iat`,
  `exp`, the back-channel logout event, a `sub` or `sid`, a `jti`, and no
  `nonce`. New types `LogoutTokenClaims` and `VerifyLogoutTokenOptions`, and
  `BACKCHANNEL_LOGOUT_EVENT`. When it throws, answer `400` — or `503` when
  `err.retryable` (the key set could not be read just now), since the server
  never retries a `400`. `IdTokenClaims` gains `sid`, which the server puts in
  every ID token from a known session.

### Changed (`@proteles/js`)

- `verifyIdToken` refuses a token typed `logout+jwt`: a logout token carries
  `iss`, one `aud`, `sub` and `exp` as an ID token does, and a caller with no
  nonce or access token to compare could otherwise take one for the other.

### Changed — breaking (`@proteles/next`)

- **The `next` peer range is `^14.2.25 || >=15.2.3`. It was `>=14`.** Earlier
  releases of Next.js let a single request header skip middleware entirely
  (CVE-2025-29927). An app that guarded its routes only with `authMiddleware`
  was open to anyone who sent that header. If your app is still on one of those
  releases, npm now reports a peer-dependency conflict when you install this
  version. Upgrade Next.js rather than overriding the range.

  The range excludes only the releases with CVE-2025-29927, so a satisfied peer
  range does not mean a safe Next.js. Later advisories were fixed in patch
  releases the range still admits. For example, the React Server Components
  remote code execution of December 2025 (CVE-2025-66478 in Next.js,
  CVE-2025-55182 in React) affects App Router apps, which every app using this
  package is, on each 15.x and 16.x minor until that minor's fix. Run the latest
  patch release of your Next.js line.

  Don't rely on middleware alone, either. Also call `currentUser()` in every
  protected page, route handler and server action, and send the visitor to sign
  in when it returns `null`. The README now says this, and the Next.js
  quickstart's protected page does it.

### Changed — breaking (`@proteles/js`, `@proteles/bff`)

- **`resolveSession` and `resolveUsableSession` throw `SessionUnavailableError`**
  when the authorization server cannot refresh the session right now, where they
  cleared the cookie and returned `null`. A caller written as
  `if (!(await app.resolveSession(req, sink))) redirect(login)` now meets an
  uncaught exception — a `500` — during every busy spell. Migration: catch
  `SessionUnavailableError` and answer `503` with `error.retryAfter` as
  `Retry-After`, not a login redirect, and let whatever the sink received reach
  that response too. The sink is usually not called, but is handed the rotated
  refresh token when the exchange went through and only the new ID token could
  not be checked.
- **`OAuthClient.revoke()` resolves a `RevocationResult`** — `{ ok: true }` for
  any `2xx`, `{ ok: false, error }` otherwise — where it resolved `void`. It
  still never throws. It used to drain every answer, `503` included, so a
  sign-out whose revocation was turned away left a thirty-day refresh family live
  with nobody told. Code that ignored the old `void` compiles unchanged; a
  subclass or test double that overrides `revoke` must now return one, because
  `@proteles/bff` reads `ok`.
- **An `issuer` with a trailing slash is refused when the client is made**
  (`OAuthClient`, and so every BFF), where it was stripped. ID Tokens are now
  compared with the issuer byte for byte, and the authorization server's `iss`
  is always `scheme://host` with no trailing slash, so a configured slash would
  fail every sign-in. Refusing it at start-up names the setting instead.
  Migration: remove the slash from `issuer` or `PROTELES_ISSUER`.

### Changed — breaking (`@proteles/bff`, and every package built on it): sign-out ends the session at Proteles

- **What happens now.** `POST {basePath}/logout` still revokes the refresh
  token and clears the session cookie, but its `303` now goes on to the
  server's end-session endpoint (OpenID Connect RP-Initiated Logout) rather
  than straight to `returnTo`. It carries the session's ID token as
  `id_token_hint` (or `client_id`) and `returnTo` as an absolute URL on the
  app's origin. The server asks the person to confirm, ends their session
  there, tells the apps registered for back-channel logout, and returns the
  browser.
- **Why.** Sign-out used to leave the person signed in at Proteles, so the
  next "Sign in" went straight through without a password — on a shared
  computer, as the previous person.
- **What to do.**
  - Register the URL sign-out returns to (`https://your.app/` for the default
    `returnTo`) as one of the app's `post_logout_redirect_uris`; without it the
    person stays on the server's signed-out page.
  - A strict `form-action` on your own pages must allow the issuer's origin;
    this package's own sign-out page already does.
  - `endSession: false` (or `PROTELES_END_SESSION=false`) keeps the old
    app-only sign-out.
  - The htmx binding's `HX-Redirect` now carries the end-session URL.

### Added (`@proteles/js`)

- `Endpoints.endSession` (conventionally `{issuer}/oauth/logout`) and
  `OAuthClient.endSessionUrl({ idTokenHint, postLogoutRedirectUri, state })`,
  which `@proteles/bff` uses for the above. An object built as a whole
  `Endpoints` needs the new member.

### Changed — breaking (`@proteles/bff`, and every package built on it)

- **Sign-out is a POST from your app's own pages.** A `GET` to
  `{basePath}/logout` now answers with a small confirmation page, a form that
  posts back to the same route with the same `returnTo`, instead of signing the
  user out. A `POST` signs out when its `Origin` is your app's (the origin of
  `redirectUri`), and when it has no `Origin` at all, which is not a browser:
  curl, a test, or another server. It is refused with `403` when the browser
  marks it `Sec-Fetch-Site: cross-site` or `same-site`, when its `Origin` is
  another one, and when its `Origin` is `null` unless the browser also marks it
  `same-origin`. Any other method is `405`. Before this, a link or an image on
  another site, or on a sibling subdomain, could sign your users out and
  revoke their refresh tokens; Fetch Metadata alone left browsers that send
  none, and subdomains, which the browser marks `same-site`.

  The SDKs' own controls already comply: every browser package's `signOut()`,
  and so every `<SignOutButton>` and `<UserButton>`, submits a form `POST`
  (below), and the htmx and Alpine AJAX examples post already. **Migration:**
  a sign-out *link* of your own, `<a href="/api/auth/logout">`, still works but
  now asks for a second click; make it a form,
  `<form method="post" action="/api/auth/logout"><button>Sign out</button></form>`,
  or call `signOut()`. A `fetch` to it from your pages sends your `Origin` and
  works. An identity provider's sign-out page that returns the browser to
  `/api/auth/logout` lands on the confirmation. The `/revalidate` *try again*
  page's way out is a form now too.

- **The cookies are `__Host-proteles_session` and `__Host-proteles_flow`
  whenever they are `Secure`**, which is the default. They keep the
  plain names when `cookieSecure` is off (`PROTELES_COOKIE_SECURE=false`, for
  plain-HTTP development), because a browser refuses a `__Host-` cookie that is
  not `Secure`. Every signed-in user of an app that upgrades signs in once
  more, and a sign-in in flight across the deploy fails once and starts again.
  The exported `SESSION_COOKIE` and `FLOW_COOKIE` constants are gone:
  `cookieNames(secure?)` gives the pair for a setting, reading
  `PROTELES_COOKIE_SECURE` when `secure` is omitted, and `AuthApp.cookieNames`
  gives the pair an app uses. **Migration:** replace
  `SESSION_COOKIE` with `app.cookieNames.session`, or `cookieNames().session`
  where there is no app to hand (the Nuxt plugin in `@proteles/vue`'s README
  does this now).

### Changed — breaking (`@proteles/react`, `@proteles/vue`, `@proteles/svelte`, `@proteles/solid`, `@proteles/alpine`)

- **The auth state has a required `isUnavailable`**: `AuthState` in
  `@proteles/react` (and so `AuthContextValue`) and in `@proteles/svelte`,
  `Auth` in `@proteles/vue` and `@proteles/solid`, and `AuthStore` in
  `@proteles/alpine`.
  A value built by hand for `AuthContext.Provider`, `PROTELES_AUTH`,
  `AuthContext` or `setAuthContext` — usually a test double — must now set it.
- **`signOut()` submits a form `POST` to the sign-out route** instead of
  navigating to it, since a `GET` there now only asks for confirmation (the
  `@proteles/bff` entry above). Vue, Svelte, Solid and Alpine take a `post`
  option beside `navigate` for tests to intercept it; React posts directly.
- **`fetchSession` reads a busy `/me` as `unavailable`**, not as signed out: a
  `503`, `429`, `408`, any other `5xx`, or no answer. `authenticated` is still
  `false` then, so a caller that reads only `authenticated` behaves as before;
  one that wants the difference reads `unavailable`.

### Changed — breaking (`@proteles/management`)

All six of these are places where the client's types disagreed with the server.
They were found by generating the wire shapes from the server's OpenAPI
document (now [`spec/openapi.json`](spec/openapi.json)) and letting `tsc`
compare them with the hand-written types.

- **`listTenants()` returns `TenantSummary[]` and `createTenant()` returns
  `TenantSummary`.** Both endpoints answer with `{id, slug, status}`. `Tenant`
  served the listing and the detail at once, so every setting on it was
  optional — and an optional field reading `undefined` says "this tenant has no
  MFA policy", not "this response does not say". The type could not tell those
  apart, so the distinction lived in a doc comment. Now `getTenant` returns
  `Tenant` with every field present, and reading a policy off a listing is a
  compile error. Migration: call `getTenant(id)` when you need settings.
- **`DomainChallenge.value` is `string | null`.** The column is nullable and the
  server models it `Option<String>`; a domain claimed before verification
  existed serialises `null`. Code that printed this into DNS instructions was
  printing "null".
- **`TenantDomain.challenge` is no longer nullable.** One serialiser builds it
  for the claim, the listing and the verify endpoint, and it is unconditional.
- **`ApiKeySummary.scopes` widened to `(ManagementScope | (string & {}))[]`.**
  A key minted before a scope was retired keeps that value in its row, and this
  endpoint reads rows. The closed union had the compiler assert that a value the
  database can hold cannot appear.
- **`CreatedApiKey.scopes` narrowed to `ManagementScope[]`.** The mint path
  validates every scope against `KNOWN_SCOPES` and answers 400 before minting,
  so the response cannot carry anything else. These two were typed the wrong way
  round: the one that can be surprising was closed, and the one that cannot was
  open.
- **`App.clientType`, `grantTypes`, `redirectUris` and `firstParty` are no
  longer optional.** The server builds the listing from a struct where none of
  them is an `Option` and nothing is `skip_serializing_if`; an empty list
  serialises as `[]`, never as a missing key. Callers can drop their guards.

One smaller narrowing came from the same comparison: `verifyDomain()` resolves
to `{ domain, verified: true }`, because the endpoint answers a domain it could
not prove with a 400, never with `verified: false`.

One more was deliberate rather than a disagreement with the server:
**`UpsertConnectionInput.provider` is the closed `Provider` union**, the four
providers the server accepts. It was that union widened with `(string & {})`,
so any string compiled. A value typed `string`, such as one read from
configuration, no longer compiles here: type it as `Provider`, which is
exported, or narrow it first. This is what the caller sends, so a typo now fails
in the editor instead of as a 400. `Connection.provider`, which the server
sends, stays open, so a provider added after this release still reads.

And one that is the server's rather than the client's, listed here because the
0.1.1 docs described the opposite: **no key is minted without scopes any
more**. `createApiKey` with `scopes: []` was the documented way to ask for an
unrestricted key; the server now answers 400, which `createApiKey` throws as a
`ManagementError`, and `rotateApiKey` answers 409 for a key that has none,
because its successor would inherit the empty list. Keys minted that way before
keep working, and `listApiKeys` shows them with no scopes. To replace one, mint
a key with the scopes it needs, then revoke the old one. This applies to every
client version, 0.1.1 included.

Three more came with the plan and billing endpoints. Each adds something, and
each also changes a type an 0.1.1 caller may already use:

- `getBilling()` — `GET /api/v1/billing`: the plan in force, where it comes from
  (`subscription`, `override` or `none`) and the subscription's status, interval,
  renewal and extra seats. Read-only, under `tenant:read`; plans are bought and
  changed in the tenant console. New types `Billing` and `BillingSubscription`.
  The generated enum `Source` is now `AppsSelfRegistrationQuotaSource`, because a
  second `source` enum arrived with `Billing`; nothing in the package imported it.
- `getPlan()`'s `TenantPlan` gains `enforced`: whether the deployment holds
  tenants to their plans (`PLANS_ENFORCED`). Its `entitlements` are what the
  server **applies**, so where plans are not enforced `includedActiveUsers`,
  `includedSeats` and `logRetentionDays` are `null` (their types widen to
  `number | null`), `allowedSessionTtlSeconds` is `null` and `sms` is `true`.
  `source` gains `none` — no override and an unpaid FREE plan, as `getBilling`
  says — and is typed with the generated `BillingSource`; the generated
  `TenantPlanSource` is gone, because the two enums are now one.
- `getUsage()` gains `effectiveSoftCap`, the cap that announces (the tenant's
  own, else the plan's included users), and `overSoftCap` is now measured
  against it; `includedActiveUsers` may be `null`.

### Changed (`@proteles/bff`)

- **`onError` also hears about refreshes and sign-outs.** It is called with the
  context `"refresh"` whenever a refresh is put off because the server is busy —
  once per request that needed one, so a busy minute produces a burst — and with
  `"logout"` when sign-out could not revoke the refresh token. Its default is a
  `console.warn`. An `onError` wired to alert on failed logins should filter on
  `context === "callback"`.

### Security

- **The BFF verifies the ID Token** (`@proteles/bff`, and so every package
  built on it; `@proteles/js`). Until now the ID Token was treated as an opaque
  string: it was copied into the session and never opened. The nonce was
  generated, sent on the authorize request and sealed into the flow cookie, but
  nothing ever compared it, so an ID Token replayed from another login of the
  same user was accepted.

  The callback now checks the RS256 signature against the issuer's published
  keys, then the issuer (byte for byte), the audience (this client, alone),
  `sub`, expiry, nonce and `at_hash`, which binds the ID Token to the access
  token it came with. An ID Token returned by a refresh is checked the same
  way, without the nonce, which a refresh cannot carry. Any other algorithm,
  `none` and `HS256` included, is refused before a key is looked up, and so is
  a header naming a `crit` extension. A token is read strictly: base64url in
  its one canonical spelling, and no JSON member named twice. A published key
  below 2048 bits, or with an exponent of one, is not a key. These are the
  rules the native SDKs follow, and the verifier is held to the same 36 signed
  vectors they are (`mobile/vectors`). **A login whose ID Token does not
  verify now fails**, and so does one that comes back with no ID Token when
  `openid` was requested. For callers of the core client, `@proteles/js`
  exports `verifyIdToken` (which takes the access token from the same
  response, or `null`) and `JwksCache`.
- **Another site can no longer sign users out** (`@proteles/bff`).
  `/api/auth/logout` answered any method, and a `SameSite=Lax` cookie still
  travels with a top-level cross-site GET, so any page could send a visitor
  there, sign them out, and revoke their refresh token. Sign-out is now a POST
  from the app's own pages, checked by origin; see "Changed — breaking" above.
  A refused one is answered `403`, nothing is revoked, no cookie is cleared,
  and `onError` hears about it with the context `"logout"`.
- **A sibling host can no longer plant a session or a sign-in**
  (`@proteles/bff`). Any host under the app's registrable domain could set
  `proteles_session` for the whole domain, and the browser sent it to the app
  too. The value is sealed, so it could not be forged, but an honest one of
  the attacker's own signed the victim into the app as the attacker, even a
  victim already signed in, because the later cookie is the one read. The
  same held for `proteles_flow` and a sign-in the attacker started. The
  `__Host-` names (above) are refused by the browser from any other host.
- **A request header no longer chooses where the browser is redirected**
  (`@proteles/bff` middleware, `@proteles/htmx`, `@proteles/alpine-ajax`). On
  the Node path, the request URL is built from `X-Forwarded-Host`, and three
  redirects were made absolute from it. Behind a cache that keys on the URL but
  not on that header, one poisoned request set the redirect everyone else was
  served. All three now send a relative `Location` (and `HX-Redirect`), which
  the browser resolves against the address it actually reached.
- **One request could stop a Node server** (`@proteles/bff`, the `node:http`
  quickstarts). A cookie that is not valid percent-encoding (`Cookie: a=%`), an
  unparseable `Host`, a `TRACE`, or an HTTP/2 pseudo-header threw inside an
  async handler. Express 4 and plain `node:http` drop that promise, and Node
  exits on an unhandled rejection. The core no longer throws on anything a
  client sent, both Express middlewares in `@proteles/express` hand any failure
  to `next(err)`, and the quickstarts catch their handler's promise.
- **`returnTo` was an open redirect through a tab** (`@proteles/bff`).
  `/%09/evil.example` passed the prefix checks, and browsers strip tab, CR and LF
  from a `Location`, so it arrived as `//evil.example`. It is now parsed and must
  resolve to the app's own origin. Control characters and backslashes are
  refused.
- **`/api/auth/me` renewed a session past its absolute cap** (`@proteles/bff`).
  It was the one path that skipped `sessionExpiresAt`, so a stolen cookie could
  be kept alive by calling it in a loop.

### Added

- **`Tenant.accountRecoveryCodesEnabled`, and `updateTenant`'s
  `accountRecoveryCodesEnabled`** (`@proteles/management`): the switch for saved
  account-recovery codes, off by default. An account with a password and
  no confirmed address may then hold a code, spent at `/account/recover` to
  choose a new password; it never gets past a second factor.
- **`@proteles/express` and `@proteles/fastify`**: bindings for the two most
  common Node server frameworks, over the same BFF. `app.use(protelesAuth())`
  (Express) and `app.register(protelesPlugin)` (Fastify) serve the auth routes
  and attach the session to every other request. Neither guards anything by
  being installed: `requireAuth()` is the opt-in. It refreshes a spent session
  rather than sending it to sign in: a browser whose access token has expired is
  redirected (`303`) through `{basePath}/revalidate`, and a JSON caller is
  refreshed in place and continues, through the same `AuthApp`, so requests
  arriving together share one token exchange whichever guard they pass. A caller
  with no session who asks for JSON gets a `401` rather than a redirect to an
  HTML login page. These are their first releases.
- **Step-up: ask for a recent sign-in, and see how the user signed in**
  (`@proteles/js`, `@proteles/bff`). `createAuthorizationUrl` takes `maxAge`,
  sent as OIDC `max_age`. Unlike `prompt: "login"`, it asks the user to sign in
  again only if they signed in longer ago than you allow, and `0` means now. The session now carries `amr`
  (RFC 8176) and `authTime` (seconds, as the claim is) from the verified ID
  Token, and `/api/auth/me` returns both. They are absent, not defaulted, when
  the token does not carry them.
- `currentUrl()` and `HX_CURRENT_URL_HEADER` (`@proteles/htmx`), for reading the
  page an htmx request came from.
- **`isUnavailable`** (`@proteles/react`, `@proteles/vue`, `@proteles/svelte`,
  `@proteles/solid`, `@proteles/alpine`): true while the last `/me` could not
  say who is signed in and another is scheduled. It sits beside `isLoading` —
  in `useUser()` and `useAuth()` in React, a ref in Vue, an accessor in Solid,
  the store value in Svelte, `$auth.isUnavailable` in Alpine — so a page can say
  the sign-in service is busy. `SessionResult`, from `fetchSession`, gains
  `unavailable` and `retryAfter`.
- **Retry information** (`@proteles/js`, `@proteles/bff`). `OAuthError` has
  `retryable` (no answer, `408`, `429`, `5xx`), `unreachable`, and `retryAfter`
  (the server's `Retry-After` in seconds, as a number or an HTTP-date, capped at
  an hour); `JwksCache` throws errors that carry them too, so a key set that
  could not be fetched is told apart from one that refused the token.
  `parseRetryAfter`, `MAX_RETRY_AFTER_SECONDS` and the `RevocationResult` type
  are exported. `SessionUnavailableError` is exported from `@proteles/bff` and
  re-exported beside `AuthApp` by `@proteles/next`, `@proteles/express`,
  `@proteles/fastify`, `@proteles/htmx`, `@proteles/solid`, `@proteles/svelte`
  and `@proteles/vue`.
- **`@proteles/management` reaches the whole API.** Seventy-five new methods,
  from sixteen in 0.1.1 to ninety-one, and every one of the eighty-nine
  operations the API publishes is reachable, and a coverage check failed the
  build if one stopped being.
  What was missing was not a random subset: the client could *create* almost
  everything and *change* or *act on* almost nothing. `createApp` with no
  `updateApp`; `listApps` with no delete; `upsertConnection` with no remove;
  `createApiKey` and `revokeApiKey` with neither rotation; `listAudit` with no
  export. Nothing on the incident path existed at all — an operator holding this
  client could read an incident in full and respond to none of it.

  - **Incident response**: `resetUserMfa`, `revokeUserSessions`,
    `deactivateUser`, `reactivateUser`, `bulkUpdateUsers`, `setTenantStatus`,
    `rotateAppSecret`, `retireAppSecret`, `rotateSigningKey`, `rotateApiKey`,
    `rotateDataKey`.
  - **Users and principals**: `findUser`, `createUser`, `searchUsers`,
    `inviteUser`, `createServiceAccount`, `bindAppServiceAccount`.
  - **Applications**: `updateApp`, `deleteApp`.
  - **Webhooks**, the whole subsystem: `listWebhooks`, `getWebhook`,
    `createWebhook`, `replaceWebhook`, `deleteWebhook`, `listDeliveries`,
    `replayDeliveries`, `replayDelivery`, `listDeadLetters`,
    `acknowledgeDeadLetters`, `discardDeadLetters`, `discardDeadLetter`.
  - **Tenant lifecycle**: `deleteTenant`, `exportTenant`, `getSessionLifetime`,
    `setSessionLifetime`, `listAttestationCas`, `addAttestationCa`,
    `removeAttestationCa`.
  - **Resources and scopes**: `listResources`, `createResource`,
    `deleteResource`, `defineScope`, `deleteScope`.
  - **Mail**: `getMailSettings`, `setMailSettings`, `clearMailSettings`,
    `sendTestMail`.
  - **Tenant settings**: `updateTenant`, which takes a patch covering every
    setting the endpoint accepts. `updateTenantBranding` stays as the narrow
    spelling and now delegates to it.
  - **Audit paging**: `listAuditPage`, which returns `nextCursor`. Without it a
    client could not read past the first page. `listAudit` now takes all seven
    of the endpoint's filters.
  - **SAML**, twenty-one methods covering two directions. The first signs a
    tenant's users in through their own SAML identity provider:
    `listSamlConnections`, `getSamlConnection`, `createSamlConnection`,
    `replaceSamlConnection` and `deleteSamlConnection`, plus the platform switch
    `getTenantSaml`/`setTenantSaml`. The second makes Proteles the identity
    provider for a customer's SAML applications: `listSamlServiceProviders`,
    `getSamlServiceProvider`, `createSamlServiceProvider`,
    `replaceSamlServiceProvider`, `deleteSamlServiceProvider`,
    `listSamlServiceProviderAssignments`, `assignSamlServiceProviderUser`,
    `unassignSamlServiceProviderUser`, `listSamlIdpKeys`, `mintSamlIdpKey`,
    `promoteSamlIdpKey`, `revokeSamlIdpKey`, and that direction's own switch,
    `getTenantSamlIdp`/`setTenantSamlIdp`. **The server does not serve the
    second direction yet.** No SSO endpoint is mounted for it, so a
    registration made now cannot sign anybody in until one is.
  - **And**: `getFleetHealth`, `setSoftCap`, `deleteConnection`, `exportAudit`.

- **The fields the types could not say.** The server sent them and the client
  dropped them, or the server accepted them and the client could not send them.
  `Tenant` gains its MFA policy and grace period, `passkeyAttestation`,
  `attestationCaCount`, `mfaEmailFactorEnabled`, `mfaSelfRecoveryHours`,
  `maxMembers` and `memberCount`. `App` gains `createdAt`, `isActive` and
  `selfRegistered`. The audit event gains `detailJson`, `leafVersion` and
  `causedByUserId`, which is who performed an action rather than whom it was
  about, and `listAudit` can filter on it. `createTenant` takes `ownerEmail`.
  `createApp` can register a `private_key_jwt` client with
  `jwtAuthPublicKeyPem`. `ManagementError.code` is typed as the thirteen codes
  the API documents, including `rate_limited`, which any operation can return
  and which is worth retrying after a pause, and `temporarily_unavailable`. It still carries an unknown code
  through.

- `index.ts` now re-exports **every** type `types.ts` declares. It was a
  hand-picked list twice, and went stale twice — most recently on the four
  aliases `types.ts` provides under the comment "so callers can name them
  without reaching into `generated/`", which this file then did not re-export.

- `@proteles/alpine-ajax` — server-side helpers for [Alpine AJAX](https://alpine-ajax.js.org):
  route and fragment guards, and the session helpers the other server packages
  have. Deliberately **not** a copy of `@proteles/htmx`: Alpine AJAX reads no
  response header that makes the browser navigate — `fetch` follows every
  redirect transparently — so a guarded fragment is answered with a `401` whose
  body is addressed to the ids in `X-Alpine-Target`, which Alpine merges in place
  because it merges bodies on error statuses too. It is already on npm: it was
  published by hand at `0.1.1` on 2026-08-22, after that release's notes were
  written, so this is the first changelog entry to list it.
- `ManagementClient.getUsage()` — reads `GET /api/v1/usage`. The definition
  string travels back with the number, because "active users" has several
  defensible meanings and each gives a different figure.

### Added (`@proteles/management`)

- `App`, `UpdatedApp`, `CreateAppInput`, `UpdateAppInput` and `CreatedApp`
  gain `backchannelLogoutUri` and `backchannelLogoutSessionRequired` (OIDC
  Back-Channel Logout 1.0 §2.2): where an app receives a signed logout token
  when a session it was issued an ID token for ends, and whether it requires a
  `sid` in it. `null` in `updateApp` stops the app being told, and clears
  `backchannelLogoutSessionRequired` with it. The server
  accepts and lists them as `backchannel_logout_uri` and
  `backchannel_logout_session_required` on `/api/v1/apps` from this release;
  an older server's listing reads as `null` and `false`.
- `SamlServiceProvider.singleLogout`: whether the application can take part in
  single logout started by another SAML application — `takes_part`,
  `no_logout_endpoint` (never told, so that logout is partial),
  `no_certificate` (its logout requests are refused and its answers cannot be
  verified, so a logout passes it over) or `no_logout_endpoint_or_certificate`.
  The server derives it from `slo_url` and the request-signing certificate and
  sends it as `single_logout` from this release. New type `SingleLogout`.
- `ManagementError.detail`: set when the server could not read a request body,
  naming the field it did not know and the ones it expected, or the value that
  did not fit — "unknown field `name`, expected one of `client_name`, …".
  `message` is unchanged ("invalid JSON body"). The server sends it as `detail`
  on those 400s from this release.
- `getTenant()`'s `Tenant` gains `issuer`: the OpenID Connect issuer an
  application configures to sign that tenant's users in (`https://<slug>.<base
  host>`, or the server's issuer for the default tenant; `null` with no tenant
  base host). The server sends it as `issuer` on `GET` and `PATCH
  /api/v1/tenants/{id}` from this release.
- `getSmsFactor` and `setSmsFactor`, for `GET`/`PUT /api/v1/tenant/sms-factor`:
  the SMS second factor's switch, whether the tenant's plan includes it (TEAM
  and BUSINESS do), whether the deployment can deliver, and the month's texts.
  Turning it on on a FREE tenant answers `403`.
- `findUser`'s `mfa` gains `email` and `sms`, and `resetUserMfa`'s result
  gains `emailRemoved` and `smsRemoved`. The server's operator reset now
  removes email and SMS factors too; before, it left them in place.
- `getUsage()` gains `resetsAt`: when `activeUsers` starts again from zero,
  00:00 UTC on the first of the next month (`2026-11-01T00:00:00Z`). That is not
  the subscription's renewal date. It's absent from a server that predates it.
- `Tenant` gains `plansEnforced`.
- `Tenant` gains `passwordSignupEnabled` and `socialSignupEnabled`, and
  `updateTenant` takes both: who may make their own account on the tenant.
  `socialSignupEnabled` decides whether a first sign-in through a
  social connection makes an account; off, a person who already has one still
  signs in that way. `passwordSignupEnabled` opens the tenant's hosted sign-up
  page, and changes nothing on a server that does not have that page yet. Both
  are false for a new tenant. The server sends and accepts them as
  `password_signup_enabled` and `social_signup_enabled` from this release.
- `Tenant` and `TenantPlan` gain `planBinding` (new type `PlanBinding`): why the
  plan does or does not bind — `"not_enforced"` (`PLANS_ENFORCED` is off),
  `"platform_tenant"` (the default tenant, which no plan limits, on a deployment
  that enforces plans) or `"plan"`. `plansEnforced` and `enforced` are false for
  both of the first two, so on the default tenant this is the only field that
  says whether the deployment enforces plans. Absent from an older server.

### Fixed

- **`UserButton`'s name no longer runs into its button** (`@proteles/react`,
  `@proteles/vue`, `@proteles/solid`). Unstyled, it read "aliceSign out": the
  label and the button had nothing between them. A space separates them now,
  as `@proteles/svelte`'s template always had. A flex or grid container ignores
  it; inline, it adds one space's width.
- **Requests racing one expired session share one refresh** (`@proteles/bff`).
  Until now, every request that arrived with an expired access token sent its
  own refresh, and any refresh that failed cleared the session cookie. The
  server spends each refresh token once, so two tabs, or a page and its fetch,
  arriving together would sign the user out. Now there is one token exchange
  per refresh token. Requests that arrive while it is in flight wait for it, and
  requests still carrying the old cookie in the next sixty seconds get the same
  answer. This works within one process only. Behind a load balancer without
  session affinity, keep each session's refreshes on one instance.
- **Client credentials are form-encoded before Basic authentication**
  (`@proteles/js`), as RFC 6749 §2.3.1 requires, and the server now decodes
  them. Nothing this server issues is affected, because generated ids and
  secrets never contain a character the encoding changes. An operator-chosen
  client id containing `:` used to move the separator and corrupt both halves.
- **`connection` does what the documentation said.** Passing
  `connection: "google"` to `createAuthorizationUrl`, or `?connection=google`
  to `/api/auth/login`, now sends an unauthenticated visitor straight to that
  provider. The SDK always sent it, but the server used to drop it. `loginHint`
  is sent and not honoured, and its doc comment no longer says that it pre-fills
  the username.
- **The Next.js quickstart did not build, and its middleware answered 500**
  (`@proteles/js`, `@proteles/bff`, `@proteles/react`, `@proteles/next`). Found
  by running it in Next.js 14.2 rather than calling the bindings directly. The
  Node 18 fallback `import("node:crypto")` was resolved by webpack into the Edge
  middleware bundle, which failed the build with `UnhandledSchemeError`; it now
  carries `/* webpackIgnore: true */`. `@proteles/react`'s context module had no
  `"use client"`, so the App Router refused `AuthProvider` in a layout. And
  Next's middleware adapter throws on a relative `Location`, which the core
  sends on purpose; `@proteles/next`'s middleware now makes both of its
  redirects, to sign-in and to `/revalidate`, absolute against the configured
  redirect URI's origin — never the request's host — and every other binding
  keeps the relative form.
- **`@proteles/svelte` needed the runtime secrets at build time.**
  `createAuthHandlers` and `createAuthHandle` built their `AuthApp` when the
  module was imported, and `vite build` imports every `+server.ts`. They build
  it on the first request now, which is also where a missing variable is
  reported.
- **Signing in from a guarded fragment landed on the bare fragment**
  (`@proteles/htmx`, `@proteles/alpine-ajax`). The sign-in's `returnTo` was the
  fragment's own URL, and the round trip ends in a navigation to it. For a
  fragment request it is now the page — htmx's `HX-Current-URL`, or the
  `Referer` of an Alpine AJAX request — path only, and only from the configured
  redirect URI's origin, else `postLoginRedirect`. A boosted htmx navigation and
  an Alpine `_top` request are pages, and keep their own URL. The Alpine AJAX
  prompt's default copy is "Sign in to see this." rather than "Your session has
  expired.", which most people who see it never had.
- **The Nuxt plugin in `@proteles/vue`'s README signed users out** (docs only;
  the README published with 0.1.0 and 0.1.1). Its step 3 seeded `protelesAuth`
  from `useFetch("/api/auth/me")` during server rendering. Once the access token
  has expired, that request refreshes it and rotates the refresh token, and Nuxt
  does not pass the rotated cookie on to the browser, which keeps the spent
  token and is signed out by its next refresh. A Nuxt app whose plugin was
  written from that README has the same bug. Migration: seed `initialUser` from
  `event.context[CONTEXT_USER_KEY]`, which the server middleware sets, and carry
  it to the browser with `useState` — the plugin now in the README and in
  `examples/nuxt-quickstart/plugins/proteles.ts`.
- **`@proteles/js` on a page served over plain http failed with an unhelpful
  error.** A page on http from any host but localhost is not a secure context,
  so the browser withholds `crypto.subtle`, and PKCE fell through to the Node 18
  fallback's `import("node:crypto")`, which fails as a module resolution. It now
  throws saying Web Crypto needs https or localhost. `@proteles/bff` gives the
  same kind of error in any runtime that has neither `crypto.subtle` nor Node.
- **The missing-configuration error named `@proteles/next` in every framework.**
  It names `@proteles/bff`, which throws it, and says the values come from
  explicit configuration or `process.env`.
- **The quickstarts did not run as their READMEs said** (`examples`, no
  package change). SvelteKit's `vite.config.js` imported `sveltekit` from the
  wrong package, and the `.env` it had you write never reached `process.env`.
  Nuxt's SSR plugin fetched `/api/auth/me`, whose refresh rotated the refresh
  token without the new cookie reaching the browser, which was then signed out
  (the `@proteles/vue` entry above).
  SolidStart asked for `vinxi@^0.4`, which no `@solidjs/start` since 1.1
  accepts, so `npm install` failed, and its production page rendered blank from a second
  copy of Solid. The Alpine AJAX page used an `x-load` attribute that does not
  exist and never showed a Sign in button. And no production start command read
  `.env`: `npm start` now uses Node's `--env-file` (Node 20.6+). The node
  examples' `.env.example`, and the `@proteles/htmx` and `@proteles/alpine`
  READMEs, also recommended an issuer at `127.0.0.1` for Node 18, which a server
  routing tenants by host can answer with 404; they now say to use Node 20+, and
  the Next.js and SvelteKit examples ask for it too.
  `scripts/verify-quickstart.mjs` installs, builds, serves and walks each
  quickstart in its own framework; Proteles' integration tests run it for
  Next.js.
- **A busy authorization server signed users out** (`@proteles/bff`, and every
  framework package built on it). Since the server's Argon2 pool was
  bounded, its token endpoint answers a full queue with `503
  temporarily_unavailable`, and its rate limiter answers `429`; both mean "come
  back shortly". The BFF cleared the session on *any* failed refresh, so
  everybody whose access token expired during a busy minute was signed out. Now
  a `503` (whatever its body), a `429`, any other `5xx` or `408`, or no answer at
  all keeps the cookie and its refresh token: `/me` answers `503` with the
  server's `Retry-After`, `/revalidate` answers a `503` *try again* page instead
  of redirecting, and the next request retries. `invalid_grant` and the other
  `4xx` still end the session as before. A refresh whose exchange went through
  but whose new ID token could not be checked, because the key set could not be
  fetched, no longer ends the session either: the rotated refresh token is kept.
  How this lines up with the native SDKs' rules (`docs/mobile-SDKs.md` §10.9),
  and the four places it does not, is in the `@proteles/bff` README.
- **A busy authorization server at sign-in ended in `login_failed`**
  (`@proteles/bff`, and every framework package built on it). A `503`, `429`,
  another `5xx` or `408`, or no answer at the code exchange now gets a `503`
  page, with the server's `Retry-After` when it sent one, that says the sign-in
  service was busy and links to `{basePath}/login` with the same `returnTo` — a
  fresh flow. The code is never presented again: it may already have been
  redeemed by an exchange whose answer was lost, and the server revokes what a
  replayed code minted. `onError` still hears about it, with the context
  `"callback"`. So does a too-tight `timeoutMs` or an issuer that cannot be
  reached, which now land on this page rather than on `login_failed`; the
  reported reason says which it was. `invalid_grant` and every other `4xx` still
  end in `login_failed`.
- **The browser packages showed a busy authorization server as a sign-out**
  (`@proteles/react`, `@proteles/vue`, `@proteles/svelte`, `@proteles/solid`,
  `@proteles/alpine`). Their `/me` fetchers read any non-`200` as signed out,
  so while `/me` answered `503` for a busy server — the cookie intact — the UI
  showed the signed-out state until the next `/me` got through. A `503`, `429`,
  `408`, any other `5xx`, or no answer now keeps the last known user (a first
  load stays loading), sets `isUnavailable`, and asks `/me` again after the
  server's `Retry-After`, capped at an hour, or else after 2 s, 4 s, 8 s and so
  on up to 30 s. A `401`, or `{ authenticated: false }`, still means signed out.
  The asking stops when the `<AuthProvider>` that does it unmounts, and in Vue
  when the plugin's app unmounts (Vue 3.5 and later).
- **Sign-out's revocation is no longer lost silently** (`@proteles/bff`). A
  revocation answered as busy within two seconds — `503`, the same full pool, at
  `/oauth/revoke`, or `429`, another `5xx` or `408` — is tried once more after
  half a second, and one that still fails, or got no answer, is reported through
  `onError` (context `"logout"`). No answer and a slower busy answer are not
  retried, so sign-out waits at most one `timeoutMs` and 2.5 seconds before the
  redirect that clears the cookie. The cookie is cleared either way.
- `ManagementScope` was missing `usage:read`, `mail:read` and `mail:write`, so
  `createApiKey(id, { scopes: ["usage:read"] })` — the call the API documents —
  did not typecheck. A CI check now asserts the union and the server's enforced
  scopes are the same set, in both directions.
- **A `returnTo` with a dot segment could redirect off-site** (`@proteles/bff`,
  and every framework package built on it). `safeReturnTo` checked the path it
  was given and returned the one the URL parser made of it, and dot-segment
  removal turns `/.//evil.example`, `/%2e//evil.example` and
  `/a/..//evil.example` into `//evil.example`, which a browser reads as another
  host. `/revalidate` sent it as `Location`, sign-in stored it for the redirect
  after the callback, and the sign-out and try-again pages linked to it. A path
  that comes out of the parser starting with `//` is now refused, and the
  configured default is used instead.
- **`@proteles/fastify` did not work under `app.register`.** Fastify gives an
  ordinary plugin a scope of its own, and a hook added there runs only for the
  routes added there. So the session hook never ran for the app's routes:
  `sessionOf` and `userOf` were `null` on all of them, and `requireAuth`
  refreshed through its own `AuthApp`, so two guarded requests with one expired
  token could each spend the refresh token. The plugin is now marked
  `skip-override`, which is what `fastify-plugin` does. Stock Fastify also has
  no parser for `application/x-www-form-urlencoded`, so it answered every SDK
  sign-out with `415`. The auth routes now get a string parser in a scope of
  their own, unless the app already registered one (such as
  `@fastify/formbody`). An app that registers one after the plugin is
  unaffected. Both framework packages are now also tested against real Fastify
  and Express.
- **ID-token verification failed on Node 18** (`@proteles/js`, and every
  server package built on it). Every package declares `node >=18.12`, and
  Node 18 has no global `crypto` by default. The verifier used the bare global
  for the key import, the signature and `at_hash`, so every sign-in there
  failed with `crypto is not defined`. It now goes through the same
  `node:crypto` fallback that PKCE has always used.
- **The key-set fetch had no timeout, and an unknown `kid` always refetched**
  (`@proteles/js`, `@proteles/bff`). Every callback and every refresh that
  carries an ID token waits on that fetch, so a key-set endpoint that never
  answered held all of them open. `JwksCache` now gives up after `timeoutMs`
  (a new optional third argument, ten seconds by default) and reports the
  failure as unreachable, so it is retryable. The BFF passes its own
  `timeoutMs`. And because the `kid` is read before the signature is checked,
  each token naming an unknown one, including the unauthenticated logout
  tokens that `verifyLogoutToken` reads, cost one request to the issuer. Now
  an unknown `kid` refetches at most once every 30 seconds. One that arrives
  sooner is refused against the key set already held.
- **A config object built a new `AuthApp` on every call** (`@proteles/vue`,
  `@proteles/solid`, `@proteles/htmx`, `@proteles/alpine-ajax`). The server
  helpers that take an optional config built a fresh app each time one was
  passed. Each request therefore had its own refresh de-duplication and its own
  key-set cache. Two requests with one expired access token each spent the
  refresh token, and the one the server refused cleared the session cookie.
  There is now one app per config object, so pass the same object on every
  call. Zero-config use was not affected.
- **`sub` is now compared where OpenID Connect requires it** (`@proteles/bff`,
  and every framework package built on it). The session takes its `sub` from
  userinfo, but only the ID token's `sub` is signed. A sign-in whose userinfo
  `sub` differs from the ID token's now ends in `login_failed` (OIDC Core
  §5.3.2). A refresh whose new ID token names a different `sub` than the
  session now ends the session, as a refused refresh does (§12.2). It is
  reported through `onError` with the context `"refresh"`.
- **`/me` is sent with `Cache-Control: no-store`** (`@proteles/bff`, and
  every framework package built on it), signed in or not. It names the person
  the cookie belongs to. A shared cache could have served one user's answer to
  the next visitor, and a browser could have shown the user as signed in after
  sign-out.
- **An id of `.`, `..` or the empty string is refused before any request**
  (`@proteles/management`). `encodeURIComponent` leaves dots alone, and the URL
  parser then resolves such a path segment away. The call went to another
  endpoint with the caller's token: `replayDelivery(".")` posted to the bulk
  replay at `/api/v1/webhook/deliveries/replay`, and `getTenant("..")` read
  `/api/v1/`. Every id that goes into a path now throws a `ManagementError`
  for these three values. Ids that merely contain dots are sent as before.


## [0.1.1] — 2026-08-12

### Fixed

- **`@proteles/bff` now forwards `timeoutMs` to the core client.** `@proteles/js`
  has always accepted it; this package never passed it, so its 10-second default
  was unreachable — no option, no environment variable, no way at all to change
  the timeout on calls to the authorization server.

  Ten seconds is a sound default and a poor hard limit. A cold-starting
  authorization server, a slow link, or a server busy minting a new tenant's
  signing keys can all exceed it, and the failure is worse than slow: the browser
  receives `?proteles_error=login_failed`, which is exactly what a *wrong client
  secret* produces. The only thing distinguishing them — `This operation was
  aborted` — appears solely in the server-side `onError` diagnostic.

  Set `timeoutMs`, or `PROTELES_TIMEOUT_MS`. An explicit value beats the
  environment, and a nonsensical one is refused at construction rather than
  silently becoming the default.

### Notes

Only `@proteles/bff` changed. The other nine are republished at `0.1.1` with no
source changes, because these ten are versioned as a set — their
inter-dependencies are pinned to a single minor, and letting them drift apart
would mean maintaining every combination.

Those inter-dependency ranges moved from `^0.1.0` to `^0.1.1`. `0.1.1` already
satisfied `^0.1.0`, so this is not required for resolution; it is here because
six packages wrap `@proteles/bff` and the accurate statement is that they want
the fixed one. Left alone, a lockfile could keep resolving `@proteles/bff@0.1.0`
and quietly reintroduce the ten-second wall.

This was also the first release published over OIDC trusted publishing rather
than a long-lived token.


## [0.1.0] — 2026-08-12

First release, published 2026-08-12. Nothing had been published to npm before
this, so everything below is "added" and the list is the set of packages rather
than a set of changes.

All ten went out together from one tag, and an anonymous
`npm install @proteles/next @proteles/react` resolves the transitive `^0.1.0`
ranges from the registry and imports.

### Added

**Core**

- `@proteles/js` — framework-agnostic OAuth2/OIDC client: PKCE challenge
  generation, code exchange, refresh with rotation, revocation, and userinfo.
  No storage and no framework assumptions; it is the layer everything else is
  built on.
- `@proteles/bff` — the Backend-for-Frontend core. Access and refresh tokens
  live only inside an AES-256-GCM encrypted `httpOnly` cookie set by your own
  server; the browser receives a sanitized user object and never a token.
  Operates on Web `Request`/`Response`, so it runs on Node, on an edge runtime,
  or under any framework that can hand it a `Request`.
- `@proteles/management` — typed client for the `/api/v1` Management API
  (tenants, apps, users, connections, branding, audit).

**Framework packages** — each wraps `@proteles/bff` and re-exports what you need:

- `@proteles/next` — Next.js catch-all route handlers, `authMiddleware`,
  `currentUser()`.
- `@proteles/react` — `<AuthProvider>`, `<SignInButton>`, `<SignedIn>`,
  `<SignedOut>`, `<Protect>`, `<UserButton>`, and the `useAuth` hook.
- `@proteles/svelte` — SvelteKit request handlers, a `handle` hook, and the
  component set. Components ship as `.svelte` source under the `svelte` export
  condition; the server half is a separate `@proteles/svelte/server` subpath
  that imports in plain Node.
- `@proteles/vue` — Nuxt/Vue provider, composables, and components.
- `@proteles/solid` — SolidStart handlers, context, and components.
- `@proteles/alpine` — an Alpine.js plugin (`$auth` magic, `x-auth` directives)
  plus a standalone browser bundle usable from a `<script>` tag with no build
  step at all.
- `@proteles/htmx` — server-side helpers for htmx: `HX-Redirect`-aware login
  flows, route guards, and fragment guards. Server-only, because htmx needs no
  client-side auth script.

### Notes

- Every package is MIT, ships its licence text, and declares
  `publishConfig.access: public`.
- `engines.node` is `>=18.12` throughout.
- The packaging itself is checked on every pipeline by what is now
  [`tools/npm-publish-readiness.mjs`](tools/npm-publish-readiness.mjs),
  which is in turn tested against trees where each of its rules is broken.

<!-- From the first release made here on, a version links to its tag
(https://github.com/proteles-auth/proteles-sdk/releases/tag/npm-vX.Y.Z) and
Unreleased to the compare view from the latest tag
(https://github.com/proteles-auth/proteles-sdk/compare/npm-vX.Y.Z...main). -->
[Unreleased]: https://github.com/proteles-auth/proteles-sdk/commits/main
[0.3.0]: https://www.npmjs.com/package/@proteles/js/v/0.3.0
[0.2.0]: https://www.npmjs.com/package/@proteles/js/v/0.2.0
[0.1.1]: https://www.npmjs.com/package/@proteles/js/v/0.1.1
[0.1.0]: https://www.npmjs.com/package/@proteles/js/v/0.1.0
