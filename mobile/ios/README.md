# ProtelesAuth (iOS)

Requires a Proteles account — sign up for free on [proteles.com](https://proteles.com/signup).

The native iOS SDK for the Proteles identity platform: sign a user in through
the system browser, keep a valid access token, and sign out — as a public
OAuth 2.0 / OpenID Connect client with PKCE.

It verifies ID tokens by the same rules as the Android SDK, and is held to the
same shared test vectors.

- **The system browser, never a web view.** `ASWebAuthenticationSession`, so the
  app never sees the password.
- **PKCE, `state`, `nonce` and RFC 9207 `iss`** on every sign-in.
- **Verified ID tokens**: RS256 only, keys from the tenant's JWKS, `at_hash`
  bound to the access token, the nonce compared, the issuer byte for byte.
- **Refresh with rotation done right**: early (at half the token's life),
  single-flight, serialised across the app's processes, and the rotated
  refresh token persisted *before* the new access token is handed out.
- **The Keychain**, `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`.
- **No dependencies.** Security, CryptoKit, AuthenticationServices and
  Foundation only.

## Install

Swift Package Manager. Requires iOS 17.4 or later (macOS 14.4 or later also
builds) and Swift 6 (Xcode 16 or later). iOS 17.4 is the first version whose
`ASWebAuthenticationSession` hands an `https` redirect back to the app, and an
`https` redirect is the only kind this server registers for an app.

In Xcode, *File › Add Package Dependencies…*, enter
`https://github.com/proteles-auth/proteles-sdk`, and add the **ProtelesAuth**
library to your app target. From another package:

```swift
dependencies: [
    .package(url: "https://github.com/proteles-auth/proteles-sdk", from: "0.1.0"),
],
targets: [
    // A URL dependency's identity is the repository's name, so "proteles-sdk" here.
    .target(name: "MyApp", dependencies: [.product(name: "ProtelesAuth", package: "proteles-sdk")]),
]
```

The package's manifest is `Package.swift` at the root of that repository,
which also holds the TypeScript SDKs; a release of this package is a plain
`X.Y.Z` tag there (the npm packages are tagged `npm-vX.Y.Z`, which SwiftPM
ignores). Until 1.0, a minor version may change the API;
`.upToNextMinor(from:)` holds an app to one.

**From a checkout**, as a local package: in Xcode, *File › Add Package
Dependencies… › Add Local…* and choose the checkout's root. From another
package:

```swift
dependencies: [
    .package(path: "../proteles-sdk"),
],
targets: [
    // A path dependency's identity is its directory's name, so "proteles-sdk" here.
    .target(name: "MyApp", dependencies: [.product(name: "ProtelesAuth", package: "proteles-sdk")]),
]
```

## Register the app

Ask the tenant's administrator for **one client per app** — not one per
install — created through the Management API (`POST /api/v1/apps`) with both of
these, because the API's defaults are neither:

- `"token_endpoint_auth_method": "none"` — a **public client**. The default is
  a confidential client with a secret, which an app cannot keep.
- `"grant_types": ["authorization_code", "refresh_token"]`. The default is
  `authorization_code` alone, which issues no refresh token, so the user would
  sign in again every time the access token expired. The `refresh_token`
  *grant*, not the `offline_access` scope, is what makes the server issue one.

And with the app's identity, `"app_identity": {"ios": {"app_id":
"ABCDE12345.com.example.app"}}`: your Team ID, a dot, and the bundle ID. The
server reads the redirect host's `apple-app-site-association` before it
registers the app, and refuses it unless the file lists that app ID in
`webcredentials.apps` (step 3 below), so serve the file first.

The server assigns the `client_id`; configure the SDK with the one it returns.
Register the redirect URI below, and the post-logout redirect URI if you use one.
Leave out `"application_type": "native"`: the server does not use it, and it can
be added on request ([What it does not do](#what-it-does-not-do)).

### Redirect URIs

The redirect is an `https` URL on a domain you control, associated with your
app. Only your app can receive it, which is the point: the authorization code
goes to whatever receives the redirect. This server registers no private-use
scheme (`com.example.app:/callback`) for any client, because any other app on
the device can claim the same scheme.

1. **Pick a callback URL** on a domain you control, for example
   `https://app.example.com/oauth/callback`, and register it on the client.
2. **Associate the domain with the app** under the `webcredentials` service: in
   Xcode, *Signing & Capabilities › Associated Domains*, add
   `webcredentials:app.example.com`. (`applinks:` alone is not enough:
   `ASWebAuthenticationSession` hands an `https` callback back only for a host
   associated through `webcredentials`.)
3. **Serve the association file** at
   `https://app.example.com/.well-known/apple-app-site-association`, over
   `https`, with no redirect, naming the app by Team ID and bundle ID:

   ```json
   { "webcredentials": { "apps": ["ABCDE12345.com.example.app"] } }
   ```

`ProtelesConfiguration` refuses, at construction, anything the server would
refuse later, and anything `ASWebAuthenticationSession` could not hand back:

| Redirect URI | |
|---|---|
| `https://app.example.com/oauth/callback` | **The redirect.** A host associated with the app under `webcredentials`, as above. |
| `com.example.app:/oauth/callback`, `myapp://callback` | **Refused**: a private-use scheme, which this server does not register for any client. |
| `http://localhost:…` | **Refused**: `localhost` gets no port exemption at the authorization endpoint. |
| `http://127.0.0.1:PORT/…`, `http://[::1]:PORT/…` | **Refused**: the server would register one, but `ASWebAuthenticationSession` cannot intercept a loopback redirect and the SDK runs no listener, so accepting it would only move the failure to the first sign-in. The Android SDK refuses it too. |
| Any other `http:` redirect | Refused. |
| Anything with a `#fragment` | Refused. |
| `https://user@app.example.com/…` | Refused: userinfo in a redirect. |

The optional `postLogoutRedirectURI` follows the same rules, and is registered
separately (as a post-logout redirect URI) on the same client. `scopes` must
include `openid` and name each scope once.

## Usage

### Configure once

```swift
import ProtelesAuth

let client = try ProtelesClient(configuration: ProtelesConfiguration(
    issuer: "https://acme.proteles.example",          // exactly as the server spells it
    clientId: "k3v9…",                                 // the client_id the registration returned
    redirectURI: "https://app.example.com/oauth/callback",
    // scopes: ["openid", "profile", "email"],          // the default; must include openid
    postLogoutRedirectURI: "https://app.example.com/oauth/signed-out"
))
```

The issuer is compared **byte for byte** with discovery, the callback and the ID
token: `https://acme.proteles.example/` (with a slash) is a different issuer,
and `HTTPS://…` is refused at construction. Keep one `ProtelesClient` for the
life of the app; it caches discovery, and the signing keys for ten minutes.

The stored session names the issuer and `clientId` it was signed in with. The
Keychain service is keyed by `clientId` alone, so an app that points one
`clientId` at several tenants shares one record: a client reads a session
stored for another issuer as signed out, and never refreshes or revokes it
(its refresh token belongs to the other tenant). Its `signOut` deletes it; its
`signIn` replaces it.

### Sign in

```swift
// From a button. `window` is the UIWindow to present over.
do {
    let user = try await client.signIn(presentationAnchor: window)
    print("Signed in as", user.email ?? user.subject)
} catch ProtelesAuthError.cancelled {
    // The user closed the browser. Not an error.
} catch ProtelesAuthError.alreadyInProgress {
    // A sign-in is already showing the browser (a double tap). Ignore it.
} catch ProtelesAuthError.browserUnavailable {
    // The system would not show a browser. Tell the user.
}
```

`signIn` fetches discovery (and checks its issuer), opens the browser with
PKCE, `state` and `nonce`, checks the callback's `state` and `iss`, redeems the
code, verifies the ID token, and **stores the session before it returns**.
Pass `prefersEphemeralWebBrowserSession: true` to share no cookies with Safari:
the user types credentials every time, and sign-out never needs the browser.

One sign-in runs at a time per client: a second call — or a sign-out that ends
the browser session — while one is running throws `.alreadyInProgress` and does
nothing else. While a 429 is being waited out (see below), `signIn` throws
`.rateLimited` **before** the browser opens, so nobody types a password for a
code that could not be redeemed — and a 429 that arrives while the browser is
showing holds back the code exchange too.

The callback must come back to the redirect URI itself — scheme, authority and
path — with a query that decodes; anything else is `.stateMismatch`, like a
wrong `state`. An `error` from the server is
`.authorization(error:description:errorURI:)`.

Cancelling the task that awaits `signIn` (a SwiftUI `.task` whose view went
away) dismisses the browser and throws `.cancelled`. Once the browser has
returned a code, nothing after it can be cancelled: the exchange,
verification and save run to the end, so a screen recreated meanwhile finds the
user signed in. If anything after the code exchange fails — the ID token is
refused, the Keychain cannot be written, the refresh lock cannot be taken — the
refresh token the server just issued is revoked, best effort, rather than left
alive for thirty days with nobody holding it.

`client.currentUser()` returns the signed-in user's claims (`subject`, `email`,
`emailVerified`, `preferredUsername`, `authTime`, `amr`, `acr`, and any claim by
name), or `nil`. They are the verified ID token's claims, kept after the token
itself expires — the ID token lives fifteen minutes; the user does not.

### Call your API

```swift
let token = try await client.validAccessToken()
request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
```

Call `validAccessToken()` **before every request** and do not cache what it
returns. It returns the stored token, refreshing first once the token is past
half its life (the server sets the lifetime; fifteen minutes by default, less
near a SAML session's end).

If that refresh fails while the stored token has not yet expired, you get the
stored token and nothing is raised — a network blip or a 429 at the
half-life point does not fail a call you could have made for several more
minutes. Three failures are the exception and end the session at once, clearing
the Keychain:

- `invalid_grant` — the family is gone (`.signInRequired`);
- a refreshed ID token that fails a **trust** rule — its signature, key,
  issuer, audience, `at_hash`, or a `sub` naming another user
  (`.idTokenRejected`); its refresh token is also revoked;
- a refresh token this client already knows is dead (refused, revoked or
  abandoned) — it is never presented again, even if the Keychain could not be
  cleared.

A Keychain that cannot be written raises `.storage` and does not end the
session. Two things about a refreshed ID token are *not* failures: the
device's clock (its `exp` and `iat` are not judged — it arrived over TLS with
the access token its `at_hash` names, and a device whose clock is wrong would
otherwise rotate its refresh token on every call; the clock rules still
apply at sign-in), and a key set that cannot be reached right now (the new
tokens are kept with the previous claims, and the next refresh verifies again).
In both cases the new claims are not adopted, as in the Android SDK.

The rotated refresh token is written to the Keychain as soon as the token
response parses, before anything else in it is checked, so a response that then
fails validation does not strand the family.

After a failed refresh the SDK does not ask again before **min(30 s, half the
stored token's remaining life)**; once the token has expired there is nothing
left to wait for, and each call tries again, so it recovers as soon as the
server does. After a **429** — from the token endpoint, revocation, discovery
or the key set — it sends no token request (refresh or code exchange), makes
no refresh — not even discovery — and opens no sign-in browser before the
server's `Retry-After` (seconds or an HTTP-date, capped at an hour), or sixty
seconds when it sent none the SDK can read. The backoff lives in memory, per
client.

The access token's lifetime is counted from just before the request that
obtained it, so time in flight is not added past its real expiry. A device
clock set back by up to a minute (an NTP correction) is not a reason to
refresh; further back, the stored times are not trusted and it refreshes.

| It throws | Meaning | Do |
|---|---|---|
| `.signInRequired` | No session, or it ended (`invalid_grant`: revoked, expired, reused, the password changed; or signed out by another process of the app). The session is already cleared. | Show sign-in. Never retry. |
| `.rateLimited(retryAfter:)` | HTTP 429. The limit is per *network* (60 token requests a minute, shared by everyone behind one NAT). `retryAfter` is how long the SDK is waiting before it refreshes again. | Wait. |
| `.network(_, status:)` | The server could not be reached (`status` is `nil`), answered with a 5xx (`status` is it), the key set answered anything but `200` or published no usable key, or another process of the app held the refresh lock past its timeout. | Retry later. |
| `.storage` | The Keychain is unavailable — e.g. before the first unlock after a reboot. The session is **not** discarded. | Retry later. |
| `.tokenEndpoint(error:description:status:)` | Any other refusal from the token endpoint (a 4xx). `error` is the OAuth code the body carried, or `nil` when it carried none. | Log it. |
| `.idTokenRejected(reason)` | The refreshed ID token failed a trust rule. The session has been cleared and its refresh token revoked. From `signIn`, it is a failed sign-in; `.expired` or `.issuedInTheFuture` there almost always means the **device clock** is more than a minute off. | Show sign-in. |

### Sign out

```swift
let result = try await client.signOut()
```

Sign-out clears the Keychain first, then revokes the refresh token at the
server — which ends its whole family — so a device offline can always sign out,
and a slow network never leaves the session on the device while it waits.
`result.revocation` says whether revocation happened: `.revoked`,
`.failed(error)` (the server refused, could not be reached, or the stored
record could not be read to find the token — it stays live on the server until
it expires unused), or `.notAttempted` (there was no refresh token). Neither
step can be cancelled by the caller: cancelling the task that awaits `signOut`
does not stop it.

It throws `.storage` only if the Keychain itself could not be cleared — and
then the refresh token **was still revoked**: you asked to sign
out, and a revoked token in a stale record fails safe. The error's message says
whether that revocation succeeded. This client will not present it again, and
reads the stale record as signed out.

The session is cleared under the refresh lock, so a refresh running in another
process cannot write its rotation back over the deletion. If the lock cannot be
taken — another process has held it past the timeout — it is cleared anyway,
and a refresh elsewhere re-reads the Keychain before each write and leaves an
empty record empty.

That ends the app's session, **not the browser's**: the next `signIn` may
complete without asking for credentials, because the browser is still signed in
to the tenant. End that too whenever the user means "sign me out of this device"
— a shared device, a "switch account" button — from a user gesture:

```swift
let result = try await client.signOut(endSessionPresentingFrom: window)
```

This opens the browser at the tenant's `end_session_endpoint` with
`id_token_hint`, `client_id`, `post_logout_redirect_uri` and `state`. The server
asks the user to confirm. Called while a sign-in or another end-session is
running, it throws `.alreadyInProgress` and does nothing — not even the local
sign-out. With a `postLogoutRedirectURI` registered and
configured, the browser comes back and `result.endSession` is `.completed` —
once the return is addressed to that URI and carries the `state` that was sent;
otherwise it is `.failed(.stateMismatch)`. Without one, the user closes it and
it is `.dismissed`.

### Extensions: sharing a session across processes

An app and its share extension (or widget) are two processes with one Keychain
record, and refresh tokens are single-use: two processes refreshing at once
leave one of them holding a dead token. To share a session safely:

1. Put the app and the extension in one **Keychain access group** and one
   **App Group** (Signing & Capabilities). Both: a session shared across
   processes with only an in-process lock is refused at construction — a
   `keychainAccessGroup` without an `appGroupIdentifier`, or
   either with `InProcessRefreshLock` passed explicitly — because two
   processes would then refresh one single-use token with nothing serialising
   them, and a refresh in the extension could put back a session the user had
   just signed out of in the app. An app with its own cross-process lock
   passes it as `lock:`.
2. Configure both:

   ```swift
   ProtelesConfiguration(
       issuer: …, clientId: …, redirectURI: …,
       keychainAccessGroup: "TEAMID.com.example.shared",
       appGroupIdentifier: "group.com.example.shared")
   ```

With `appGroupIdentifier`, refreshes are serialised across processes with
`flock(2)` on a lock file in the group container, and every refresh re-reads
the Keychain after taking the lock — and again before each write, so a record
another process replaced or deleted meanwhile is left alone. **Without it,
refreshes are serialised only within one process**; `client.lockScope` tells
you which (`.crossProcess` or `.inProcess`). On iOS, a configured App Group
whose container is unavailable (the entitlement is missing) is a configuration
error, not a silent downgrade. (macOS names a container whether or not the app
is entitled; the SDK does not open it at launch to find out, because that can
wait on a privacy prompt.)

A waiter gives up after 60 seconds; `validAccessToken()` then re-reads the
Keychain and hands out the stored token if it is still usable (the other
process has usually refreshed it by then), and sign-out clears anyway. A
sign-in that cannot take the lock to store its tokens fails and revokes them.

iOS terminates a suspended app that holds a file lock in a shared container
(`0xdead10cc`). A refresh holds the lock across the token request and, when the
new ID token names a signing key the client has not fetched yet, a key-set
request — each bounded by the transport's timeouts (30 s idle, 60 s in all, by
default). Discovery happens before the lock is taken; sign-in and sign-out hold
it only for a Keychain write. The SDK runs every refresh under
`ProcessInfo.performExpiringActivity` (which works in extensions too), and when
iOS says the background time is up it cancels the refresh, which releases the
lock before the process is suspended; the refresh is tried again on the next
call. With only the in-process lock (no App Group) there is no file lock to
release, and a refresh already sent is left to finish when the app resumes
instead: abandoned after the server rotated, it would lose the new refresh
token.

## What it does not do

- **No web view**, and no `login_hint` — the server ignores it.
- **No userinfo call and no introspection** — the ID token's claims are the
  user record, and a public client cannot introspect.
- **No per-install registration.** One `client_id` per app, registered by the
  tenant's administrator.
- **No `application_type`.** OpenID Connect registration lets a client declare
  `"application_type": "native"`. The SDK does not send it, and the server does
  not use it: every client is held to the native-app redirect rules, whatever it
  declares, so the declaration would change nothing. If your tooling or your own
  policies need the server to record it, it can be added on request.
- **No back- or front-channel logout.** The server has no `sid` yet; the app
  learns its session ended elsewhere when a refresh returns `invalid_grant`.
- **No device authorization grant, `prompt`, `max_age` or `acr_values`** yet.
- **It cannot tell a throttled account from a wrong password** — the server's
  per-account login limit is deliberately indistinguishable from bad
  credentials, and both happen inside the browser.

## Customising

Everything the SDK touches is a protocol, so tests — and apps with unusual
needs — can supply their own:

| Protocol | Default | For |
|---|---|---|
| `AuthorizationBrowser` | `SystemBrowser` (`ASWebAuthenticationSession`; one browser at a time per instance, `.alreadyInProgress` otherwise; `.browserUnavailable` when the system will not show one) | Tests. Never a web view. |
| `HTTPTransport` | `URLSessionTransport` (ephemeral: no cookies, no cache, no redirects; a response body over 1 MiB is a `.network` error, with an app's own `URLSession` too) | Certificate pinning, proxies, tests. |
| `TokenStore` | `KeychainTokenStore` (service `com.proteles.auth.<clientId>`) | Tests (`InMemoryTokenStore`). Never `UserDefaults` or a file. |
| `RefreshLock` | `FileRefreshLock` with an App Group, `InProcessRefreshLock` without | Tests; an app's own cross-process lock. `InProcessRefreshLock` is refused for a shared session. |

```swift
let client = try ProtelesClient(configuration: configuration,
                                transport: MyPinnedTransport(),
                                store: KeychainTokenStore(configuration: configuration))
```

On macOS the Keychain store uses the data-protection keychain, which needs a
signed app with an application identifier.

## Security notes

- ID-token verification runs in this order —
  algorithm, key, signature over the bytes as received, then claims — and
  refuses base64url that is padded or not the one canonical spelling of its
  bytes, a header that does not parse, a header or payload naming one member
  twice (by code point, as the reference compares names — two canonically
  equivalent spellings of one name are two members, and neither is readable),
  a `crit` header, keys whose `use` or `alg` say otherwise, RSA keys
  below 2048 bits or with an exponent below three or even, several audiences,
  and a missing nonce or `at_hash`. Clock skew is 60 seconds. Everything the
  SDK receives as JSON — discovery, the key set, token responses — is read by
  the same strict parser.
- `ProtelesAuthError` messages are diagnostic; log them, do not show them to
  users verbatim.
- The refresh token never leaves the Keychain except in a request to the
  tenant's token or revocation endpoint, over HTTPS (plain `http` only for a
  loopback development issuer, and then only to an endpoint on loopback).

## For contributors

It implements the native SDK contract in
[`docs/mobile-SDKs.md` §10](../../docs/mobile-SDKs.md#10-the-native-sdk-contract),
and verifies ID tokens by the rules in §5.2, held to the shared vectors in
[`mobile/vectors/`](../vectors/) that every native SDK runs. Registering an
app, for both SDKs, is walked through in [`mobile/README.md`](../README.md).

Where the rules above come from, for anyone changing them:

- The redirect rules and loopback's refusal: §2.1 and §10.1. No private-use
  scheme, and so the Universal Link and the iOS 17.4 floor: M7 in §1 and
  §6 P0.1.
- A valid access token and the refresh fallback: §10.3 and §10.9 items 1–3; the
  clock rule for a refreshed ID token is item 2, and §5.2's clock rules apply at
  sign-in.
- Sign-out revoking even when the Keychain cannot be cleared: §10.9 item 6.
- A sign-in that cannot store what it got revoking it: §10.9 item 7.
- One sign-in at a time: §10.9 item 8. The shared-session lock: §10.6 and
  §10.9 item 9.
- The verifier's order and refusals: §5 and §5.2 (M2, M3).

### Develop

From the repository root, where `Package.swift` is:

```bash
swift build && swift test                     # plain SwiftPM, with a full Xcode selected
mobile/ios/scripts/swift-test.sh              # the same on the macOS host, off-device, with only the Command Line Tools
mobile/ios/scripts/ios-build-check.sh         # compile for iOS simulator + device, type-check the example
```

The tests run the verifier against **every vector** in
`mobile/vectors/vectors.json` (read from the repository at test time, with
each vector's `expect.now` as the clock and its `jwks` as the only key set),
each refusal for the reason `reference-verify.mjs` gives it — its
`EXPECTED_REASON` table is read from that file, not retyped, and the vectors and
the table must name the same refusals (no pinned count: the file grows) — and
cover PKCE (RFC 7636 Appendix B), request building, callback parsing, the token
client against a stub transport, rotation ordering, backoff, writers outside
the lock, a lock that cannot be taken, background expiry releasing the lock,
the browser hop's cancellation, JWKS refresh with concurrent refreshes
collapsing into one fetch, the cross-process lock against a real second
process, and configuration validation. Only `ASWebAuthenticationSession`
itself, `performExpiringActivity` and the Keychain need a device or simulator.

`scripts/swift-test.sh` is plain `swift test` with a full Xcode selected. With
only the Command Line Tools it adds the `Testing.framework` search paths, and
works around a Command Line Tools install whose `PackageDescription` module
carries stale `*.private.swiftinterface` files (every manifest then fails with
`extra argument 'swiftLanguageModes'`); the script's header explains both.

### Against a real server

`Tests/ProtelesAuthTests/LiveTests.swift` runs the SDK against a real Proteles
server that `mobile/live/run-live.sh` starts and seeds (it builds nothing:
point `PROTELES_LIVE_BIN_DIR` at `oauth-server` and `admin-cli` built from the
server repository), or one already running that you name with
`PROTELES_LIVE_ISSUER` and the other values (`mobile/live/README.md`). From
the repository root:

```bash
PROTELES_LIVE_BIN_DIR=/path/to/bins \
  mobile/live/run-live.sh -- mobile/ios/scripts/swift-test.sh --filter Live
```

Without `PROTELES_LIVE_ISSUER` the suite is skipped, so `scripts/swift-test.sh`
and CI need no server and report its tests as skipped. It covers sign-in end to end (the real login
form, the callback's `state` and `iss`, the code exchange, the ID token against
the published key set), a token the server accepts at userinfo, rotation at
half-life with the spent token refused, sign-out's revocation, a family revoked
behind the SDK's back, a sign-in that cannot be stored revoking what it got, two
clients over one store refreshing at once, and ending the browser session. Only
the person at the browser is stood in for: `LiveBrowser` fills in the server's
own forms over `URLSession` and keeps its own cookies, because Foundation's
cookie store will not keep the server's `Secure` `__Host-` cookies from plain
`http://localhost`. The store is in memory — a test binary has no Keychain
entitlement — and a test clock moves the device past half-life while the
server keeps the real time.

The example app is in [`Example/`](Example/).

### Not done yet

- **A first release.** The package is resolvable by URL once the repository
  carries its first `X.Y.Z` tag; there is nothing else to publish for iOS.
- **Live verification in CI.** The live suite above runs by hand; it is not yet
  a job. CI's `mobile-ios` job runs the off-device suite on macOS and prints the
  Xcode and Swift versions it used, but does not pin them (§8).
- **On-simulator tests** of the parts that need the platform: the
  `ASWebAuthenticationSession` hop (including cancelling the awaiting task, and
  a second `open` while one is showing), the Keychain store, and
  `performExpiringActivity` expiring while a refresh holds the App Group lock.
- **A checked-in Xcode project** for the example (it is source, type-checked
  against the iOS SDK by `scripts/ios-build-check.sh`).
