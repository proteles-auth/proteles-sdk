# Proteles for Android

Requires a Proteles account — sign up for free on [proteles.com](https://proteles.com/signup).

Native OAuth 2.0 / OpenID Connect sign-in for Android apps, against a Proteles
tenant: the system browser (a Custom Tab, never a WebView), PKCE, a verified ID
token, refresh with rotation that survives two processes, Keystore-sealed
storage, and a sign-out that ends the refresh family. The iOS SDK behaves the
same way.

<!-- unpublished: build.gradle.kts leaves each such block out of the README in the javadoc jar -->

[`mobile/README.md`](../README.md) covers both SDKs, starting with how to
register the app.

<!-- /unpublished -->

Two artifacts:

- **`com.proteles:proteles-auth-android`** — what an app depends on. The browser
  hop, the redirect activity, Keystore storage and the cross-process lock.
- **`com.proteles:proteles-auth-core`** — every protocol rule, in plain
  Kotlin/JVM, with no Android dependency. It comes with the one above.

## Install

Requires **minSdk 26** (Android 8.0) and Kotlin 2.2 or later. The API is
`suspend` functions. Call `signIn` from a scope that **survives configuration
changes** — `viewModelScope`, or an application-wide scope — not
`lifecycleScope` or an Activity's own scope: a rotation, a dark-mode switch or
unfolding the device while the browser is in front recreates the Activity and
would cancel the sign-in as the user comes back. (Once the browser has
returned, the SDK finishes the exchange and saves the session even if the
caller is cancelled; what a cancelled caller loses is the browser hop itself.)

**From Maven Central:**

```kotlin
// settings.gradle.kts of the app: mavenCentral() is usually there already
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
    }
}

// app/build.gradle.kts
dependencies {
    implementation("com.proteles:proteles-auth-android:0.1.0")
}
```

<!-- unpublished: the javadoc jar's README is Central's own, so it shows Central alone -->

It is not on Maven Central yet: the first release is still to be made.

**From a checkout of
[proteles-sdk](https://github.com/proteles-auth/proteles-sdk)**, until then:
build a local Maven repository from this directory and point the app at it:

```bash
cd mobile/android
./gradlew publishAllPublicationsToBuildRepository   # writes build/repo
```

```kotlin
// settings.gradle.kts of the app
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        maven { url = uri("/path/to/proteles-sdk/mobile/android/build/repo") }
    }
}

// app/build.gradle.kts
dependencies {
    implementation("com.proteles:proteles-auth-android:0.1.0")
}
```

Or, to build from source with the app, a composite build:

```kotlin
// settings.gradle.kts of the app
includeBuild("/path/to/proteles-sdk/mobile/android") {
    dependencySubstitution {
        substitute(module("com.proteles:proteles-auth-android")).using(project(":android"))
        substitute(module("com.proteles:proteles-auth-core")).using(project(":core"))
    }
}
```

<!-- /unpublished -->

## Register the app

**One client per app**, registered by the tenant's administrator through the
Management API (`POST /api/v1/apps`) — not one per install. The client must be:

- **public** — `token_endpoint_auth_method: "none"`. The app holds no secret;
  PKCE is what binds the code to it.
- registered for the **`refresh_token` grant**, or it gets no refresh token and
  the user signs in again every fifteen minutes. `offline_access` does not
  change this.
- registered with the **exact redirect URI** the app configures, and the exact
  post-logout redirect URI if it uses one.
- registered with the **app's identity**: `"app_identity": {"android":
  {"package_name": "com.example.app", "sha256_cert_fingerprints": ["14:6D:…"]}}`,
  the package and the SHA-256 fingerprint of the certificate the app is signed
  with (for an app on Google Play, the app signing key's, from the Play
  Console). The server reads the redirect host's `assetlinks.json` before it
  registers the app, and refuses it unless the file grants
  `delegate_permission/common.handle_all_urls` to that package with one of those
  fingerprints ([Redirect URIs](#redirect-uris), step 2), so serve the file
  first.

The API's defaults are neither of the first two — a confidential client with
only `authorization_code` — so both have to be asked for. The server assigns
the `client_id`; configure the SDK with the one it returns. Leave out
`"application_type": "native"`: the server does not use it, and it can be added
on request ([What it does not do](#what-it-does-not-do)).

<!-- unpublished -->

[`mobile/README.md`](../README.md#1-register-the-app) has the request.

<!-- /unpublished -->

## Redirect URIs

The redirect is an Android App Link: an `https` URL on a domain you control,
verified as belonging to your app, so that only your app can receive it. The
authorization code goes to whatever receives the redirect, which is why this
server registers no private-use scheme (`com.example.app:/callback`) for any
client: any other app on the device can claim the same scheme.

1. **Pick a callback URL** on a domain you control, for example
   `https://app.example.com/oauth/callback`, and register it on the client.
2. **Serve the association file** at
   `https://app.example.com/.well-known/assetlinks.json`, over `https`, with no
   redirect and `Content-Type: application/json`, naming the app's package and
   the SHA-256 fingerprint of its signing certificate (for an app distributed
   through Google Play, the app signing key's):

   ```json
   [{
     "relation": ["delegate_permission/common.handle_all_urls"],
     "target": {
       "namespace": "android_app",
       "package_name": "com.example.app",
       "sha256_cert_fingerprints": ["14:6D:E9:83:C5:73:06:50:D8:EE:B9:95:2F:34:FC:64:16:A0:83:42:E6:1D:BE:A8:8A:04:96:B2:3F:CF:44:E5"]
     }
   }]
   ```
3. **Declare the redirect activity** with an `autoVerify` intent filter for
   that host and path ([below](#declare-the-redirect-activity)). Android checks
   the file when the app is installed. `adb shell pm get-app-links
   com.example.app` shows whether the domain is `verified`; until it is, the
   browser keeps the link instead of handing it to the app.

What the SDK accepts, and why the rest are refused when the configuration is
built — not at the first sign-in, where the failure would be a server error page
in a browser the app cannot read:

| Redirect URI | |
|---|---|
| `https://app.example.com/oauth/callback` | **The redirect.** An App Link, verified as above. |
| `com.example.app:/oauth/callback`, `myapp:/callback` | **Refused**: a private-use scheme, which this server does not register for any client. |
| `HTTPS://App.Example.com/cb` | Refused on Android: intent filters match the scheme and host case-sensitively, and browsers lower-case both. |
| `http://127.0.0.1:PORT/cb`, `http://[::1]:PORT/cb` | Refused: a loopback redirect needs a local HTTP listener, which neither native SDK runs. |
| `http://localhost:PORT/cb` | Refused: registrable, but never port-exempt at this server — and loopback besides. |
| anything with `#fragment`, `http://` elsewhere, `javascript:` … | Refused. |

The issuer must be `https:` (or `http:` on `localhost`, `127.0.0.1` or `[::1]`,
for a server on the same machine during development) and is compared **byte
for byte**: `https://auth.example.com/` and `https://auth.example.com` are
different issuers. Its discovery document's endpoints are held to the same
rule: `https:`, or — only when the issuer is `http:` — `http:` on one of those
three loopback hosts, never on another host. The `clientId` must be visible
ASCII, as on iOS.

## Declare the redirect activity

The app declares the SDK's `RedirectActivity` in **its own**
`AndroidManifest.xml`, with a verified App Link intent filter for its
redirect's host and path:

```xml
<activity
    android:name="com.proteles.auth.android.RedirectActivity"
    android:exported="true"
    android:theme="@android:style/Theme.Translucent.NoTitleBar">
    <intent-filter android:autoVerify="true">
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="https" android:host="app.example.com" android:pathPrefix="/oauth/" />
    </intent-filter>
</activity>
```

`android:pathPrefix="/oauth/"` covers both the sign-in redirect
(`/oauth/callback`) and the post-logout one (`/oauth/signed-out`); use
`android:path` for one exact path. `autoVerify` is what has Android check the
domain's `assetlinks.json`.

The SDK checks this before it opens the browser: a redirect URI no activity of
the app handles — including a filter without `category.DEFAULT`, which a
browser's implicit `startActivity` can never reach — is a
`ProtelesException.Configuration`, not a sign-in that waits forever. The library's own manifest contributes the `INTERNET` permission, the
package-visibility `<queries>` needed to find a browser, and the (unexported)
activity that holds a request while the browser is open.

## Usage

```kotlin
import com.proteles.auth.ProtelesConfiguration
import com.proteles.auth.ProtelesException
import com.proteles.auth.SignOutResult
import com.proteles.auth.android.ProtelesAndroid
import com.proteles.auth.android.signIn
import com.proteles.auth.android.signOut

// Once per process — e.g. in Application.onCreate — and share it.
val client = ProtelesAndroid.client(
    context,
    ProtelesConfiguration(
        issuer = "https://auth.example.com",           // your tenant's issuer, exactly
        clientId = "k3v9…",                              // the client_id the registration returned
        redirectUri = "https://app.example.com/oauth/callback",
        // scopes = listOf("openid", "profile", "email"), // the default; openid is required
        postLogoutRedirectUri = "https://app.example.com/oauth/signed-out", // optional
    ),
)

// Sign in, from the Activity in front, in a scope that outlives it (see Install).
// Suspends while the user is in the browser.
viewModelScope.launch {
    try {
        val claims = client.signIn(activity)
        showUser(claims.preferredUsername ?: claims.subject)
    } catch (e: ProtelesException.Cancelled) {
        // The user closed the browser. Not an error.
    } catch (e: ProtelesException.AlreadyInProgress) {
        // A double tap: the sign-in already showing carries on.
    }
}

// Before every API call. Refreshes first when the token is past half its life;
// if that refresh fails for a passing reason (no network, a 5xx, a 429) while
// the token is still valid, you get the token anyway. What ends the session
// instead is under "What it does".
val accessToken = client.validAccessToken()
request.header("Authorization", "Bearer $accessToken")

// Who is signed in — valid for the session, not just the ID token's 15 minutes.
val claims = client.currentClaims() // null when nobody is

// Sign out. Clears the device, then tells the server; says whether it heard.
val result = client.signOut(activity, endSession = false) // Storage only if the device could not be cleared
if (result.revocation is SignOutResult.Revocation.Failed) {
    // Signed out here; the refresh token lives on server-side until it expires.
}
```

**Sign-out has two halves**, and the second is optional:

1. `signOut(...)` **clears the store, then revokes** the refresh token (`POST
   revocation_endpoint`) — even offline, in which case
   `result.revocation` is `Failed` and the device is still signed out. Neither
   step can be cancelled by the caller. If the store cannot be cleared, the
   token is revoked anyway and `Storage` is raised; this client never presents
   that token again. A record that cannot be read is still deleted, and
   reported as a `Failed` revocation rather than as nothing to revoke. A stored
   refresh token this client already knows is dead is revoked too, as on iOS:
   an earlier revocation of it may have failed, and revoking any member of a
   family ends the family server-side.
2. With `endSession = true`, it then sends the browser to the issuer's
   `end_session_endpoint` with `id_token_hint`, `client_id`,
   `post_logout_redirect_uri` and `state`. Without it, the browser keeps its
   session cookie and **the next `signIn` completes without asking for a
   password** — which is what most apps want, and what a "switch account" button,
   or an app on a shared device, does not. Only call it from a user gesture: it puts a browser page in front
   of the user, and the server asks them to confirm.

### Errors

Every failure is a `ProtelesException` subclass — one per thing a caller does
differently. Messages are for logs, never for end users, and never
contain a token.

| Exception | Means | Do |
|---|---|---|
| `Configuration` | The configuration can never work, or discovery says so (404, no RedirectActivity for the scheme, …) | Fix the app or the tenant registration |
| `Cancelled` | The user closed the browser | Nothing |
| `StateMismatch` | The callback is not the answer to this request | Offer sign-in again; do not retry automatically |
| `IssuerMismatch` | The callback's `iss` (RFC 9207), or discovery's `issuer`, is not the configured issuer | Treat as an attack or a misconfiguration |
| `AuthorizationError` | The server answered the browser with `error` (e.g. `access_denied`) | Show that sign-in did not complete |
| `TokenEndpointError` | The token endpoint refused (HTTP 4xx: `error`, `httpStatus`); `invalid_response` for a malformed 200 | Show that sign-in failed |
| `IdTokenRejected` | The ID token failed a rule; `reason` says which | Treat as an attack or a server fault |
| `Network` | The server could not be reached, or answered 5xx (`httpStatus`) — from the token, revocation, discovery or key-set endpoint; or another process held the refresh lock past the 60 s wait | Retry later |
| `RateLimited` | HTTP 429; `retryAfterSeconds` is the wait the SDK now observes: `Retry-After` (seconds or an HTTP-date, capped at an hour), or 60 s when the server sent none it can read | Wait that long. Until then the SDK sends nothing to the token endpoint, and `signIn` refuses before opening the browser |
| `SignInRequired` | Nobody is signed in, or the session has ended — the refresh token was refused (`invalid_grant`) or is one this client already knows is dead — and it has been cleared | Call `signIn` |
| `Storage` | The Keystore-sealed store could not be read or written, or the lock file opened. Never read as "signed out": the session has not been deleted | Retry later; report it |
| `BrowserUnavailable` | No browser on the device can show the sign-in page | Ask the user to install or enable one |
| `AlreadyInProgress` | Another sign-in or end-session of this client is showing the browser; this call did nothing | Nothing: it is a double tap |

## What it does

Each item has a test (`core/src/test`, `android/src/test`,
`android/src/androidTest`).

- **Discovery** — `GET {issuer}/.well-known/openid-configuration`; its `issuer`
  must equal the configured one byte for byte; endpoints must be https. Cached
  for the life of the client; a failure is not cached.
- **PKCE** — a 32-byte verifier (43 characters), `S256` challenge (43
  characters: the server refuses any other length); 32-byte `state` and
  `nonce`. No `login_hint` (the server ignores it).
- **The browser hop** — a Custom Tab in the app's task, always pinned to an
  installed browser package so neither an App Link on the issuer's domain nor
  the chooser can take the page: the default browser's Custom Tab, else the
  first installed browser that offers Custom Tabs, else a browser without them
  (the default, else the first) — never a WebView, never an unpinned intent.
- **The callback** — addressed to the redirect URI; `state` equal; `iss`
  present and equal (**absent is a refusal**, RFC 9207); then `error`; then one
  `code`. State and issuer are checked before an error is believed.
- **The exchange** — `authorization_code`, `code`, the identical
  `redirect_uri`, `client_id`, `code_verifier`. No secret.
- **ID-token verification**, in order: `RS256` only, before any key
  is looked up; the key by `kid` (a JWK is usable only with `kty` RSA, `use`
  absent or `sig`, `alg` absent or `RS256`); the signature over the bytes as
  they arrived; then `iss` byte-exact, `aud` a single value naming this client,
  `sub`, `exp` and future `iat` with 60 s skew; the nonce (`null` is the only
  skip, and only the refresh grant passes it); `at_hash` whenever the access
  token from the same response is held. Held to every vector in
  `mobile/vectors/vectors.json`, each refusal for the reason its name gives.
- **Keys** — cached for ten minutes; an unknown `kid` refetches (a rotation);
  concurrent refetches **collapse into one fetch**; a failed refetch falls back
  to a stale key that is present; a key set with no usable key is an error.
- **Persist, then return** — the session is sealed into the store before
  `signIn` returns.
- **Refresh early** — at half the access token's life, as `expires_in` says (a
  SAML session deadline can shorten it), counted from just before the request
  that obtained it was sent — at sign-in as at refresh — so a slow answer never
  makes the token look younger than it is. An `expires_in` that is not a
  positive number is an `invalid_response`, as on iOS (this server never sends
  0, and some libraries read 0 as "never expires"); a fraction is kept in whole
  seconds, never rounded to none. **Single-flight** in the process, and
  **serialised across processes** by a `FileChannel` lock on a file in the app's
  files directory; after taking the lock the store is **re-read**, so a refresh
  another process made is used, not repeated. A waiter gives up after 60 s (as
  on iOS) and then re-reads the store, returning a stored token that has not
  expired. `ProtelesClient` refuses, at construction, a store
  shared across processes (`KeystoreTokenStore`) with a lock that is only
  in-process.
- **A failed refresh is not the caller's problem while the token is valid** —
  a network failure, a 5xx, a 429 or a
  malformed answer at the half-life point returns the stored access token, and
  the next attempt waits `min(30 s, half the token's remaining life)` — after a
  429, `Retry-After` (60 s when there is none it can read, never more than an
  hour) — so an outage does not turn every API call into a token request. Once
  the stored token has expired, the failure is raised. Three failures end the
  session at once — the store is cleared and the failure raised: `invalid_grant`
  (`SignInRequired`), a refresh-minted ID token that fails a trust rule
  (`IdTokenRejected`), and a refresh token this client already knows is dead
  (`SignInRequired`). A store that cannot be written raises `Storage` at once
  and does not end the session.
- **Rotation** — the new refresh token is **written as soon as a 200 body
  parses as JSON and carries one**, before any other member is checked (a
  response refused for a missing `expires_in` still leaves the new token on
  disk); then the refresh-minted ID token is verified (explicit null nonce, the
  new access token's `at_hash`, and the same `sub` as before); then the new
  access token is written and returned. A refresh, once sent, finishes even if
  the caller's coroutine is cancelled (a closed screen): the server rotates when
  it answers, so an abandoned response would be a signed-out user.
- **What ends a session on refresh, and what does not** — a refresh-minted ID
  token that fails a trust rule (signature, key, `iss`, `aud`, `at_hash`, a
  changed `sub`) ends the session and revokes its family. Two things do not, because
  they say nothing against a token the token endpoint has just handed this
  client for its own refresh token: a key set that cannot be fetched (the new
  tokens are kept with the previous claims, so a JWKS outage neither signs the
  user out nor makes every call rotate again), and `exp`/`iat` that disagree
  with the device's clock (a clock set back by hand, an RTC reset — `at_hash`
  already proves the token belongs to this response). Such a token is not
  adopted; the previous claims stay.
- **`invalid_grant` is terminal** — the session is cleared and
  `SignInRequired` raised, once; never retried. Even when the store cannot be
  cleared, the dead refresh token is never presented again by this client: the
  session reads as signed out, and the next `validAccessToken` clears it.
- **429** — from the token endpoint, discovery or the key set: no retry loop,
  and no request to the token endpoint until `Retry-After` has passed (60 s
  without a usable one, an hour at most; a request into a latched bucket keeps
  it latched); `signIn` refuses before the browser opens rather than have
  the user type a password for a code that cannot be redeemed.
- **One sign-in at a time** — a second `signIn`, or a `signOut` with
  `endSession`, while one is showing the browser raises `AlreadyInProgress`
  and does nothing.
- **Storage** — an AES-256-GCM key generated inside the Android Keystore under
  the alias `com.proteles.auth.<clientId>` (no user-authentication requirement,
  so a background refresh works), the session sealed with it (the alias bound
  in as associated data) and written atomically to `noBackupFilesDir` — the
  temporary file fsync'd, renamed over the old record, and the directory
  fsync'd, so a power loss straight after a refresh cannot bring back a
  refresh token the server has rotated away. A record that can never be opened
  — the key was invalidated, the file tampered with, another format — is
  `UnreadableSessionException` from the store: the client reads it as signed
  out, sign-out deletes it (reporting a `Failed` revocation), and the next
  sign-in overwrites it. Any other read failure is `Storage`, never signed out.
- **Your own store** — `TokenStore` is an interface for apps that need their
  own. Build `ProtelesClient` directly, and give it the **same lock**
  `ProtelesAndroid` would: the lock has no default, because every process of
  the app and every other client in this process that uses the record must
  queue behind it. If other processes read and write your store,
  override `sharedAcrossProcesses` to say so, and the client will refuse an
  in-process lock over it. Throw `UnreadableSessionException`
  from `read()` for a record that is there but can never be read.

  ```kotlin
  val client = ProtelesClient(
      configuration,
      store = MyTokenStore(),
      crossProcessLock = FileCrossProcessLock.forClient(context, configuration.clientId),
  )
  ```

## What it does not do

- **Survive process death during the browser hop.** If Android kills the app
  while the Custom Tab is in front, the suspended `signIn` died with it; the
  redirect that arrives later finds nothing waiting and is dropped. The user
  taps sign-in again (usually silent: the browser session exists).
- **Hear about sign-outs elsewhere.** There is no back- or front-channel logout
  and no `sid`: the app finds out when a refresh returns
  `invalid_grant`.
- **Loopback redirects.** No local HTTP listener on Android, and neither SDK
  accepts one.
- **Keep a browser without Custom Tabs in the app's task.** When no installed
  browser offers Custom Tabs (rare), the page opens in that browser's own task;
  returning to the app before finishing counts as closing the browser
  (`Cancelled`), as it does in AppAuth.
- **Share what it learns across processes.** The refresh hold-off after a
  failure, the 429 wait, and the list of refresh tokens known to be dead, are
  per client instance. Another process
  learns of an `invalid_grant` from the server — once.
- **Register the app.** One `client_id` per app, registered by the tenant's
  administrator; no per-install dynamic registration.
- **No `application_type`.** OpenID Connect registration lets a client declare
  `"application_type": "native"`. The SDK does not send it, and the server does
  not use it: every client is held to the native-app redirect rules, whatever it
  declares, so the declaration would change nothing. If your tooling or your own
  policies need the server to record it, it can be added on request.
- **Call `userinfo`**, introspect tokens, or send `login_hint`, `prompt` or
  `max_age`.
- **Revoke the access token** at sign-out. The server needs no second request
  for it: revoking the refresh token ends the grant, and the server's userinfo
  and introspection endpoints then refuse that grant's access tokens (RFC 7009
  §2.1). An API that verifies the JWT itself, without
  asking the issuer, still accepts it until its `exp`, up to fifteen minutes.
  Nor does a new sign-in revoke the refresh token of the session it replaces.
- **Tell whether the user confirmed an end-session** when they close the
  browser instead of letting it redirect back: that is `EndSession.Dismissed`.
- **Offer a Java-friendly API.** The API is `suspend` functions.

## Dependencies

- **`kotlinx-coroutines-core`** (the only third-party runtime dependency of
  `proteles-auth-core`): `suspend` is the natural shape for a sign-in that waits
  on a browser, and `Mutex` gives single-flight refresh and the key-set dedupe
  without blocking threads. Nearly every Android app already has it.
- **`androidx.browser`** (in `proteles-auth-android`): Custom Tabs.
- **No JSON library.** `org.json` is built into Android but not the JVM, and a
  JSON library inside the ID-token path is a dependency inside an
  authentication path; `core` has a ~250-line strict RFC 8259 parser that also
  **refuses duplicate member names**, so a JOSE header or payload means one
  thing to every reader.
- **Cryptography is the platform's**: `java.security` (`SHA256withRSA`,
  `RSAPublicKeySpec`, SHA-256, `SecureRandom`), `javax.crypto` with the
  `AndroidKeyStore` provider. HTTP is `java.net.HttpURLConnection` behind a
  `Transport` interface, redirects not followed, 10 s timeouts, responses
  capped at 1 MiB. The SDK sets no cookies, but `HttpURLConnection` cannot opt
  out of a process-wide `CookieHandler`: if the app installs one
  (`CookieHandler.setDefault`), it sends its cookies for the issuer's host with
  the SDK's requests and keeps any the issuer sets. The iOS SDK's transport is
  cookie-free; an app that installs a cookie handler and wants the same passes
  its own `Transport`.

Every JDK API `core` uses exists on Android 8.0 (API 26). Android Lint cannot
check a plain JVM module, so `CoreApiLevelTest` does: it reads the compiled
`core` classes with `javap` and looks up every platform method, field and class
in the compile SDK's `api-versions.xml`.

## For contributors

This SDK implements the native SDK contract in
[`docs/mobile-SDKs.md` §10](../../docs/mobile-SDKs.md#10-the-native-sdk-contract),
verifies ID tokens by §5 and §5.2, and is held to the shared vectors in
[`mobile/vectors/`](../vectors/). Where the rules above come from, for
anyone changing them:

- Registration: one client per app, never per install (M4); the refresh grant
  rather than `offline_access` (trap 4 in §3). Redirect URIs: §2.1 and §10.1
  (loopback refused); private-use schemes refused for every
  client (M7) and `localhost` trap 1. The 43-character challenge is trap 5.
- A valid access token and the refresh fallback: §10.3 and §10.9 items 1–3; the
  429 latch is §2.5. Errors: §10.7, with §10.9 item 4 for 5xx.
- Sign-out's two halves: M5, and §10.9 item 6 for clearing first and revoking
  even a token known to be dead. One sign-in at a time: §10.9 item 8.
- Storage and the lock: §10.5, §10.6 and §10.9 item 9.
- The verifier: §5 and §5.2 (M2, M3). No `login_hint`: §6 P2.12. Not told of
  a sign-out elsewhere: §6 P1.4.
- App identity: M7 in §1 and §6 P0.1. No private-use
  scheme is registrable, so the redirect is a verified App Link.
- Revoking a refresh token also refusing its grant's access tokens: §10.4
  (RFC 7009 §2.1); the live suite checks it at userinfo.

The javadoc jar that Maven Central requires holds this README as released: the
root `build.gradle.kts` (`publishedReadme`) leaves out this section and every
`<!-- unpublished … -->` block, which is where anything that points into this
repository, or stops being true once the SDK is on Central, belongs.
`scripts/publish-readiness.mjs` checks the jar's copy.

### Develop

```bash
cd mobile/android
./gradlew :core:test                       # every protocol rule, on the JVM
./gradlew :android:testDebugUnitTest       # file lock (with a real second process), store format, API floor, example app
./gradlew :android:assembleRelease :example:assembleDebug :android:lintDebug
./gradlew :android:connectedDebugAndroidTest   # on an emulator or device: Keystore, Custom Tab hop, full sign-in
./gradlew :core:liveTest                   # against a real server; skipped unless PROTELES_LIVE_ISSUER is set (below)
```

**Against a real server.** `core/src/liveTest` runs the real `ProtelesClient`,
with its default transport, against a Proteles server that
`mobile/live/run-live.sh` starts and seeds. `HttpBrowser` stands in for the
Custom Tab: it requests the authorization URL, posts the real login form (and
a consent page, if one is shown), and follows redirects until one is addressed
to the redirect URI. It keeps its own cookie jar, because the server's cookies
are `__Host-`/`Secure` on plain-http localhost and `java.net.CookieManager`
never sends those back to an http URL. From the repository root:

```bash
mobile/live/run-live.sh -- mobile/android/gradlew -p mobile/android :core:liveTest
```

The suite covers sign-in (discovery, PKCE, the callback's `state` and `iss`,
the code exchange, and the ID token verified against the real key set with the
real nonce and `at_hash`), `currentClaims` against userinfo, `validAccessToken`
at userinfo, and a refresh forced past half-life by a test clock. After the
refresh, the server refuses the old refresh token. It also covers a second
client over the same store, sign-out (the server then refuses the refresh
token), and end-session. Negative controls break the signature, the nonce,
`at_hash`, `iss` and `state` in turn, and check that the refresh token issued
on each refused sign-in is revoked. The source set sees only the public API.
`:core:test` compiles it, so CI notices if it stops compiling, but it runs only
under `run-live.sh`. Each run gets its own database, named for its port, so it
can run beside the iOS suite given its own `PROTELES_LIVE_DIR`.

Toolchain: JDK 17, Gradle 9.7.1 (the wrapper), AGP 9.3.2, Kotlin 2.4.20,
`compileSdk` 37, `minSdk` 26. Set `sdk.dir` in `local.properties` (not
committed) or `ANDROID_HOME`.

The shared ID-token vectors are read from `../../vectors` at test time — never
copied — and are a declared input of `:core:test`, so a changed `vectors.json`
reruns it. The expected refusal reasons are read from `reference-verify.mjs`
rather than retyped, and no vector count is pinned: the file is held to be
the canonical copy — the bytes `SHA256SUMS` records, each vector well-formed
(`../vectors/SOURCE.md`) — so a new vector is picked up by refreshing the copy,
not by editing a test.

`example/` is a one-screen app (sign in, call an API with the access token,
sign out) that consumes the library the way a customer would, including the
manifest entry above. It never shows the token — only the API's HTTP status —
and `ExampleAppTest` holds it to that. Point it at a tenant with
`-PprotelesIssuer=… -PprotelesClientId=…`; the API it calls is the issuer's
userinfo endpoint unless `-PprotelesApiUrl=…` names another.

### Beyond §10

Where this SDK goes past, or had to interpret, the contract:

- **Verifier refusals the first `reference-verify.mjs` did not make**, none
  reachable by a token this server issues, and all six since settled into §5.2
  (2026-09-25): a non-canonical base64url segment (a last character with
  non-zero unused bits), a `crit` header, duplicate JSON member names, a header
  that does not parse, RSA keys under 2048 bits or with an even or tiny
  exponent. `IdTokenVerifierTest` and `JwksCacheTest` cover them; the shared
  vectors cover whatever `vectors.json` holds when the tests run.
- **A refresh-minted ID token must name the same `sub`** (OIDC Core §12.2), or
  the session ends.
- **Tokens the SDK will not hold are revoked**, best-effort, rather than left
  alive server-side for thirty days (§10.9 item 7): an ID token refused at
  sign-in or on refresh, a malformed token response that named a refresh
  token, a sign-in whose session could not be saved or whose lock could not be
  taken, and a rotation that finds the device signed out meanwhile.
- **Details §10.9 leaves open, answered as the iOS SDK answers them**: a
  refresh-minted ID token whose times disagree with the device clock is kept
  but not adopted (item 2 says only that the clock is no ground to refuse it;
  the session goes on either way), and its `exp` must still be present. A key
  set that cannot be fetched keeps the new tokens with the previous claims. The
  lock waits 60 s and reports a timeout as `Network`. A rotation re-reads the
  record before it writes, so a sign-out made without the lock stands.
  At sign-in, §5.2's times apply unchanged: a device clock more than 60 s
  behind the server fails sign-in with `issued-in-the-future`.
- **Nothing is abandoned half-way** — a refresh in flight, the code exchange
  after the browser returns, and sign-out's clear-and-revoke all finish even if
  the caller is cancelled.
- **Sign-out revokes a refresh token this client already knows is dead**, as
  §10.9 item 6 now says and the iOS SDK also does. Revocation is not the
  refresh grant: the server answers 200 for a token it already refused (RFC
  7009 §2.2), files no stale-presentation warning, and burns the whole family,
  which ends one left live when an earlier revocation failed offline.
- **A 5xx from the token or revocation endpoint is `Network`**, as it is from
  discovery and the key set (§10.9 item 4): "try later", not a refusal.
- **A callback addressed to another path than the redirect URI** is a
  `StateMismatch`: it is not the response to this request.
