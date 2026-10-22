# Proteles for iOS and Android

Requires a Proteles account — sign up for free on [proteles.com](https://proteles.com/signup).

Sign your users in to a native app with your Proteles tenant: the system
browser shows your tenant's sign-in page, the app gets verified tokens, keeps a
valid access token for your API, and signs the user out again.

## Which SDK

| Your app | SDK | Requires | Details |
|---|---|---|---|
| iOS (also macOS) | `ProtelesAuth`, a Swift package | iOS 17.4 / macOS 14.4, Swift 6 (Xcode 16) | [ios/README.md](ios/README.md) |
| Android | `com.proteles:proteles-auth-android` | minSdk 26 (Android 8.0), Kotlin 2.2 | [android/README.md](android/README.md) |

The two behave the same way: the same sign-in, the same rules for trusting a
token, the same refresh and the same sign-out, each written in its platform's
own idiom. Neither has a web view, and neither ever sees the user's password.

## 1. Register the app

Each app is **one client** in your tenant — one per app, not one per install —
and it must be registered as a **public** client: an app on a phone cannot keep
a secret, so instead PKCE binds each authorization code to the sign-in that
asked for it. Apps are created through the Management API, with a key that has
the `apps:write` scope (the one sign-up gives you has it).

```bash
curl -sS "$PROTELES_URL/api/v1/apps" \
  -H "Authorization: Bearer $PROTELES_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "Acme",
    "token_endpoint_auth_method": "none",
    "grant_types": ["authorization_code", "refresh_token"],
    "redirect_uris": ["https://app.acme.com/oauth/callback"],
    "post_logout_redirect_uris": ["https://app.acme.com/oauth/signed-out"],
    "scopes": ["openid", "profile", "email"],
    "app_identity": {
      "android": {
        "package_name": "com.acme.app",
        "sha256_cert_fingerprints": ["14:6D:E9:83:C5:73:06:50:D8:EE:B9:95:2F:34:FC:64:16:A0:83:42:E6:1D:BE:A8:8A:04:96:B2:3F:CF:44:E5"]
      },
      "ios": { "app_id": "ABCDE12345.com.acme.app" }
    }
  }'
```

```json
{ "client_id": "k3v9…", "client_name": "Acme" }
```

The `client_id` in the answer is the one to configure the app with; the server
chooses it. There is no `client_secret`, and that is right for a public client.

**Two fields are not optional, although the API lets you leave them out:**

- `"token_endpoint_auth_method": "none"`. Left out, the client is created
  **confidential** (`client_secret_basic`), and the SDK, which holds no
  secret, cannot redeem a sign-in with it.
- `"grant_types": ["authorization_code", "refresh_token"]`. Left out, the
  client gets `authorization_code` alone and **no refresh token**, so the user
  signs in again every time the access token expires (fifteen minutes by
  default). Asking for the `offline_access` scope does not change that; the
  grant does.

**Redirect URIs.** The redirect is an `https` URL on a domain you control,
associated with your app, so that only your app can receive it: a Universal
Link on iOS, an App Link on Android. The authorization code goes to whatever
receives the redirect, which is why this server registers **no private-use
scheme** (`com.acme.app:/callback`, `myapp://callback`) for any client: any
other app on the device can claim the same scheme. Each platform's README says
what the association takes: an `apple-app-site-association` file and an
Associated Domains entitlement on iOS, an `assetlinks.json` file and a verified
intent filter on Android. One domain can serve both.

The server compares redirect URIs byte for byte. Each SDK checks its
configuration when it is created and refuses a redirect URI that could not
work, so the mistake shows up in development rather than at a user's first
sign-in. Never a `#fragment` or a user name, and never `http://localhost` or
another loopback address: the API registers those for desktop apps, but neither
SDK can receive one.

The `post_logout_redirect_uris` are where the browser comes back after an
optional sign-out of the browser session (below); they follow the same rules.
Leave them out if the app will not use it.

**`app_identity` is the app itself**: its Android package and the SHA-256
fingerprint of its signing certificate (for an app on Google Play, the app
signing key's), its Apple Team ID and bundle ID, or both if one client serves
both platforms. The server reads each redirect host's association files before
it registers the app: `assetlinks.json` must grant
`delegate_permission/common.handle_all_urls` to that package with one of those
fingerprints, and `apple-app-site-association` must list the app ID in
`webcredentials.apps`. If either does not, the request is a 400 that names the
host and what its file lacked, and nothing is created. Changing the redirect
URIs later checks them again. Set up the files first, as each platform's README
describes, then register.

`scopes` defaults to exactly these three; `openid` is required. The first
time a user signs in to the app, they are shown a consent screen naming it.

**Do not send `"application_type": "native"`, and nothing is lost by leaving it
out.** OpenID Connect registration defines it; the SDKs do not send it, and the
server neither stores nor reads it. Every client is held to the native-app
redirect rules above, whatever it declares. If your tooling or your own policies
need the server to record it, it can be added on request.

### With `@proteles/management`

The same request from TypeScript:

```ts
import { ManagementClient } from "@proteles/management";

const proteles = new ManagementClient({ baseUrl: process.env.PROTELES_URL!, token: process.env.PROTELES_API_KEY! });

const app = await proteles.createApp({
  clientName: "Acme",
  tokenEndpointAuthMethod: "none",
  grantTypes: ["authorization_code", "refresh_token"],
  redirectUris: ["https://app.acme.com/oauth/callback"],
  postLogoutRedirectUris: ["https://app.acme.com/oauth/signed-out"],
  scopes: ["openid", "profile", "email"],
  appIdentity: {
    android: { packageName: "com.acme.app", sha256CertFingerprints: ["14:6D:E9:83:C5:73:06:50:D8:EE:B9:95:2F:34:FC:64:16:A0:83:42:E6:1D:BE:A8:8A:04:96:B2:3F:CF:44:E5"] },
    ios: { appId: "ABCDE12345.com.acme.app" },
  },
});
// app.clientId; app.clientSecret is undefined for a public client
```

## 2. Set up the app

Install the SDK and configure it once, with your tenant's issuer, the
`client_id` from step 1 and the same redirect URIs:

| | Install | Configure |
|---|---|---|
| iOS | [Swift Package Manager](ios/README.md#install) | [`ProtelesConfiguration`](ios/README.md#configure-once) |
| Android | [Gradle](android/README.md#install), plus [the redirect activity](android/README.md#declare-the-redirect-activity) in your manifest | [`ProtelesAndroid.client`](android/README.md#usage) |

**The issuer is compared byte for byte** — with discovery, with the sign-in
response and with every ID token. Use it exactly as the tenant's discovery
document spells it: `https://acme.proteles.example` and
`https://acme.proteles.example/` are two different issuers, and the SDK refuses
the second when the server says the first.

## 3. Sign in, and call your API

```swift
// iOS
let user = try await client.signIn(presentationAnchor: window)
let token = try await client.validAccessToken()
request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
```

```kotlin
// Android
val claims = client.signIn(activity)
val token = client.validAccessToken()
request.header("Authorization", "Bearer $token")
```

Call `validAccessToken()` **before every request** and do not keep what it
returns. It refreshes the token when it is past half its life, and when that
refresh fails for a passing reason — no network, a busy server — while the
current token is still valid, it hands you the current one rather than an
error. When the session is over — the refresh token was revoked or has
expired, or the user's password changed — it raises "sign-in required": show
sign-in, and do not retry.

**Your API** receives a signed JWT. Verify it with the keys at the tenant's
`jwks_uri` (from its discovery document): the signature (RS256), `iss` equal to
the issuer, `exp`, `token_use` equal to `"access"` (so an ID token is never
accepted in its place), and `aud`, which is the `client_id` of the app that
obtained it. For the user's profile, the ID token's claims are already in the
app (`currentUser()` on iOS, `currentClaims()` on Android); the API can also
ask the tenant's `userinfo_endpoint` with the same token.

## 4. Sign out

```swift
// iOS
let result = try await client.signOut()
```

```kotlin
// Android
val result = client.signOut(activity, endSession = false)
```

Sign-out has two halves. **Always do the first; add the second when the user
means "sign me out of this device"** — a shared device, a "switch account"
button, or anywhere the next person to open the app must not be signed in
silently.

1. **The app's session.** The device is cleared first, then the refresh token
   is revoked at the server, which ends its whole family: nothing from that
   sign-in can be refreshed again, and the tenant's userinfo and introspection
   refuse its access tokens. An API that verifies the JWT itself accepts one
   until it expires. It works offline: the device is signed out either way,
   and the result says whether the server heard.
2. **The browser's session, optionally.** The browser the user signed in with
   still has its own session with your tenant, so the next sign-in may not ask
   for a password. To end that too, sign out with the end-session option
   (`signOut(endSessionPresentingFrom:)` on iOS, `endSession = true` on
   Android), from a button the user pressed: the browser opens, the tenant asks
   the user to confirm, and it returns to your post-logout redirect URI.

## For contributors

Both SDKs implement the native SDK contract in
[`docs/mobile-SDKs.md` §10](../docs/mobile-SDKs.md#10-the-native-sdk-contract),
verify ID tokens by §5.2, and are held to the shared vectors in
[`vectors/`](vectors/). [`live/`](live/) starts a real server for their live
suites. The decisions behind them are recorded there: M1–M7 in §1, and the
answers both builds settled on in §10.9. How a release is
cut is in [`RELEASING.md`](../RELEASING.md),
and what each one changed is in [CHANGELOG.md](CHANGELOG.md).
