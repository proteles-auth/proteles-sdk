# Mobile SDKs — iOS/Swift and Android/Kotlin

**This document is the design record for the native SDKs.** It says what the
Proteles server gives a native app, the behaviour that surprises an SDK author,
what a client must do, how an ID token is verified, and the contract both SDKs
are built to. The code in this repository cites it by section (`§10.2`, `§5.2`,
`trap 1`, `P2.12`), so the numbering is stable: a section that no longer applies
says so rather than disappearing.

The native SDKs are [`mobile/ios`](../mobile/ios) (the Swift package
`ProtelesAuth`) and [`mobile/android`](../mobile/android) (a JVM `core` and an
Android library). Both are built to §10 and held to the shared vectors in
[`mobile/vectors/`](../mobile/vectors). How to use them is in
[`mobile/README.md`](../mobile/README.md); this file is for anyone changing
them. The TypeScript packages under [`packages/`](../packages) share §5's
ID-token rules and the same vectors.

**Contents**

1. [Decisions taken before writing code](#1-decisions-taken-before-writing-code)
2. [What the server already gives a native app](#2-what-the-server-already-gives-a-native-app)
3. [The traps — behaviour that will surprise an SDK author](#3-the-traps--behaviour-that-will-surprise-an-sdk-author)
4. [What the SDK must do (client obligations)](#4-what-the-sdk-must-do-client-obligations)
5. [ID-token verification, in order](#5-id-token-verification-in-order)
6. [Server behaviour an SDK has to allow for](#6-server-behaviour-an-sdk-has-to-allow-for)
7. [What an SDK package is in this repository](#7-what-an-sdk-package-is-in-this-repository)
8. [CI, verification and release](#8-ci-verification-and-release)
9. [How the SDKs were built](#9-how-the-sdks-were-built)
10. [The native SDK contract](#10-the-native-sdk-contract)

---

## 1. Decisions taken before writing code

These are the questions a first commit would have answered by accident. Each
was decided before the first release; the code cites them as M1–M7.

| # | Question | Decision | Why |
|---|---|---|---|
| M1 | **iOS or Android first?** | **Android first**, for releases. Both SDKs are built; a release can ship one platform at a time (`MOBILE_RELEASE_PLATFORMS`, [`RELEASING.md`](../RELEASING.md)) and iOS follows on the same tag scheme. | Building both at once doubles the surface before either has met a customer; the release order is where that choice still matters. |
| M2 | **Which ID-token verifier is the intended behaviour?** | **§5.2, for every verifier**, held to the shared vectors in CI. | Independent verifiers disagree on small things (§5.1). A native SDK cannot be specified as "do what another file does" without picking a side on each, and shared vectors hold Swift, Kotlin and TypeScript to the same rules without a reviewer reading three languages. |
| M3 | **Is `at_hash` verification mandatory?** | **Mandatory** in the native SDKs, and in `@proteles/js`, whenever the caller holds the access token from the same response. | The server emits `at_hash` on every ID token. A mobile app is a public client that receives both halves in one response, which is exactly the binding `at_hash` exists for. |
| M4 | **Should a native app register itself per install?** | **No: one client ID per app, registered by the tenant's administrator.** | Dynamic registration is off by default and capped per tenant, and its registration access token cannot be recovered or rotated. A per-install client is not a posture the server supports. |
| M5 | **What does "sign out" mean for a native app?** | `signOut()` **revokes the refresh token**, and **opens the system browser at the end-session endpoint** when the app wants the browser session ended too. Both READMEs say when to do the second: a shared device, or a person who means "sign me out of this device". | `/oauth/logout` ends only the browser's session, and dropping the app's own tokens does not end the refresh family. Ending the browser session needs a user gesture (§10.4). |
| M6 | **Does the SDK declare `application_type: "native"`?** | **No, for now.** Both READMEs say so under "What it does not do", and that it can be added on request. | The server does not act on `application_type` (P2.11): the native redirect rules apply to every client unconditionally. |
| M7 | **App-identity attestation: verify it, require it, or accept the risk?** | **Require it and verify it**: no private-use scheme is registrable for any client, a stored one is not honoured, and both SDKs take an `https` redirect only (iOS 17.4). A public client registered with its app's identity has `assetlinks.json` and `apple-app-site-association` checked on every redirect host (§6 P0.1). | Nothing stops a second app claiming a private-use scheme, and a first-party public client is not asked to consent again, so such an app would receive an authorization code silently. The server cannot tell a mobile app from a desktop one, so the rule applies to every client. |

§10.9 records ten more answers the two builds settled the same way.

---

## 2. What the server already gives a native app

### 2.1 Redirect URIs

One rule decides what may go on a client's list, and both registration doors
use it: `POST /register` (dynamic registration) and the Management API, on
create and on update.

| Form | Registrable? |
|---|---|
| `https://app.example.com/cb` (app link / universal link) | Yes, anywhere |
| `http://127.0.0.1:PORT/cb`, `http://[::1]:PORT/cb`, `http://localhost:PORT/cb` | Yes — `http` only for these three hosts |
| `com.example.app:/cb`, `com.example.app://cb`, `myapp:/cb` (private-use schemes) | **No** — M7, for every client; RFC 8252 §7.1 would allow the dotted forms. A stored one is not honoured either |
| `http://10.0.0.1/cb` (non-loopback http) | No |
| Anything with a fragment | No |
| `javascript:`, `data:`, `vbscript:`, `mailto:` | No |

At `/oauth/authorize` the match is exact string equality against the registered
list, with **one** exemption (RFC 8252 §7.3): a loopback **IP literal** redirect
may differ in port only. Path, query, userinfo and the literal itself must
match; `127.0.0.1` does not match `[::1]`. An unregistered value gets a
non-redirecting 400 page, never a redirect. `redirect_uri` may be omitted when
exactly one is registered. The token endpoint compares byte-for-byte again, so
the app must send the same ephemeral-port URI it authorized with.

### 2.2 PKCE

Two rules, deliberately separate:

- **Who must send a challenge:** every public client, plus any client with
  `require_pkce` — and every client registered through either door has
  `require_pkce: true` forced. *(The live harness in
  [`mobile/live`](../mobile/live) seeds its client with the server's admin
  command line, which a tenant administrator does not reach.)*
- **What a challenge must look like**, applied to anyone who sends one: 43–128
  unreserved characters (RFC 7636 §4.2), then **exactly 43 characters** because
  S256 is the only method; `code_challenge_method=S256` required, `plain`
  refused, and an **absent method refused** rather than defaulted to `plain` as
  RFC 7636 §4.3 would have it.

Redemption re-checks independently, and a public client with no stored
challenge is refused. Discovery advertises
`code_challenge_methods_supported: ["S256"]`.

### 2.3 Public clients, tokens and rotation

- A client is public when `token_endpoint_auth_method` is `none`; it gets no
  secret, and the token endpoint runs no secret check for it.
- **A refresh token is issued because the client registered the
  `refresh_token` grant, not because anyone asked for `offline_access`**, on
  the authorization-code path and on the device path alike.
- Access token 15 minutes (`ACCESS_TOKEN_TTL_SECONDS`); refresh token 30 days
  from its issue (`REFRESH_TOKEN_TTL_SECONDS`), capped at its family's end, 30
  days after the token exchange that started it however often it rotates
  (`REFRESH_FAMILY_MAX_AGE_SECONDS`) — past it the refresh is `invalid_grant`,
  which the SDKs already treat as "sign in again". At these defaults the cap is
  always the nearer end, so nothing slides: a user signs in again 30 days after
  they last did, however often they use the app. A SAML sign-in's
  `SessionNotOnOrAfter` can end the family sooner, and shortens every token
  minted near it, so an SDK must honour whatever `expires_in` says rather than
  assume fifteen minutes.
- **Rotation is single-use and revokes before it responds**, so a lost
  response leaves the app holding a dead token.
- Presenting a spent token has three outcomes, and **the request fails in all
  three**: a spent successor burns the whole family (`refresh_token_reuse`); no
  successor within 60 seconds leaves the family alone (`refresh_token_retry`);
  later, the family is burned too (`refresh_token_reuse` with
  `successor_spent: false`; RFC 9700 §4.14.2), or, when it holds no live token
  to burn, the presentation is filed at `Info`
  (`refresh_token_family_already_ended`). A burn also revokes the access tokens
  the family minted. The 60-second window decides only whether the rest of the
  family — in the lost-response case, the successor the app never received —
  dies with it.
- Seven things end a family: revocation, reuse as above, deactivation, a
  credential change, natural expiry, the family's maximum age (above), and —
  for a SAML sign-in that asserted one — the identity provider's session
  deadline, an absolute instant inherited by every rotation.

### 2.4 ID token

RS256 only. Always present: `iss` (the per-tenant issuer), `sub`, `aud` (the
`client_id`), `exp`, `iat`. Conditionally present, omitted rather than null:
`auth_time` (the session's instant, **inherited across rotation, never
restamped**), `amr`, `nonce`, `sid` (the session, on every ID token from a known
session), `email`, `email_verified`, `preferred_username`, `acr` (one value:
the PAPE multi-factor URI), and `at_hash` — **on every ID token this server
issues**. No `azp`.

### 2.5 Everything else a native SDK touches

- **Discovery** at `/.well-known/openid-configuration` and
  `/.well-known/oauth-authorization-server`, every URL built from the
  per-tenant issuer. `authorization_response_iss_parameter_supported: true` —
  RFC 9207's `iss` is on every authorization response, errors included.
- **Revocation** accepts public clients (`none` is in
  `revocation_endpoint_auth_methods_supported`). **Introspection does not** — a
  native app validates tokens against JWKS instead.
- **Device authorization grant** works for public clients
  (`POST /oauth/device_authorization`), user code `XXXX-XXXX`, 600-second
  codes, 5-second poll interval.
- **Rate limits** for public clients are keyed on the client's **network**,
  never on client id: `POST /oauth/token` 60/min, `POST /register` 10/min. A
  429 carries `Retry-After`, and ignoring it is counterproductive — a refusal
  latches the bucket empty until the advertised time.
- **A second budget is per account, not per network:** password guesses per
  user (20 an hour by default) at `POST /login` — which the authorization hop
  reaches in the system browser — and at the account pages that ask for the
  password again. **Its refusal is deliberately indistinguishable from a wrong
  password**, so a throttled account looks to an SDK like bad credentials
  rather than a 429.
- **CORS is irrelevant to native apps and to the loopback redirect** — a
  top-level navigation is not CORS-governed, and the token request comes from
  the app process. It matters only inside a WebView with a web origin.

---

## 3. The traps — behaviour that will surprise an SDK author

1. **`localhost` gets no port exemption.** `http://localhost:PORT/cb` is
   *registrable* but is **not** port-exempt at `/oauth/authorize` (RFC 8252
   §8.3 grounds). An SDK that registers `http://localhost/cb` and then requests
   `http://localhost:51004/cb` gets a non-redirecting 400. **Use
   `127.0.0.1`.** `[::1]` matches too, and lands in Chrome and Edge after the
   sign-in or consent form like any other: the server's forms leave through a
   page that moves on by meta refresh, so no `form-action` has to name it.
2. **Post-logout has no port exemption at all.** An app that binds an
   ephemeral port and reuses it for `post_logout_redirect_uri` gets no redirect
   back. Register a fixed port for logout, or do not use a loopback logout
   target.
3. **No private-use scheme is registrable** (M7). `myapp://callback`, what most
   tutorials show, and the reverse-DNS `com.example.app://callback` that RFC
   8252 §7.1 allows are both a 400. A second app can claim any scheme. Use a
   claimed `https` link: a Universal Link on iOS, whose host is associated under
   `webcredentials` for `ASWebAuthenticationSession` to hand it back, or a
   verified App Link on Android.
4. **`offline_access` does nothing.** The grant, not the scope, decides whether
   a refresh token is issued. Requesting the scope on a client without the
   grant gets you none.
5. **The code challenge must be exactly 43 characters.** A valid-grammar
   64-character challenge is refused — the message says so ("code_challenge
   must be the 43-character BASE64URL-encoded SHA-256 of the verifier").
6. **A missing `code_challenge_method` is refused**, not defaulted to `plain`.
7. **The ID token expires in 15 minutes** — it shares the access token's TTL.
   An SDK that caches it as "the user record" will see it expire mid-session.
   Cache the claims, not the token's validity.
8. **`auth_time` is never restamped by rotation.** That is deliberate, so
   `max_age` and step-up keep meaning across months of refreshes.
9. **60 token requests per minute per network, shared.** This holds for the
   SDKs, which are public clients; only a confidential server gets an allowance
   of its own. Every user behind one corporate NAT, carrier-grade NAT or VPN
   egress shares the bucket. An SDK that retries aggressively will 429 in a way
   that looks like a server fault, and a retry loop on `invalid_grant` past the
   first minute burns the token family and files `refresh_token_reuse`
   warnings, the theft signal, against the tenant.
10. **`/oauth/logout` ends the browser's session only.** See M5.

---

## 4. What the SDK must do (client obligations)

They are obligations, not suggestions: the server offers no recovery for any
of them.

- **Persist before you use.** Write the new refresh token to storage *before*
  issuing any request with the new access token. The rotation already revoked
  the old one server-side; if the app dies between the response and the write,
  the user is signed out.
- **Refresh early**, not on a 401. A refresh at half the access token's life —
  7m30s into the default fifteen minutes — turns a race into a retry.
- **Treat `invalid_grant` as "sign in again".** It is terminal. Do not retry
  it: retries cost rate-limit budget and file warnings against the tenant.
- **Serialise refreshes across the whole app, including across processes.** An
  iOS app and its share extension, or an Android app and a background worker,
  are two processes with one keychain entry; two concurrent refreshes mean one
  of them holds a dead token. Use a cross-process lock, not an in-process
  mutex.
- **Store tokens in the platform keystore.** iOS: Keychain with
  `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`. Android: Keystore. Never
  `UserDefaults`, never `SharedPreferences`, never a file.
- **Send the same redirect URI at the token endpoint** that you sent at the
  authorization endpoint, ephemeral port included.
- **Honour `Retry-After`** on a 429.
- **Verify the ID token** — §5, in that order.

---

## 5. ID-token verification, in order

**The order is the security property.** A verifier that reads a claim before
checking the signature has already trusted the attacker's bytes.

1. **Refuse any algorithm but `RS256`, first** — before the key lookup and
   before any claim is read. `none` means no signature; `HS256` means verifying
   an RSA token with a symmetric algorithm whose key is the public one, which
   anybody can fetch.
2. **Look up the key by `kid`** in a JWKS cache. No `kid` is an error. Refresh
   on an unknown `kid`; on a refresh failure, fall back to a stale-but-present
   key rather than failing closed. Filter each JWK: `kty` must be RSA, `alg` if
   present must be RS256, `use` if present must be `sig`. A document with no
   usable key is an error, not an empty cache. Collapse concurrent refreshes
   into one fetch.
3. **Verify the signature over the bytes exactly as they arrived**, never a
   re-encoding of parsed values.
4. **Only then read claims:** `iss`, `aud`, `exp`, `iat`.
5. **Compare the nonce, and treat a missing expectation as an error rather than
   a skip.** An absent expectation silently accepting an absent nonce is the
   check quietly not happening. On the refresh grant, where the server mints no
   `nonce`, the skip must be explicit.
6. **Verify `at_hash`** against the access token received in the same response
   (M3).

The verifiers in this repository:
[`packages/js/src/idtoken.ts`](../packages/js/src/idtoken.ts) (TypeScript),
[`mobile/ios/Sources/ProtelesAuth/IDTokenVerifier.swift`](../mobile/ios/Sources/ProtelesAuth/IDTokenVerifier.swift),
[`mobile/android/core/src/main/kotlin/com/proteles/auth/IdTokenVerifier.kt`](../mobile/android/core/src/main/kotlin/com/proteles/auth/IdTokenVerifier.kt),
and [`mobile/vectors/reference-verify.mjs`](../mobile/vectors/reference-verify.mjs),
the rules as code.

### 5.1 The seven questions a verifier has to answer (M2)

Verifiers written independently against the same specifications disagreed on
these seven, and each disagreement is a token one accepts and another refuses.

| # | Question | What goes wrong when two verifiers answer differently |
|---|---|---|
| 1 | How much clock skew? | A token just past `exp` is accepted by one and refused by the other |
| 2 | Is the issuer compared byte for byte, or after stripping trailing slashes? | A deployment configured `https://auth.example.com/` works against one and fails every login against the other |
| 3 | Must `iss`/`aud` be compared in constant time? | Timing posture only; the values are public |
| 4 | What does a missing expected nonce mean? | A verifier with no explicit skip cannot verify a refresh-minted ID token at all |
| 5 | Is a JWK's `use` read? | An encryption key sharing a `kid` would be imported by one |
| 6 | Is base64url with padding accepted? | A padded token verifies under one and is refused by the other |
| 7 | Do concurrent key-set refreshes collapse into one fetch? | After a key rotation, a burst of sign-ins is one fetch against one implementation and N against the other. §5 step 2 requires the dedupe |

Two more checks belong with them: `azp` (never sent by this issuer, which is
conformant because `aud` is always a single value) and `nbf` (not emitted here,
but a conforming issuer may send it).

### 5.2 The seven, settled — for every verifier here (M2)

The answers are written down once, as code and as vectors, in
[`mobile/vectors/`](../mobile/vectors):

| # | Settled as | Why this side |
|---|---|---|
| 1 | Clock skew **60 s**, on `exp` and on `iat` in the future | Two minutes is generous for a device, and a phone's clock is corrected by the network |
| 2 | Issuer compared **byte for byte** | The server emits one spelling per tenant; normalising a slash is how two issuers become one |
| 3 | Comparisons need **not** be constant-time | `iss`, `aud` and `nonce` are public or single-use; nothing is learned by timing them |
| 4 | Expected nonce: **`null` is the explicit skip** (refresh), a string must be present and equal, `""` is an expectation that cannot be met | The only reading that can verify a refresh-minted token and still never skip by accident |
| 5 | A JWK whose `use` is present and not `sig`, or whose `alg` is present and not `RS256`, **is not a verification key** | Both fields say what a key is for; a key for something else is not this one |
| 6 | Base64url segments with **padding are refused** | RFC 7515 §2 defines base64url without padding; accepting it is a second spelling of one token |
| 7 | Concurrent key-set refreshes **collapse into one fetch** | Behavioural, so not a vector — each SDK tests it itself |

Plus **M3: `at_hash` is mandatory** whenever the caller holds the access token
from the same response, and **`aud` as an array is accepted only as one element
naming this client** — several audiences need `azp`, which this issuer never
sends.

**Six more, settled the same way** because the two native SDKs, built in
parallel, each refused something the other might not — and a refusal only one
of them makes is the drift the vectors exist to stop. Each is now a vector:

| Settled as | Why |
|---|---|
| A base64url segment is refused unless it is the **one canonical spelling** of its bytes (a final character's unused bits are zero) | A lenient decoder and a strict one read different bytes from the same token |
| A header carrying **`crit`** is refused | RFC 7515 §4.1.11: a critical extension must be understood, and these verifiers understand none |
| A header or payload naming **one member twice** is refused | One JSON parser keeps the first and another the last, so the same bytes name two people |
| …and "twice" means **the same code units** (RFC 8259 §8.3): `é` and `e`+`◌́` are two names, and a token carrying both is accepted | Swift's `String ==` is Unicode canonical equivalence; a verifier comparing that way refuses a token the others accept |
| A header that **does not parse** is a refusal, not a crash | A verifier must answer every input with a verdict |
| An RSA key **below 2048 bits** is not a verification key | The server's own floor for keys it trusts; a smaller key can be factored |
| An RSA key whose **exponent is one** (or even) is not a verification key | With `e = 1` the signature is the padded digest, which anybody can write — the vector is a real forgery against a verifier that does not look |

`vectors.json` holds 36 signed tokens (29 refusals, 7 acceptances) and the
verdict each must reach; `reference-verify.mjs` is the rules as code, and proves
each refusing vector is refused for the reason its name gives. The vectors are
generated, with test-only keys, in the Proteles server repository and copied
here unchanged ([`mobile/vectors/SOURCE.md`](../mobile/vectors/SOURCE.md)).
`@proteles/js`, the iOS SDK and the Android SDK each run every vector in their
own test suites, and so do Proteles' server-side verifiers.

---

## 6. Server behaviour an SDK has to allow for

What the server does, or does not yet do, that shapes the SDKs. Items that no
longer apply keep their numbers, because the code cites them.

### P0 — decided before the SDKs shipped

1. **App identity (M7).** No private-use scheme is registrable or honoured, for
   any client, so there is no scheme for a second app to claim, and both SDKs
   take only an `https` redirect. The iOS SDK requires iOS 17.4, the first
   version whose `ASWebAuthenticationSession` hands an `https` callback back,
   and only for a host associated under `webcredentials`. A public client can
   be registered with its app's identity (`app_identity` on the Management API:
   an Android package and certificate fingerprints, an Apple app ID, or both).
   Before the server writes it, it reads each redirect host's `assetlinks.json`
   (`delegate_permission/common.handle_all_urls` for the package with one of
   the fingerprints, served as `application/json`) and
   `apple-app-site-association` (the app ID in `webcredentials.apps`), and
   refuses with a 400 that names the host and what its file lacked. It checks
   again whenever such a client's redirects change.
   **Still to build, in the Android SDK: Chrome's Auth Tab** (Chrome 137+,
   androidx.browser 1.9.0), which returns a verified `https` redirect to the
   app directly. A plain Custom Tab depends on the browser handing the App Link
   to the app, which not every browser does (AppAuth-Android issue 784), so an
   Android release should wait for Auth Tab. Neither path is verified on a
   device yet.
2. **A native "sign out" is two calls** (M5). §10.4 is the contract, §10.9 item
   6 the order (clear, then revoke), and both SDK READMEs say it to the app
   developer. The second call needs a user gesture.
3. **One set of ID-token rules** (M2, §5.2), pinned by the 36 shared vectors,
   which every verifier runs.

### P1 — needed for a good SDK, not for a correct one

4. **A native app is not told when its session ends elsewhere.** The server
   puts `sid` in its ID tokens and supports OpenID Connect Back-Channel Logout,
   but a logout token is delivered to a server endpoint, which a native app
   does not have. The app finds out when a refresh fails. An app with its own
   backend can register one there.
5. **No per-app view of refresh families for the person.** The account pages
   list browser sessions, so a user cannot see or end one app's refresh family
   from another device. Offer sign-out in the app itself.
6. **Discovery in the client core.** Both native SDKs read discovery and
   compare its `issuer` byte for byte (§10.2 step 1; iOS `Discovery.swift`,
   Android `ProviderMetadata.kt`). `@proteles/js` derives endpoints by
   convention (`resolveEndpoints` in `client.ts`).
7. **A cross-process refresh lock.** Built, as §10.6 and §10.9 item 9 describe:
   iOS `RefreshLock.swift` (`flock` in the app group container), Android
   `FileCrossProcessLock.kt` (`FileChannel.lock`). The TypeScript packages need
   none: they keep tokens in an encrypted session cookie, not a shared store.
8. **`claims_supported` lists `at_hash` and `acr`**, as it lists every claim
   the server emits; [`mobile/live/curl-check.sh`](../mobile/live/curl-check.sh)
   holds a live server to it.

### P2 — worth knowing

9. *(No longer applies.)*
10. *(No longer applies.)*
11. **Some registration metadata is accepted and dropped**: `application_type`,
    `software_statement`, `contacts`, `tos_uri`, `policy_uri` and `client_uri`.
    An SDK that round-trips its own registration document sees those fields
    vanish. `initiate_login_uri` is stored and returned when it is on the
    origin of one of the client's redirect URIs, and dropped otherwise.
12. **`loginHint` is sent by `@proteles/js` and not honoured**: the authorize
    endpoint does not read it. The native SDKs do not send `login_hint` at all
    (§10.2 step 3).

### P3 — recorded, not built

13. **No step-up API surface for `acr_values`** beyond the single PAPE
    multi-factor value.
14. **`private_key_jwt` is not accepted at introspection or revocation** —
    irrelevant to public clients, noted for completeness.

---

## 7. What an SDK package is in this repository

A TypeScript package is a `src/`, a `test/`, a `package.json` and a README
under [`packages/`](../packages), usually an example under
[`examples/`](../examples), and a `verify-*.mjs` in [`scripts/`](../scripts)
that runs it against a live server.

A native SDK is a peer of those when it has:

- **A live verification suite.** Both have one, run against a real server that
  [`mobile/live/run-live.sh`](../mobile/live/run-live.sh) starts or one you
  already run (§10.8), not against a mocked transport.
- **Tests that do not need the platform.** The protocol core — PKCE, state, the
  verifier, storage policy — is tested off-device; only the browser hop and the
  keystore need a simulator or a device.
- **The shared vectors.** Every implementation of the ID-token rules runs
  [`mobile/vectors/vectors.json`](../mobile/vectors/vectors.json): signed
  tokens plus the verdict each must reach.
- **A README and an example**, in the shape the other packages use.

---

## 8. CI, verification and release

- **CI** is GitHub Actions. [`checks.yml`](../.github/workflows/checks.yml)
  has three jobs: `sdk` (the TypeScript packages, on Ubuntu, with a pinned and
  asserted Node major), `mobile-ios` (`swift build`, `swift test` and an iOS
  build check on macOS; it prints the Xcode and Swift versions it ran with) and
  `mobile-android` (the JVM core's and the library's tests, a release build,
  and the Maven publication's readiness, on Ubuntu with JDK 17 and the pinned
  Android platform). [`ci.yml`](../.github/workflows/ci.yml) runs all three on
  every pull request, every push to `main` and nightly.
- **The live suites run by hand** (§10.8), against a server you start with
  `mobile/live/run-live.sh` or one you already run. They are skipped unless
  `PROTELES_LIVE_ISSUER` is set, so CI needs no server.
- **Releases** come from tags, each with its own version
  ([`RELEASING.md`](../RELEASING.md)): `npm-vX.Y.Z` publishes the thirteen
  TypeScript packages to npm with provenance; a plain `X.Y.Z` releases the
  native SDKs — Android to Maven Central through the Central Portal, signed,
  and stopping at *validated* until a maintainer publishes it; iOS by the tag
  alone, because `Package.swift` is at the repository root and SwiftPM resolves
  the package by URL and tag. Each release workflow runs the same checks again
  on the tagged commit before anything is published.
- **Not covered:** CocoaPods and the Gradle plugin portal.

---

## 9. How the SDKs were built

In this order, which is still the order to follow for another platform:

1. **Decide M1–M6.** M2 and M3 change the first file anyone writes.
2. **Settle the verifier**: write the answers into §5, add the shared vector
   file, and hold every existing implementation to it. This is useful whether
   or not a native SDK ever ships.
3. **Build the protocol core**: discovery, PKCE, the authorization hop, the
   token exchange, the verifier, rotation with a cross-process lock,
   revocation, and the storage policy of §4.
4. **Wire the live verification** (§10.8) and a CI job for the platform.
5. **Then the next platform**, letting the first one's shape decide what the
   shared core is.

App identity (M7, §6 P0.1) was decided in parallel; it is a server-side and
product question as much as an SDK one. Both platforms were in fact built at
once, to §10, which was written before either.

---

## 10. The native SDK contract

*Written before either platform, so both are built to one shape.* iOS and
Android implement the same behaviour with platform-idiomatic names; where a
platform cannot, it says so in its README rather than approximating.

### 10.1 Configuration

`issuer` (URL, byte-exact — §5.2), `clientId`, `redirectUri`, `scopes` (default
`openid profile email`), `postLogoutRedirectUri` (optional). Refused at
construction, not at the first sign-in: any private-use scheme (trap 3, M7),
any `http:` redirect (trap 1), a fragment, and an `issuer` that is not
`https:` except on loopback (`localhost`, `127.0.0.1`, `[::1]` — for development
and integration tests only).

*Also established live:* the server's issuer **follows the request's `Host`**,
so a development server reached as `127.0.0.1` calls itself
`http://127.0.0.1:PORT` and one reached through an Android emulator's
`10.0.2.2` answers 404. Configure the SDK with exactly the issuer discovery
names, and reach a laptop server from the emulator with `adb reverse`, not
`10.0.2.2`.

*Settled while building both SDKs:* **a loopback redirect is refused too**, on
both platforms. This section used to allow `http://127.0.0.1` and `[::1]`
redirects, but neither SDK can receive one — `ASWebAuthenticationSession` does
not intercept them, and the Android SDK runs no local listener — so accepting
one at construction only moved the failure to the first sign-in.

### 10.2 Sign in

1. **Discovery**: `GET {issuer}/.well-known/openid-configuration`; its `issuer`
   must equal the configured one byte for byte. Cached for the process.
2. **PKCE** (§2.2): 32 random bytes as base64url without padding (43 chars) for
   the verifier; the challenge is base64url(SHA-256(verifier)), `S256`. `state`:
   32 random bytes; `nonce`: 32 random bytes; both base64url.
3. **The browser hop**: `ASWebAuthenticationSession` on iOS, a Custom Tab on
   Android — never a WebView. Parameters: `response_type=code`, `client_id`,
   `redirect_uri`, `scope`, `state`, `nonce`, `code_challenge`,
   `code_challenge_method=S256`. **No `login_hint`** (P2.12 — the server ignores it).
4. **The callback**: `state` must equal what was sent; **`iss` must be present
   and equal the issuer** (RFC 9207 — discovery advertises
   `authorization_response_iss_parameter_supported`, so its absence is a
   refusal); `error`/`error_description` become a typed authorization error; a
   user dismissing the browser is its own error, not a failure.
5. **The token exchange**: `POST token_endpoint`, form-encoded:
   `grant_type=authorization_code`, `code`, `redirect_uri` (identical to step 3),
   `client_id`, `code_verifier`. No client secret — a native app is a public
   client (M4: one `client_id` per app, registered by the tenant administrator).
6. **Verify the ID token** (§5, §5.2) with the nonce from step 2 and the access
   token from step 5.
7. **Persist, then return.** Tokens go to the platform store (§10.5) before the
   caller sees the session.

### 10.3 A valid access token

`validAccessToken()` returns the stored access token, refreshing first when it
is past half its life (§4 "refresh early"). The refresh: `POST token_endpoint`,
`grant_type=refresh_token`, `refresh_token`, `client_id`. The response's refresh
token **replaces** the stored one (rotation is single-use, §2.3), and is
**persisted before** the new access token is returned. A refresh-minted ID token
is verified with the explicit null nonce and the new access token's `at_hash`, and
its `sub` must equal the stored one (OpenID Connect Core §12.2).
Refreshes are **single-flight** in the process and **serialised across
processes** (§10.6). `invalid_grant` is terminal: clear the session and raise
"sign-in required" — never retry it. A `429` raises a rate-limited error carrying
`Retry-After`; no automatic retry loop.

*Settled while building both, because the two SDKs read this differently:* **a
refresh that fails for any reason but `invalid_grant`, while the stored access
token has not yet expired, returns the stored token** and raises nothing.
Refreshing at half-life exists so that expiry is a non-event; raising on a
network blip or a `429` at the half-life point would fail a call the caller
could have made for several more minutes. The failure surfaces — as network,
rate-limited or token-endpoint error — once there is no longer a valid token to
return, and after a `429` no refresh is attempted before `Retry-After` has
passed. `invalid_grant` is never softened: the session is cleared at once. The
other exceptions, and the backoff, are in §10.9.

### 10.4 Sign out

*Established against a live server:* **revoking the refresh token also ends the
access tokens of its grant** at userinfo and introspection (RFC 7009 §2.1) — the
token that answered 200 a moment before answers 401. Only a resource server that
validates the JWT itself, without asking, still accepts it until `exp`. And the
optional browser half is **two taps when a browser session is live**: the
end-session GET shows a confirmation page and only its POST signs out; with no
session the GET redirects at once.

`signOut()` revokes the refresh token — `POST revocation_endpoint`,
`token=<refresh token>`, `token_type_hint=refresh_token`, `client_id` (public
clients may: `none` is advertised) — and clears the store **whether or not the
revocation succeeded**: a device that cannot reach the server must still be able
to sign out locally, and the failure is reported, not hidden. Optionally, with a
user gesture, the browser is sent to `end_session_endpoint` with
`id_token_hint`, `client_id`, `post_logout_redirect_uri` and `state` to end the
browser session too (M5). Both halves are documented, because the first alone
leaves the browser signed in and the next sign-in silent.

### 10.5 Storage

iOS: Keychain, `kSecClassGenericPassword`, service `com.proteles.auth.<clientId>`,
`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, optional access group.
Android: an AES-256-GCM key generated in the Android Keystore, the token record
encrypted with it and kept in the app's private storage. Never plaintext
`UserDefaults`, `SharedPreferences` or files. Storage is a protocol/interface so
tests and unusual apps can supply their own.

### 10.6 The cross-process lock

Two processes of one app (an iOS app and its share extension; an Android app and
a background worker) share one token record, and two concurrent refreshes mean
one of them holds a dead token (§4). iOS: `flock` on a lock file in the app
group container when one is configured, in-process only otherwise — and the
README says which. Android: `FileChannel.lock` on a file in the app's private
files directory, which every process of the app can reach. After acquiring the
lock, **re-read the store**: another process may already have refreshed.

### 10.7 Errors

One typed error per outcome a caller acts on differently: configuration,
cancelled by the user, state mismatch, issuer mismatch, authorization error
(`error` + description), token endpoint error (`error` + description), ID token
rejected (with the reason), network, rate limited (with `Retry-After`), and
sign-in required — and, added while building because both SDKs needed them,
**storage** (the store could not be read or written; never read as "signed out"),
**browser unavailable** (no browser can open the sign-in page) and **already in
progress** (§10.9 item 8).

### 10.8 What each package ships

A library, tests that run off-device (everything but the browser hop and the
platform store: PKCE, request building, callback parsing, the token client
against a stub transport, rotation ordering, the verifier **against every vector
in `mobile/vectors/vectors.json`**, and the JWKS refresh dedupe), a README in the
shape of the TypeScript packages', and an example app.

*Live verification:* [`mobile/live/run-live.sh`](../mobile/live/run-live.sh)
starts a real server from prebuilt binaries on a fresh database and seeds it,
or checks one you already run; `curl-check.sh` drives the protocol by hand, and
each SDK has a live suite that signs in through the real login form with a
browser stand-in, refreshes, runs two clients over one store, and signs out —
Android `./gradlew :core:liveTest`, iOS `scripts/swift-test.sh --filter Live`.
Both are skipped unless `PROTELES_LIVE_ISSUER` is set, so CI does not need a
server; see [`mobile/live/README.md`](../mobile/live/README.md).

### 10.9 Settled while building both

The two SDKs were built in parallel, reviewed, and fixed; each review found
things §10.1–10.7 did not say, and the two fix rounds answered some of them
differently. These are the answers both are held to. Each is small, and each is
the choice that fails safe without failing the person.

1. **Refresh fallback, exactly.** A failed refresh returns the stored access
   token while it has not expired (§10.3), except for three failures that end
   the session at once — clear the store and raise: `invalid_grant`
   (sign-in required); a refresh-minted ID token that fails a *trust* rule —
   signature, key, issuer, audience, `at_hash`, or a `sub` different from the
   stored one (ID token rejected); and a refresh token the SDK already knows is
   dead. A store that cannot be written raises the storage error and does not
   end the session.
2. **A refresh-minted ID token's clock is not judged.** `exp` and `iat` are not
   grounds to refuse it: it arrived over TLS in the response that minted it, and
   `at_hash` binds it to the new access token. A device whose clock is wrong
   would otherwise rotate its refresh token on every call and fail each time.
   §5.2's clock rules still apply at sign-in.
3. **Backoff after a failed refresh.** No new attempt before
   `min(30 s, half the remaining lifetime of the stored token)`, or after a
   `429` before `Retry-After`. `Retry-After` is read as seconds or an HTTP-date
   and **capped at one hour**; a `429` without a usable one backs off 60 s.
   Backoff lives in memory, per client.
4. **Server errors are network errors.** A `5xx` from the token, revocation or
   key-set endpoint is the network error (carrying the status), because it is
   retryable; the token-endpoint error is for an OAuth `error` on a `4xx`.
5. **The new refresh token is saved first.** As soon as a `200` refresh body
   parses, its `refresh_token` is persisted, before any other field is checked,
   so a response that then fails validation does not strand the family.
6. **Sign-out: clear, then revoke.** The store is cleared first, then the
   refresh token revoked; neither step can be cancelled by the caller. If the
   store cannot be cleared the storage error is reported **and the token is
   still revoked** — the person asked to sign out, and a revoked token in a
   stale store fails safe on its next use. The token is revoked **even when
   the client knows it is dead**: the server burns the whole family for any
   member presented, spent ones included, which also ends a family an earlier
   revocation left alive by failing offline. An unreadable record is still
   deleted, and reported as a storage failure rather than as "nothing to
   revoke" (iOS, whose record is not sealed, revokes a refresh token it can
   still read from it when the record names this issuer and client).
7. **A sign-in that fails after the code exchange revokes what it got.** A
   rejected ID token, a store that cannot be written or a lock that cannot be
   taken after the token response revokes the refresh token, best effort, rather
   than leave a thirty-day family nobody holds. Nothing after the code exchange
   can be cancelled by the caller.
8. **One sign-in at a time.** A second sign-in or end-session while one is
   showing raises **already in progress** (a §10.7 outcome: the caller ignores a
   double tap). A `429` backoff is checked before the browser opens.
9. **The cross-process lock is not optional where it is needed.** An app that
   shares its token store across processes (an App Group on iOS, a shared
   store on Android) must use the file lock; a shared store with only an
   in-process lock is refused at construction. When the lock cannot be taken in
   time, sign-out clears anyway and a refresh re-reads the store and returns a
   usable token if one is there.
10. **A stored session belongs to one issuer and one client.** The record
   carries both, and a record for another reads as signed out: it is never
   refreshed or revoked by this configuration, and sign-in overwrites it. An
   app reconfigured to another tenant with the same `client_id` would otherwise
   hand out the old tenant's access token. A record that is present but cannot
   be decoded also reads as signed out for `validAccessToken`; sign-out is where
   it is reported (item 6).
