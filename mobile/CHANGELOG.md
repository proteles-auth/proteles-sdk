# Changelog

The native SDKs — `ProtelesAuth` for iOS, and `com.proteles:proteles-auth-android`
with `com.proteles:proteles-auth-core` for Android — are versioned and released
together, from one plain `X.Y.Z` tag, so this is one file for both. The
version is `VERSION_NAME` in `android/gradle.properties`; how a release is cut
is in [`RELEASING.md`](../RELEASING.md). The TypeScript packages have their
own, in [`CHANGELOG.md`](../CHANGELOG.md), and their own `npm-vX.Y.Z` tags.

The format is [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
versioning is [semver](https://semver.org/spec/v2.0.0.html). While the major is
`0`, a minor bump is where a breaking change goes.

## [Unreleased]

The first release. Nothing has been published yet: the Maven Central account
and the signing key are still to be set up. The iOS package needs no mirror:
its manifest is `Package.swift` at the repository root, so the release tag
itself is the iOS release.

### Added — both SDKs

- **Sign-in through the system browser**, never a web view:
  `ASWebAuthenticationSession` on iOS, a Custom Tab pinned to an installed
  browser on Android. PKCE (S256), `state`, `nonce` and the RFC 9207 `iss` on
  every sign-in; the callback must come back to the configured redirect URI.
- **ID tokens verified before they are believed**: RS256 only, the key from the
  tenant's key set, the signature over the bytes as received, then issuer
  (byte for byte), audience, expiry, nonce and `at_hash`. Both SDKs are held to
  the same shared vectors, each refusal for the same reason.
- **A valid access token on demand** (`validAccessToken`): refreshed at half its
  life, one refresh at a time — across processes too, where an app's processes
  share a session — and the rotated refresh token stored before anything else
  is done with the response. A refresh that fails for a passing reason — no
  network, a 5xx, a 429, a malformed answer — while the stored token is still
  valid returns the stored token. `invalid_grant`, a refreshed ID token that
  fails a trust rule (its family is revoked too), or a refresh token the client
  already knows is dead ends the session at once; storage that cannot be
  written raises without ending it.
- **Storage that stays on the device**: the Keychain
  (`AfterFirstUnlockThisDeviceOnly`) on iOS; a Keystore AES-GCM key sealing a
  file in `noBackupFilesDir` on Android.
- **Sign-out in two halves**: the device is cleared and the refresh token
  revoked (which ends its family at the server); optionally the browser's
  session is ended at the tenant's `end_session_endpoint` too.
- **One error type per thing a caller does differently**, and a backoff after a
  429 that honours `Retry-After`.
- **No third-party dependencies** on iOS; `kotlinx-coroutines-core` and
  `androidx.browser` on Android.

### Packaging

- MIT licence, the repository's own, in each SDK's directory.
- iOS: a Swift package whose manifest is `Package.swift` at the repository
  root, so `.package(url: "https://github.com/proteles-auth/proteles-sdk", from:)`
  resolves it from the release tag.
- Android: POMs, sources and README javadoc jars, signatures and checksums for
  Maven Central, checked before release (`android/scripts/publish-readiness.mjs`).
