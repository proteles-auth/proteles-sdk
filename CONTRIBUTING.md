# Contributing

Thank you for helping. Issues and pull requests are welcome; for a security
problem, follow [`SECURITY.md`](SECURITY.md) instead of opening an issue.

## Build and test

The TypeScript packages need Node 18.12 or later (CI builds and publishes with
the Node major pinned in [`.github/workflows/checks.yml`](.github/workflows/checks.yml)):

```bash
npm ci               # install the workspaces from the lockfile
npm run build        # build every package (js, then bff, then the rest)
npm run typecheck
npm test             # every package, then the scripts', vectors' and tools' self-tests
node tools/npm-publish-readiness.mjs   # the packaging checks a release runs
```

The native SDKs:

```bash
swift test                                         # iOS, from the repository root
(cd mobile/android && ./gradlew :core:test :android:testDebugUnitTest)
```

`mobile/ios/README.md` and `mobile/android/README.md` cover simulators,
devices and the live suites. The `scripts/verify-*.mjs` checks need a live
Proteles server or tenant; each script's header lists what it reads.

CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) runs all of this on
every pull request. A pull request should keep it green, add tests for what it
changes, and add a line to [`CHANGELOG.md`](CHANGELOG.md) (npm packages) or
[`mobile/CHANGELOG.md`](mobile/CHANGELOG.md) (native SDKs) under *Unreleased*.

## Things that are copies

- [`spec/openapi.json`](spec/openapi.json) is the Proteles server's OpenAPI
  document at the commit in `spec/SERVER_COMMIT`.
  `packages/management/src/generated/` is generated from it by
  `tools/generate-management-wire.mjs` and `tools/generate-management-enums.mjs`;
  CI fails if the two drift. Do not edit either by hand.
- [`mobile/vectors/vectors.json`](mobile/vectors/vectors.json) is a copy of the
  shared ID-token test vectors, checked by `SHA256SUMS`. Never edit it here
  ([`mobile/vectors/SOURCE.md`](mobile/vectors/SOURCE.md)).

## Changes that touch the server

These packages are clients of the Proteles service. A change that depends on
server behaviour — a new endpoint, field, error code, cookie or redirect rule,
or a different reading of an existing one — is coordinated with Proteles: open
an issue first, so the server side can be agreed, released, and the spec in
`spec/` refreshed before the client relies on it.

## Releases

Maintainers release from tags, each with its own version numbers:
`npm-vX.Y.Z` for the npm packages (all thirteen at one version, published with
provenance) and a plain `X.Y.Z` for the native SDKs. Never push a `vX.Y.Z` tag:
SwiftPM would read it as an iOS release. [`RELEASING.md`](RELEASING.md) is the
runbook.

## License

By contributing you agree that your contribution is licensed under the
repository's [MIT License](LICENSE).
