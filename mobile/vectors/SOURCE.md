# Where these vectors come from

`vectors.json` is a **copy**. The canonical shared ID-token vectors live in the
Proteles server repository (private), which also holds the generator
(`generate.mjs`) and the test-only RSA keys it signs them with. Those stay
there: nothing in this repository signs a vector, and no test here needs a
private key — every SDK test only *verifies* the tokens in `vectors.json`
against the public `jwks` each vector carries.

| | |
|---|---|
| Copied from | `sdk/mobile/vectors/vectors.json` in the server repository |
| At commit | `b891ec63` (the same commit as `spec/SERVER_COMMIT`) |
| SHA-256 | recorded in [`SHA256SUMS`](SHA256SUMS) |

The other file here, `reference-verify.mjs`, is the ID-token rules of
`docs/mobile-SDKs.md` §5 and §5.2 as code. It reads only `vectors.json` and
needs no key. It proves every vector reaches its verdict, each refusal for the
reason its name gives, and its `EXPECTED_REASON` table is what the iOS and
Android tests read the expected reasons from.

## What reads them

- `packages/js/test/vectors.test.ts` (`npm test`): `@proteles/js`'s verifier,
  every vector; and the check that `vectors.json` matches `SHA256SUMS`.
- `mobile/ios/Tests/ProtelesAuthTests/VectorTests.swift` (`swift test` at the
  repository root): the iOS verifier, every vector.
- `mobile/android/core/src/test/.../IdTokenVectorsTest.kt` (`:core:test`): the
  Kotlin verifier, every vector; and the same `SHA256SUMS` check.
- `node mobile/vectors/reference-verify.mjs` (`npm run test:vectors`, part of
  `npm test`): the reference itself.

CI runs all four, so a `vectors.json` edited by hand, truncated, or refreshed
without its sum fails the build. By hand:

```sh
cd mobile/vectors && shasum -a 256 -c SHA256SUMS   # or: sha256sum -c SHA256SUMS
```

## Refreshing the copy

When the server repository regenerates its vectors (a new rule, a new vector):

1. Copy the server repository's `vectors.json` over this one, byte for byte.
   If its `reference-verify.mjs` changed in the same commit, copy that too.
2. `cd mobile/vectors && shasum -a 256 vectors.json > SHA256SUMS`
3. Update the commit in the table above.
4. Run `npm test`, `swift test` and `./gradlew :core:test` (from
   `mobile/android`). A vector one of the SDKs now gets wrong is the point of
   the refresh: fix the SDK, not the vector.

Never regenerate or edit `vectors.json` here. A vector is a claim about what
every Proteles verifier must do; it is decided once, in the server repository,
and copied to each SDK unchanged.
