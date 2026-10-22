# Releasing

This repository makes two releases, each from a tag of its own and each with
its own version number:

| | npm packages | Native SDKs |
| --- | --- | --- |
| What | the 13 `@proteles/*` packages under `packages/`, always at one version | `ProtelesAuth` (iOS) and `com.proteles:proteles-auth-core` / `proteles-auth-android` (Android), at one version |
| Version lives in | every `packages/*/package.json` | `VERSION_NAME` in `mobile/android/gradle.properties` |
| Tag | `npm-vX.Y.Z` | `X.Y.Z` (no `v`) |
| Workflow | [`release-npm.yml`](.github/workflows/release-npm.yml) | [`release-mobile.yml`](.github/workflows/release-mobile.yml) |
| Approval | environment `npm-publish` | environment `mobile-release` |
| Goes to | npm, with provenance | Android: Maven Central. iOS: nothing is uploaded; the tag is the release |
| Changelog | [`CHANGELOG.md`](CHANGELOG.md) | [`mobile/CHANGELOG.md`](mobile/CHANGELOG.md) |

**Never push a `vX.Y.Z` tag.** `Package.swift` is at the repository root, so
SwiftPM reads this repository's tags as versions of the iOS package, and it
reads both `X.Y.Z` and `vX.Y.Z`. A `v` tag would be an iOS release nobody
meant. The npm tags start with `npm-v`, which SwiftPM ignores.

Every pull request, every push to `main` and a nightly run go through
[`ci.yml`](.github/workflows/ci.yml). Before anything is published, each release
workflow runs the checks for what it releases again, on the tagged commit: the
same jobs, from the same [`checks.yml`](.github/workflows/checks.yml), so a
release cannot be held to less than a pull request was.

## What cannot be undone

- **npm never accepts a version twice.** `npm unpublish` works only for 72
  hours, only if nothing depends on the package, and the version number stays
  used. A bad publish is fixed with a new version, in public.
- **Maven Central never deletes or replaces a version.** The release uploads
  with the publishing type `USER_MANAGED`, so the upload stops at *validated*
  and nothing is public until someone presses **Publish** in the Central
  Portal. That button is the step to take slowly.
- **A pushed `X.Y.Z` tag is an iOS release.** An app that has resolved it
  records its commit in `Package.resolved`, so moving or deleting the tag breaks
  that app's next resolution. Treat a pushed tag as final.
- **What a release publishes about itself is public for good**: npm provenance
  (the repository, commit and workflow run that built each version, in a public
  transparency log), and each Android POM's URLs and developer entry.

## One-time setup

### GitHub

1. **Environments** (*Settings › Environments*):
   - `npm-publish`: **Required reviewers**: the people who may release.
     **Deployment branches and tags**: *Selected*, with the tag rule `npm-v*`.
     No secrets: it holds none, and the publish job refuses to run if it finds
     an npm token.
   - `mobile-release`: **Required reviewers** as above. **Deployment branches
     and tags**: *Selected*, with the tag rule `[0-9]*.[0-9]*.[0-9]*`.
     **Environment secrets**: the four listed under [Maven
     Central](#maven-central). Environment secrets, not repository secrets: only
     the job that deploys to `mobile-release` receives them, and only after a
     reviewer approves it.
2. **Tag rulesets** (*Settings › Rules › Rulesets › New tag ruleset*), targeting
   `npm-v*` and `[0-9]*.[0-9]*.[0-9]*`: restrict creations, updates and
   deletions, with the maintainers on the bypass list. Only they can start a
   release, and nobody moves or deletes a release tag.
3. **Branch protection for `main`**: require a pull request, and require the
   checks `checks / sdk`, `checks / mobile-ios`, `checks / mobile-android` and
   `deps-npm`. A release is tagged on a commit those passed on.
4. **Actions** (*Settings › Actions › General*): workflow permissions *Read
   repository contents* (every workflow here also declares `contents: read`
   itself and widens it only in the job that needs more), and approval
   required before workflows run for outside contributors.

### npm

All 13 packages exist on npm. A trusted publisher can only be attached to a
package that exists, so a package added later is first published by hand (see
[Adding a package](#adding-a-package)).

**Trusted publishers.** Each package names this workflow as the only one
allowed to publish it. On npmjs.com: the package › *Settings* › *Trusted
publisher* › *GitHub Actions*:

| Field | Value |
| --- | --- |
| Organization or user | `proteles-auth` |
| Repository | `proteles-sdk` |
| Workflow filename | `release-npm.yml` |
| Environment name | `npm-publish` |

Every field must match what the run presents. A mismatch shows only when the
release reaches that package, as a refusal. Renaming the workflow file or the
environment means changing all 13. A package has one trusted publisher: if it
has one for another CI system, revoke that first (`npm trust list` shows its
id, `npm trust revoke --id <id> <package>` removes it).

Or from a terminal, with npm 11.15 or later, signed in with `npm login`
(`npm trust` asks for a two-factor code and refuses tokens that bypass it):

```sh
for p in js bff management react next htmx svelte vue solid alpine alpine-ajax express fastify; do
  npm trust github "@proteles/$p" --file release-npm.yml --repo proteles-auth/proteles-sdk --env npm-publish --allow-publish --yes
  sleep 2
done
npm trust list @proteles/js
```

Then, once a release has gone through, set each package's *Publishing access*
to **Require two-factor authentication and disallow tokens**. Trusted
publishing is unaffected; a stolen token is not.

**No npm token anywhere**: not as a repository secret, not as an environment
secret. With one present npm would quietly prefer it over OIDC, so the publish
job refuses to run if `NPM_TOKEN` or `NODE_AUTH_TOKEN` is set, or if an
`.npmrc` holds a credential.

### Maven Central

1. An account on the Central Portal (<https://central.sonatype.com>), with the
   namespace `com.proteles` verified (a DNS TXT record on `proteles.com`).
2. A user token (*Account › Generate User Token*): its two halves are the
   `mobile-release` secrets `CENTRAL_PORTAL_TOKEN_USERNAME` and
   `CENTRAL_PORTAL_TOKEN_PASSWORD`.
3. A signing key. Central checks every signature against a public key server,
   so publish the public half (`gpg --keyserver keyserver.ubuntu.com
   --send-keys <id>`). The ASCII-armoured secret half (`gpg --armor
   --export-secret-keys <id>`, the whole text from `-----BEGIN PGP PRIVATE KEY
   BLOCK-----` to its END line) is the secret `MOBILE_SIGNING_KEY`, and its
   passphrase `MOBILE_SIGNING_KEY_PASSWORD`. The workflow writes the key to a
   file only the job's user can read and removes it when the step ends.
4. `POM_DEVELOPER_EMAIL` in `mobile/android/gradle.properties` set to a real,
   public address. It is a placeholder on `.invalid` until then, and the
   release refuses to start while any placeholder is left.

## Releasing the npm packages

1. **Bump the versions**, all 13 together, from the repository root:

   ```sh
   npm version 0.4.0 --workspaces --no-git-tag-version
   ```

   That changes each `package.json`, but not the `^0.3.0` ranges the packages
   use to depend on each other: change those too. Change the pinned version in
   `packages/alpine/README.md`'s CDN URLs as well. Then `npm install`, so that
   `package-lock.json` agrees (CI installs with `npm ci`, which refuses a lockfile
   out of step), and:

   ```sh
   node tools/npm-publish-readiness.mjs
   ```

   It names every range no sibling satisfies (rule 4) and every pinned URL that
   names another version (rule 10).
2. **Write the changelog**: in `CHANGELOG.md`, move *Unreleased* down to the new
   version, and start a fresh *Unreleased* above it.
3. **Open a pull request**, and merge it once it is green.
4. **Before tagging**, open <https://proteles.com/signup> and check that it
   answers. Every package's README sends readers there before its install line,
   and a published README cannot be changed without another version.
5. **Tag the merged commit** on `main`:

   ```sh
   git switch main && git pull --ff-only
   git tag npm-v0.4.0
   git push origin npm-v0.4.0
   ```

6. **Approve.** The `release-npm` run checks the commit (`verify`), builds the
   tarballs (`pack`), and then waits on the `npm-publish` environment. Once both
   are green, *Review deployments* › approve. `publish` sends the 13 tarballs.
7. **Verify**, as a stranger would:

   ```sh
   npm view @proteles/js@0.4.0 version
   cd "$(mktemp -d)" && npm init -y >/dev/null && npm install @proteles/next @proteles/react && npm audit signatures
   ```

   `npm audit signatures` checks the registry signatures and the provenance
   attestations. Each package's npm page also shows its provenance, linking the
   commit and the workflow run.

### What `release-npm.yml` does

1. `verify`: the `sdk` checks of every pull request, publish readiness included.
2. `pack`: refuses a tag that does not name the workspace's version, then
   `npm ci`, `npm run build` (the root script, which builds `js`, then `bff`,
   then the rest) and `npm pack` for each package. It has no publish identity:
   install scripts and build tools are third-party code, and none of it runs
   where a token can be minted.
3. `publish`, in the `npm-publish` environment, the only job with
   `id-token: write`. It installs and builds nothing. It refuses: Node other than
   the pinned major, npm older than 11.5.1, an npm token, no OIDC token, a tag
   that does not name the version, a tag that no longer names the run's commit.
   Then it publishes pack's tarballs in dependency order (`js`, `bff`, then the
   rest) with `--provenance --ignore-scripts --access public`, skipping any
   version npm already has.

**If it stops part-way**, re-run the failed job: what is already on npm is
skipped. A package refused with an authentication error has no trusted
publisher, or one that does not match the table above: fix it on npmjs.com,
then re-run.

### Adding a package

npm will not attach a trusted publisher to a package that does not exist, so a
new package's first version is published by hand, once every package it depends
on is on npm at that version. Signed in as an owner of the `proteles`
organization, with two-factor authentication and no token:

```sh
npm login
npm ci && npm run build
PKGS="new-package"
for p in $PKGS; do npm publish --workspace "@proteles/$p" --access public; done
```

Then register its trusted publisher (above), and add it to both publish lists:
the two loops in `release-npm.yml` and the one in [Publishing by
hand](#publishing-by-hand). `tools/npm-publish-readiness.mjs` (rule 9) fails
until every package the workspace builds is in every list.

### Publishing by hand

Only when the workflow cannot run and the release cannot wait. Nothing
published this way carries provenance.

```sh
npm ci && npm run build
node tools/npm-publish-readiness.mjs
for p in js bff management react next htmx svelte vue solid alpine alpine-ajax express fastify; do
  npm publish --workspace "@proteles/$p" --access public
done
```

`npm run build`, never `npm run build --workspaces`, which goes alphabetically
and builds `bff` before the `js` it imports. npm asks for a two-factor code;
expect to give it more than once over 13 packages.

## Releasing the native SDKs

1. **Bump `VERSION_NAME`** in `mobile/android/gradle.properties`, and the install
   lines in `mobile/README.md`, `mobile/android/README.md` and
   `mobile/ios/README.md`. `node mobile/android/scripts/publish-readiness.mjs`
   fails on any install line that names another version.
2. **Write [`mobile/CHANGELOG.md`](mobile/CHANGELOG.md)**: move *Unreleased* down
   to the new version, and start a fresh one above it.
3. **Open a pull request**, and merge it once it is green.
4. **Tag the merged commit** on `main`, with the bare version:

   ```sh
   git switch main && git pull --ff-only
   git tag 0.2.0
   git push origin 0.2.0
   ```

5. **Approve.** The `release-mobile` run checks the tag against `VERSION_NAME`
   (`plan`), runs the iOS checks on macOS and the Android checks (`test`), and
   then `android` waits on the `mobile-release` environment. Approve it; it runs
   [`mobile/scripts/release.sh`](mobile/scripts/release.sh), which builds and
   signs the artifacts, checks them, uploads them to the Central Portal and
   waits up to fifteen minutes for validation.
6. **Publish on Central.** In the Central Portal, open the deployment the log
   names (`proteles-android-X.Y.Z`), check its files, and press **Publish**.
7. **iOS needs nothing.** The tag is the release, and the run's `ios` job
   records it. An app adds:

   ```swift
   .package(url: "https://github.com/proteles-auth/proteles-sdk", from: "0.2.0")
   ```

### One platform, or a retry

*Actions › release-mobile › Run workflow*, with *Use workflow from* set to the
tag (under *Tags*) and *platforms* set to:

- `android`: test and release Android only. This is the retry: whatever Central
  already has at this version is skipped.
- `ios`: re-run the iOS checks on the tag. Nothing is published either way.
- `both`: what a tag push runs.

A run started on a branch, or on a tag that is not `X.Y.Z` or does not name
`VERSION_NAME`, stops before anything builds.

**One case a retry cannot see**: an upload that validated but has not been
published is not on Central yet, so a re-run would upload a second deployment.
Press **Publish** (or **Drop**) on the first one before re-running.

### What `release.sh` refuses, before it builds anything

A tag that is not `X.Y.Z` or does not match `VERSION_NAME`; any of the four
secrets missing (named all at once); a `MOBILE_SIGNING_KEY` that is not an
ASCII-armoured secret key; a placeholder left in `gradle.properties`; a
repository with no `Package.swift` at its root. Its header is the reference, and
`node mobile/scripts/release-check.mjs`, which every pull request runs, drives
it against a stub Central to show each refusal, each answer Central can give,
and the skip.
