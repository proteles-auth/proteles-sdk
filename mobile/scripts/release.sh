#!/usr/bin/env bash
# Releases the native SDKs from a plain `X.Y.Z` tag. It is the body of the
# mobile release workflow (run on the tag); RELEASING.md is the runbook.
#
# **Only Android is uploaded here.** The iOS package's manifest is Package.swift
# at the repository root, so SwiftPM resolves `.package(url:from:)` straight
# from this repository's tags: the `X.Y.Z` tag that started this run *is* the
# iOS release, and there is nothing to push anywhere. (The npm packages are
# tagged `npm-vX.Y.Z`, which is neither this script's pattern nor a version
# SwiftPM reads.)
#
# Everything that can refuse, refuses before anything is built: the tag against
# VERSION_NAME, every credential variable, the placeholders in
# android/gradle.properties. Then the Android artifacts are built, signed,
# checked and uploaded to Maven Central through the Central Portal's publisher
# API. What is already on Central is skipped, so a retry after a partial failure
# finishes the release rather than failing on it.
#
# With the default CENTRAL_PUBLISHING_TYPE (USER_MANAGED) the upload stops at
# VALIDATED and waits for someone to press Publish in the Central Portal.
#
# Variables (the release environment's secrets; RELEASING.md lists them):
#   MOBILE_SIGNING_KEY             path to a file holding the ASCII-armoured secret key
#   MOBILE_SIGNING_KEY_PASSWORD    its passphrase
#   CENTRAL_PORTAL_TOKEN_USERNAME  the two halves of a Central Portal user token
#   CENTRAL_PORTAL_TOKEN_PASSWORD
# From the workflow:
#   GITHUB_REF_NAME                the tag, X.Y.Z
#   GITHUB_SHA                     the commit it names (logged)
# Optional:
#   CENTRAL_PUBLISHING_TYPE        USER_MANAGED (default) or AUTOMATIC
#   CENTRAL_PORTAL_URL             default https://central.sonatype.com
#
# For release-check.mjs only, which drives this against a stub Central and a
# fixture tree: MOBILE_RELEASE_ROOT (the repository root).

set -euo pipefail

ROOT="${MOBILE_RELEASE_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
MOBILE="$ROOT/mobile"
ANDROID="$MOBILE/android"

say() { printf 'mobile-release: %s\n' "$*" >&2; }
die() { printf '\nmobile-release: FAILED: %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Preflight. Nothing below this block runs until all of it has passed.
# ---------------------------------------------------------------------------

TAG="${GITHUB_REF_NAME:-}"
[[ "$TAG" =~ ^([0-9]+\.[0-9]+\.[0-9]+)$ ]] ||
  die "'$TAG' is not a mobile release tag (a plain MAJOR.MINOR.PATCH: no 'v', no 'npm-v', no 'mobile-v')"
WANT="${BASH_REMATCH[1]}"
prop() { sed -n "s/^$1=//p" "$ANDROID/gradle.properties" | tail -1; }
HAVE="$(prop VERSION_NAME)"
[ "$WANT" = "$HAVE" ] || die "tag $TAG wants $WANT, but VERSION_NAME in mobile/android/gradle.properties is ${HAVE:-unset}.
Bump VERSION_NAME and re-tag, or tag $HAVE."
VERSION="$HAVE"
say "tag $TAG (${GITHUB_SHA:-commit not given}) matches VERSION_NAME $VERSION"

# The tag is the iOS release only while the manifest is where SwiftPM looks.
[ -f "$ROOT/Package.swift" ] ||
  die "there is no Package.swift at the repository root, so the tag $TAG releases nothing for iOS"

needed=(MOBILE_SIGNING_KEY MOBILE_SIGNING_KEY_PASSWORD CENTRAL_PORTAL_TOKEN_USERNAME CENTRAL_PORTAL_TOKEN_PASSWORD)
missing=()
for v in "${needed[@]}"; do
  [ -n "${!v:-}" ] || missing+=("$v")
done
if [ "${#missing[@]}" -gt 0 ]; then
  die "these variables are not set: ${missing[*]}
They are secrets of the release environment, which only the release workflow
receives, on a release tag; RELEASING.md lists what each one is."
fi
[ -f "$MOBILE_SIGNING_KEY" ] && grep -q 'BEGIN PGP PRIVATE KEY BLOCK' "$MOBILE_SIGNING_KEY" ||
  die "MOBILE_SIGNING_KEY is not the path of a file holding an ASCII-armoured secret key"
PUBLISHING_TYPE="${CENTRAL_PUBLISHING_TYPE:-USER_MANAGED}"
case "$PUBLISHING_TYPE" in USER_MANAGED|AUTOMATIC) ;; *) die "CENTRAL_PUBLISHING_TYPE must be USER_MANAGED or AUTOMATIC" ;; esac
CENTRAL="${CENTRAL_PORTAL_URL:-https://central.sonatype.com}"

# The POM is public for good once Central takes it.
placeholders="$(grep -n '\.invalid' "$ANDROID/gradle.properties" | grep -v '^[0-9]*:#' || true)"
[ -z "$placeholders" ] || die "mobile/android/gradle.properties still has placeholders the owner fills in:
$placeholders"

for tool in node curl zip java; do
  command -v "$tool" >/dev/null || die "$tool is not on PATH"
done

work="$(mktemp -d "${TMPDIR:-/tmp}/mobile-release.XXXXXX")"
trap 'rm -rf "$work"' EXIT

say "preflight passed: credentials present, no placeholders, publishing type $PUBLISHING_TYPE"
say "iOS: the tag $TAG is the release (Package.swift at the repository root); nothing to upload"

# ---------------------------------------------------------------------------
# Android: Maven Central, through the Central Portal's publisher API.
# ---------------------------------------------------------------------------

# The token goes to curl on stdin, never in its arguments, where anyone on this
# machine could read it from the process list.
central() { # METHOD PATH [curl args…]; prints the body, fails on HTTP >= 400
  local method="$1" path="$2"; shift 2
  local auth
  auth="$(printf '%s:%s' "$CENTRAL_PORTAL_TOKEN_USERNAME" "$CENTRAL_PORTAL_TOKEN_PASSWORD" | base64 | tr -d '\n')"
  printf 'header = "Authorization: Bearer %s"\n' "$auth" |
    curl -sS --fail-with-body --max-time 300 -K - -X "$method" "$CENTRAL$path" "$@"
}
json() { node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const v=JSON.parse(s)[process.argv[1]];console.log(typeof v==="object"?JSON.stringify(v):v)})' "$1"; }

ARTIFACT_IDS=(proteles-auth-core proteles-auth-android)
published=0
for id in "${ARTIFACT_IDS[@]}"; do
  answer="$(central GET "/api/v1/publisher/published?namespace=com.proteles&name=$id&version=$VERSION")" ||
    die "could not ask Central whether com.proteles:$id:$VERSION is published: $answer"
  [ "$(printf '%s' "$answer" | json published)" = "true" ] && published=$((published + 1))
done
if [ "$published" -eq "${#ARTIFACT_IDS[@]}" ]; then
  say "Android: com.proteles:*:$VERSION is already on Maven Central; skipping"
elif [ "$published" -gt 0 ]; then
  die "Android: only $published of ${#ARTIFACT_IDS[@]} artifacts are published at $VERSION. One deployment holds both,
so this is not a state a release leaves; look in the Central Portal before doing anything else."
else
  say "Android: publishing signed artifacts to build/repo"
  rm -rf "$ANDROID/build/repo"
  export ANDROID_HOME="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
  # A fresh Gradle home for the one build that holds the signing key: Gradle
  # runs every init script it finds in
  # ~/.gradle/init.d, nothing turns them off (`-I` only adds another), and this
  # build has the key in its environment. On a runner that also builds other
  # people's changes, one of them could have left one there. Under $work, so
  # the trap removes it. The price is a cold download of Gradle — checked
  # against `distributionSha256Sum` in gradle-wrapper.properties — and of the
  # build's dependencies, once per release.
  export GRADLE_USER_HOME="$work/gradle-home"
  mkdir -p "$GRADLE_USER_HOME"
  ORG_GRADLE_PROJECT_signingInMemoryKey="$(cat "$MOBILE_SIGNING_KEY")" \
  ORG_GRADLE_PROJECT_signingInMemoryKeyPassword="$MOBILE_SIGNING_KEY_PASSWORD" \
    "$ANDROID/gradlew" -p "$ANDROID" --no-daemon --console=plain publishAllPublicationsToBuildRepository
  # The same check CI runs on every change, on the signed output itself, with
  # placeholders fatal.
  node "$ANDROID/scripts/publish-readiness.mjs" --repo "$ANDROID/build/repo" --signed --release

  # The component files only. maven-metadata.xml describes Gradle's local
  # repository, not the component; Central keeps its own.
  bundle="$ANDROID/build/central-bundle-$VERSION.zip"
  rm -f "$bundle"
  ( cd "$ANDROID/build/repo" && zip -qr "$bundle" com -x '*maven-metadata*' )
  say "Android: uploading $(basename "$bundle") ($PUBLISHING_TYPE)"
  deployment="$(central POST "/api/v1/publisher/upload?name=proteles-android-$VERSION&publishingType=$PUBLISHING_TYPE" \
    -F "bundle=@$bundle")" || die "the upload was refused: $deployment"
  say "Android: deployment $deployment; waiting for Central to validate it"
  want_state=VALIDATED
  [ "$PUBLISHING_TYPE" = AUTOMATIC ] && want_state=PUBLISHED
  state=""
  for _ in $(seq 1 90); do
    status="$(central POST "/api/v1/publisher/status?id=$deployment")" || die "could not read deployment $deployment: $status"
    state="$(printf '%s' "$status" | json deploymentState)"
    case "$state" in
      "$want_state") break ;;
      FAILED) die "Central refused deployment $deployment: $(printf '%s' "$status" | json errors)" ;;
      PUBLISHED) break ;;
    esac
    sleep 10
  done
  [ "$state" = "$want_state" ] || [ "$state" = PUBLISHED ] ||
    die "deployment $deployment is still $state after 15 minutes; it is not failed. Check the Central Portal, and
do not re-run this release until it has settled: a re-run uploads a second deployment."
  if [ "$state" = VALIDATED ]; then
    say "Android: deployment $deployment is VALIDATED. It is not public until someone presses Publish on it in the
Central Portal — and until then this script cannot see it, so press Publish (or Drop) before running it again."
  else
    say "Android: deployment $deployment is $state"
  fi
fi

say "released $TAG"
