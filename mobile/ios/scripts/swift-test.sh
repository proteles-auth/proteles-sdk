#!/bin/sh
# Builds and tests ProtelesAuth on the macOS host with the Command Line Tools'
# `swift`, off-device (docs/mobile-SDKs.md §10.8). The package is the
# repository root's Package.swift, so it runs there, from wherever it is called.
# Extra arguments go to `swift test` (e.g. `--filter VectorTests`). With `build`
# as the first argument it runs `swift build` instead, with the same
# workarounds (e.g. `build -c release`, the way an app's Release configuration
# compiles the package).
#
#   mobile/ios/scripts/swift-test.sh
#   mobile/ios/scripts/swift-test.sh build -c release
#
# Two things about a Command Line Tools install need working around, and this
# script does each only when it is needed:
#
# 1. **A stale PackageDescription interface.** An install upgraded in place can
#    keep `PackageDescription.swiftmodule/*.private.swiftinterface` files from
#    an older Swift (5.10 on the machine this was written on). The compiler
#    prefers the private interface, so *every* manifest fails — `extra argument
#    'swiftLanguageModes'`, then a link failure — including `swift package
#    init`'s own template. The script overlays the current public interface on
#    the stale private one for the manifest compile only, with a module cache
#    of its own so the stale build is not reused. Nothing outside the scratch
#    directory is touched.
# 2. **swift-testing's framework path.** Without Xcode, SwiftPM cannot look up
#    the platform path, so it never adds the Command Line Tools'
#    `Testing.framework` to the search and rpaths; `import Testing` fails.
#
# With a full Xcode selected (`xcode-select -s`), neither applies and this is
# plain `swift test`.

set -eu

# mobile/ios/scripts -> the repository root, where Package.swift is.
root=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$root"
[ -f Package.swift ] || { echo "error: no Package.swift at $root" >&2; exit 1; }

swift_bin=$(xcrun -f swift)
toolchain=$(cd "$(dirname "$swift_bin")/.." && pwd)
developer=$(cd "$toolchain/.." && pwd)
scratch="${TMPDIR:-/tmp}/protelesauth-swiftpm"
mkdir -p "$scratch"

extra=""

manifest_api="$toolchain/lib/swift/pm/ManifestAPI/PackageDescription.swiftmodule"
if [ -d "$manifest_api" ] && ls "$manifest_api"/*.private.swiftinterface >/dev/null 2>&1; then
  stale=""
  for private in "$manifest_api"/*.private.swiftinterface; do
    public="${private%.private.swiftinterface}.swiftinterface"
    [ -f "$public" ] || continue
    if [ "$(sed -n 2p "$private")" != "$(sed -n 2p "$public")" ]; then
      stale="$stale $private"
    fi
  done
  if [ -n "$stale" ]; then
    echo "note: overlaying stale PackageDescription private interfaces:$stale" >&2
    overlay="$scratch/manifest-overlay.yaml"
    {
      printf '{ "version": 0, "case-sensitive": "false", "redirecting-with": "fallthrough", "roots": [\n'
      printf '  { "type": "directory", "name": "%s", "contents": [\n' "$manifest_api"
      first=1
      for private in $stale; do
        [ $first -eq 1 ] || printf ',\n'
        first=0
        printf '    { "type": "file", "name": "%s", "external-contents": "%s" }' \
          "$(basename "$private")" "${private%.private.swiftinterface}.swiftinterface"
      done
      printf '\n  ]}\n]}\n'
    } > "$overlay"
    extra="$extra -Xbuild-tools-swiftc -vfsoverlay -Xbuild-tools-swiftc $overlay -Xbuild-tools-swiftc -module-cache-path -Xbuild-tools-swiftc $scratch/manifest-module-cache"
  fi
fi

frameworks="$developer/Library/Developer/Frameworks"
if [ "$(basename "$developer")" = "CommandLineTools" ] && [ -d "$frameworks/Testing.framework" ]; then
  interop="$developer/Library/Developer/usr/lib"
  extra="$extra -Xswiftc -F -Xswiftc $frameworks -Xlinker -F -Xlinker $frameworks -Xlinker -rpath -Xlinker $frameworks -Xlinker -rpath -Xlinker $interop"
fi

subcommand=test
if [ "${1:-}" = "build" ]; then
  subcommand=build
  shift
fi

echo "+ swift $subcommand$extra $*" >&2
# shellcheck disable=SC2086 # $extra is a list of flags, split on purpose
exec swift "$subcommand" $extra "$@"
