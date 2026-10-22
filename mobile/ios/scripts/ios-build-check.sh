#!/bin/sh
# Compiles ProtelesAuth for iOS — the simulator and a device — and type-checks
# the example app against the iOS SDK. Needs an Xcode (for the iOS SDKs), not
# a simulator or a device, and runs nothing.
#
# It calls the Xcode toolchain's `swift-build` and `swiftc` directly rather
# than `xcodebuild`: on the machine this was written on, Xcode 16.2 on macOS
# 26 cannot load `xcodebuild` at all (CoreDevice fails to link against the
# system's Mercury framework), and `xcrun` goes through it. The compilers and
# the SDKs themselves are fine.
#
# The package is the repository root's Package.swift, so it runs there, from
# wherever it is called:
#
#   DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer mobile/ios/scripts/ios-build-check.sh

set -eu

# mobile/ios/scripts -> the repository root, where Package.swift is.
root=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$root"
[ -f Package.swift ] || { echo "error: no Package.swift at $root" >&2; exit 1; }

developer="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"
case "$developer" in
  */CommandLineTools*) developer=/Applications/Xcode.app/Contents/Developer ;;
esac
bin="$developer/Toolchains/XcodeDefault.xctoolchain/usr/bin"
platforms="$developer/Platforms"
mac="$platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk"
simulator="$platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator.sdk"
device="$platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk"
scratch="${TMPDIR:-/tmp}/protelesauth-ios"

for path in "$bin/swift-build" "$simulator" "$device"; do
  [ -e "$path" ] || { echo "error: $path not found; set DEVELOPER_DIR to an Xcode" >&2; exit 1; }
done

"$bin/swiftc" --version 2>&1 | head -1
host_arch=$(uname -m)
sim_triple="$host_arch-apple-ios17.4-simulator"

# SDKROOT is the macOS SDK so the manifest compiles for the host; --sdk is
# the SDK the package is built against.
echo "+ swift-build --triple $sim_triple (iPhoneSimulator.sdk)" >&2
SDKROOT="$mac" "$bin/swift-build" --scratch-path "$scratch/simulator" \
  --triple "$sim_triple" --sdk "$simulator" --target ProtelesAuth

echo "+ swift-build --triple arm64-apple-ios17.4 (iPhoneOS.sdk)" >&2
SDKROOT="$mac" "$bin/swift-build" --scratch-path "$scratch/device" \
  --triple arm64-apple-ios17.4 --sdk "$device" --target ProtelesAuth

modules=$(SDKROOT="$mac" "$bin/swift-build" --scratch-path "$scratch/simulator" \
  --triple "$sim_triple" --sdk "$simulator" --show-bin-path)/Modules
echo "+ swiftc -typecheck mobile/ios/Example/ProtelesAuthExample/*.swift (iPhoneSimulator.sdk)" >&2
SDKROOT="$simulator" "$bin/swiftc" -typecheck -parse-as-library -swift-version 6 \
  -target "$sim_triple" -sdk "$simulator" -I "$modules" \
  mobile/ios/Example/ProtelesAuthExample/*.swift

echo "iOS build check passed" >&2
