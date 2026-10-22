// swift-tools-version: 6.0
//
// ProtelesAuth — the native iOS SDK for a Proteles tenant. Its source is
// mobile/ios; this manifest is at the repository root because SwiftPM resolves
// `.package(url:from:)` only from a repository whose root holds Package.swift.
// So an iOS release is nothing more than a plain `X.Y.Z` tag on this
// repository (the npm packages are tagged `npm-vX.Y.Z`, which SwiftPM ignores).
//
//     .package(url: "https://github.com/proteles-auth/proteles-sdk", from: "0.1.0")
//     .product(name: "ProtelesAuth", package: "proteles-sdk")
//
// No dependencies. Everything the protocol needs is in the platform:
// Security (RSA PKCS#1 v1.5 verification, SecRandomCopyBytes, Keychain),
// CryptoKit (SHA-256), AuthenticationServices (the browser hop) and
// Foundation (URLSession). A third-party JOSE or OAuth library inside the
// authentication path would be a dependency bought for a few hundred lines.
//
// macOS is a platform so the protocol core — PKCE, request building, callback
// parsing, the token client, the verifier against the shared vectors — runs
// under `swift test` on the host, off-device (docs/mobile-SDKs.md §10.8).
//
// iOS 17.4 and macOS 14.4 because the redirect is a Universal Link (M7 in
// docs/mobile-SDKs.md): the server registers no private-use scheme, and
// `ASWebAuthenticationSession.Callback.https(host:path:)`, the only way the
// system browser hands an https redirect back to the app, arrived in those
// versions.

import PackageDescription

let package = Package(
    name: "ProtelesAuth",
    platforms: [
        .iOS("17.4"),
        .macOS("14.4"),
    ],
    products: [
        .library(name: "ProtelesAuth", targets: ["ProtelesAuth"]),
    ],
    targets: [
        .target(
            name: "ProtelesAuth",
            path: "mobile/ios/Sources/ProtelesAuth"
        ),
        .testTarget(
            name: "ProtelesAuthTests",
            dependencies: ["ProtelesAuth"],
            path: "mobile/ios/Tests/ProtelesAuthTests"
        ),
    ]
    // swift-tools-version 6.0 builds every target in the Swift 6 language
    // mode, with complete strict-concurrency checking.
)
