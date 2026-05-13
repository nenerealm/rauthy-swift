// swift-tools-version: 6.0
//
// Rauthy Swift SDK — client-side SDK for the Rauthy OIDC/OAuth2 identity provider.
// See README.md and the design doc for status and scope.

import PackageDescription

let package = Package(
    name: "Rauthy",
    platforms: [
        .iOS(.v16),
        .macOS(.v13),
        .tvOS(.v16),
        .visionOS(.v1),
    ],
    products: [
        .library(
            name: "Rauthy",
            targets: ["Rauthy"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-log.git", from: "1.5.0"),
    ],
    targets: [
        .target(
            name: "Rauthy",
            dependencies: [
                .product(name: "Logging", package: "swift-log"),
            ],
            swiftSettings: [
                .enableUpcomingFeature("ExistentialAny"),
                .enableExperimentalFeature("StrictConcurrency=complete"),
            ]
        ),
        .testTarget(
            name: "RauthyTests",
            dependencies: ["Rauthy"]
        ),
    ],
    swiftLanguageModes: [.v6]
)
