# Rauthy Swift SDK

A client-side Swift SDK for [Rauthy](https://github.com/sebadob/rauthy), the
open-source Rust OIDC/OAuth2 identity provider. SwiftUI-first, Swift 6 strict
concurrency, no third-party crypto dependencies.

[![CI](https://github.com/nenerealm/rauthy-swift/actions/workflows/test.yml/badge.svg)](https://github.com/nenerealm/rauthy-swift/actions/workflows/test.yml)
[![Swift 6](https://img.shields.io/badge/Swift-6.0+-orange.svg)](https://swift.org)
[![Platforms](https://img.shields.io/badge/Platforms-iOS%2016+%20|%20macOS%2013+%20|%20tvOS%2016+%20|%20visionOS%201+-blue.svg)](#platform-support)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

**Status: v1.0 GA.** Verified end-to-end against a real Rauthy server. 110 tests,
multi-pass adversarial review, Swift 6 concurrency-clean.

## Platform support

- iOS 16+
- macOS 13+
- tvOS 16+
- visionOS 1+
- watchOS: not supported (no `ASWebAuthenticationSession` on watchOS)

SwiftUI-first. UIKit not supported.

## Installation

Swift Package Manager. In your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/nenerealm/rauthy-swift", from: "1.0.0"),
],
targets: [
    .target(
        name: "MyApp",
        dependencies: [
            .product(name: "Rauthy", package: "rauthy-swift"),
        ]
    )
]
```

Or in Xcode: **File → Add Package Dependencies → paste the repo URL.**

## What ships in v1.0

- **Full PKCE sign-in flow** via `ASWebAuthenticationSession` (RFC 7636)
- **Token refresh** — auto-refresh via `validAccessToken()` plus explicit
  `refreshSession()`. Single-flight coalescing prevents concurrent refresh
  storms.
- **Token revocation** (RFC 7009) via `signOut(scope: .revokeTokens)`
- **RP-Initiated Logout** (OIDC 1.0) via `signOut(scope: .rpInitiated)` / `.full`
- **ID token signature validation** — Ed25519 (CryptoKit) + RSA RS256/384/512
  (Security framework via PKCS#1 DER encoder)
- **ID token claims validation** — iss / aud / azp / exp / nbf / nonce /
  email_verified
- **OIDC discovery** + JWKS fetch with refetch-on-kid-miss
- **Keychain-backed storage** (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`) +
  in-memory variant for tests
- **Account self-service API** — profile / preferred username / devices
  (list, revoke, rename) / avatar (upload / delete) / passkey conversion /
  account deletion
- **Passkey API** — list, register, delete (uses
  `ASAuthorizationPlatformPublicKeyCredentialProvider`)
- **`Browser.openAccountDashboard`** — bounce users to Rauthy's web account UI
  for things the SDK doesn't expose
- **SwiftUI primitives** — `RauthyAuthState`, `RauthyAuthGate`,
  `.rauthyPresentationContext()`, `@RauthyUser`, `.rauthyRequiresClaim` /
  `.rauthyRequiresRole` / `.rauthyRequiresGroup`, `.rauthyErrorAlert(_:)`
- **`ClaimRule`** — declarative authorization rules (`.role`, `.group`,
  combinators `.and` / `.or` / `.not`)
- **Localized error messages** — English / Simplified Chinese / Japanese,
  runtime-switchable via `Rauthy.locale`. Format-string safe (translator
  typos can't crash the error path)
- **`swift-log` integration** — plus `RauthyOSLogHandler` for OSLog routing
  out of the box
- **Swift 6 strict concurrency** mode (`StrictConcurrency=complete`)
- **DocC documentation** — getting started, claim rules, SwiftUI integration,
  localization
- **110 tests** across 28 suites — unit, wire-protocol, single-flight refresh,
  multi-language switching, signature validation

## What's NOT in v1.0 (intentionally)

- **DPoP token binding** (RFC 9449) — deferred to v1.1. Designed but blocked
  on upstream Rauthy ES256 signature support.
- **Multi-account** — deferred to v1.5. Single-account covers the common case.
- **Passkey-as-sign-in flow** — Rauthy's web login page already handles passkey
  authentication through the OAuth code flow redirect, so the SDK doesn't need
  a parallel implementation.
- **`/users/request_reset`** (forgot-password) — requires a server PoW solver;
  this belongs in Rauthy's web UI, not an SDK for already-signed-in users.
- **Email confirmation endpoint** — user clicks the email link, server handles
  the rest; no SDK call needed.
- **UIKit support** — explicitly out of scope. SwiftUI-only.
- **CocoaPods / XCFramework distribution** — SwiftPM only. The localization
  bundle requires SwiftPM's `Bundle.module`.

## Quick start

```swift
import Rauthy
import SwiftUI

@main
struct MyApp: App {
    let rauthy = RauthyClient(config: .production(
        issuer: URL(string: "https://your-rauthy.example.com/auth/v1")!,
        clientID: "my-app",
        redirectURI: URL(string: "myapp://callback")!,
        userClaim: .or([.group("users")]),
        adminClaim: .or([.role("admin")])
    ))

    @StateObject var auth: RauthyAuthState

    init() {
        let client = rauthy
        _auth = StateObject(wrappedValue: RauthyAuthState(client: client))

        // Optional: localize error messages.
        Rauthy.locale = Locale(identifier: "zh-Hans")
    }

    var body: some Scene {
        WindowGroup {
            RauthyAuthGate { user in
                MainView(user: user)
            } signedOut: {
                LoginView()
            }
            .environmentObject(auth)
            .rauthyPresentationContext()
            .rauthyErrorAlert(auth)
            .task { await auth.bootstrap() }
        }
    }
}

struct LoginView: View {
    @EnvironmentObject var auth: RauthyAuthState

    var body: some View {
        Button("Sign in") {
            Task { await auth.signIn() }
        }
        .disabled(auth.isBusy)
    }
}

struct MainView: View {
    let user: User
    @EnvironmentObject var auth: RauthyAuthState

    var body: some View {
        VStack {
            Text("Hi, \(user.email ?? "anonymous")")

            // Declarative authorization — visible only to admins.
            AdminPanel()
                .rauthyRequiresRole("admin")
        }
        .toolbar {
            Button("Sign out") {
                Task { await auth.signOut() }
            }
        }
    }
}
```

## Try the sample app

A complete SwiftUI iOS app showing sign-in, user info, account management,
and passkey registration lives at `Samples/NotesApp/`.

```bash
cd Samples/NotesApp
brew install xcodegen     # one-time
xcodegen generate
open NotesApp.xcodeproj
```

Edit `NotesApp/Config.swift` to point at your own Rauthy server. Full setup
walkthrough (admin client registration, manual Xcode path) lives in
[`Samples/NotesApp/SETUP.md`](Samples/NotesApp/SETUP.md).

## Building and testing

```bash
swift build
swift test --no-parallel    # serial: Rauthy.locale is a process global
```

Requires Swift 6.0+ (tested with Swift 6.3 / Xcode 16+).

For DocC documentation:

```bash
swift package generate-documentation --target Rauthy
```

## Localization

Default locale follows the system. Override at runtime:

```swift
Rauthy.locale = Locale(identifier: "zh-Hans")
// or "ja", or nil to follow system

catch let err as RauthyError {
    showAlert(err.localizedDescription)  // 网络不可用,请检查网络连接后重试。
}
```

Ships translations for `en` / `zh-Hans` / `ja`. Other locales fall back to
English. Pull requests adding new translations are welcome — see
`Sources/Rauthy/Resources/<lang>.lproj/Localizable.strings`.

## Roadmap

| Milestone | Status | Highlights |
|-----------|--------|------------|
| v1.0 | ✅ Shipped | PKCE + Account API + Passkey + SwiftUI primitives + i18n |
| v1.1 | Planned | DPoP token binding (RFC 9449) — blocked on upstream Rauthy ES256 |
| v1.5 | Planned | Multi-account support |
| v2.0 | Future | Secure Enclave key storage; revisit XCFramework distribution |

## License

[Apache 2.0](LICENSE) — matches Rauthy.

## Contributing

Bug reports, questions, and translation contributions are welcome via GitHub
Issues and Discussions. For non-trivial feature work, please open a Discussion
to align on scope first.

The upstream Rauthy project lives at https://github.com/sebadob/rauthy —
coordinate any client-server protocol questions there.

## Acknowledgements

Built on top of Rauthy by Sebastian Dobe and contributors. This SDK is an
unofficial, community-maintained client; it is not endorsed by the Rauthy
project (yet — happy to coordinate if the maintainers would like it to be).
