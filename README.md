# Rauthy Swift SDK

A client-side Swift SDK for [Rauthy](https://github.com/sebadob/rauthy), an open-source OIDC/OAuth2 identity provider.

**Status: v0.1 in development.** This is a learning vehicle and proposal artifact. The author has not yet pinged the upstream Rauthy maintainer for endorsement. See "Status & roadmap" below.

## Platform support

- iOS 16+
- macOS 13+
- tvOS 16+
- visionOS 1+
- watchOS: not supported (no `ASWebAuthenticationSession`)

SwiftUI-first. UIKit is not supported.

## Installation

Swift Package Manager. In your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/<owner>/rauthy-swift", from: "0.1.0"),
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

Or in Xcode: File → Add Package Dependencies → paste the repo URL.

## What works today (v0.1)

- **Full PKCE sign-in flow** via `ASWebAuthenticationSession`
- **Token refresh** (auto-refresh via `validAccessToken()`, explicit `refreshSession()`)
- **`/userinfo` fetch** to retrieve the latest user state
- **Token revocation** (RFC 7009) via `signOut(scope: .revokeTokens)`
- **ID token validation** — Ed25519 signature + claims (iss/aud/azp/exp/nonce/email_verified)
- **OIDC discovery** + JWKS fetching with refetch-on-kid-miss
- **Keychain-backed storage** + in-memory storage for tests
- **`ClaimRule`** declarative authorization rules
- **`swift-log` integration** for diagnostic observability
- Core types: `Token`, `IDToken`, `IDTokenClaims`, `User`, `RauthyConfig`, etc.
- 66 Swift Testing unit + wire tests

## What is NOT in v0.1 yet

- RSA signature support (RS256/384/512) — Ed25519 only for now; coming in v0.2
- Single-flight refresh coalescing (parallel callers may collide)
- DPoP token binding — deferred to v1.1
- Multi-account — deferred to v1.5
- SwiftUI primitives (`RauthyAuthGate`, `.rauthyRequiresClaim`, `@RauthyUser`) — coming in v1.0
- Passkey registration/management API — v1.0
- RP-Initiated Logout (`.rpInitiated`, `.full` sign-out scopes) — v0.2
- Account management API (profile/password/devices/etc) — v1.0
- UIKit support — explicitly out of scope (SwiftUI-only)

See the design doc for the full v1.0 roadmap.

## Try the sample app

A minimal SwiftUI app showing sign-in, user info display, and sign-out lives at
`Samples/NotesApp/`. It points at `https://misspinkelf.com/auth/v1` by default —
edit `NotesApp/Config.swift` to point at your own Rauthy instance.

```bash
cd Samples/NotesApp
brew install xcodegen     # one-time
xcodegen generate
open NotesApp.xcodeproj
```

Full setup walkthrough (including Rauthy admin client registration and the
manual Xcode path if you don't want xcodegen) is in
[`Samples/NotesApp/SETUP.md`](Samples/NotesApp/SETUP.md).

## Hello world (current v0.1 surface)

This shows the types that exist today. Sign-in is not wired up yet:

```swift
import Rauthy

let config = RauthyConfig.production(
    issuer: URL(string: "https://auth.example.com/auth/v1")!,
    clientID: "my-app",
    redirectURI: URL(string: "myapp://callback")!,
    userClaim: .or([.group("my-app-users")]),
    adminClaim: .or([.role("admin")])
)

// Inspect a hypothetical token
let token = Token(
    id: UUID().uuidString,
    accessToken: "...",
    refreshToken: nil,
    idToken: nil,
    tokenType: .bearer,
    scope: ["openid", "profile", "email"],
    issuedAt: Date(),
    expiresIn: 3600
)
print(token.expiresAt)
print(token.isExpired(graceInterval: 60))

// Evaluate a claim rule against a user's roles/groups
let rule: ClaimRule = .or([.role("admin"), .group("ops")])
print(rule.matches(roles: ["admin"], groups: []))  // true
```

## Building and testing

```bash
swift build
swift test
```

Requires Swift 6.0+ (tested with Swift 6.3 / Xcode 16+).

## Status & roadmap

This project is split into three milestones:

| Milestone | Scope | Estimated effort |
|-----------|-------|------------------|
| **v0.1** (now) | Core types, config, scaffolding | 6–10 weeks FTE |
| **v1.0** | Sign-in flow, Account API, Passkey, SwiftUI primitives | 6–9 months FTE |
| **v1.1+** | DPoP support, multi-account, Secure Enclave key storage | (after v1.0 ships) |

See the [design doc](https://github.com/<owner>/rauthy-swift/blob/main/DESIGN.md) for full architecture and decision rationale.

## License

Apache 2.0 (matches Rauthy).

## Contributing

This SDK is in early development. Before opening implementation PRs, please open a discussion to align on scope. Bug reports and questions are welcome at any time.

The upstream Rauthy project lives at https://github.com/sebadob/rauthy — coordinate any client-server protocol questions there.
