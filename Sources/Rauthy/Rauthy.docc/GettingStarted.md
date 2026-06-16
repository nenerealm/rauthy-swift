# Getting started

Set up Rauthy, sign your user in, and use the access token.

## Overview

A minimal SwiftUI app needs roughly 30 lines to integrate Rauthy. This
article walks through each step.

## Prerequisites

You'll need:

1. **A Rauthy server.** Either a public-facing deployment or `LOCAL_TEST=true`
   running on `localhost:8443` for development. See the
   [Rauthy book](https://sebadob.github.io/rauthy/) for setup.
2. **A registered OIDC client** in Rauthy's admin UI:
   - Client Type: `Public` (mobile apps can't keep a secret)
   - Token Algorithm: `EdDSA` (or `RS256`)
   - Allowed Scopes / Default Scopes: `openid`, `profile`, `email`
   - Redirect URIs: `myapp://callback` (matching your `Info.plist` URL Type)
   - PKCE required, S256 only
3. **A URL scheme registered** in your app's `Info.plist` matching the
   redirect URI scheme.

## Configure the client

Create a single ``RauthyClient`` for the app's lifetime, wrapped in
``RauthyAuthState`` for SwiftUI:

```swift
import Rauthy

@MainActor
let auth = RauthyAuthState(
    client: RauthyClient(
        config: .production(
            issuer: URL(string: "https://auth.example.com/auth/v1")!,
            clientID: "my-app",
            redirectURI: URL(string: "myapp://callback")!,
            userClaim: .or([.group("my-app-users")]),
            adminClaim: .or([.role("admin")])
        ),
        storage: KeychainStorage()
    )
)
```

The ``ClaimRule`` values define who can use your app:

- `userClaim` — enforced at sign-in. A user who does not satisfy this rule
  is rejected with ``RauthyError/notAuthorized`` and never reaches the
  signed-in state. Pass ``ClaimRule/any`` to admit any Rauthy user.
- `adminClaim` — a sub-group of users marked as admins. Pass
  ``ClaimRule/none`` if you don't have admins.

> Note: `.group(...)` / `.role(...)` rules are checked against the ID
> token's `groups` / `roles` claims, which are only present when the
> matching scope was requested. Request the `groups` scope when gating on
> groups; ``ClaimRule/any`` admits everyone regardless of claims.

## Wire up SwiftUI

```swift
@main
struct MyApp: App {
    @StateObject var auth: RauthyAuthState = ...

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
```

``RauthyAuthGate`` switches its content based on the current auth state.
The ``rauthyPresentationContext()`` modifier captures the host window so
`ASWebAuthenticationSession` knows where to anchor.

## Trigger sign-in

```swift
struct LoginView: View {
    @EnvironmentObject var auth: RauthyAuthState

    var body: some View {
        Button("Sign in") {
            Task { await auth.signIn() }
        }
    }
}
```

When the user taps:

1. iOS opens an `ASWebAuthenticationSession` browser sheet pointing at
   Rauthy's `/authorize` endpoint with PKCE parameters.
2. The user authenticates on Rauthy's hosted login page.
3. Rauthy redirects back to `myapp://callback?code=...`.
4. The SDK exchanges the code for tokens, validates the ID token's
   signature against Rauthy's JWKS, and stores the result in the Keychain.
5. ``RauthyAuthState/status`` transitions to ``RauthyAuthState/Status/signedIn(_:)``
   and ``RauthyAuthGate`` swaps in the `signedIn` content.

## Call your backend with the access token

```swift
extension RauthyAuthState {
    func loadNotes() async throws -> [Note] {
        // Get a known-valid access token (auto-refreshes if expired).
        let token = try await client.validAccessToken()

        var request = URLRequest(url: URL(string: "https://api.example.com/notes")!)
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        let (data, _) = try await URLSession.shared.data(for: request)
        return try JSONDecoder().decode([Note].self, from: data)
    }
}
```

Or use ``RauthyClient/authorize(_:)-(inout_URLRequest)`` to decorate an
existing `URLRequest` automatically.

## Sign out

```swift
await auth.signOut()
```

By default this only clears local storage. Pass a scope for stronger
sign-out:

```swift
await auth.signOut(scope: .revokeTokens)  // also calls /oidc/revoke
```

See ``SignOutScope`` for all options.
