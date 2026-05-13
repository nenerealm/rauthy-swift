# SwiftUI integration

Use Rauthy idiomatically inside a SwiftUI app.

## The three pieces

Three primitives cover 95% of integrations:

1. ``RauthyAuthState`` — `@ObservableObject` wrapping ``RauthyClient``.
   Exposes ``RauthyAuthState/status``, ``RauthyAuthState/lastError``, and
   ``RauthyAuthState/isBusy`` as `@Published` properties.
2. ``RauthyAuthGate`` — view that swaps content based on auth state.
3. ``rauthyPresentationContext()`` — view modifier that captures the
   host `UIWindow` so `ASWebAuthenticationSession` knows where to anchor.

## Wiring

A complete SwiftUI app entry:

```swift
@main
struct MyApp: App {
    @StateObject var auth = RauthyAuthState(client: makeClient())

    var body: some Scene {
        WindowGroup {
            RauthyAuthGate { user in
                MainTabView(user: user)
            } signedOut: {
                LoginView()
            } loading: {
                SplashView()    // optional — defaults to ProgressView()
            }
            .environmentObject(auth)
            .rauthyPresentationContext()
            .rauthyErrorAlert(auth)
            .task { await auth.bootstrap() }
        }
    }
}
```

That's the full setup. The four modifiers in order:

- `.environmentObject(auth)` — makes ``RauthyAuthState`` available to
  any descendant via `@EnvironmentObject` or ``RauthyUser``.
- ``rauthyPresentationContext()`` — captures host window for sign-in
  sheets.
- ``rauthyErrorAlert(_:)`` — surfaces ``RauthyAuthState/lastError``
  as a system alert. Optional; you can present errors yourself.
- `.task { await auth.bootstrap() }` — restore session from Keychain
  on app launch.

## Accessing the user

Inside any descendant view:

```swift
struct ProfileView: View {
    @RauthyUser var user

    var body: some View {
        if let user {
            Text("Hi, \(user.preferredUsername ?? "there")")
        }
    }
}
```

Or with full access to the state:

```swift
struct SettingsView: View {
    @EnvironmentObject var auth: RauthyAuthState

    var body: some View {
        Form {
            Button("Sign out") {
                Task { await auth.signOut() }
            }
        }
    }
}
```

## Gating views

Use ``rauthyRequiresClaim(_:fallback:)`` to declaratively show/hide
content based on the current user's roles and groups:

```swift
AdminTools()
    .rauthyRequiresRole("admin")

PremiumFeatures()
    .rauthyRequiresClaim(.and([.group("paid"), .role("verified")])) {
        UpgradePrompt()
    }
```

See <doc:ClaimRules> for the full ``ClaimRule`` reference.

## Error handling

``RauthyAuthState/lastError`` accumulates the most recent error.
``rauthyErrorAlert(_:)`` automatically presents it. To present errors
inline instead:

```swift
struct LoginView: View {
    @EnvironmentObject var auth: RauthyAuthState

    var body: some View {
        VStack {
            Button("Sign in") {
                Task { await auth.signIn() }
            }
            if let error = auth.lastError {
                Text("Couldn't sign in: \(error)")
                    .foregroundStyle(.red)
            }
        }
    }
}
```

## Loading states

``RauthyAuthState/isBusy`` flips true while sign-in or sign-out is
in flight. Use to disable buttons or show progress:

```swift
Button {
    Task { await auth.signIn() }
} label: {
    if auth.isBusy {
        ProgressView()
    } else {
        Text("Sign in")
    }
}
.disabled(auth.isBusy)
```

The ``RauthyAuthGate``'s `loading` branch is shown only during
``RauthyAuthState/bootstrap()`` — between app launch and the first
storage check completing. It's NOT shown during subsequent sign-in
attempts; those flip ``RauthyAuthState/isBusy`` instead, while
``RauthyAuthState/status`` remains `.signedOut`.

## Multi-platform notes

- **iOS / tvOS / visionOS** — fully supported.
- **macOS** — core SDK works, but ``rauthyPresentationContext()`` is
  UIKit-only. macOS apps need to pass an `NSWindow` directly to
  ``RauthyClient/signIn(anchor:)`` until a v1.1 macOS modifier ships.
- **watchOS** — explicitly unsupported. `ASWebAuthenticationSession`
  is not available on watchOS.
