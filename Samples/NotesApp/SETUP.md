# NotesApp Sample — Setup

A comprehensive iOS SwiftUI app that exercises the Rauthy Swift SDK's public
API. Use it to test against your Rauthy server, to learn what each API does in
context, or as a starting point for your own integration.

## What the app demonstrates

Three tabs, each focused on a different surface:

| Tab | SDK APIs exercised |
|---|---|
| **Profile** | `User` snapshot · `RauthyClient.pictureURL` for avatar display · `WebFlows.openAccountDashboard` handoff for editing · `RauthyAuthState.refreshUser` |
| **Settings** | `Rauthy.locale` runtime switching · `.rauthyRequiresRole/Group/Claim` view modifiers · `WebFlows.openAccountDashboard` / `openAccountURL` · all four `signOut(scope:)` modes |
| **Debug** | `@RauthyUser` property wrapper · raw user JSON · `Rauthy.locale` state · `RauthyOSLogHandler` pointer · token refresh · interactive `ClaimRule` sandbox |

Plus on the login screen: pre-login language preview showing how
`Rauthy.locale` changes error message strings in real time across English /
Simplified Chinese / Japanese.

## Step 1: Register a client in Rauthy

Open your Rauthy admin UI (e.g. `https://misspinkelf.com/auth/v1/admin/`) and
create a new client:

| Field | Value |
|-------|-------|
| Client ID | `notes-ios-app` |
| Client Type | Public (no secret) |
| Allowed Scopes | `openid`, `profile`, `email` |
| Default Scopes | `openid`, `profile`, `email` |
| Redirect URIs | `notesapp://callback` |
| Post Logout Redirect URIs | `notesapp://logged-out` *(optional — needed for "RP-Initiated Logout" sign-out mode)* |
| Allowed Origins | `notesapp://*` (or leave empty for native) |
| Token Algorithm | `EdDSA` or any of `RS256` / `RS384` / `RS512` |
| PKCE | required, `S256` only |
| Refresh Token | enabled |

> **Note:** Public client = no client secret. iOS apps can't keep secrets
> per RFC 8252, so PKCE replaces the secret.

Save and note the assigned `Client ID`.

## Step 2: Update Config.swift

`NotesApp/Config.swift`:

```swift
static let issuer = URL(string: "https://misspinkelf.com/auth/v1")!
static let clientID = "notes-ios-app"
static let redirectURI = URL(string: "notesapp://callback")!
```

Test the issuer by fetching `<issuer>/.well-known/openid-configuration` in a
browser — you should get JSON.

## Step 3: Generate the Xcode project

```bash
brew install xcodegen   # one-time
cd Samples/NotesApp
xcodegen generate
open NotesApp.xcodeproj
```

This reads `project.yml` and produces a ready-to-build `.xcodeproj` with:

- iOS 17+ deployment target (sample uses iOS 17 SwiftUI APIs; SDK itself stays iOS 16+)
- `notesapp://` URL scheme registered in Info.plist
- The local Rauthy package as a dependency
- Swift 6 strict concurrency mode

## Step 4: Build and run

```
Cmd-R in Xcode
```

Or from CLI:

```bash
xcodebuild -project NotesApp.xcodeproj -scheme NotesApp \
  -sdk iphonesimulator \
  -destination 'platform=iOS Simulator,name=iPhone 17 Pro' \
  build
```

You'll see the login screen → tap "Sign in with Rauthy" →
`ASWebAuthenticationSession` opens → log in on Rauthy → return to the three-tab
main view.

## Per-tab notes

### Profile tab

- **Read-only** display of the `User` snapshot: avatar (`RauthyClient.pictureURL`),
  username, name, email-verified, roles, and groups.
- **Manage profile in browser** opens Rauthy's hosted web account dashboard
  (`WebFlows.openAccountDashboard`). Profile, username, avatar, passwords,
  passkeys, and devices are all edited there — Rauthy's self-service endpoints
  require a session cookie / API-key, which a native OIDC Bearer token isn't,
  so the SDK hands off to the web UI instead of wrapping those mutations.

### Settings tab

- **Language picker** flips `Rauthy.locale` at runtime. Try changing it, then
  tap a button that triggers an error (e.g., sign out while offline) — the
  error message appears in the chosen language.
- **`.rauthyRequiresRole` / `Group` / `Claim`** rows: the view below each row
  is visible only if the user matches that rule. Useful for testing
  role-gated UI.
- **Web flows:** "Open account dashboard" and "Open /account/devices" launch
  Rauthy's hosted UI in Safari (reusing your existing Rauthy session) for
  profile, password, passkey, device, and account-deletion management.
- **Sign-out modes:** `local` (Keychain only) → `revokeTokens` (RFC 7009) →
  `rpInitiated` (browser end-session) → `full` (both). The `rpInitiated` /
  `full` modes require `notesapp://logged-out` to be registered as a
  post-logout redirect URI in Rauthy.

### Debug tab

- **`@RauthyUser`** demo — same `User` resolved via property wrapper instead
  of `EnvironmentObject`.
- **Locale state** shows live `Rauthy.locale` value plus a sample localized
  error string.
- **User JSON** dumps the full `User` struct as JSON for inspection.
- **Force refresh** and **Re-fetch /userinfo** exercise `client.refreshSession()`
  and `auth.refreshUser()` directly.
- **ClaimRule sandbox** lets you build a rule interactively (`any` / `none` /
  `or` / `and`) and see whether the current user matches.

## Troubleshooting

**"Sign-in error: missingDiscoveryDocument"**
- `<issuer>/.well-known/openid-configuration` isn't reachable. Check the
  issuer URL in `Config.swift`. Open it in Safari to confirm the JSON loads.

**"Sign-in error: oauth(invalid_request)"**
- The `redirect_uri` in `Config.swift` doesn't match what's registered in
  Rauthy. They must match exactly, including scheme.

**Sheet opens but loops forever / returns to login**
- Check the URL Types entry in Info.plist matches the redirect URI scheme.
- Check Rauthy's client config has `notesapp://callback` in Redirect URIs.

**"oauth(access_denied)"**
- You clicked Cancel in the Rauthy login page, OR your user account is
  disabled / not allowed to use this client.

**Sign-in succeeds but no user info shown**
- Your client may not be granted the `profile` and `email` scopes. Check
  Rauthy's client config → Allowed Scopes / Default Scopes.

**"invalidJWT(.emailNotVerified)"**
- Your Rauthy user account hasn't verified their email. Either verify
  through Rauthy's account UI, OR edit `NotesAppApp.swift` and set
  `requireVerifiedEmail: false` in the `RauthyConfig.production()` call.

**RP-Initiated logout opens a sheet that errors immediately**
- `notesapp://logged-out` isn't in Rauthy's allowed post-logout redirect URIs.

## Cleaning up

If you want to wipe the stored Keychain item (to test a fresh sign-in):

```bash
# On simulator:
xcrun simctl spawn booted security delete-generic-password \
  -s com.example.notesapp.rauthy 2>/dev/null
```

Or just delete the app from the simulator/device.

## What this demo doesn't cover

These are intentionally cut from v1.0 — see the main
[README roadmap](../../README.md#roadmap):

- DPoP token binding (v1.1)
- Multi-account support (v1.5)
- Passkey-as-sign-in flow (handled by Rauthy's web login, not the SDK)
- Forgot-password flow (requires server PoW, lives in Rauthy's web UI)
- Native account / passkey management APIs (removed — Rauthy rejects OIDC
  Bearer on `/users/{id}/self*`; use `WebFlows.openAccountDashboard` instead)
