# NotesApp Sample — Setup

A minimal iOS SwiftUI app demonstrating the Rauthy Swift SDK against your own
Rauthy server. Walks through sign-in, displays user claims, and signs out
with token revocation.

## Step 1: Register a client in Rauthy

Open your Rauthy admin UI (e.g. `https://misspinkelf.com/auth/v1/admin/`) and
create a new client with these settings:

| Field | Value |
|-------|-------|
| Client ID | `notes-ios-app` |
| Client Type | Public (no secret) |
| Allowed Scopes | `openid`, `profile`, `email` |
| Default Scopes | `openid`, `profile`, `email` |
| Redirect URIs | `notesapp://callback` |
| Allowed Origins | `notesapp://*` (or leave empty for native) |
| Token Algorithm | `EdDSA` (Rauthy's default) |
| PKCE | required, `S256` only |
| Refresh Token | enabled (if you want sign-in to persist) |

> **Note:** Public client = no client secret. iOS apps are public clients
> per RFC 8252 — they can't keep secrets, so PKCE replaces the secret.

Save. Note the assigned `Client ID` — you'll paste it into `Config.swift`.

## Step 2: Update Config.swift

Open `NotesApp/Config.swift` and confirm/edit:

```swift
static let issuer = URL(string: "https://misspinkelf.com/auth/v1")!
static let clientID = "notes-ios-app"
static let redirectURI = URL(string: "notesapp://callback")!
```

The `issuer` is the URL Rauthy's discovery document responds on. Test by
fetching `<issuer>/.well-known/openid-configuration` in your browser — you
should get JSON.

## Step 3: Generate the Xcode project

You have two options.

### Option A — xcodegen (one command, recommended)

```bash
brew install xcodegen   # one-time
cd Samples/NotesApp
xcodegen generate
open NotesApp.xcodeproj
```

This reads `project.yml` and produces a ready-to-build `.xcodeproj` with:
- iOS 16+ deployment target
- The `notesapp://` URL scheme registered in Info.plist
- The local Rauthy package as a dependency
- Swift 6 strict concurrency

### Option B — Create the Xcode project by hand

1. Xcode → File → New → Project → iOS App
   - Product Name: `NotesApp`
   - Interface: SwiftUI
   - Language: Swift
   - Use Core Data: no
   - Include Tests: no (optional)
   - Save to: `Samples/NotesApp/` (replace the directory contents — or create elsewhere and copy the files in)

2. Delete the auto-generated `ContentView.swift` and `NotesAppApp.swift`.

3. Add the 7 source files from `Samples/NotesApp/NotesApp/`:
   - `NotesAppApp.swift`
   - `ContentView.swift`
   - `LoginView.swift`
   - `MainView.swift`
   - `AuthViewModel.swift`
   - `WindowAnchor.swift`
   - `Config.swift`

4. Add the Rauthy package as a local dependency:
   - File → Add Package Dependencies → Add Local → select `rauthy-swift/`
   - Choose the `Rauthy` library product → Add Package

5. Register the URL scheme:
   - Project navigator → NotesApp target → Info tab → URL Types
   - Click `+`
   - Identifier: `com.example.notesapp.callback`
   - URL Schemes: `notesapp`

6. Set deployment target to iOS 16.0 or later.

## Step 4: Build and run

```
Cmd-R in Xcode
```

You should see the "Sign in with Rauthy" screen. Tap it →
`ASWebAuthenticationSession` opens a sheet → Rauthy login page loads → sign in →
sheet closes → you see your user info on the Main screen → Sign Out works.

## Troubleshooting

**"Sign-in error: missingDiscoveryDocument"**
- `https://misspinkelf.com/auth/v1/.well-known/openid-configuration` isn't
  reachable. Check the issuer URL in `Config.swift`. Open it in Safari to
  confirm the JSON loads.

**"Sign-in error: oauth(invalid_request)"**
- Likely the `redirect_uri` in `Config.swift` doesn't match what's registered
  in Rauthy. They must match exactly, including scheme.

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
  through Rauthy's account UI, OR edit `AuthViewModel.swift` and set
  `requireVerifiedEmail: false` in the `RauthyConfig.production()` call.

**"invalidJWT(.wrongAlgorithm(...))"**
- v0.1 only supports EdDSA signatures. If your Rauthy is configured to issue
  RS256/384/512 tokens, you'll hit this. Either switch Rauthy's signing algorithm
  to EdDSA (Rauthy's default) or wait for v0.2 which adds RSA support.

## What this demo does NOT do (yet)

- Persistent multi-account
- DPoP token binding
- RP-Initiated Logout (the sign-out only does revocation, doesn't open the
  Rauthy end-session URL)
- Passkey registration / management
- The account dashboard web flow (change password, etc.)

These arrive in later SDK releases.

## Cleaning up

If you want to wipe the stored Keychain item (e.g., to test a fresh sign-in):

```bash
# On simulator:
xcrun simctl spawn booted security delete-generic-password \
  -s com.example.notesapp.rauthy 2>/dev/null
```

Or just delete the app from the simulator/device.
