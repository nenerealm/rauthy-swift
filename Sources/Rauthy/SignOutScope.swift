import Foundation

/// How thoroughly to sign the user out.
///
/// All four variants clear local Keychain storage on success. They differ in
/// what they additionally do server-side.
public enum SignOutScope: Sendable, Equatable {
    /// Clear local storage only. Server-side session may still exist and
    /// could mint new tokens via refresh on another device. Fastest, no
    /// network call. Use when you just want to "log out from this device."
    case local

    /// Revoke the refresh token at Rauthy's `/oidc/revoke` endpoint
    /// (RFC 7009), then clear local storage. Invalidates the server-side
    /// session for this client. One network call, no UI.
    case revokeTokens

    /// Drive RP-Initiated Logout 1.0: open Rauthy's `end_session_endpoint`
    /// in `ASWebAuthenticationSession`, sign the user out server-side,
    /// receive the post-logout redirect, then clear local storage.
    ///
    /// Requires an `ASPresentationAnchor` (UIWindow) to host the auth sheet.
    /// The `postLogoutRedirect` URL must:
    ///   - use a custom scheme (e.g. `myapp://logged-out`)
    ///   - be registered in the Rauthy client's "Allowed Post Logout Redirect URIs"
    ///   - also be registered in your app's `Info.plist` → URL Types
    case rpInitiated(postLogoutRedirect: URL)

    /// Both `.revokeTokens` AND `.rpInitiated` — server session cleared via
    /// both the revoke endpoint AND the end-session UI flow. Most thorough.
    ///
    /// Same anchor + redirect URL requirements as `.rpInitiated`.
    case full(postLogoutRedirect: URL)
}
