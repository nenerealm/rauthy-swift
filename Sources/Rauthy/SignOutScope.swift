import Foundation

/// How thoroughly to sign the user out.
///
/// v0.1 supports two modes. RP-Initiated Logout (which opens
/// `end_session_endpoint` in a browser session) arrives in v0.2.
public enum SignOutScope: Sendable, Equatable {
    /// Clear local Keychain storage only. Server-side session may still
    /// exist and could mint new tokens via refresh on another device.
    /// Fastest. No network call.
    case local

    /// Revoke the refresh token at Rauthy's `/oidc/revoke` endpoint
    /// (RFC 7009), invalidating the server-side session. Then clear local
    /// storage. Requires a network call.
    case revokeTokens
}
