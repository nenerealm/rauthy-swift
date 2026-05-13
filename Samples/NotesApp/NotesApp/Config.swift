import Foundation

/// Rauthy server configuration for this sample app.
///
/// 1. Replace these values with what you registered in your Rauthy admin UI.
/// 2. The redirect URI scheme (here: `notesapp`) must ALSO be registered in
///    `Info.plist` → `URL Types`. xcodegen does this automatically via the
///    `project.yml` in this directory.
enum SampleConfig {
    /// Your Rauthy server's issuer URL. For a default Rauthy deployment, this
    /// is `https://<host>/auth/v1`.
    static let issuer = URL(string: "https://misspinkelf.com/auth/v1")!

    /// Client ID. Register a client in Rauthy's admin UI (Clients → New Client)
    /// and copy its ID here.
    ///
    /// Recommended settings for this sample:
    /// - Client Type: public
    /// - PKCE method: S256
    /// - Redirect URI: `notesapp://callback`
    /// - Allowed scopes: openid, profile, email
    /// - Algorithm: EdDSA (default)
    static let clientID = "notes-ios-app"

    /// Where Rauthy sends the user back after sign-in. Must match what's
    /// registered in the Rauthy client config exactly.
    static let redirectURI = URL(string: "notesapp://callback")!
}
