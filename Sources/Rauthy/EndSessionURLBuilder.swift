import Foundation

/// Constructs the URL for Rauthy's `end_session_endpoint` per the
/// OpenID Connect RP-Initiated Logout 1.0 spec.
public enum EndSessionURLBuilder {
    /// Build the logout URL with the standard parameters.
    ///
    /// - Parameters:
    ///   - endpoint: Rauthy's end-session endpoint, from the discovery doc.
    ///   - idTokenHint: The raw ID token string for the session being ended.
    ///     Some servers require this; others fall back to the active session
    ///     cookie. Pass `nil` only if you don't have it on hand.
    ///   - postLogoutRedirect: Where Rauthy should send the user after
    ///     logout. Must match a registered post-logout redirect in the
    ///     Rauthy client config.
    ///   - clientID: This app's client ID. Included for servers that scope
    ///     the post-logout redirect by client.
    ///   - state: Optional state parameter that will be echoed in the
    ///     redirect (useful for cross-tab logout coordination; usually nil
    ///     for native apps).
    public static func build(
        endpoint: URL,
        idTokenHint: String?,
        postLogoutRedirect: URL,
        clientID: String,
        state: String? = nil
    ) -> URL {
        var components = URLComponents(url: endpoint, resolvingAgainstBaseURL: false)!
        var items = components.queryItems ?? []
        if let idTokenHint, !idTokenHint.isEmpty {
            items.append(URLQueryItem(name: "id_token_hint", value: idTokenHint))
        }
        items.append(URLQueryItem(
            name: "post_logout_redirect_uri",
            value: postLogoutRedirect.absoluteString
        ))
        items.append(URLQueryItem(name: "client_id", value: clientID))
        if let state {
            items.append(URLQueryItem(name: "state", value: state))
        }
        components.queryItems = items
        // swift-format-ignore: NeverForceUnwrap
        return components.url!
    }
}
