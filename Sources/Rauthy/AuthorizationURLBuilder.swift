import Foundation

/// Constructs the URL to load in `ASWebAuthenticationSession` for the
/// authorization-code-with-PKCE flow.
public enum AuthorizationURLBuilder {
    /// Build the `/authorize` URL with all required and optional parameters.
    public static func build(
        config: RauthyConfig,
        discovery: OpenIDConfiguration,
        state: String,
        nonce: String,
        pkce: PKCE
    ) -> URL {
        var components = URLComponents(
            url: discovery.authorizationEndpoint,
            resolvingAgainstBaseURL: false
        )!

        var items = components.queryItems ?? []
        items.append(URLQueryItem(name: "response_type", value: "code"))
        items.append(URLQueryItem(name: "client_id", value: config.clientID))
        items.append(URLQueryItem(name: "redirect_uri", value: config.redirectURI.absoluteString))
        items.append(URLQueryItem(name: "scope", value: config.scopes.joined(separator: " ")))
        items.append(URLQueryItem(name: "state", value: state))
        items.append(URLQueryItem(name: "nonce", value: nonce))
        items.append(URLQueryItem(name: "code_challenge", value: pkce.codeChallenge))
        items.append(URLQueryItem(name: "code_challenge_method", value: pkce.codeChallengeMethod))
        components.queryItems = items

        // swift-format-ignore: NeverForceUnwrap
        return components.url!
    }

    /// Generate a cryptographically random state or nonce string.
    public static func randomToken(byteCount: Int = 16) -> String {
        var bytes = [UInt8](repeating: 0, count: byteCount)
        guard SecRandomCopyBytes(kSecRandomDefault, byteCount, &bytes) == errSecSuccess else {
            preconditionFailure("SecRandomCopyBytes failed — refusing to generate a predictable state/nonce")
        }
        return Data(bytes).base64URLEncodedString()
    }

    /// Extract the authorization code and state from a callback URL.
    ///
    /// Returns `(code, state)` on success or throws if the callback contained
    /// an `error` parameter (per OAuth 2.0 §4.1.2.1).
    public static func parseCallback(_ url: URL) throws -> (code: String, state: String) {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let items = components.queryItems
        else {
            throw RauthyError.oauth(OAuthError(code: .invalidRequest, description: "callback has no query parameters"))
        }

        // Accumulate rather than `Dictionary(uniqueKeysWithValues:)`: a
        // malicious or buggy caller can deliver a custom-scheme URL with
        // duplicate query parameters (`?code=a&code=b`), and the uniqueing
        // initializer traps on duplicates. Last value wins — matches how
        // most HTTP stacks (and the spec's PRECEDENCE-undefined wording)
        // resolve repeats.
        var dict: [String: String] = [:]
        for item in items {
            guard let value = item.value else { continue }
            dict[item.name] = value
        }

        if let errorCode = dict["error"] {
            let oauthCode = OAuthError.Code(rawValue: errorCode) ?? .serverError
            throw RauthyError.oauth(OAuthError(
                code: oauthCode,
                description: dict["error_description"],
                uri: dict["error_uri"].flatMap(URL.init)
            ))
        }

        guard let code = dict["code"] else {
            throw RauthyError.oauth(OAuthError(code: .invalidRequest, description: "callback missing code"))
        }
        guard let state = dict["state"] else {
            throw RauthyError.oauth(OAuthError(code: .invalidRequest, description: "callback missing state"))
        }
        return (code, state)
    }
}
