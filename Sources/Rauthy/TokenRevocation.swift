import Foundation

/// POST to Rauthy's `/oidc/revoke` endpoint per RFC 7009.
///
/// Revoking the refresh token invalidates the server-side session — any
/// access token derived from it stops working immediately. The SDK uses this
/// for `SignOutScope.revokeTokens` and `.full`.
public enum TokenRevocation {
    /// Revoke the user's refresh token (or access token if no refresh exists).
    ///
    /// Per RFC 7009 §2.2, the server SHOULD return 200 OK regardless of whether
    /// the token was valid — exposing that information would be a leak. So we
    /// treat any non-error response as success.
    public static func revoke(
        token: Token,
        config: RauthyConfig,
        discovery: OpenIDConfiguration,
        session: URLSession = .shared
    ) async throws {
        guard let endpoint = discovery.revocationEndpoint else {
            // Rauthy publishes a revocation endpoint, but if the discovery
            // doc omits it (older versions, custom builds), surface clearly.
            throw RauthyError.missingDiscoveryDocument
        }

        // Prefer revoking the refresh token — that invalidates everything
        // derived from it. Fall back to the access token.
        let (tokenString, hint): (String, String)
        if let refresh = token.refreshToken {
            tokenString = refresh
            hint = "refresh_token"
        } else {
            tokenString = token.accessToken
            hint = "access_token"
        }

        var formComponents = URLComponents()
        formComponents.queryItems = [
            URLQueryItem(name: "token", value: tokenString),
            URLQueryItem(name: "token_type_hint", value: hint),
            URLQueryItem(name: "client_id", value: config.clientID),
        ]
        guard let body = formComponents.percentEncodedQuery?.data(using: .utf8) else {
            throw RauthyError.unexpected(TokenRevocationError.failedToEncodeForm)
        }

        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.httpBody = body

        let (data, response): (Data, URLResponse)
        do {
            (data, response) = try await session.data(for: request)
        } catch {
            throw RauthyError.networkUnavailable
        }

        guard let http = response as? HTTPURLResponse else {
            throw RauthyError.networkUnavailable
        }

        // RFC 7009: 200 means revoked (or token was already invalid).
        // Other 2xx are unusual but treat as success. 4xx/5xx = real error.
        if http.statusCode >= 400 {
            if let oauthError = try? JSONDecoder().decode(OAuthError.self, from: data) {
                throw RauthyError.oauth(oauthError)
            }
            throw RauthyError.server(ServerError(
                statusCode: http.statusCode,
                message: String(data: data, encoding: .utf8)
            ))
        }
    }
}

private enum TokenRevocationError: Error, Sendable {
    case failedToEncodeForm
}
