import Foundation

/// Calls Rauthy's `/token` endpoint with the two grant types this SDK supports:
/// `authorization_code` (sign-in) and `refresh_token` (refresh).
///
/// Does NOT validate the ID token signature — that's done separately so the
/// token endpoint can be tested in isolation from JWKS fetching.
public enum TokenExchange {
    /// Exchange an authorization code for tokens (sign-in path).
    public static func exchange(
        code: String,
        verifier: String,
        config: RauthyConfig,
        discovery: OpenIDConfiguration,
        session: URLSession = .shared,
        now: Date = Date()
    ) async throws -> Token {
        let items = [
            URLQueryItem(name: "grant_type", value: "authorization_code"),
            URLQueryItem(name: "code", value: code),
            URLQueryItem(name: "redirect_uri", value: config.redirectURI.absoluteString),
            URLQueryItem(name: "client_id", value: config.clientID),
            URLQueryItem(name: "code_verifier", value: verifier),
        ]
        return try await performTokenRequest(
            formItems: items,
            config: config,
            discovery: discovery,
            session: session,
            now: now
        )
    }

    /// Exchange a refresh token for fresh tokens.
    ///
    /// Rauthy rotates refresh tokens — the response includes a new
    /// `refresh_token` that should replace the old one. The SDK persists this
    /// atomically before returning, so a crash mid-refresh doesn't leave the
    /// user logged out.
    public static func refresh(
        refreshToken: String,
        scope: [String]? = nil,
        config: RauthyConfig,
        discovery: OpenIDConfiguration,
        session: URLSession = .shared,
        now: Date = Date()
    ) async throws -> Token {
        var items: [URLQueryItem] = [
            URLQueryItem(name: "grant_type", value: "refresh_token"),
            URLQueryItem(name: "refresh_token", value: refreshToken),
            URLQueryItem(name: "client_id", value: config.clientID),
        ]
        if let scope, !scope.isEmpty {
            items.append(URLQueryItem(name: "scope", value: scope.joined(separator: " ")))
        }
        return try await performTokenRequest(
            formItems: items,
            config: config,
            discovery: discovery,
            session: session,
            now: now
        )
    }

    // MARK: - Internal

    private static func performTokenRequest(
        formItems: [URLQueryItem],
        config: RauthyConfig,
        discovery: OpenIDConfiguration,
        session: URLSession,
        now: Date
    ) async throws -> Token {
        var formComponents = URLComponents()
        formComponents.queryItems = formItems
        guard let body = formComponents.percentEncodedQuery?.data(using: .utf8) else {
            throw RauthyError.unexpected(TokenExchangeError.failedToEncodeForm)
        }

        var request = URLRequest(url: discovery.tokenEndpoint)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
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

        if http.statusCode != 200 {
            throw decodeServerErrorResponse(statusCode: http.statusCode, data: data)
        }

        let body2: TokenResponse
        do {
            body2 = try JSONDecoder().decode(TokenResponse.self, from: data)
        } catch {
            throw RauthyError.unexpected(TokenExchangeError.failedToDecodeResponse)
        }

        if let typeString = body2.tokenType,
           typeString.caseInsensitiveCompare("bearer") != .orderedSame
        {
            throw RauthyError.server(ServerError(
                statusCode: 200,
                errorCode: "unsupported_token_type",
                message: "Server returned token_type=\(typeString); only Bearer is supported in this SDK version (DPoP arrives in v1.1)"
            ))
        }

        var idToken: IDToken? = nil
        if let idTokenString = body2.idToken {
            idToken = try JWTDecoder.parseIDToken(idTokenString)
        }

        let scope: [String]
        if let scopeString = body2.scope, !scopeString.isEmpty {
            scope = scopeString.split(separator: " ").map(String.init)
        } else {
            scope = config.scopes
        }

        return Token(
            id: UUID().uuidString,
            accessToken: body2.accessToken,
            refreshToken: body2.refreshToken,
            idToken: idToken,
            tokenType: .bearer,
            scope: scope,
            issuedAt: now,
            expiresIn: body2.expiresIn
        )
    }
}

private struct TokenResponse: Codable {
    let accessToken: String
    let refreshToken: String?
    let idToken: String?
    let tokenType: String?
    let expiresIn: TimeInterval
    let scope: String?

    private enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"
        case refreshToken = "refresh_token"
        case idToken = "id_token"
        case tokenType = "token_type"
        case expiresIn = "expires_in"
        case scope
    }
}

private enum TokenExchangeError: Error, Sendable {
    case failedToEncodeForm
    case failedToDecodeResponse
}
