import Foundation

/// Subset of OpenID Connect Discovery 1.0 metadata, scoped to the fields
/// this SDK actually uses.
///
/// Fetched from `<issuer>/.well-known/openid-configuration`.
public struct OpenIDConfiguration: Sendable, Codable, Equatable {
    public let issuer: URL
    public let authorizationEndpoint: URL
    public let tokenEndpoint: URL
    public let userinfoEndpoint: URL?
    public let jwksURI: URL
    public let endSessionEndpoint: URL?
    public let revocationEndpoint: URL?
    public let deviceAuthorizationEndpoint: URL?
    public let scopesSupported: [String]?
    public let responseTypesSupported: [String]
    public let grantTypesSupported: [String]?
    public let idTokenSigningAlgValuesSupported: [String]?
    public let codeChallengeMethodsSupported: [String]?

    public init(
        issuer: URL,
        authorizationEndpoint: URL,
        tokenEndpoint: URL,
        userinfoEndpoint: URL? = nil,
        jwksURI: URL,
        endSessionEndpoint: URL? = nil,
        revocationEndpoint: URL? = nil,
        deviceAuthorizationEndpoint: URL? = nil,
        scopesSupported: [String]? = nil,
        responseTypesSupported: [String] = ["code"],
        grantTypesSupported: [String]? = nil,
        idTokenSigningAlgValuesSupported: [String]? = nil,
        codeChallengeMethodsSupported: [String]? = nil
    ) {
        self.issuer = issuer
        self.authorizationEndpoint = authorizationEndpoint
        self.tokenEndpoint = tokenEndpoint
        self.userinfoEndpoint = userinfoEndpoint
        self.jwksURI = jwksURI
        self.endSessionEndpoint = endSessionEndpoint
        self.revocationEndpoint = revocationEndpoint
        self.deviceAuthorizationEndpoint = deviceAuthorizationEndpoint
        self.scopesSupported = scopesSupported
        self.responseTypesSupported = responseTypesSupported
        self.grantTypesSupported = grantTypesSupported
        self.idTokenSigningAlgValuesSupported = idTokenSigningAlgValuesSupported
        self.codeChallengeMethodsSupported = codeChallengeMethodsSupported
    }

    private enum CodingKeys: String, CodingKey {
        case issuer
        case authorizationEndpoint = "authorization_endpoint"
        case tokenEndpoint = "token_endpoint"
        case userinfoEndpoint = "userinfo_endpoint"
        case jwksURI = "jwks_uri"
        case endSessionEndpoint = "end_session_endpoint"
        case revocationEndpoint = "revocation_endpoint"
        case deviceAuthorizationEndpoint = "device_authorization_endpoint"
        case scopesSupported = "scopes_supported"
        case responseTypesSupported = "response_types_supported"
        case grantTypesSupported = "grant_types_supported"
        case idTokenSigningAlgValuesSupported = "id_token_signing_alg_values_supported"
        case codeChallengeMethodsSupported = "code_challenge_methods_supported"
    }
}

/// Fetches the OpenID Connect discovery document from an issuer URL.
public enum OIDCDiscovery {
    /// Fetch `<issuer>/.well-known/openid-configuration` and decode it.
    ///
    /// - Throws: `RauthyError.missingDiscoveryDocument` on network or parse failure.
    public static func fetch(
        issuer: URL,
        session: URLSession = .shared
    ) async throws -> OpenIDConfiguration {
        let url = discoveryURL(for: issuer)

        do {
            let (data, response) = try await session.data(from: url)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
                throw RauthyError.missingDiscoveryDocument
            }
            return try JSONDecoder().decode(OpenIDConfiguration.self, from: data)
        } catch is RauthyError {
            throw RauthyError.missingDiscoveryDocument
        } catch {
            throw RauthyError.missingDiscoveryDocument
        }
    }

    /// Compute the discovery document URL for a given issuer. Public for tests.
    public static func discoveryURL(for issuer: URL) -> URL {
        let issuerString = issuer.absoluteString
        let trimmed = issuerString.hasSuffix("/") ? String(issuerString.dropLast()) : issuerString
        return URL(string: "\(trimmed)/.well-known/openid-configuration")!
    }
}

/// Fetches a JWKS (JSON Web Key Set) from a URL.
public enum JWKSFetcher {
    /// Fetch and decode a JWKS document.
    public static func fetch(
        url: URL,
        session: URLSession = .shared
    ) async throws -> JWKSet {
        do {
            let (data, response) = try await session.data(from: url)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
                throw RauthyError.server(ServerError(statusCode: -1, message: "JWKS fetch failed"))
            }
            return try JSONDecoder().decode(JWKSet.self, from: data)
        } catch let error as RauthyError {
            throw error
        } catch {
            throw RauthyError.networkUnavailable
        }
    }
}
