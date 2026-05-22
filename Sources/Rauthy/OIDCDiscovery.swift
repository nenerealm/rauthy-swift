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
    /// Verifies that the returned `issuer` field matches the URL the SDK
    /// fetched it from (per OIDC Discovery 1.0 §4.3). A mismatch surfaces
    /// as `RauthyError.discoveryIssuerMismatch` rather than being silently
    /// accepted — this catches misconfigured or impersonating IdPs.
    ///
    /// - Throws:
    ///   - `RauthyError.networkUnavailable` if the request itself fails at
    ///     the transport layer (DNS, TLS, timeout, no connection)
    ///   - `RauthyError.missingDiscoveryDocument` for non-200 responses or
    ///     when the JSON body fails to decode
    ///   - `RauthyError.discoveryIssuerMismatch` if the document's `issuer`
    ///     doesn't match the requested one (trailing slash tolerated)
    public static func fetch(
        issuer: URL,
        session: URLSession = .shared
    ) async throws -> OpenIDConfiguration {
        let url = discoveryURL(for: issuer)

        let decoded: OpenIDConfiguration
        do {
            let (data, response) = try await session.data(from: url)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
                throw RauthyError.missingDiscoveryDocument
            }
            decoded = try JSONDecoder().decode(OpenIDConfiguration.self, from: data)
        } catch is URLError {
            // Transport-layer failure (DNS, TLS, timeout, offline). Distinct
            // from "server returned non-200" so callers can surface a more
            // accurate "check your connection" message.
            throw RauthyError.networkUnavailable
        } catch is RauthyError {
            throw RauthyError.missingDiscoveryDocument
        } catch {
            // JSON decode or other unexpected failure — treat as missing
            // document since we can't usefully act on the issuer's response.
            throw RauthyError.missingDiscoveryDocument
        }

        guard normalizeForComparison(decoded.issuer)
            == normalizeForComparison(issuer)
        else {
            throw RauthyError.discoveryIssuerMismatch(
                expected: issuer,
                got: decoded.issuer
            )
        }
        return decoded
    }

    /// Compute the discovery document URL for a given issuer. Public for tests.
    public static func discoveryURL(for issuer: URL) -> URL {
        let issuerString = issuer.absoluteString
        let trimmed = issuerString.hasSuffix("/") ? String(issuerString.dropLast()) : issuerString
        return URL(string: "\(trimmed)/.well-known/openid-configuration")!
    }

    /// Strip a trailing slash so `https://x/auth/v1` and `https://x/auth/v1/`
    /// compare equal — Rauthy publishes the trailing-slash form, callers
    /// often configure without.
    private static func normalizeForComparison(_ url: URL) -> String {
        let s = url.absoluteString
        return s.hasSuffix("/") ? String(s.dropLast()) : s
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
