#if canImport(AuthenticationServices)
import Foundation
import AuthenticationServices
import Logging

/// Top-level entry point for the Rauthy Swift SDK.
///
/// Owns the config, storage, and cached discovery/JWKS state. Implements the
/// PKCE-with-authorization-code sign-in flow against a Rauthy instance.
///
/// Construct once per Rauthy issuer per app lifetime. Holds an actor's worth
/// of mutable state — safe to access concurrently from any task.
public actor RauthyClient {
    public let config: RauthyConfig
    private let storage: any SessionStorage
    private let urlSession: URLSession

    private var cachedDiscovery: OpenIDConfiguration?
    private var cachedJWKS: JWKSet?

    public init(
        config: RauthyConfig,
        storage: any SessionStorage = InMemoryStorage(),
        urlSession: URLSession = .shared
    ) {
        self.config = config
        self.storage = storage
        self.urlSession = urlSession
    }

    // MARK: - Sign in

    /// Drive the full authorization-code-with-PKCE sign-in flow:
    ///
    /// 1. Fetch (or use cached) discovery document.
    /// 2. Generate PKCE pair, state, nonce.
    /// 3. Open `ASWebAuthenticationSession` at the authorize endpoint.
    /// 4. On callback: verify state, extract code.
    /// 5. POST code to token endpoint with code_verifier.
    /// 6. Validate ID token signature + claims.
    /// 7. Persist token via `SessionStorage`.
    ///
    /// - Parameter anchor: The window to anchor the auth UI to.
    /// - Returns: The newly-issued token.
    public func signIn(anchor: ASPresentationAnchor) async throws -> Token {
        let discovery = try await discoveryDocument()

        let pkce = PKCE()
        let state = AuthorizationURLBuilder.randomToken()
        let nonce = AuthorizationURLBuilder.randomToken()

        let authURL = AuthorizationURLBuilder.build(
            config: config,
            discovery: discovery,
            state: state,
            nonce: nonce,
            pkce: pkce
        )

        guard let callbackScheme = config.redirectURI.scheme else {
            throw RauthyError.invalidIssuerURL
        }

        config.logger.debug("Starting auth flow", metadata: [
            "issuer": "\(config.issuer)",
            "client_id": "\(config.clientID)",
        ])

        let callbackURL = try await WebAuthBridge.authenticate(
            url: authURL,
            callbackScheme: callbackScheme,
            anchor: anchor
        )

        let (code, returnedState) = try AuthorizationURLBuilder.parseCallback(callbackURL)
        if returnedState != state {
            config.logger.warning("State mismatch — possible CSRF attempt")
            throw RauthyError.stateMismatch
        }

        let token = try await TokenExchange.exchange(
            code: code,
            verifier: pkce.codeVerifier,
            config: config,
            discovery: discovery,
            session: urlSession
        )

        if let idToken = token.idToken {
            try await validateIDToken(idToken, nonce: nonce, discovery: discovery)
        } else if config.scopes.contains("openid") {
            // openid scope was requested but no ID token came back — surprising.
            config.logger.warning("openid scope requested but no id_token returned")
        }

        try await storage.save(token)

        config.logger.info("Sign-in succeeded", metadata: [
            "sub": "\(token.idToken?.payload.sub ?? "unknown")",
        ])

        return token
    }

    // MARK: - Sign out

    /// Sign out with the given scope.
    ///
    /// - `.local`: clears the stored token only. Server-side session may persist.
    /// - `.revokeTokens`: revokes the refresh token at Rauthy's `/oidc/revoke`
    ///   endpoint per RFC 7009. Server invalidates the session; SDK clears
    ///   local storage on success.
    public func signOut(scope: SignOutScope = .local) async throws {
        let token = try await storage.load()

        switch scope {
        case .local:
            try await storage.clear()
            config.logger.info("Local sign-out complete")

        case .revokeTokens:
            guard let token else {
                // Nothing to revoke — just clear storage.
                try await storage.clear()
                return
            }
            let discovery = try await discoveryDocument()
            try await TokenRevocation.revoke(
                token: token,
                config: config,
                discovery: discovery,
                session: urlSession
            )
            try await storage.clear()
            config.logger.info("Token revocation + local sign-out complete")
        }
    }

    // MARK: - Session restoration

    /// Restore a previously-stored token from `SessionStorage`. Returns nil
    /// if no token is stored. Does NOT validate the token against the server
    /// or refresh — caller should check `Token.isExpired()` and act accordingly.
    public func restoreSession() async throws -> Token? {
        try await storage.load()
    }

    /// Get a token string that is valid right now. Auto-refreshes if the
    /// token has expired (or will expire within `graceInterval` seconds) and
    /// a refresh token is available.
    ///
    /// > Note: v0.1 does not coalesce concurrent refresh attempts. Two
    /// > parallel callers may each trigger a refresh; in practice the second
    /// > will fail (the server has already rotated the refresh token).
    /// > Single-flight coalescing arrives in v0.2.
    public func validAccessToken(graceInterval: TimeInterval = 60) async throws -> String {
        guard var token = try await storage.load() else {
            throw RauthyError.reauthenticationRequired
        }
        if token.isExpired(graceInterval: graceInterval) {
            token = try await refresh(token)
        }
        return token.accessToken
    }

    /// Explicitly refresh the current session, regardless of token expiry.
    /// Useful when an access token is rejected by your backend with 401 and
    /// you want a fresh one before deciding to log the user out.
    public func refreshSession() async throws -> Token {
        guard let token = try await storage.load() else {
            throw RauthyError.reauthenticationRequired
        }
        return try await refresh(token)
    }

    /// Fetch the current user from Rauthy's `/userinfo` endpoint.
    ///
    /// Returns a richer `User` than constructing from the ID token alone
    /// (includes `mfaEnabled` and reflects the latest server-side state).
    public func fetchUser() async throws -> User {
        let token = try await validAccessToken(graceInterval: 60)
        let discovery = try await discoveryDocument()
        guard let userinfoURL = discovery.userinfoEndpoint else {
            throw RauthyError.missingDiscoveryDocument
        }
        var request = URLRequest(url: userinfoURL)
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Accept")

        let (data, response): (Data, URLResponse)
        do {
            (data, response) = try await urlSession.data(for: request)
        } catch {
            throw RauthyError.networkUnavailable
        }

        guard let http = response as? HTTPURLResponse else {
            throw RauthyError.networkUnavailable
        }
        if http.statusCode == 401 {
            throw RauthyError.reauthenticationRequired
        }
        if http.statusCode != 200 {
            throw RauthyError.server(ServerError(
                statusCode: http.statusCode,
                message: String(data: data, encoding: .utf8)
            ))
        }
        return try User(userInfoResponse: data)
    }

    // MARK: - Internal helpers

    private func refresh(_ token: Token) async throws -> Token {
        guard let refreshToken = token.refreshToken else {
            throw RauthyError.reauthenticationRequired
        }
        let discovery = try await discoveryDocument()
        do {
            let new = try await TokenExchange.refresh(
                refreshToken: refreshToken,
                config: config,
                discovery: discovery,
                session: urlSession
            )
            try await storage.save(new)
            config.logger.debug("Token refreshed", metadata: ["expires_in": "\(new.expiresIn)"])
            return new
        } catch RauthyError.oauth(let err) where err.code == .invalidGrant {
            // Refresh token revoked or expired; user must re-auth.
            try? await storage.clear()
            throw RauthyError.reauthenticationRequired
        } catch let error as RauthyError {
            throw error
        } catch {
            throw RauthyError.tokenRefreshFailed(underlying: error)
        }
    }

    private func discoveryDocument() async throws -> OpenIDConfiguration {
        if let cached = cachedDiscovery {
            return cached
        }
        let discovery = try await OIDCDiscovery.fetch(
            issuer: config.issuer,
            session: urlSession
        )
        cachedDiscovery = discovery
        return discovery
    }

    private func jwks() async throws -> JWKSet {
        if let cached = cachedJWKS {
            return cached
        }
        let discovery = try await discoveryDocument()
        let set = try await JWKSFetcher.fetch(url: discovery.jwksURI, session: urlSession)
        cachedJWKS = set
        return set
    }

    private func validateIDToken(
        _ idToken: IDToken,
        nonce: String,
        discovery: OpenIDConfiguration
    ) async throws {
        // 1. Find a matching key. If kid miss, refetch JWKS once.
        var keySet = try await jwks()
        let kid = idToken.header.kid ?? ""
        var matchingKey = keySet.key(for: kid)

        if matchingKey == nil {
            config.logger.debug("Key id miss — refetching JWKS", metadata: ["kid": "\(kid)"])
            cachedJWKS = nil
            keySet = try await jwks()
            matchingKey = keySet.key(for: kid)
        }

        guard let key = matchingKey else {
            throw RauthyError.invalidJWT(.signatureInvalid)
        }

        // 2. Verify the cryptographic signature.
        let parts = try JWTDecoder.decode(idToken.raw)
        try JWTSignatureValidator.validate(
            parts: parts,
            algorithm: idToken.header.alg,
            jwk: key
        )

        // 3. Verify the claims.
        let context = JWTClaimsValidator.Context(
            issuer: discovery.issuer,
            clientID: config.clientID,
            nonce: nonce,
            requireVerifiedEmail: config.requireVerifiedEmail,
            allowedAlgorithms: config.allowedAlgorithms
        )
        try JWTClaimsValidator.validate(idToken, against: context)
    }
}
#endif
