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
    internal let storage: any SessionStorage
    internal let urlSession: URLSession

    private var cachedDiscovery: OpenIDConfiguration?
    private var cachedJWKS: JWKSet?

    /// In-flight refresh task. When non-nil, concurrent callers wait on this
    /// task instead of starting another refresh. Cleared after completion
    /// (success or failure) so subsequent callers re-fetch from storage.
    private var refreshInFlight: Task<Token, any Error>?

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
    /// - `.rpInitiated(postLogoutRedirect:)`: opens Rauthy's end-session
    ///   endpoint in `ASWebAuthenticationSession`, signs the user out server-
    ///   side, receives the post-logout redirect, then clears local storage.
    ///   Requires `anchor`.
    /// - `.full(postLogoutRedirect:)`: both revoke + RP-Initiated. Requires `anchor`.
    public func signOut(
        scope: SignOutScope = .local,
        anchor: ASPresentationAnchor? = nil
    ) async throws {
        let token = try await storage.load()

        switch scope {
        case .local:
            try await storage.clear()
            config.logger.info("Local sign-out complete")

        case .revokeTokens:
            guard let token else {
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

        case .rpInitiated(let postLogoutRedirect):
            guard let anchor else { throw RauthyError.missingPresentationContext }
            try await performRPInitiatedLogout(
                token: token,
                postLogoutRedirect: postLogoutRedirect,
                anchor: anchor
            )
            try await storage.clear()
            config.logger.info("RP-Initiated sign-out complete")

        case .full(let postLogoutRedirect):
            guard let anchor else { throw RauthyError.missingPresentationContext }
            // Try revoke first (so server invalidates even if the web flow fails).
            // Don't throw on revoke failure — we still want to drive the user
            // through RP-Initiated as a fallback.
            if let token {
                let discovery = try? await discoveryDocument()
                if let discovery {
                    try? await TokenRevocation.revoke(
                        token: token,
                        config: config,
                        discovery: discovery,
                        session: urlSession
                    )
                }
            }
            try await performRPInitiatedLogout(
                token: token,
                postLogoutRedirect: postLogoutRedirect,
                anchor: anchor
            )
            try await storage.clear()
            config.logger.info("Full sign-out (revoke + RP-Initiated) complete")
        }
    }

    private func performRPInitiatedLogout(
        token: Token?,
        postLogoutRedirect: URL,
        anchor: ASPresentationAnchor
    ) async throws {
        let discovery = try await discoveryDocument()
        guard let endpoint = discovery.endSessionEndpoint else {
            throw RauthyError.missingDiscoveryDocument
        }
        guard let callbackScheme = postLogoutRedirect.scheme else {
            throw RauthyError.invalidIssuerURL
        }

        let url = EndSessionURLBuilder.build(
            endpoint: endpoint,
            idTokenHint: token?.idToken?.raw,
            postLogoutRedirect: postLogoutRedirect,
            clientID: config.clientID
        )

        // Wait for the redirect to come back. We don't care about its
        // contents — its arrival means the server-side logout completed.
        _ = try await WebAuthBridge.authenticate(
            url: url,
            callbackScheme: callbackScheme,
            anchor: anchor
        )
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
        // Single-flight: if a refresh is already in progress, wait for its
        // result rather than firing a parallel request (the second would
        // fail because Rauthy rotates refresh tokens — first use wins).
        if let inFlight = refreshInFlight {
            return try await inFlight.value
        }

        let task = Task<Token, any Error> { [config, urlSession, storage] in
            guard let refreshToken = token.refreshToken else {
                throw RauthyError.reauthenticationRequired
            }
            let discovery = try await self.discoveryDocument()
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
                try? await storage.clear()
                throw RauthyError.reauthenticationRequired
            } catch let error as RauthyError {
                throw error
            } catch {
                throw RauthyError.tokenRefreshFailed(underlying: error)
            }
        }
        refreshInFlight = task
        defer { refreshInFlight = nil }
        return try await task.value
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
