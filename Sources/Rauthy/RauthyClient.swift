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
    /// `config` never changes after construction; readable without awaiting
    /// the actor so synchronous URL builders (avatar URL, account dashboard
    /// URL) can use it from any context.
    public nonisolated let config: RauthyConfig
    internal let storage: any SessionStorage
    internal let urlSession: URLSession

    /// How long the cached discovery document stays fresh. After this
    /// elapses, the next `discoveryDocument()` call refetches. JWKS is also
    /// cleared on the same beat (kid rotation usually coincides with
    /// endpoint config changes, and the cache is small).
    private let discoveryTTL: TimeInterval

    private var cachedDiscovery: (config: OpenIDConfiguration, fetchedAt: Date)?
    private var cachedJWKS: JWKSet?

    /// In-flight refresh task. When non-nil, concurrent callers wait on this
    /// task instead of starting another refresh. Cleared after completion
    /// (success or failure) so subsequent callers re-fetch from storage.
    private var refreshInFlight: Task<Token, any Error>?

    public init(
        config: RauthyConfig,
        storage: any SessionStorage = InMemoryStorage(),
        urlSession: URLSession? = nil,
        discoveryTTL: TimeInterval = 3600
    ) {
        Self.validateIssuerScheme(config: config)
        self.config = config
        self.storage = storage
        self.urlSession = urlSession ?? Self.defaultURLSession(for: config)
        self.discoveryTTL = discoveryTTL
    }

    /// Drop the cached discovery document and JWKS, forcing the next call to
    /// refetch from the issuer. Useful when you know the IdP config has
    /// changed (rotation, redeploy) and don't want to wait for the TTL.
    public func invalidateDiscoveryCache() {
        cachedDiscovery = nil
        cachedJWKS = nil
    }

    /// Build the public URL for downloading a user's avatar. Synchronous —
    /// doesn't need an access token because picture downloads are public.
    /// Use with `AsyncImage` or `URLSession`. Account/avatar *management*
    /// lives in Rauthy's web dashboard (see `Browser.openAccountDashboard`).
    public nonisolated func pictureURL(userID: String, pictureID: String) -> URL {
        let baseString = config.issuer.absoluteString
        let trimmedBase = baseString.hasSuffix("/")
            ? String(baseString.dropLast())
            : baseString
        let safeUser = userID.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed)
            ?? userID
        let safePicture = pictureID.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed)
            ?? pictureID
        // swift-format-ignore: NeverForceUnwrap
        return URL(string: "\(trimmedBase)/users/\(safeUser)/picture/\(safePicture)")!
    }

    /// Derive a URLSession from `config.localDev`. With no localDev settings,
    /// returns `URLSession.shared`. With `trustedSelfSignedCAs` populated,
    /// returns a session whose delegate evaluates server trust against those
    /// anchor certificates. Callers can still override by passing a custom
    /// session to `init`.
    private static func defaultURLSession(for config: RauthyConfig) -> URLSession {
        if let localDev = config.localDev {
            return LocalDevURLSession.make(settings: localDev)
        }
        return .shared
    }

    /// Refuse to construct a client against a plain-HTTP issuer unless
    /// `localDev.allowInsecureHTTP` is explicitly true. This catches the
    /// "I copy-pasted the dev config into production" footgun before any
    /// network traffic happens. Reachable via the standard `init`, so it
    /// also runs for callers who built their own `RauthyConfig`.
    private static func validateIssuerScheme(config: RauthyConfig) {
        switch issuerSchemeValidation(for: config) {
        case .ok:
            return
        case .insecureHTTPNotAllowed(let url):
            preconditionFailure(
                "RauthyConfig.issuer uses insecure http:// (\(url)) but localDev.allowInsecureHTTP is not enabled. Use RauthyConfig.development(...) for local testing, or change the issuer to https://."
            )
        case .unsupportedScheme(let url):
            preconditionFailure(
                "RauthyConfig.issuer must use http(s):// scheme; got \(url)"
            )
        }
    }

    /// Non-trapping form of the issuer scheme check, exposed `internal` so
    /// the test target can exercise each branch without crashing the suite.
    /// `validateIssuerScheme` wraps this and turns failures into
    /// `preconditionFailure` calls.
    internal enum IssuerSchemeValidation: Equatable, Sendable {
        case ok
        case insecureHTTPNotAllowed(URL)
        case unsupportedScheme(URL)
    }

    internal static func issuerSchemeValidation(
        for config: RauthyConfig
    ) -> IssuerSchemeValidation {
        let scheme = config.issuer.scheme?.lowercased() ?? ""
        switch scheme {
        case "https":
            return .ok
        case "http":
            return config.localDev?.allowInsecureHTTP == true
                ? .ok
                : .insecureHTTPNotAllowed(config.issuer)
        default:
            return .unsupportedScheme(config.issuer)
        }
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
    /// - Parameters:
    ///   - anchor: The window to anchor the auth UI to.
    ///   - prefersEphemeralWebBrowserSession: When `true`, no cookies are
    ///     shared with Safari — the auth sheet runs in a sandboxed jar.
    ///     Recommended when you want every sign-in to require a fresh
    ///     credential entry (no "auto-selected from prior session" footgun).
    ///     Defaults to `false` to match `ASWebAuthenticationSession`'s own
    ///     default — set `true` for security-sensitive apps.
    /// - Returns: The newly-issued token.
    public func signIn(
        anchor: ASPresentationAnchor,
        prefersEphemeralWebBrowserSession: Bool = false
    ) async throws -> Token {
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
            anchor: anchor,
            prefersEphemeralWebBrowserSession: prefersEphemeralWebBrowserSession
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
            try await validateIDToken(
                idToken,
                accessToken: token.accessToken,
                nonce: nonce,
                discovery: discovery
            )
        } else if config.scopes.contains("openid") {
            // openid scope was requested but no ID token came back — surprising.
            config.logger.warning("openid scope requested but no id_token returned")
        }

        try await storage.save(token)

        // Sub is a stable user identifier; log at info without it (the fact
        // that sign-in succeeded is the part most monitoring cares about),
        // include sub only at debug for diagnostic spelunking. OSLogHandler
        // marks metadata `.public`, so info-level identifiers would be
        // visible in Console.app on shipped builds.
        config.logger.info("Sign-in succeeded")
        config.logger.debug("Sign-in token issued", metadata: [
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
            // through RP-Initiated as a fallback — but log it so operators
            // can see the server-side session may be lingering.
            var revokeSucceeded = false
            if let token {
                do {
                    let discovery = try await discoveryDocument()
                    try await TokenRevocation.revoke(
                        token: token,
                        config: config,
                        discovery: discovery,
                        session: urlSession
                    )
                    revokeSucceeded = true
                } catch {
                    config.logger.warning(
                        "Token revocation failed during .full sign-out; continuing with RP-Initiated",
                        metadata: ["error": "\(error)"]
                    )
                }
            }
            try await performRPInitiatedLogout(
                token: token,
                postLogoutRedirect: postLogoutRedirect,
                anchor: anchor
            )
            try await storage.clear()
            config.logger.info(
                "Full sign-out complete",
                metadata: ["revoked": "\(revokeSucceeded)"]
            )
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
    /// Concurrent callers coalesce into a single refresh: the second caller
    /// awaits the first call's result rather than firing a parallel refresh
    /// (which would fail anyway — Rauthy rotates refresh tokens, so first
    /// use wins). See `parallelCallersCoalesce` test.
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
        if let cached = cachedDiscovery,
           Date().timeIntervalSince(cached.fetchedAt) < discoveryTTL {
            return cached.config
        }
        let discovery = try await OIDCDiscovery.fetch(
            issuer: config.issuer,
            session: urlSession
        )
        cachedDiscovery = (discovery, Date())
        // Endpoint rotation often coincides with JWKS rotation; drop the
        // JWKS cache too so the next signature check picks up new keys.
        cachedJWKS = nil
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
        accessToken: String,
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

        // 3. Verify the claims. The validation context pins issuer to the
        // user-configured value (the root of authority), not the discovery
        // document's issuer field. Discovery already verifies those match
        // (`RauthyError.discoveryIssuerMismatch`), so this is defense in
        // depth — if the discovery cache is somehow stale or compromised,
        // the token-side check still anchors against config.
        let context = JWTClaimsValidator.Context(
            issuer: config.issuer,
            clientID: config.clientID,
            nonce: nonce,
            requireVerifiedEmail: config.requireVerifiedEmail,
            allowedAlgorithms: config.allowedAlgorithms,
            accessToken: accessToken
        )
        try JWTClaimsValidator.validate(idToken, against: context)
    }
}
#endif
