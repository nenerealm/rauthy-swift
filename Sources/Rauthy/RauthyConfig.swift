import Foundation
import Logging

/// Top-level SDK configuration. Pass one to `RauthyClient` at construction time.
///
/// Use the static factories (`.production`, `.development`) for the common cases.
/// The full `init` is available when you need finer control.
public struct RauthyConfig: Sendable {
    /// The Rauthy issuer URL. The SDK will fetch
    /// `<issuer>/.well-known/openid-configuration` from this base.
    public let issuer: URL

    /// Client ID registered in Rauthy's admin UI for this app.
    public let clientID: String

    /// Redirect URI registered in Rauthy for this app. Must match exactly.
    /// Custom schemes work everywhere; HTTPS callbacks require iOS 17.4+.
    public let redirectURI: URL

    /// Scopes to request at sign-in. `openid` is mandatory; the rest are
    /// optional and depend on what your app needs.
    public let scopes: [String]

    /// If `true`, tokens with `email_verified: false` (or absent) are rejected
    /// at validation time. Matches Rauthy's strict default.
    public let requireVerifiedEmail: Bool

    /// JWT signing algorithms accepted from Rauthy. Tokens signed with any
    /// other algorithm are rejected at validation time.
    public let allowedAlgorithms: Set<SigningAlgorithm>

    /// Required: rule that gates whether an authenticated user may use this
    /// app at all. **Enforced at sign-in** — a user who does not satisfy this
    /// rule is rejected with `RauthyError.notAuthorized`. Pass `.any` to admit
    /// any Rauthy user.
    ///
    /// Note: `.group(...)` / `.role(...)` rules are evaluated against the ID
    /// token's `groups` / `roles` claims, which are only present when the
    /// matching scope was requested. Request the `groups` scope (and ensure
    /// Rauthy emits `roles`) when gating on them — otherwise use `.any`.
    public let userClaim: ClaimRule

    /// Required: rule that determines whether the user is an admin. Used by
    /// your own checks and the SwiftUI claim gates. Pass `.none` if the app
    /// has no admin concept.
    public let adminClaim: ClaimRule

    /// Optional local-dev settings. Set to `nil` for production builds.
    public let localDev: LocalDevSettings?

    /// Logger for SDK diagnostic output. Wire to your app's logging backend
    /// (OSLog, Sentry, Datadog, etc.) via swift-log handlers.
    public let logger: Logger

    public init(
        issuer: URL,
        clientID: String,
        redirectURI: URL,
        scopes: [String] = ["openid", "profile", "email"],
        requireVerifiedEmail: Bool = true,
        allowedAlgorithms: Set<SigningAlgorithm> = Set(SigningAlgorithm.allCases),
        userClaim: ClaimRule,
        adminClaim: ClaimRule,
        localDev: LocalDevSettings? = nil,
        logger: Logger = Logger(label: "rauthy.swift")
    ) {
        self.issuer = issuer
        self.clientID = clientID
        self.redirectURI = redirectURI
        self.scopes = scopes
        self.requireVerifiedEmail = requireVerifiedEmail
        self.allowedAlgorithms = allowedAlgorithms
        self.userClaim = userClaim
        self.adminClaim = adminClaim
        self.localDev = localDev
        self.logger = logger
    }

    /// Standard production config. Use this 99% of the time.
    public static func production(
        issuer: URL,
        clientID: String,
        redirectURI: URL,
        scopes: [String] = ["openid", "profile", "email"],
        allowedAlgorithms: Set<SigningAlgorithm> = Set(SigningAlgorithm.allCases),
        userClaim: ClaimRule,
        adminClaim: ClaimRule,
        logger: Logger = Logger(label: "rauthy.swift")
    ) -> Self {
        Self(
            issuer: issuer,
            clientID: clientID,
            redirectURI: redirectURI,
            scopes: scopes,
            allowedAlgorithms: allowedAlgorithms,
            userClaim: userClaim,
            adminClaim: adminClaim,
            logger: logger
        )
    }

    /// Localhost Rauthy dev preset. Use when running Rauthy via
    /// `docker run -it --rm -e LOCAL_TEST=true -p 8443:8443 ghcr.io/sebadob/rauthy`.
    ///
    /// Enables `allowInsecureHTTP` for the localhost case and uses Rauthy's
    /// default local dev client.
    public static func development(
        port: Int = 8443,
        clientID: String = "dev-test",
        redirectURI: URL,
        userClaim: ClaimRule = .any,
        adminClaim: ClaimRule = .none,
        logger: Logger = Logger(label: "rauthy.swift")
    ) -> Self {
        let issuer = URL(string: "https://localhost:\(port)/auth/v1")!
        return Self(
            issuer: issuer,
            clientID: clientID,
            redirectURI: redirectURI,
            scopes: ["openid", "profile", "email"],
            requireVerifiedEmail: false,
            userClaim: userClaim,
            adminClaim: adminClaim,
            localDev: LocalDevSettings(allowInsecureHTTP: true, trustedSelfSignedCAs: []),
            logger: logger
        )
    }

    /// Settings that only apply to local development. Should not be present
    /// in production configs.
    ///
    /// Two knobs, both enforced by `RauthyClient`:
    ///
    /// - ``allowInsecureHTTP`` is a precondition gate: `RauthyClient.init`
    ///   refuses to construct against a plain-HTTP issuer URL unless this is
    ///   `true`. Catches the "I copy-pasted dev config to prod" footgun.
    /// - ``trustedSelfSignedCAs`` is consumed when `RauthyClient.init` derives
    ///   its default `URLSession` — the session pins server trust against
    ///   those anchor certificates so a Rauthy instance with its own CA
    ///   (`LOCAL_TEST=true`) doesn't trip TLS validation. Pass your own
    ///   `URLSession` to `init` to override.
    ///
    /// Note that this does NOT bypass App Transport Security. If your issuer
    /// is `http://...`, you still need an `NSAppTransportSecurity` exception
    /// in your app's Info.plist (or use `NSAllowsLocalNetworking` for the
    /// localhost case).
    public struct LocalDevSettings: Sendable {
        /// Allow plain `http://` issuer URLs at `RauthyClient.init` time.
        /// Required for localhost dev where you don't have a TLS cert. Has
        /// no effect on ATS — configure your Info.plist separately.
        public let allowInsecureHTTP: Bool

        /// Self-signed CA certificates (DER-encoded) to add as trust anchors
        /// when talking to the issuer. Applied via a URLSession delegate that
        /// `RauthyClient` constructs for you. Use when running Rauthy with
        /// `LOCAL_TEST=true` (it generates its own CA on first start —
        /// usually written to `rauthy.local.dev.pem` or similar).
        public let trustedSelfSignedCAs: [Data]

        public init(allowInsecureHTTP: Bool, trustedSelfSignedCAs: [Data]) {
            self.allowInsecureHTTP = allowInsecureHTTP
            self.trustedSelfSignedCAs = trustedSelfSignedCAs
        }
    }
}
