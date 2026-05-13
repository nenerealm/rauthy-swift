import Foundation

/// Validates ID token claims against expected context (issuer, audience,
/// nonce, expiry, etc.). Stateless — pure logic given the inputs.
///
/// Separate from `JWTSignatureValidator` so each can be tested in isolation
/// and called at different points in the auth pipeline.
public enum JWTClaimsValidator {
    /// Context the validator needs to evaluate a token's claims against.
    public struct Context: Sendable {
        public let issuer: URL
        public let clientID: String
        public let nonce: String?
        public let requireVerifiedEmail: Bool
        public let allowedAlgorithms: Set<SigningAlgorithm>
        /// Clock-skew tolerance, in seconds. Default 60s matches OIDC norms.
        public let leeway: TimeInterval

        public init(
            issuer: URL,
            clientID: String,
            nonce: String?,
            requireVerifiedEmail: Bool,
            allowedAlgorithms: Set<SigningAlgorithm>,
            leeway: TimeInterval = 60
        ) {
            self.issuer = issuer
            self.clientID = clientID
            self.nonce = nonce
            self.requireVerifiedEmail = requireVerifiedEmail
            self.allowedAlgorithms = allowedAlgorithms
            self.leeway = leeway
        }
    }

    /// Validate the claims of an ID token against the given context.
    ///
    /// - Throws: `RauthyError.invalidJWT(.something)` with a specific failure
    ///   reason if any check fails.
    public static func validate(
        _ idToken: IDToken,
        against context: Context,
        now: Date = Date()
    ) throws {
        // Algorithm allowlist.
        guard context.allowedAlgorithms.contains(idToken.header.alg) else {
            throw RauthyError.invalidJWT(
                .wrongAlgorithm(
                    allowed: Array(context.allowedAlgorithms),
                    got: idToken.header.alg.rawValue
                )
            )
        }

        let claims = idToken.payload

        // Issuer check. Normalize both URLs to handle trailing-slash differences.
        if normalize(claims.iss) != normalize(context.issuer) {
            throw RauthyError.invalidJWT(
                .wrongIssuer(expected: context.issuer, got: claims.iss)
            )
        }

        // Audience must contain our client ID.
        if !claims.aud.contains(context.clientID) {
            throw RauthyError.invalidJWT(
                .wrongAudience(expected: context.clientID, got: claims.aud)
            )
        }

        // Authorized party, when present, must match our client ID.
        if let azp = claims.azp, azp != context.clientID {
            throw RauthyError.invalidJWT(
                .wrongAzp(expected: context.clientID, got: azp)
            )
        }

        // Expiry.
        if now.timeIntervalSince(claims.exp) > context.leeway {
            throw RauthyError.invalidJWT(.expired)
        }

        // Nonce: required when we sent one in the auth request.
        if let expectedNonce = context.nonce {
            guard let tokenNonce = claims.nonce else {
                throw RauthyError.invalidJWT(.missingNonce)
            }
            if tokenNonce != expectedNonce {
                throw RauthyError.invalidJWT(.nonceMismatch)
            }
        }

        // Email verification when required.
        if context.requireVerifiedEmail {
            if claims.emailVerified != true {
                throw RauthyError.invalidJWT(.emailNotVerified)
            }
        }
    }

    /// Trim a trailing slash so `https://x/` and `https://x` compare equal.
    private static func normalize(_ url: URL) -> String {
        let s = url.absoluteString
        return s.hasSuffix("/") ? String(s.dropLast()) : s
    }
}
