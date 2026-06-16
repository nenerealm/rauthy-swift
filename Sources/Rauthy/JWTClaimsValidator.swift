import Foundation
import CryptoKit

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
        /// Raw access token string. Used to verify the id_token's `at_hash`
        /// claim per OIDC Core §3.1.3.6 when present. Pass `nil` to skip
        /// the binding check (e.g. when validating outside the code-flow
        /// callback where you only have an id_token in hand).
        public let accessToken: String?

        public init(
            issuer: URL,
            clientID: String,
            nonce: String?,
            requireVerifiedEmail: Bool,
            allowedAlgorithms: Set<SigningAlgorithm>,
            leeway: TimeInterval = 60,
            accessToken: String? = nil
        ) {
            self.issuer = issuer
            self.clientID = clientID
            self.nonce = nonce
            self.requireVerifiedEmail = requireVerifiedEmail
            self.allowedAlgorithms = allowedAlgorithms
            self.leeway = leeway
            self.accessToken = accessToken
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

        // Not-before: a token whose nbf is meaningfully in the future is
        // not yet usable. Within `leeway` seconds we tolerate (clock skew).
        if let nbf = claims.nbf, nbf.timeIntervalSince(now) > context.leeway {
            throw RauthyError.invalidJWT(.notYetValid)
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

        // at_hash binding (OIDC Core §3.1.3.6). Skip if either side is
        // absent — the claim is OPTIONAL per spec, and a caller validating
        // an id_token in isolation (no access_token in hand) has nothing
        // to compare against.
        if let claimed = claims.atHash, let accessToken = context.accessToken {
            let computed = computeAtHash(
                accessToken: accessToken,
                algorithm: idToken.header.alg
            )
            if computed != claimed {
                throw RauthyError.invalidJWT(.atHashMismatch)
            }
        }

        // Email verification when required.
        if context.requireVerifiedEmail {
            if claims.emailVerified != true {
                throw RauthyError.invalidJWT(.emailNotVerified)
            }
        }
    }

    /// Compute `at_hash` per OIDC Core §3.1.3.6: take the hash that matches
    /// the JOSE `alg` parameter, keep the left half of the digest, and
    /// base64url-encode it.
    ///
    /// - RS256 → SHA-256 / 16 bytes
    /// - RS384 → SHA-384 / 24 bytes
    /// - RS512, EdDSA → SHA-512 / 32 bytes
    ///
    /// EdDSA (Ed25519) hashes with SHA-512 internally, and Rauthy maps
    /// `EdDSA → Sha512` for `at_hash` (see Rauthy `src/service/src/token_set.rs`,
    /// `AtHashAlg::try_from`), taking the left 32 of 64 bytes. Rauthy DOES emit
    /// `at_hash` (verified against a live EdDSA token), so this MUST match —
    /// using SHA-256 here produces `.atHashMismatch`.
    internal static func computeAtHash(
        accessToken: String,
        algorithm: SigningAlgorithm
    ) -> String {
        let bytes = Data(accessToken.utf8)
        let half: Data
        switch algorithm {
        case .rs256:
            half = Data(SHA256.hash(data: bytes).prefix(16))
        case .rs384:
            half = Data(SHA384.hash(data: bytes).prefix(24))
        case .rs512, .eddsa:
            half = Data(SHA512.hash(data: bytes).prefix(32))
        }
        return half.base64URLEncodedString()
    }

    /// Trim a trailing slash so `https://x/` and `https://x` compare equal.
    private static func normalize(_ url: URL) -> String {
        let s = url.absoluteString
        return s.hasSuffix("/") ? String(s.dropLast()) : s
    }
}
