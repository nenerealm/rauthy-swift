import Foundation

/// Specific failure mode when an otherwise-well-formed JWT fails validation.
///
/// Distinguished from `RauthyError.malformedJWT` (which signals a developer bug —
/// you handed the SDK a string that wasn't a JWT at all). A `JWTValidationFailure`
/// means the structure was fine but the contents were wrong — signature failed,
/// expired, wrong issuer, etc.
public enum JWTValidationFailure: Sendable, Equatable, Error, LocalizedError {
    /// Token's `iss` claim doesn't match the configured issuer.
    case wrongIssuer(expected: URL, got: URL)

    /// Token's `aud` claim doesn't contain the expected client ID.
    case wrongAudience(expected: String, got: [String])

    /// Token's `azp` claim doesn't match the configured client ID.
    case wrongAzp(expected: String, got: String?)

    /// Token is past its `exp` time (accounting for clock skew).
    case expired

    /// Token's `nbf` (not-before) time is in the future.
    case notYetValid

    /// Cryptographic signature check failed.
    case signatureInvalid

    /// Token's `alg` header is not in the SDK's allowed set.
    case wrongAlgorithm(allowed: [SigningAlgorithm], got: String)

    /// Expected a `nonce` claim but the token had none.
    case missingNonce

    /// Token's `nonce` doesn't match the one sent in the authorization request.
    case nonceMismatch

    /// `email_verified` claim is missing or false, and the SDK requires verified email.
    case emailNotVerified

    /// A claim required by the SDK or config (e.g., `sub`) is absent.
    case missingRequiredClaim(String)

    public var errorDescription: String? {
        switch self {
        case .wrongIssuer:
            return RauthyL10n.string("jwt.wrongIssuer")
        case .wrongAudience:
            return RauthyL10n.string("jwt.wrongAudience")
        case .wrongAzp:
            return RauthyL10n.string("jwt.wrongAzp")
        case .expired:
            return RauthyL10n.string("jwt.expired")
        case .notYetValid:
            return RauthyL10n.string("jwt.notYetValid")
        case .signatureInvalid:
            return RauthyL10n.string("jwt.signatureInvalid")
        case .wrongAlgorithm:
            return RauthyL10n.string("jwt.wrongAlgorithm")
        case .missingNonce:
            return RauthyL10n.string("jwt.missingNonce")
        case .nonceMismatch:
            return RauthyL10n.string("jwt.nonceMismatch")
        case .emailNotVerified:
            return RauthyL10n.string("jwt.emailNotVerified")
        case .missingRequiredClaim:
            return RauthyL10n.string("jwt.missingRequiredClaim")
        }
    }
}
