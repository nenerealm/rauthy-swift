import Foundation

/// Top-level error type for all SDK operations.
///
/// Granular by design — different cases have different recovery paths. Apps
/// don't need to handle every case explicitly; most catch a few specific ones
/// (`.userCancelled`, `.reauthenticationRequired`) and treat the rest as
/// generic failures.
public enum RauthyError: Error, Sendable, LocalizedError {
    // MARK: Configuration / setup

    /// `RauthyConfig.issuer` was not a valid URL.
    case invalidIssuerURL

    /// Could not fetch `.well-known/openid-configuration` from the issuer.
    case missingDiscoveryDocument

    /// The discovery document was fetched, but its `issuer` field does not
    /// match the issuer URL the SDK was configured with. Per OIDC Discovery
    /// 1.0 §4.3, these must be identical — a mismatch indicates a misconfigured
    /// or potentially malicious IdP.
    case discoveryIssuerMismatch(expected: URL, got: URL)

    /// `signIn()` was called before a presentation anchor was set up via
    /// `.rauthyPresentationContext()` SwiftUI modifier.
    case missingPresentationContext

    // MARK: User-driven outcomes

    /// User cancelled the sign-in flow (closed the ASWebAuthenticationSession,
    /// declined biometrics, etc.).
    case userCancelled

    /// Server indicated interactive auth is required (e.g., re-consent screen).
    case userInteractionRequired

    /// State parameter returned in the callback didn't match the state we sent.
    /// Indicates a possible cross-site request forgery attempt.
    case stateMismatch

    // MARK: Network / protocol

    case networkUnavailable
    case oauth(OAuthError)
    case server(ServerError)

    // MARK: Session / token

    case sessionNotFound(id: String)
    case tokenExpired
    case tokenRefreshFailed(underlying: any Error & Sendable)
    case insufficientScope(required: [String], have: [String])

    /// Server requires the user to re-authenticate (e.g., refresh token revoked).
    /// Recovery: prompt for sign-in again.
    case reauthenticationRequired

    // MARK: JWT problems

    /// The provided string isn't a well-formed JWT. Almost always a developer bug.
    case malformedJWT(reason: String)

    /// JWT was well-formed but failed semantic validation (signature, claims, etc.).
    case invalidJWT(JWTValidationFailure)

    // MARK: Storage

    case keychainError(KeychainError)

    // MARK: Catch-all

    case unexpected(any Error & Sendable)
}

extension RauthyError: Equatable {
    public static func == (lhs: RauthyError, rhs: RauthyError) -> Bool {
        switch (lhs, rhs) {
        case (.invalidIssuerURL, .invalidIssuerURL),
             (.missingDiscoveryDocument, .missingDiscoveryDocument),
             (.missingPresentationContext, .missingPresentationContext),
             (.userCancelled, .userCancelled),
             (.userInteractionRequired, .userInteractionRequired),
             (.stateMismatch, .stateMismatch),
             (.networkUnavailable, .networkUnavailable),
             (.tokenExpired, .tokenExpired),
             (.reauthenticationRequired, .reauthenticationRequired):
            return true
        case (.discoveryIssuerMismatch(let aExp, let aGot),
              .discoveryIssuerMismatch(let bExp, let bGot)):
            return aExp == bExp && aGot == bGot
        case (.oauth(let a), .oauth(let b)):
            return a == b
        case (.server(let a), .server(let b)):
            return a == b
        case (.sessionNotFound(let a), .sessionNotFound(let b)):
            return a == b
        case (.insufficientScope(let aReq, let aHave), .insufficientScope(let bReq, let bHave)):
            return aReq == bReq && aHave == bHave
        case (.malformedJWT(let a), .malformedJWT(let b)):
            return a == b
        case (.invalidJWT(let a), .invalidJWT(let b)):
            return a == b
        case (.keychainError(let a), .keychainError(let b)):
            return a == b
        case (.tokenRefreshFailed, .tokenRefreshFailed),
             (.unexpected, .unexpected):
            // Boxed `any Error` is not Equatable. Treat same-case as equal.
            return true
        default:
            return false
        }
    }
}

/// Errors from Keychain operations.
public enum KeychainError: Error, Sendable, Equatable, LocalizedError {
    /// No item found for the given service/account.
    case itemNotFound

    /// An item with the same service/account already exists.
    case duplicateItem

    /// Access was denied (e.g., biometric authentication failed or cancelled).
    case accessDenied

    /// Operation requires user presence but app is in the background.
    /// Common when using biometric-gated storage during background refresh.
    case requiresUserPresence

    /// Other Keychain error, identified by its OSStatus code.
    case osStatus(Int32)
}

// MARK: - LocalizedError

extension RauthyError {
    public var errorDescription: String? {
        switch self {
        case .invalidIssuerURL:
            return RauthyL10n.string("error.invalidIssuerURL")
        case .missingDiscoveryDocument:
            return RauthyL10n.string("error.missingDiscoveryDocument")
        case .discoveryIssuerMismatch:
            return RauthyL10n.string("error.discoveryIssuerMismatch")
        case .missingPresentationContext:
            return RauthyL10n.string("error.missingPresentationContext")
        case .userCancelled:
            return RauthyL10n.string("error.userCancelled")
        case .userInteractionRequired:
            return RauthyL10n.string("error.userInteractionRequired")
        case .stateMismatch:
            return RauthyL10n.string("error.stateMismatch")
        case .networkUnavailable:
            return RauthyL10n.string("error.networkUnavailable")
        case .oauth(let inner):
            return inner.errorDescription
        case .server(let inner):
            return inner.errorDescription
        case .sessionNotFound:
            return RauthyL10n.string("error.sessionNotFound")
        case .tokenExpired:
            return RauthyL10n.string("error.tokenExpired")
        case .tokenRefreshFailed:
            return RauthyL10n.string("error.tokenRefreshFailed")
        case .insufficientScope:
            return RauthyL10n.string("error.insufficientScope")
        case .reauthenticationRequired:
            return RauthyL10n.string("error.reauthenticationRequired")
        case .malformedJWT:
            return RauthyL10n.string("error.malformedJWT")
        case .invalidJWT(let inner):
            return inner.errorDescription
        case .keychainError(let inner):
            return inner.errorDescription
        case .unexpected(let inner):
            return RauthyL10n.string("error.unexpected", inner.localizedDescription)
        }
    }
}

extension KeychainError {
    public var errorDescription: String? {
        switch self {
        case .itemNotFound:
            return RauthyL10n.string("keychain.itemNotFound")
        case .duplicateItem:
            return RauthyL10n.string("keychain.duplicateItem")
        case .accessDenied:
            return RauthyL10n.string("keychain.accessDenied")
        case .requiresUserPresence:
            return RauthyL10n.string("keychain.requiresUserPresence")
        case .osStatus(let code):
            return RauthyL10n.string("keychain.osStatus", String(code))
        }
    }
}
