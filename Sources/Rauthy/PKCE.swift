import Foundation
import CryptoKit

/// Proof Key for Code Exchange (RFC 7636) parameters.
///
/// Generated fresh for each authorization request. The `codeVerifier` stays on
/// the device; the `codeChallenge` is sent to the authorization endpoint. When
/// the SDK exchanges the auth code for tokens, it presents `codeVerifier` —
/// the server verifies that SHA-256(verifier) matches the challenge it saw.
///
/// This prevents an attacker who intercepts the auth code from exchanging it
/// for tokens (they don't have the verifier).
public struct PKCE: Sendable, Equatable {
    /// 43–128 character base64url-no-pad string. Held by the SDK on-device.
    public let codeVerifier: String

    /// Base64url-no-pad encoding of SHA-256(codeVerifier). Sent to the server.
    public let codeChallenge: String

    /// Always `"S256"` — `"plain"` is intentionally not supported.
    public let codeChallengeMethod: String = "S256"

    /// Generate a fresh PKCE pair using 32 bytes of cryptographically secure
    /// randomness (resulting in a 43-character verifier).
    public init() {
        var bytes = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        let verifierData = Data(bytes)
        let verifier = verifierData.base64URLEncodedString()

        let hash = SHA256.hash(data: Data(verifier.utf8))
        let challenge = Data(hash).base64URLEncodedString()

        self.codeVerifier = verifier
        self.codeChallenge = challenge
    }

    /// Construct from an existing verifier. Mainly used by tests; production
    /// code calls `PKCE()` to generate a fresh pair.
    ///
    /// **Precondition:** the verifier must conform to RFC 7636 §4.1 —
    /// 43–128 characters from the set `[A-Z][a-z][0-9]-._~`. Non-conforming
    /// input traps with `preconditionFailure`. Callers who want to test
    /// validity before constructing can use `PKCE.isValidVerifier(_:)`.
    public init(codeVerifier: String) {
        precondition(
            PKCE.isValidVerifier(codeVerifier),
            "PKCE code verifier must be 43-128 chars from [A-Z][a-z][0-9]-._~ (RFC 7636 §4.1); got \(codeVerifier.count) chars"
        )
        self.codeVerifier = codeVerifier
        let hash = SHA256.hash(data: Data(codeVerifier.utf8))
        self.codeChallenge = Data(hash).base64URLEncodedString()
    }

    /// Whether `verifier` satisfies the RFC 7636 §4.1 grammar:
    /// 43–128 characters drawn from `ALPHA / DIGIT / "-" / "." / "_" / "~"`.
    /// Use this to pre-validate input from untrusted sources.
    public static func isValidVerifier(_ verifier: String) -> Bool {
        let count = verifier.count
        guard count >= 43, count <= 128 else { return false }
        for char in verifier.unicodeScalars {
            switch char {
            case "A"..."Z", "a"..."z", "0"..."9":
                continue
            case "-", ".", "_", "~":
                continue
            default:
                return false
            }
        }
        return true
    }
}
