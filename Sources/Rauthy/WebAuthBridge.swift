#if canImport(AuthenticationServices)
import Foundation
import AuthenticationServices

/// Async/await wrapper around `ASWebAuthenticationSession`.
///
/// Apple's API is delegate-based and forces a synchronous `start()` followed
/// by an async completion handler. This bridge converts it to a single
/// `async throws -> URL` call.
@MainActor
public enum WebAuthBridge {
    /// Open `url` in a sandboxed browser session and wait for a callback to
    /// `callbackScheme://...`. Returns the full callback URL on success.
    ///
    /// - Parameters:
    ///   - url: The authorization URL to load.
    ///   - callbackScheme: The custom URL scheme registered for callbacks
    ///     (e.g., `"myapp"` to match a `myapp://callback` redirect URI).
    ///     Must match the scheme of the `redirectURI` in `RauthyConfig`.
    ///   - anchor: The window to anchor the auth session UI to.
    ///   - prefersEphemeralWebBrowserSession: When `true`, no cookies are
    ///     shared with Safari. Recommended for sensitive flows where you
    ///     don't want a previously-logged-in identity to be auto-selected.
    /// - Throws: `RauthyError.userCancelled` if the user dismisses the sheet,
    ///   `RauthyError.unexpected(_)` for other framework errors.
    public static func authenticate(
        url: URL,
        callbackScheme: String,
        anchor: ASPresentationAnchor,
        prefersEphemeralWebBrowserSession: Bool = false
    ) async throws -> URL {
        let provider = AnchorProvider(anchor: anchor)

        return try await withCheckedThrowingContinuation { continuation in
            let session = ASWebAuthenticationSession(
                url: url,
                callbackURLScheme: callbackScheme
            ) { callbackURL, error in
                if let error {
                    continuation.resume(throwing: Self.map(error))
                    return
                }
                guard let callbackURL else {
                    continuation.resume(throwing: RauthyError.unexpected(WebAuthBridgeError.missingCallback))
                    return
                }
                continuation.resume(returning: callbackURL)
            }
            session.presentationContextProvider = provider
            session.prefersEphemeralWebBrowserSession = prefersEphemeralWebBrowserSession

            if !session.start() {
                continuation.resume(throwing: RauthyError.unexpected(WebAuthBridgeError.failedToStart))
            }
        }
    }

    private static func map(_ error: any Error) -> RauthyError {
        if let asError = error as? ASWebAuthenticationSessionError {
            switch asError.code {
            case .canceledLogin:
                return .userCancelled
            case .presentationContextNotProvided, .presentationContextInvalid:
                return .missingPresentationContext
            @unknown default:
                return .unexpected(asError)
            }
        }
        return .unexpected(error)
    }
}

private final class AnchorProvider: NSObject, ASWebAuthenticationPresentationContextProviding {
    let anchor: ASPresentationAnchor

    init(anchor: ASPresentationAnchor) {
        self.anchor = anchor
    }

    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        anchor
    }
}

private enum WebAuthBridgeError: Error, Sendable {
    case missingCallback
    case failedToStart
}
#endif
