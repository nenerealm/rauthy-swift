import Foundation
import Security

/// Builds a `URLSession` configured for `LocalDevSettings` — specifically, one
/// that trusts the self-signed CA certificates listed in
/// `trustedSelfSignedCAs`. Used by `RauthyClient` when the caller passes a
/// `RauthyConfig` with `localDev` set but does not provide their own
/// `URLSession`.
///
/// **Scope.** This only handles TLS trust evaluation against caller-supplied
/// anchor certificates. It does NOT — and cannot — bypass App Transport
/// Security. If the issuer URL uses plain `http://`, the call still fails at
/// the OS layer unless the app's Info.plist grants an ATS exception
/// (`NSAppTransportSecurity` / `NSAllowsLocalNetworking`). `allowInsecureHTTP`
/// on `LocalDevSettings` is enforced by `RauthyClient`'s scheme guard, not
/// here.
///
/// **Production safety.** Only invoked when `config.localDev != nil`.
/// Production configs leave that nil, so production traffic goes through
/// `URLSession.shared` with system defaults — no anchor injection, no custom
/// delegate, identical to "no SDK in the picture."
internal enum LocalDevURLSession {
    /// Build a session that pins trust to the supplied CA certificates.
    ///
    /// If `trustedSelfSignedCAs` is empty, returns `URLSession.shared` —
    /// no point spinning up a custom delegate that doesn't change behavior.
    static func make(settings: RauthyConfig.LocalDevSettings) -> URLSession {
        if settings.trustedSelfSignedCAs.isEmpty {
            return .shared
        }
        let delegate = TrustingDelegate(trustedCAs: settings.trustedSelfSignedCAs)
        let configuration = URLSessionConfiguration.ephemeral
        return URLSession(
            configuration: configuration,
            delegate: delegate,
            delegateQueue: nil
        )
    }
}

/// URLSessionDelegate that augments the default server-trust evaluation with
/// caller-supplied anchor certificates. Matches the contract of
/// `URLSessionDelegate.urlSession(_:didReceive:completionHandler:)` for
/// server-trust challenges.
private final class TrustingDelegate: NSObject, URLSessionDelegate, @unchecked Sendable {
    private let anchorCerts: [SecCertificate]

    init(trustedCAs: [Data]) {
        self.anchorCerts = trustedCAs.compactMap { data in
            SecCertificateCreateWithData(nil, data as CFData)
        }
        super.init()
    }

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let serverTrust = challenge.protectionSpace.serverTrust
        else {
            completionHandler(.performDefaultHandling, nil)
            return
        }

        SecTrustSetAnchorCertificates(serverTrust, anchorCerts as CFArray)
        // Augment, not replace: still honor the system trust store too, so
        // a host whose chain rolls back into a public CA continues to work.
        SecTrustSetAnchorCertificatesOnly(serverTrust, false)

        var error: CFError?
        if SecTrustEvaluateWithError(serverTrust, &error) {
            completionHandler(.useCredential, URLCredential(trust: serverTrust))
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}
