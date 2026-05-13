import Foundation

/// Base64URL encoding/decoding helpers per RFC 4648 §5 (URL-safe, no padding).
///
/// Used throughout OAuth/JWT: PKCE code_challenge, JWT header.payload.signature,
/// JWK public key components.
extension Data {
    /// Encode as base64url with no `=` padding.
    func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// Decode from base64url. Accepts strings with or without `=` padding.
    init?(base64URLEncoded string: String) {
        var s = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let padLength = (4 - s.count % 4) % 4
        s.append(String(repeating: "=", count: padLength))
        self.init(base64Encoded: s)
    }
}
