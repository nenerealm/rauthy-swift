import Foundation

/// Parses a JWT string into its three component byte ranges.
///
/// JWT format: `<header>.<payload>.<signature>` where each segment is
/// base64url-no-pad encoded. This decoder validates only the structural
/// shape — it does NOT verify the signature or claims. Use
/// `JWTSignatureValidator` and `JWTClaimsValidator` for those.
public enum JWTDecoder {
    /// Raw byte segments of a JWT.
    public struct Parts: Sendable, Equatable {
        /// Decoded bytes of the header (typically JSON).
        public let headerBytes: Data
        /// Decoded bytes of the payload (typically JSON).
        public let payloadBytes: Data
        /// Decoded bytes of the signature.
        public let signature: Data
        /// The `header.payload` substring — used as input to signature verification.
        public let signedInput: String
    }

    /// Parse a JWT string into its three byte segments.
    ///
    /// - Throws: `RauthyError.malformedJWT` if the string doesn't have exactly
    ///   three dot-separated segments or if any segment is not valid base64url.
    public static func decode(_ token: String) throws -> Parts {
        let segments = token.split(separator: ".", omittingEmptySubsequences: false)
        guard segments.count == 3 else {
            throw RauthyError.malformedJWT(
                reason: "expected 3 dot-separated segments, got \(segments.count)"
            )
        }
        let headerSegment = String(segments[0])
        let payloadSegment = String(segments[1])
        let signatureSegment = String(segments[2])

        guard let headerBytes = Data(base64URLEncoded: headerSegment) else {
            throw RauthyError.malformedJWT(reason: "header is not valid base64url")
        }
        guard let payloadBytes = Data(base64URLEncoded: payloadSegment) else {
            throw RauthyError.malformedJWT(reason: "payload is not valid base64url")
        }
        guard let signature = Data(base64URLEncoded: signatureSegment) else {
            throw RauthyError.malformedJWT(reason: "signature is not valid base64url")
        }

        return Parts(
            headerBytes: headerBytes,
            payloadBytes: payloadBytes,
            signature: signature,
            signedInput: "\(headerSegment).\(payloadSegment)"
        )
    }

    /// Parse a JWT all the way to typed `IDToken`.
    ///
    /// This is the common entry point when handling an ID token from the
    /// `/token` endpoint. Calls `decode(_:)` first, then JSON-decodes the
    /// header and payload into typed models.
    public static func parseIDToken(_ token: String) throws -> IDToken {
        let parts = try decode(token)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970

        let header: JWTHeader
        do {
            header = try decoder.decode(JWTHeader.self, from: parts.headerBytes)
        } catch {
            throw RauthyError.malformedJWT(reason: "header JSON decode failed: \(error)")
        }

        let payload: IDTokenClaims
        do {
            payload = try decoder.decode(IDTokenClaims.self, from: parts.payloadBytes)
        } catch {
            throw RauthyError.malformedJWT(reason: "payload JSON decode failed: \(error)")
        }

        return IDToken(
            raw: token,
            header: header,
            payload: payload,
            signature: parts.signature
        )
    }
}
