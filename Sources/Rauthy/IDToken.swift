import Foundation

/// A parsed and (cryptographically) validated OIDC ID Token.
///
/// The `raw` string is the full JWT (header.payload.signature, base64url-encoded
/// with `.` separators). The other fields are decoded for convenient access.
public struct IDToken: Sendable, Codable, Equatable {
    /// The raw JWT string, as received from Rauthy.
    public let raw: String

    /// Parsed JWT header (`{"alg":..., "typ":..., "kid":...}`).
    public let header: JWTHeader

    /// Parsed claims (`{"sub":..., "email":..., ...}`).
    public let payload: IDTokenClaims

    /// Raw signature bytes (base64url-decoded). Verified against the
    /// rauthy-published JWKS at SDK boundary; stored here for completeness
    /// but not re-verified per access.
    public let signature: Data

    public init(
        raw: String,
        header: JWTHeader,
        payload: IDTokenClaims,
        signature: Data
    ) {
        self.raw = raw
        self.header = header
        self.payload = payload
        self.signature = signature
    }
}

/// The header (first segment) of a JWT.
public struct JWTHeader: Sendable, Codable, Equatable, Hashable {
    /// Signing algorithm.
    public let alg: SigningAlgorithm

    /// Token type. Usually `"JWT"`. May be absent on some tokens.
    public let typ: String?

    /// Key ID — points to a specific key in the issuer's JWKS. Required for
    /// signature validation against rotating keys.
    public let kid: String?

    public init(alg: SigningAlgorithm, typ: String? = nil, kid: String? = nil) {
        self.alg = alg
        self.typ = typ
        self.kid = kid
    }
}
