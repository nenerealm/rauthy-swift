import Foundation

/// JSON Web Key per RFC 7517. Public-key half only (no private parameters
/// supported — this is a client SDK, not a key authority).
public struct JWK: Sendable, Codable, Equatable {
    /// Key type. `"OKP"` for Ed25519, `"RSA"` for RSA-based keys.
    public let kty: String

    /// Optional algorithm tag. May be absent — algorithm can be inferred
    /// from the JWT header instead.
    public let alg: SigningAlgorithm?

    /// Key ID. Used to match a JWT's `kid` header against the right key
    /// during rotation.
    public let kid: String?

    /// Intended use. Typically `"sig"` (signature verification) for JWKS
    /// served by an OIDC IdP.
    public let use: String?

    // OKP-only:
    /// Curve name. `"Ed25519"` for Ed25519 keys.
    public let crv: String?

    /// Public key bytes, base64url-no-pad. 32 bytes for Ed25519.
    public let x: String?

    // RSA-only:
    /// Modulus, base64url-no-pad.
    public let n: String?

    /// Public exponent, base64url-no-pad.
    public let e: String?

    public init(
        kty: String,
        alg: SigningAlgorithm? = nil,
        kid: String? = nil,
        use: String? = nil,
        crv: String? = nil,
        x: String? = nil,
        n: String? = nil,
        e: String? = nil
    ) {
        self.kty = kty
        self.alg = alg
        self.kid = kid
        self.use = use
        self.crv = crv
        self.x = x
        self.n = n
        self.e = e
    }
}

/// A JSON Web Key Set as published at an IdP's `jwks_uri`.
public struct JWKSet: Sendable, Codable, Equatable {
    public let keys: [JWK]

    public init(keys: [JWK]) {
        self.keys = keys
    }

    /// Look up a key by its `kid`. Returns nil if no match.
    public func key(for kid: String) -> JWK? {
        keys.first { $0.kid == kid }
    }
}
