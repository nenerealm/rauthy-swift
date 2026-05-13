import Foundation

/// JWT signing algorithms supported by Rauthy.
///
/// Mirrors `JwkKeyPairAlg` in the Rauthy server (`src/data/src/entity/jwk.rs`).
/// Note that ES256 (and other ECDSA variants) are intentionally absent —
/// Rauthy uses Ed25519 by default and RSA variants for legacy compatibility.
public enum SigningAlgorithm: String, Sendable, Codable, CaseIterable {
    case rs256 = "RS256"
    case rs384 = "RS384"
    case rs512 = "RS512"
    case eddsa = "EdDSA"
}
