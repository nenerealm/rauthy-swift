import Foundation
import CryptoKit

/// Cryptographic signature validation for JWTs.
///
/// v0.1 supports Ed25519 (OKP) only. RSA support (RS256/384/512) arrives in
/// a later release once RSA public-key DER encoding helpers are in place.
public enum JWTSignatureValidator {
    /// Validate the signature on a parsed JWT against the given key.
    ///
    /// - Throws: `RauthyError.invalidJWT(.signatureInvalid)` on cryptographic
    ///   failure or unsupported algorithm.
    public static func validate(
        parts: JWTDecoder.Parts,
        algorithm: SigningAlgorithm,
        jwk: JWK
    ) throws {
        switch algorithm {
        case .eddsa:
            try validateEd25519(parts: parts, jwk: jwk)
        case .rs256, .rs384, .rs512:
            // RSA validation requires DER encoding of (n, e) into a SecKey,
            // which we haven't implemented yet. Until then, reject explicitly
            // so callers see a clear failure instead of false positives.
            throw RauthyError.invalidJWT(
                .wrongAlgorithm(allowed: [.eddsa], got: algorithm.rawValue)
            )
        }
    }

    private static func validateEd25519(parts: JWTDecoder.Parts, jwk: JWK) throws {
        guard jwk.kty == "OKP", jwk.crv == "Ed25519" else {
            throw RauthyError.invalidJWT(.signatureInvalid)
        }
        guard let xValue = jwk.x,
              let publicKeyData = Data(base64URLEncoded: xValue)
        else {
            throw RauthyError.invalidJWT(.signatureInvalid)
        }

        let publicKey: Curve25519.Signing.PublicKey
        do {
            publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: publicKeyData)
        } catch {
            throw RauthyError.invalidJWT(.signatureInvalid)
        }

        let signedInput = Data(parts.signedInput.utf8)
        let isValid = publicKey.isValidSignature(parts.signature, for: signedInput)
        if !isValid {
            throw RauthyError.invalidJWT(.signatureInvalid)
        }
    }
}
